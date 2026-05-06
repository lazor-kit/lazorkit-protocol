/**
 * Secp256r1 two-phase signing flow + auxiliary data-payload builders.
 * Mirrors sdk-legacy/src/utils/signing.ts in the kit (web3.js v2) world.
 *
 * Phase split:
 *   1. prepareSecp256r1  → builds the SHA-256 challenge to send to the
 *                          authenticator.
 *   2. finalizeSecp256r1 → consumes the WebAuthn response and produces the
 *                          auth_payload + Secp256r1 precompile instruction.
 *
 * Browser flows are intrinsically async (popups, redirects) — splitting
 * lets callers freely await between phases without closing over signing
 * state. For programmatic flows (tests, backends), `signWithSecp256r1`
 * collapses both phases into a single async call.
 */
import { type Address, type Instruction } from '@solana/kit';
import {
  buildAuthPayload,
  buildAuthPayloadPrefix,
  buildSecp256r1Challenge,
  type Secp256r1Signer,
} from './secp256r1.js';
import { AUTH_TYPE_SECP256R1 } from '../instructions/builders.js';
import { SECP256R1_PROGRAM_ADDRESS } from '../instructions/system.js';

/** Output of `prepareSecp256r1` — everything needed to call the authenticator. */
export interface PreparedSecp256r1 {
  /** SHA-256 challenge to pass to `navigator.credentials.get()`. */
  challenge: Uint8Array;
  /** Internal state preserved for the finalize step. */
  _internal: {
    slot: bigint;
    counter: number;
    sysvarIxIndex: number;
    publicKeyBytes: Uint8Array;
  };
}

/** Raw WebAuthn authenticator response — what the browser gives back. */
export interface WebAuthnResponse {
  /** 64-byte raw ECDSA signature (r || s), low-S normalized. */
  signature: Uint8Array;
  /** Authenticator data bytes from the WebAuthn response. */
  authenticatorData: Uint8Array;
  /** SHA256 of the clientDataJSON. */
  clientDataJsonHash: Uint8Array;
  /** Raw clientDataJSON bytes from the authenticator. */
  clientDataJson: Uint8Array;
}

/**
 * Phase 1: prepare the SHA-256 challenge for the authenticator.
 */
export function prepareSecp256r1(params: {
  discriminator: Uint8Array;
  signedPayload: Uint8Array;
  sysvarIxIndex: number;
  slot: bigint;
  counter: number;
  payer: Address;
  programId: Address;
  publicKeyBytes: Uint8Array;
}): PreparedSecp256r1 {
  const challengePrefix = buildAuthPayloadPrefix({
    slot: params.slot,
    counter: params.counter,
    sysvarIxIndex: params.sysvarIxIndex,
  });
  const challenge = buildSecp256r1Challenge({
    discriminator: params.discriminator,
    authPayload: challengePrefix,
    signedPayload: params.signedPayload,
    payer: params.payer,
    counter: params.counter,
    programId: params.programId,
  });
  return {
    challenge,
    _internal: {
      slot: params.slot,
      counter: params.counter,
      sysvarIxIndex: params.sysvarIxIndex,
      publicKeyBytes: params.publicKeyBytes,
    },
  };
}

/**
 * Phase 2: consume the WebAuthn response, return the auth_payload bytes
 * and the Secp256r1 precompile instruction to prepend to the transaction.
 */
export function finalizeSecp256r1(
  prepared: PreparedSecp256r1,
  response: WebAuthnResponse,
): { authPayload: Uint8Array; precompileIx: Instruction } {
  const { slot, counter, sysvarIxIndex, publicKeyBytes } = prepared._internal;

  const authPayload = buildAuthPayload({
    slot,
    counter,
    sysvarIxIndex,
    authenticatorData: response.authenticatorData,
    clientDataJson: response.clientDataJson,
  });

  const precompileMessage = concatBytes([
    response.authenticatorData,
    response.clientDataJsonHash,
  ]);
  const precompileIx = buildSecp256r1PrecompileIx(
    publicKeyBytes,
    precompileMessage,
    response.signature,
  );

  return { authPayload, precompileIx };
}

/**
 * Single-call convenience for programmatic flows (tests, backends).
 * Real browser flows should call `prepareSecp256r1` and
 * `finalizeSecp256r1` directly.
 */
export async function signWithSecp256r1(params: {
  signer: Secp256r1Signer;
  discriminator: Uint8Array;
  signedPayload: Uint8Array;
  sysvarIxIndex: number;
  slot: bigint;
  counter: number;
  payer: Address;
  programId: Address;
}): Promise<{ authPayload: Uint8Array; precompileIx: Instruction }> {
  const prepared = prepareSecp256r1({
    discriminator: params.discriminator,
    signedPayload: params.signedPayload,
    sysvarIxIndex: params.sysvarIxIndex,
    slot: params.slot,
    counter: params.counter,
    payer: params.payer,
    programId: params.programId,
    publicKeyBytes: params.signer.publicKeyBytes,
  });
  const response = await params.signer.sign(prepared.challenge);
  return finalizeSecp256r1(prepared, response);
}

// ─── Data payload builders (for instruction data fields) ─────────────

/**
 * Builds the data payload portion of an AddAuthority instruction:
 *   [type(1)][role(1)][padding(6)][credential(32)]
 *   [secp256r1Pubkey?(33)][rpIdLen?(1)][rpId?(N)]
 *
 * Used as the `signed_payload` input to `prepareSecp256r1` for AddAuthority.
 */
export function buildDataPayloadForAdd(
  newType: number,
  newRole: number,
  credentialOrPubkey: Uint8Array,
  secp256r1Pubkey?: Uint8Array,
  rpId?: string,
): Uint8Array {
  const parts: Uint8Array[] = [
    new Uint8Array([newType, newRole]),
    new Uint8Array(6),
    credentialOrPubkey,
  ];
  if (newType === AUTH_TYPE_SECP256R1 && secp256r1Pubkey) {
    parts.push(secp256r1Pubkey);
    if (rpId) {
      const rp = new TextEncoder().encode(rpId);
      parts.push(new Uint8Array([rp.length]), rp);
    }
  }
  return concatBytes(parts);
}

/**
 * Builds the data payload portion of a TransferOwnership instruction:
 *   [auth_type(1)][full_auth_data]
 */
export function buildDataPayloadForTransfer(
  newType: number,
  credentialOrPubkey: Uint8Array,
  secp256r1Pubkey?: Uint8Array,
  rpId?: string,
): Uint8Array {
  const parts: Uint8Array[] = [
    new Uint8Array([newType]),
    credentialOrPubkey,
  ];
  if (newType === AUTH_TYPE_SECP256R1 && secp256r1Pubkey) {
    parts.push(secp256r1Pubkey);
    if (rpId) {
      const rp = new TextEncoder().encode(rpId);
      parts.push(new Uint8Array([rp.length]), rp);
    }
  }
  return concatBytes(parts);
}

/**
 * Builds the data payload portion of a CreateSession instruction:
 *   [session_key(32)][expires_at(8)][actions_len(2)][actions(N)]
 */
export function buildDataPayloadForSession(
  sessionKey: Uint8Array,
  expiresAt: bigint,
  actionsBuffer?: Uint8Array,
): Uint8Array {
  const actionsLen = actionsBuffer?.length ?? 0;
  const buf = new Uint8Array(42 + actionsLen);
  buf.set(sessionKey, 0);
  new DataView(buf.buffer).setBigInt64(32, expiresAt, true);
  buf[40] = actionsLen & 0xff;
  buf[41] = (actionsLen >> 8) & 0xff;
  if (actionsBuffer && actionsLen > 0) buf.set(actionsBuffer, 42);
  return buf;
}

// ─── Secp256r1 precompile instruction ────────────────────────────────

/**
 * Builds the Solana native Secp256r1Verify precompile instruction.
 *
 * The on-chain LazorKit program reads this via sysvar instructions
 * introspection — it does not validate the signature itself, it just
 * checks that the precompile validated the same payload.
 */
export function buildSecp256r1PrecompileIx(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Instruction {
  if (signature.length !== 64) {
    throw new Error(
      `Secp256r1 signature must be 64 bytes (raw r||s), got ${signature.length}`,
    );
  }
  if (publicKey.length !== 33) {
    throw new Error(
      `Secp256r1 public key must be 33 bytes (compressed), got ${publicKey.length}`,
    );
  }
  if (message.length > 0xffff) {
    throw new Error(
      `Precompile message length must fit in u16 (got ${message.length})`,
    );
  }

  const HEADER_SIZE = 16;
  const sigOffset = HEADER_SIZE;
  const pubkeyOffset = sigOffset + 64;
  const msgOffset = pubkeyOffset + 33 + 1; // 1-byte alignment padding

  const data = new Uint8Array(HEADER_SIZE + 64 + 33 + 1 + message.length);
  const view = new DataView(data.buffer);
  let off = 0;
  data[off++] = 1; // num_signatures
  data[off++] = 0; // padding
  view.setUint16(off, sigOffset, true); off += 2;
  view.setUint16(off, 0xffff, true); off += 2; // sig_instruction_index
  view.setUint16(off, pubkeyOffset, true); off += 2;
  view.setUint16(off, 0xffff, true); off += 2;
  view.setUint16(off, msgOffset, true); off += 2;
  view.setUint16(off, message.length, true); off += 2;
  view.setUint16(off, 0xffff, true); off += 2;

  data.set(signature, sigOffset);
  data.set(publicKey, pubkeyOffset);
  data.set(message, msgOffset);

  return {
    programAddress: SECP256R1_PROGRAM_ADDRESS,
    accounts: [],
    data,
  };
}

// ─── Internal helpers ────────────────────────────────────────────────

function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
