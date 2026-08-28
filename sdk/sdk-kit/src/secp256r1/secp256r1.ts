/**
 * Secp256r1 / WebAuthn helpers for the LazorKit kit-flavored SDK.
 *
 * Wire formats are byte-identical with sdk-legacy/src/utils/secp256r1.ts;
 * tests/secp256r1.test.ts proves byte-level parity. The kit version is
 * adapted to use kit's Address branding and to read account data from a
 * kit-style RPC client.
 */
import { createHash } from 'node:crypto';
import {
  getAddressEncoder,
  type Address,
  type Rpc,
  type GetAccountInfoApi,
} from '@solana/kit';
import { ACCOUNT_DISCRIMINATOR } from '../constants.js';

const addressEncoder = getAddressEncoder();

// ─── WebAuthn authenticator data helper ──────────────────────────────

/**
 * Generates WebAuthn authenticator data for a given RP ID.
 *
 * Format: rpIdHash(32) + flags(1) + counter(4) = 37 bytes
 * - Flags: 0x01 (User Present)
 * - Counter: 0 (LazorKit uses its own odometer counter, not WebAuthn's)
 */
export function generateAuthenticatorData(rpId: string): Uint8Array {
  const rpIdHash = createHash('sha256').update(rpId).digest();
  const data = new Uint8Array(37);
  data.set(rpIdHash, 0);
  data[32] = 0x01; // User Present flag
  // Counter bytes (33-36) stay 0
  return data;
}

// ─── Signer interface ────────────────────────────────────────────────

/**
 * Callback interface for Secp256r1 (passkey/WebAuthn) signing.
 * The SDK never touches private keys.
 *
 * Secp256r1 authorities are **passkeys only** — real browser authenticators
 * producing raw clientDataJSON. Programmatic/bot signing should use
 * Ed25519 authorities instead.
 *
 * The sign() method receives a SHA-256 challenge and must:
 *   1. Call `navigator.credentials.get({ challenge, ... })` (or platform equivalent)
 *   2. Return the raw WebAuthn response — signature, authenticatorData, and
 *      the raw clientDataJSON bytes
 */
export interface Secp256r1Signer {
  /** Compressed public key (33 bytes). */
  publicKeyBytes: Uint8Array;
  /** SHA256 of the credential ID (32 bytes) — used as PDA seed. */
  credentialIdHash: Uint8Array;
  /** RP ID string (e.g. "lazorkit.app"). */
  rpId: string;
  /** Signs the SHA-256 challenge with the passkey. */
  sign(challenge: Uint8Array): Promise<{
    /** 64-byte raw ECDSA signature (r || s), low-S normalized. */
    signature: Uint8Array;
    /** WebAuthn authenticator data bytes. */
    authenticatorData: Uint8Array;
    /** SHA256 of the clientDataJSON. */
    clientDataJsonHash: Uint8Array;
    /** Raw clientDataJSON bytes from the authenticator. */
    clientDataJson: Uint8Array;
  }>;
}

// ─── On-chain authority reads ────────────────────────────────────────

/**
 * Reads the current odometer counter from an on-chain authority account.
 * The counter is a u32 LE at offset 8 of the AuthorityAccountHeader.
 */
export async function readAuthorityCounter(
  rpc: Rpc<GetAccountInfoApi>,
  authorityPda: Address,
): Promise<number> {
  const info = await rpc
    .getAccountInfo(authorityPda, { encoding: 'base64' })
    .send();
  if (!info.value)
    throw new Error(`Authority account not found: ${authorityPda}`);
  const bytes = base64ToBytes(info.value.data[0]);
  if (bytes.length < 12) throw new Error('Authority account data too short');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(8, /* le */ true);
}

/**
 * Reads the compressed Secp256r1 public key (33 bytes) from an on-chain
 * authority account. Layout:
 *   [header(48)] [credential_id_hash(32)] [compressed_pubkey(33)] ...
 */
export async function readAuthorityPubkey(
  rpc: Rpc<GetAccountInfoApi>,
  authorityPda: Address,
): Promise<Uint8Array> {
  const info = await rpc
    .getAccountInfo(authorityPda, { encoding: 'base64' })
    .send();
  if (!info.value)
    throw new Error(`Authority account not found: ${authorityPda}`);
  const bytes = base64ToBytes(info.value.data[0]);
  // Min size = 48 (header) + 32 (credential_id_hash) + 33 (pubkey) = 113.
  if (bytes.length < 113)
    throw new Error('Authority account too small for Secp256r1');
  if (bytes[0] !== ACCOUNT_DISCRIMINATOR.AUTHORITY)
    throw new Error('Not an Authority account');
  if (bytes[1] !== 1) throw new Error('Authority is not Secp256r1');
  return bytes.slice(80, 80 + 33);
}

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// ─── Auth payload builders ───────────────────────────────────────────

/**
 * Builds the auth_payload bytes for a Secp256r1 instruction.
 *
 * Layout:
 *   [slot(8)] [counter(4)] [sysvarIxIdx(1)] [reserved(1)]
 *   [authDataLen(2 LE)] [authenticatorData(M)]
 *   [cdjLen(2 LE)] [clientDataJson(N)]
 */
export function buildAuthPayload(params: {
  slot: bigint;
  counter: number;
  sysvarIxIndex: number;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
}): Uint8Array {
  const authDataLen = params.authenticatorData.length;
  const cdjLen = params.clientDataJson.length;
  if (authDataLen > 0xffff) {
    throw new Error(
      `authenticatorData length must fit in u16 (got ${authDataLen})`,
    );
  }
  if (cdjLen > 0xffff) {
    throw new Error(`clientDataJson length must fit in u16 (got ${cdjLen})`);
  }
  const totalLen = 8 + 4 + 1 + 1 + 2 + authDataLen + 2 + cdjLen;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);
  let off = 0;

  view.setBigUint64(off, params.slot, true);
  off += 8;
  view.setUint32(off, params.counter, true);
  off += 4;
  buf[off++] = params.sysvarIxIndex;
  buf[off++] = 0x80; // reserved (formerly Mode 1 flag)
  view.setUint16(off, authDataLen, true);
  off += 2;
  buf.set(params.authenticatorData, off);
  off += authDataLen;
  view.setUint16(off, cdjLen, true);
  off += 2;
  buf.set(params.clientDataJson, off);

  return buf;
}

/**
 * Builds the 14-byte fixed prefix of the auth_payload for challenge computation.
 * Used in phase 1 of the two-phase signing flow when authenticatorData /
 * clientDataJSON are not yet known.
 */
export function buildAuthPayloadPrefix(params: {
  slot: bigint;
  counter: number;
  sysvarIxIndex: number;
}): Uint8Array {
  const buf = new Uint8Array(14);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, params.slot, true);
  view.setUint32(8, params.counter, true);
  buf[12] = params.sysvarIxIndex;
  buf[13] = 0x80;
  return buf;
}

/**
 * Computes the SHA-256 challenge hash that must be signed by the passkey.
 *
 * Hash = SHA256(
 *   discriminator || auth_payload_prefix || signed_payload ||
 *   payer || counter_le(4) || program_id
 * )
 *
 * Must exactly match the on-chain `sol_sha256` call in
 * program/src/auth/secp256r1/mod.rs.
 */
export function buildSecp256r1Challenge(params: {
  discriminator: Uint8Array;
  authPayload: Uint8Array;
  signedPayload: Uint8Array;
  payer: Address;
  counter: number;
  programId: Address;
}): Uint8Array {
  const counterBuf = new Uint8Array(4);
  new DataView(counterBuf.buffer).setUint32(0, params.counter, true);

  const hash = createHash('sha256');
  hash.update(params.discriminator);
  hash.update(params.authPayload);
  hash.update(params.signedPayload);
  hash.update(addressEncoder.encode(params.payer) as Uint8Array);
  hash.update(counterBuf);
  hash.update(addressEncoder.encode(params.programId) as Uint8Array);
  return new Uint8Array(hash.digest());
}
