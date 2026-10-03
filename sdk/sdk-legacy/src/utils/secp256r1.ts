import { Buffer } from 'buffer';
import { Connection, PublicKey } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2';
import { type ChallengeReadOptions, readChallengeCounter, readChallengeKey } from './challengeReads';

export type { ChallengeReadOptions } from './challengeReads';

/**
 * Generates WebAuthn authenticator data for a given RP ID.
 *
 * Format: rpIdHash(32) + flags(1) + counter(4) = 37 bytes
 * - Flags: 0x01 (User Present)
 * - Counter: 0 (LazorKit uses its own odometer counter, not WebAuthn counter)
 */
export function generateAuthenticatorData(rpId: string): Uint8Array {
  const rpIdHash = sha256(rpId);
  const data = new Uint8Array(37);
  data.set(rpIdHash, 0);
  data[32] = 0x01; // User Present flag
  // Counter bytes (33-36) stay 0
  return data;
}

/**
 * Callback interface for Secp256r1 (passkey/WebAuthn) signing.
 * The SDK never touches private keys.
 *
 * Secp256r1 authorities are **passkeys only** — real browser authenticators
 * producing raw clientDataJSON. Programmatic/bot signing should use
 * Ed25519 authorities instead.
 *
 * The sign() method receives a SHA-256 challenge and must:
 * 1. Call `navigator.credentials.get({ challenge, ... })` or the platform equivalent
 * 2. Return the raw WebAuthn response — signature, authenticatorData, and the
 *    raw clientDataJSON bytes (the on-chain program validates `challenge` and
 *    `type` fields directly from these bytes)
 *
 * Transactions only. The SDK calls `sign` with nothing but the 32-byte
 * challenge it computed for one instruction ({@link buildSecp256r1Challenge}),
 * and to the program a passkey signature over a 32-byte value approves
 * whatever instruction hashes to it. Never pass other bytes through a signer
 * that signs this way — a message, a nonce from a server, a challenge from a
 * URL. For a message the passkey signs `signedMessageChallenge(message)`; for
 * an ownership proof, `createTaggedOwnershipChallenge()`.
 */
export interface Secp256r1Signer {
  /** Compressed public key (33 bytes) */
  publicKeyBytes: Uint8Array;
  /** SHA256 of the credential ID (32 bytes) — used as PDA seed */
  credentialIdHash: Uint8Array;
  /** RP ID string (e.g. "lazorkit.app") */
  rpId: string;
  /**
   * Signs the SHA-256 challenge with the passkey: a 32-byte transaction
   * challenge the SDK computed, never caller bytes.
   * MUST return the raw `clientDataJson` bytes — the SDK no longer supports
   * the on-chain-reconstructed (Mode 0) flow.
   */
  sign(challenge: Uint8Array): Promise<{
    /** 64-byte raw ECDSA signature (r || s), low-S normalized */
    signature: Uint8Array;
    /** WebAuthn authenticator data bytes */
    authenticatorData: Uint8Array;
    /** SHA256 of the clientDataJSON */
    clientDataJsonHash: Uint8Array;
    /** Raw clientDataJSON bytes from the authenticator */
    clientDataJson: Uint8Array;
  }>;
}

/**
 * Reads the current odometer counter from an on-chain authority account.
 * The counter is a u32 LE at offset 8 of the AuthorityAccountHeader.
 *
 * Read at `opts.commitment` (default `'confirmed'`, or `'processed'` on a
 * Connection at `'processed'`) and, with `opts.minContextSlot`, from a node at
 * or past that slot: see {@link ChallengeReadOptions}.
 */
export async function readAuthorityCounter(
  connection: Connection,
  authorityPda: PublicKey,
  opts?: ChallengeReadOptions,
): Promise<number> {
  // Read with `getAccountInfoAndContext`: `getAccountInfo` rethrows RPC errors
  // without their code.
  return readChallengeCounter(connection, authorityPda, opts);
}

/**
 * Reads the compressed Secp256r1 public key (33 bytes) from an on-chain
 * authority account. Layout:
 *   [header(48)] [credential_id_hash(32)] [compressed_pubkey(33)] ...
 *
 * Throws if the account doesn't exist, isn't an Authority, or isn't a Secp256r1
 * authority. `opts` as for {@link readAuthorityCounter}: the key never changes,
 * but an authority added by the previous transaction exists only from its slot.
 */
export async function readAuthorityPubkey(
  connection: Connection,
  authorityPda: PublicKey,
  opts?: ChallengeReadOptions,
): Promise<Uint8Array> {
  return readChallengeKey(connection, authorityPda, opts);
}

/**
 * Builds the auth_payload bytes for a Secp256r1 Execute (raw clientDataJSON).
 *
 * Layout:
 *   [slot(8)][counter(4)][sysvarIxIdx(1)][reserved(1)]
 *   [authDataLen(2 LE)][authenticatorData(M)]
 *   [cdjLen(2 LE)][clientDataJson(N)]
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
  // Length fields are u16 LE — guard the upper bound so a pathological
  // authenticator response can't silently wrap and produce a malformed payload.
  if (authDataLen > 0xffff) {
    throw new Error(`authenticatorData length must fit in u16 (got ${authDataLen})`);
  }
  if (cdjLen > 0xffff) {
    throw new Error(`clientDataJson length must fit in u16 (got ${cdjLen})`);
  }
  const totalLen = 8 + 4 + 1 + 1 + 2 + authDataLen + 2 + cdjLen;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf.writeBigUInt64LE(params.slot, offset); offset += 8;
  buf.writeUInt32LE(params.counter, offset); offset += 4;
  buf.writeUInt8(params.sysvarIxIndex, offset); offset += 1;
  // Reserved byte (formerly Mode 1 flag — now always set for backwards-compatible
  // auth_payload_prefix layout).
  buf.writeUInt8(0x80, offset); offset += 1;
  buf.writeUInt16LE(authDataLen, offset); offset += 2;
  Buffer.from(params.authenticatorData).copy(buf, offset); offset += authDataLen;
  buf.writeUInt16LE(cdjLen, offset); offset += 2;
  Buffer.from(params.clientDataJson).copy(buf, offset);

  return new Uint8Array(buf);
}

/**
 * Builds the 14-byte fixed prefix of the auth_payload for challenge computation.
 * The challenge is computed BEFORE signing — at that point we don't yet have
 * authenticatorData/clientDataJSON, so only the deterministic prefix is hashed.
 */
export function buildAuthPayloadPrefix(params: {
  slot: bigint;
  counter: number;
  sysvarIxIndex: number;
}): Uint8Array {
  const buf = Buffer.alloc(14);
  buf.writeBigUInt64LE(params.slot, 0);
  buf.writeUInt32LE(params.counter, 8);
  buf.writeUInt8(params.sysvarIxIndex, 12);
  buf.writeUInt8(0x80, 13);
  return new Uint8Array(buf);
}

/**
 * Computes the SHA-256 challenge hash that must be signed by the passkey.
 *
 * Hash = SHA256(discriminator || auth_payload || signed_payload || payer || wallet
 *               || counter_le(4) || program_id)
 *
 * `wallet` is the wallet the authenticating authority belongs to — the `wallet`
 * field of its account header: the wallet PDA for every v2 instruction, the v1
 * wallet for `MigrateWallet`. Without it a signature for `CreateSession`,
 * `AddAuthority` or `TransferOwnership` — or for `Execute` or `Authorize` when
 * no inner instruction touches an account derived from the wallet — names no
 * wallet, and could be submitted again on another wallet holding the same
 * passkey at the same counter, through the same payer.
 *
 * Note: slot is already encoded as the first 8 bytes of auth_payload, so it is NOT hashed again
 * here. The previous redundant `slot_le` field was removed to keep hash inputs non-repetitive.
 * This must exactly match the on-chain `sol_sha256` call in secp256r1/mod.rs.
 */
export function buildSecp256r1Challenge(params: {
  discriminator: Uint8Array;
  authPayload: Uint8Array;
  signedPayload: Uint8Array;
  slot: bigint;
  payer: PublicKey;
  wallet: PublicKey;
  counter: number;
  programId: PublicKey;
}): Uint8Array {
  const pid = params.programId;
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32LE(params.counter);

  const hash = sha256.create();
  hash.update(params.discriminator);
  hash.update(params.authPayload);
  hash.update(params.signedPayload);
  hash.update(params.payer.toBuffer());
  hash.update(params.wallet.toBuffer());
  hash.update(counterBuf);
  hash.update(pid.toBuffer());
  return hash.digest();
}
