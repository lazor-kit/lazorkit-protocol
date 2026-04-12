import { Connection, PublicKey } from '@solana/web3.js';
import { createHash } from 'crypto';
import { PROGRAM_ID } from '../generated';

/**
 * Callback interface for Secp256r1 (passkey/WebAuthn) signing.
 * The SDK never touches private keys.
 */
export interface Secp256r1Signer {
  /** Compressed public key (33 bytes) */
  publicKeyBytes: Uint8Array;
  /** SHA256 of the credential ID (32 bytes) — used as PDA seed */
  credentialIdHash: Uint8Array;
  /** RP ID string (e.g. "lazorkit.app") */
  rpId: string;
  /**
   * Signs the SHA-256 challenge with the passkey.
   * Returns { signature, authenticatorData } from the WebAuthn assertion.
   * `signature` is the raw DER-encoded ECDSA signature.
   * `authenticatorData` is the raw authenticator data bytes.
   */
  sign(challenge: Uint8Array): Promise<{
    signature: Uint8Array;
    authenticatorData: Uint8Array;
  }>;
}

/**
 * Reads the current odometer counter from an on-chain authority account.
 * The counter is a u64 LE at offset 8 of the AuthorityAccountHeader.
 */
export async function readAuthorityCounter(
  connection: Connection,
  authorityPda: PublicKey,
): Promise<bigint> {
  const info = await connection.getAccountInfo(authorityPda);
  if (!info) throw new Error(`Authority account not found: ${authorityPda.toBase58()}`);
  if (info.data.length < 16) throw new Error('Authority account data too short');
  const view = new DataView(info.data.buffer, info.data.byteOffset);
  return view.getBigUint64(8, true); // offset 8, little-endian
}

/**
 * Builds the auth_payload bytes for a Secp256r1 operation.
 *
 * Layout:
 *   [slot(8)][counter(8)][sysvarIxIdx(1)][sysvarSlotIdx(1)]
 *   [typeAndFlags(1)][rpIdLen(1)][rpId(N)][authenticatorData(M)]
 */
export function buildAuthPayload(params: {
  slot: bigint;
  counter: bigint;
  sysvarIxIndex: number;
  sysvarSlotHashesIndex: number;
  typeAndFlags: number;
  rpId: string;
  authenticatorData: Uint8Array;
}): Uint8Array {
  const rpIdBytes = Buffer.from(params.rpId, 'utf-8');
  const totalLen =
    8 + 8 + 1 + 1 + 1 + 1 + rpIdBytes.length + params.authenticatorData.length;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf.writeBigUInt64LE(params.slot, offset);
  offset += 8;
  buf.writeBigUInt64LE(params.counter, offset);
  offset += 8;
  buf.writeUInt8(params.sysvarIxIndex, offset);
  offset += 1;
  buf.writeUInt8(params.sysvarSlotHashesIndex, offset);
  offset += 1;
  buf.writeUInt8(params.typeAndFlags, offset);
  offset += 1;
  buf.writeUInt8(rpIdBytes.length, offset);
  offset += 1;
  rpIdBytes.copy(buf, offset);
  offset += rpIdBytes.length;
  Buffer.from(params.authenticatorData).copy(buf, offset);

  return new Uint8Array(buf);
}

/**
 * Computes the SHA-256 challenge hash that must be signed by the passkey.
 *
 * Hash = SHA256(discriminator || auth_payload || signed_payload || slot_le || payer || counter_le || program_id)
 *
 * This must exactly match the on-chain `sol_sha256` call in secp256r1/mod.rs.
 */
export function buildSecp256r1Challenge(params: {
  discriminator: Uint8Array;
  authPayload: Uint8Array;
  signedPayload: Uint8Array;
  slot: bigint;
  payer: PublicKey;
  counter: bigint;
  programId?: PublicKey;
}): Uint8Array {
  const pid = params.programId ?? PROGRAM_ID;
  const slotBuf = Buffer.alloc(8);
  slotBuf.writeBigUInt64LE(params.slot);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64LE(params.counter);

  const hash = createHash('sha256');
  hash.update(params.discriminator);
  hash.update(params.authPayload);
  hash.update(params.signedPayload);
  hash.update(slotBuf);
  hash.update(params.payer.toBuffer());
  hash.update(counterBuf);
  hash.update(pid.toBuffer());
  return new Uint8Array(hash.digest());
}
