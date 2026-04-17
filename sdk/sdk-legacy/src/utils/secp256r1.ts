import { Connection, PublicKey } from '@solana/web3.js';
import { createHash } from 'crypto';
import { PROGRAM_ID } from '../constants';

/**
 * Generates WebAuthn authenticator data for a given RP ID.
 *
 * Format: rpIdHash(32) + flags(1) + counter(4) = 37 bytes
 * - Flags: 0x01 (User Present)
 * - Counter: 0 (LazorKit uses its own odometer counter, not WebAuthn counter)
 */
export function generateAuthenticatorData(rpId: string): Uint8Array {
  const rpIdHash = createHash('sha256').update(rpId).digest();
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
 * The sign() method receives a SHA-256 challenge and must:
 * 1. Build clientDataJSON: `{ type: "webauthn.get", challenge: base64url(challenge), origin: "https://<rpId>", crossOrigin: false }`
 * 2. Compute clientDataJsonHash = SHA256(clientDataJSON)
 * 3. Sign: signature = ECDSA_SIGN(authenticatorData || clientDataJsonHash)
 * 4. Return { signature (64-byte raw r||s, low-S normalized), authenticatorData, clientDataJsonHash }
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
   * Returns { signature, authenticatorData, clientDataJsonHash, clientDataJson? }.
   *
   * If `clientDataJson` (raw bytes) is returned, the SDK uses Mode 1 (raw clientDataJSON)
   * which forwards the exact bytes to the on-chain program. This is required for real
   * browser authenticators whose clientDataJSON varies by platform.
   *
   * If `clientDataJson` is omitted, Mode 0 (on-chain reconstruction) is used.
   */
  sign(challenge: Uint8Array): Promise<{
    /** 64-byte raw ECDSA signature (r || s), low-S normalized */
    signature: Uint8Array;
    /** WebAuthn authenticator data bytes */
    authenticatorData: Uint8Array;
    /** SHA256 of the clientDataJSON */
    clientDataJsonHash: Uint8Array;
    /** Raw clientDataJSON bytes from the authenticator (enables Mode 1 if provided) */
    clientDataJson?: Uint8Array;
  }>;
}

/**
 * Reads the current odometer counter from an on-chain authority account.
 * The counter is a u32 LE at offset 8 of the AuthorityAccountHeader.
 */
export async function readAuthorityCounter(
  connection: Connection,
  authorityPda: PublicKey,
): Promise<number> {
  const info = await connection.getAccountInfo(authorityPda);
  if (!info) throw new Error(`Authority account not found: ${authorityPda.toBase58()}`);
  if (info.data.length < 12) throw new Error('Authority account data too short');
  const view = new DataView(info.data.buffer, info.data.byteOffset);
  return view.getUint32(8, true); // offset 8, little-endian, u32
}

/** Mode 1 flag: bit 7 of the flags byte signals raw clientDataJSON mode. */
export const MODE_RAW_CLIENT_DATA_JSON = 0x80;

/**
 * Builds the auth_payload bytes for a Secp256r1 operation.
 *
 * **Mode 0** (reconstructed, default):
 *   [slot(8)][counter(4)][sysvarIxIdx(1)][typeAndFlags(1)][authenticatorData(M)]
 *
 * **Mode 1** (raw clientDataJSON — pass `clientDataJson`):
 *   [slot(8)][counter(4)][sysvarIxIdx(1)][0x80(1)][authDataLen(2 LE)][authenticatorData(M)][cdjLen(2 LE)][clientDataJson(N)]
 */
export function buildAuthPayload(params: {
  slot: bigint;
  counter: number;
  sysvarIxIndex: number;
  typeAndFlags: number;
  authenticatorData: Uint8Array;
  /** If provided, builds Mode 1 (raw clientDataJSON) payload */
  clientDataJson?: Uint8Array;
}): Uint8Array {
  if (params.clientDataJson) {
    // Mode 1: raw clientDataJSON
    const authDataLen = params.authenticatorData.length;
    const cdjLen = params.clientDataJson.length;
    const totalLen = 8 + 4 + 1 + 1 + 2 + authDataLen + 2 + cdjLen;
    const buf = Buffer.alloc(totalLen);
    let offset = 0;

    buf.writeBigUInt64LE(params.slot, offset); offset += 8;
    buf.writeUInt32LE(params.counter, offset); offset += 4;
    buf.writeUInt8(params.sysvarIxIndex, offset); offset += 1;
    buf.writeUInt8(MODE_RAW_CLIENT_DATA_JSON, offset); offset += 1;
    buf.writeUInt16LE(authDataLen, offset); offset += 2;
    Buffer.from(params.authenticatorData).copy(buf, offset); offset += authDataLen;
    buf.writeUInt16LE(cdjLen, offset); offset += 2;
    Buffer.from(params.clientDataJson).copy(buf, offset);

    return new Uint8Array(buf);
  }

  // Mode 0: reconstructed clientDataJSON (existing behavior)
  const totalLen = 8 + 4 + 1 + 1 + params.authenticatorData.length;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf.writeBigUInt64LE(params.slot, offset); offset += 8;
  buf.writeUInt32LE(params.counter, offset); offset += 4;
  buf.writeUInt8(params.sysvarIxIndex, offset); offset += 1;
  buf.writeUInt8(params.typeAndFlags, offset); offset += 1;
  Buffer.from(params.authenticatorData).copy(buf, offset);

  return new Uint8Array(buf);
}

/**
 * Builds the 14-byte fixed prefix of the auth_payload for Mode 1 challenge computation.
 * The challenge must be computed BEFORE signing (we don't yet have authenticatorData/clientDataJSON),
 * so only the deterministic prefix is hashed.
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
  buf.writeUInt8(MODE_RAW_CLIENT_DATA_JSON, 13);
  return new Uint8Array(buf);
}

/**
 * Computes the SHA-256 challenge hash that must be signed by the passkey.
 *
 * Hash = SHA256(discriminator || auth_payload || signed_payload || payer || counter_le(4) || program_id)
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
  counter: number;
  programId?: PublicKey;
}): Uint8Array {
  const pid = params.programId ?? PROGRAM_ID;
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32LE(params.counter);

  const hash = createHash('sha256');
  hash.update(params.discriminator);
  hash.update(params.authPayload);
  hash.update(params.signedPayload);
  hash.update(params.payer.toBuffer());
  hash.update(counterBuf);
  hash.update(pid.toBuffer());
  return new Uint8Array(hash.digest());
}
