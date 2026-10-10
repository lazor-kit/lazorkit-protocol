// Program-derived addresses without @solana/web3.js: the same rule as
// `PublicKey.findProgramAddressSync` (sha256 over seeds, bump, program id and
// "ProgramDerivedAddress", first result off the ed25519 curve).

import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { base58Encode, concat, decodeAddress } from './bytes';
import { SEED_AUTHORITY, SEED_SESSION, SEED_VAULT } from './constants';

const PDA_MARKER = asciiBytes('ProgramDerivedAddress');

function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function isOnCurve(point: Uint8Array): boolean {
  try {
    ed25519.ExtendedPoint.fromHex(point);
    return true;
  } catch {
    return false;
  }
}

function addressBytes(address: string | Uint8Array, what: string): Uint8Array {
  if (typeof address !== 'string') {
    if (address.length !== 32) throw new Error(`${what} must be 32 bytes`);
    return address;
  }
  const bytes = decodeAddress(address);
  if (!bytes) throw new Error(`${what} is not a base58 address: ${address}`);
  return bytes;
}

/** `[address, bump]` for `seeds` under `programId`, as web3.js finds it. */
export function findProgramAddress(
  seeds: Uint8Array[],
  programId: string | Uint8Array,
): [Uint8Array, number] {
  const program = addressBytes(programId, 'programId');
  for (const s of seeds) if (s.length > 32) throw new Error('a seed is longer than 32 bytes');
  for (let bump = 255; bump >= 0; bump--) {
    const hash = sha256(concat([...seeds, new Uint8Array([bump]), program, PDA_MARKER]));
    if (!isOnCurve(hash)) return [hash, bump];
  }
  throw new Error('no viable bump');
}

/** SHA-256 of a WebAuthn credential id: the authority PDA's seed. */
export function credentialIdHash(credentialId: Uint8Array): Uint8Array {
  return sha256(credentialId);
}

/** The passkey authority PDA `["lk2:authority", wallet, sha256(credentialId)]`, base58. */
export function findAuthorityAddress(
  wallet: string | Uint8Array,
  credentialIdHashBytes: Uint8Array,
  programId: string | Uint8Array,
): string {
  if (credentialIdHashBytes.length !== 32) throw new Error('credentialIdHash must be 32 bytes');
  return base58Encode(
    findProgramAddress(
      [asciiBytes(SEED_AUTHORITY), addressBytes(wallet, 'wallet'), credentialIdHashBytes],
      programId,
    )[0],
  );
}

/** The session PDA `["lk2:session", wallet, sessionKey]`, base58. */
export function findSessionAddress(
  wallet: string | Uint8Array,
  sessionKey: string | Uint8Array,
  programId: string | Uint8Array,
): string {
  return base58Encode(
    findProgramAddress(
      [asciiBytes(SEED_SESSION), addressBytes(wallet, 'wallet'), addressBytes(sessionKey, 'sessionKey')],
      programId,
    )[0],
  );
}

/** The vault PDA `["lk2:vault", wallet]`, base58. */
export function findVaultAddress(wallet: string | Uint8Array, programId: string | Uint8Array): string {
  return base58Encode(
    findProgramAddress([asciiBytes(SEED_VAULT), addressBytes(wallet, 'wallet')], programId)[0],
  );
}
