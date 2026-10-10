// Decoders for the accounts a typed request is checked against, from raw
// account data (what `getMultipleAccounts` returns). Layouts follow
// program/src/state; each decoder applies the program's own header check
// (owner, discriminator, minimum length, layout version) and returns null
// when the account is not what it must be.

import { base58Encode, readI64LE, readU16LE, readU32LE, readU64LE } from './bytes';
import {
  ACCOUNT_LAYOUT_VERSION,
  DISC_AUTHORITY_ACCOUNT,
  DISC_SESSION_ACCOUNT,
  DISC_WALLET_ACCOUNT,
  SPL_TOKEN_2022_PROGRAM_ADDRESS,
  SPL_TOKEN_PROGRAM_ADDRESS,
} from './constants';

/** An account as read: base58 owner, lamports, raw data. */
export interface AccountSnapshot {
  owner: string;
  lamports: bigint;
  data: Uint8Array;
}

export interface ClockFacts {
  slot: bigint;
  /** Unix seconds by the cluster's clock. */
  unixTimestamp: bigint;
}

/** The Clock sysvar: slot at 0, unix_timestamp (i64) at 32. */
export function decodeClock(data: Uint8Array): ClockFacts | null {
  if (data.length < 40) return null;
  return { slot: readU64LE(data, 0), unixTimestamp: readI64LE(data, 32) };
}

export interface WalletFacts {
  ownerCount: number;
}

/** A v2 wallet account: discriminator 0x21, version at 2, owner_count u32 at 4. */
export function decodeWalletAccount(acc: AccountSnapshot | null | undefined, programId: string): WalletFacts | null {
  if (!acc || acc.owner !== programId) return null;
  const d = acc.data;
  if (d.length < 8 || d[0] !== DISC_WALLET_ACCOUNT || d[2] !== ACCOUNT_LAYOUT_VERSION) return null;
  return { ownerCount: readU32LE(d, 4) };
}

export type AuthorityRole = 'owner' | 'admin' | 'delegate';
const ROLES: Record<number, AuthorityRole> = { 0: 'owner', 1: 'admin', 2: 'delegate' };

export interface AuthorityFacts {
  type: 'ed25519' | 'passkey';
  role: AuthorityRole;
  /** The stored counter; a passkey signs counter + 1. */
  counter: number;
  /** The wallet this authority belongs to, base58. */
  wallet: string;
  /** Ed25519: the 32-byte key. Passkey: the 33-byte compressed key. */
  publicKey: Uint8Array;
  /** Passkey only: SHA-256 of the credential id. */
  credentialIdHash?: Uint8Array;
  /** Passkey only: SHA-256 of the rpId it was registered under. */
  rpIdHash?: Uint8Array;
  /** The policy buffer; empty when it has none. */
  policy: Uint8Array;
}

/**
 * An authority account: header (48: disc, type, role, bump, version, pad,
 * counter u32 at 8, policy_len u16 at 12, pad, wallet at 16), then for
 * Ed25519 the key (32), for a passkey credential hash (32) + compressed key
 * (33) + rpIdHash (32), then `policy_len` policy bytes.
 */
export function decodeAuthorityAccount(acc: AccountSnapshot | null | undefined, programId: string): AuthorityFacts | null {
  if (!acc || acc.owner !== programId) return null;
  const d = acc.data;
  if (d.length < 48 || d[0] !== DISC_AUTHORITY_ACCOUNT || d[4] !== ACCOUNT_LAYOUT_VERSION) return null;
  const role = ROLES[d[2]];
  if (!role) return null;
  const policyLen = readU16LE(d, 12);
  const wallet = base58Encode(d.subarray(16, 48));
  const counter = readU32LE(d, 8);
  if (d[1] === 0) {
    if (d.length < 80 + policyLen) return null;
    return {
      type: 'ed25519',
      role,
      counter,
      wallet,
      publicKey: d.slice(48, 80),
      policy: d.slice(80, 80 + policyLen),
    };
  }
  if (d[1] === 1) {
    if (d.length < 145 + policyLen) return null;
    return {
      type: 'passkey',
      role,
      counter,
      wallet,
      credentialIdHash: d.slice(48, 80),
      publicKey: d.slice(80, 113),
      rpIdHash: d.slice(113, 145),
      policy: d.slice(145, 145 + policyLen),
    };
  }
  return null;
}

export interface SessionFacts {
  wallet: string;
  sessionKey: string;
  /** As stored: Unix seconds on a time-expiry binary; a slot if written before it. */
  expiresAt: bigint;
  actions: Uint8Array;
}

/** A session account: header (80: disc, bump, version, pad, wallet, session_key, expires_at u64 at 72), then actions. */
export function decodeSessionAccount(acc: AccountSnapshot | null | undefined, programId: string): SessionFacts | null {
  if (!acc || acc.owner !== programId) return null;
  const d = acc.data;
  if (d.length < 80 || d[0] !== DISC_SESSION_ACCOUNT || d[2] !== ACCOUNT_LAYOUT_VERSION) return null;
  return {
    wallet: base58Encode(d.subarray(8, 40)),
    sessionKey: base58Encode(d.subarray(40, 72)),
    expiresAt: readU64LE(d, 72),
    actions: d.slice(80),
  };
}

export interface MintFacts {
  decimals: number;
  tokenProgram: 'token' | 'token-2022';
}

/**
 * An initialized SPL Token or Token-2022 mint: decimals at 44, is_initialized
 * at 45. A Token-2022 mint longer than 82 bytes carries account type 1 at 165.
 */
export function decodeMintAccount(acc: AccountSnapshot | null | undefined): MintFacts | null {
  if (!acc) return null;
  const d = acc.data;
  let tokenProgram: MintFacts['tokenProgram'];
  if (acc.owner === SPL_TOKEN_PROGRAM_ADDRESS) {
    if (d.length !== 82) return null;
    tokenProgram = 'token';
  } else if (acc.owner === SPL_TOKEN_2022_PROGRAM_ADDRESS) {
    if (d.length !== 82 && !(d.length > 165 && d[165] === 1)) return null;
    tokenProgram = 'token-2022';
  } else {
    return null;
  }
  if (d[45] !== 1) return null;
  return { decimals: d[44], tokenProgram };
}
