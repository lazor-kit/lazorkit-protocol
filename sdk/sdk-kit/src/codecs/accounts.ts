/**
 * On-chain account decoders for LazorKit (kit / web3.js v2 flavor).
 *
 * Layouts mirror the Rust state structs in program/src/state/. The
 * sdk-legacy v1 SDK has a parallel implementation at
 * sdk/sdk-legacy/src/utils/accounts.ts; tests/accounts.test.ts proves
 * decoder parity between the two on representative byte fixtures.
 */
import {
  fixDecoderSize,
  getAddressDecoder,
  getBytesDecoder,
  getStructDecoder,
  getU8Decoder,
  getU32Decoder,
  getU64Decoder,
  type Address,
  type ReadonlyUint8Array,
} from '@solana/kit';

// ─── Authority Account ───────────────────────────────────────────────
//
// AuthorityAccountHeader on-chain layout (48 bytes):
//   [0]      discriminator: u8
//   [1]      authorityType: u8       // 0 = ed25519, 1 = secp256r1
//   [2]      role:          u8       // 0 = owner, 1 = spender
//   [3]      bump:          u8
//   [4]      version:       u8
//   [5..8]   _padding:      [u8; 3]
//   [8..12]  counter:       u32 LE
//   [12..16] _padding:      [u8; 4]
//   [16..48] wallet:        Pubkey   (32 bytes)
//
// Past offset 48 the bytes are kind-specific (ed25519 vs secp256r1).
// The header is sufficient for SDK-side wallet ↔ authority join logic;
// kind-specific layouts are not parsed by this module yet.

export interface AuthorityAccountData {
  discriminator: number;
  authorityType: number;
  role: number;
  bump: number;
  version: number;
  counter: number;
  wallet: Address;
}

export const AUTHORITY_HEADER_SIZE = 48;

const authorityHeaderDecoder = getStructDecoder([
  ['discriminator', getU8Decoder()],
  ['authorityType', getU8Decoder()],
  ['role', getU8Decoder()],
  ['bump', getU8Decoder()],
  ['version', getU8Decoder()],
  // 3 bytes pad to align u32 on offset 8
  ['_padHi', fixDecoderSize(getBytesDecoder(), 3)],
  ['counter', getU32Decoder()],
  // 4 bytes pad to align Pubkey on offset 16
  ['_padLo', fixDecoderSize(getBytesDecoder(), 4)],
  ['wallet', getAddressDecoder()],
]);

export function decodeAuthorityAccount(
  data: ReadonlyUint8Array,
): AuthorityAccountData {
  if (data.length < AUTHORITY_HEADER_SIZE) {
    throw new Error(
      `Authority account data too short: ${data.length} < ${AUTHORITY_HEADER_SIZE}`,
    );
  }
  const decoded = authorityHeaderDecoder.decode(data);
  return {
    discriminator: decoded.discriminator,
    authorityType: decoded.authorityType,
    role: decoded.role,
    bump: decoded.bump,
    version: decoded.version,
    counter: decoded.counter,
    wallet: decoded.wallet,
  };
}

// ─── Session Account ─────────────────────────────────────────────────
//
// SessionAccount on-chain layout (80-byte fixed header + optional actions):
//   [0]      discriminator: u8
//   [1]      bump:          u8
//   [2]      version:       u8
//   [3..8]   _padding:      [u8; 5]
//   [8..40]  wallet:        Pubkey
//   [40..72] sessionKey:    Pubkey
//   [72..80] expiresAt:     u64 LE
//   [80..]   actions buffer (variable, optional)
//
// The actions buffer is parsed separately (see codecs/actions.ts for the
// per-action wire format).

export interface SessionAccountData {
  discriminator: number;
  bump: number;
  version: number;
  wallet: Address;
  sessionKey: Address;
  expiresAt: bigint;
}

export const SESSION_HEADER_SIZE = 80;

const sessionHeaderDecoder = getStructDecoder([
  ['discriminator', getU8Decoder()],
  ['bump', getU8Decoder()],
  ['version', getU8Decoder()],
  // 5 bytes pad to align Pubkey on offset 8
  ['_pad', fixDecoderSize(getBytesDecoder(), 5)],
  ['wallet', getAddressDecoder()],
  ['sessionKey', getAddressDecoder()],
  ['expiresAt', getU64Decoder()],
]);

export function decodeSessionAccount(
  data: ReadonlyUint8Array,
): SessionAccountData {
  if (data.length < SESSION_HEADER_SIZE) {
    throw new Error(
      `Session account data too short: ${data.length} < ${SESSION_HEADER_SIZE}`,
    );
  }
  const decoded = sessionHeaderDecoder.decode(data);
  return {
    discriminator: decoded.discriminator,
    bump: decoded.bump,
    version: decoded.version,
    wallet: decoded.wallet,
    sessionKey: decoded.sessionKey,
    expiresAt: decoded.expiresAt,
  };
}

// ─── Wallet Account ──────────────────────────────────────────────────
//
// WalletAccount on-chain layout (8-byte fixed header — minimal):
//   [0]   discriminator: u8 (must be 1)
//   [1]   bump:          u8
//   [2]   version:       u8
//   [3..8] _padding:     [u8; 5]
//
// The wallet is a trust anchor; no funds or per-user state live in it.
// The vault PDA holds assets; the authority PDAs hold per-key metadata.

export interface WalletAccountData {
  discriminator: number;
  bump: number;
  version: number;
}

export const WALLET_HEADER_SIZE = 8;

const walletHeaderDecoder = getStructDecoder([
  ['discriminator', getU8Decoder()],
  ['bump', getU8Decoder()],
  ['version', getU8Decoder()],
  ['_pad', fixDecoderSize(getBytesDecoder(), 5)],
]);

export function decodeWalletAccount(
  data: ReadonlyUint8Array,
): WalletAccountData {
  if (data.length < WALLET_HEADER_SIZE) {
    throw new Error(
      `Wallet account data too short: ${data.length} < ${WALLET_HEADER_SIZE}`,
    );
  }
  const decoded = walletHeaderDecoder.decode(data);
  return {
    discriminator: decoded.discriminator,
    bump: decoded.bump,
    version: decoded.version,
  };
}
