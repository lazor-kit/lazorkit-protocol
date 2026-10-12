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
  getU16Decoder,
  getU32Decoder,
  getU64Decoder,
  type Address,
  type ReadonlyUint8Array,
} from '@solana/kit';
import { ACCOUNT_DISCRIMINATOR, RENT_PAYER_LAYOUT_VERSION, RENT_PAYER_LEN } from '../constants.js';

// ─── Layout revisions ────────────────────────────────────────────────

/** Where an authority's key material ends: 80 for Ed25519, 145 for a passkey. */
export function authorityKeyEnd(authorityType: number): number | null {
  if (authorityType === 0) return 80;
  if (authorityType === 1) return 145;
  return null;
}

/**
 * Where an authority's policy starts: after its key material in layout
 * revision 1, after the key material and the 32-byte rent payer from
 * revision 2. `null` for an unknown type or revision.
 */
export function authorityPolicyOffset(authorityType: number, version: number): number | null {
  const keyEnd = authorityKeyEnd(authorityType);
  if (keyEnd === null) return null;
  if (version === 1) return keyEnd;
  if (version === RENT_PAYER_LAYOUT_VERSION) return keyEnd + RENT_PAYER_LEN;
  return null;
}

/** Where a session's actions start: 80 in layout revision 1, 112 from revision 2. */
export function sessionActionsOffset(version: number): number | null {
  if (version === 1) return 80;
  if (version === RENT_PAYER_LAYOUT_VERSION) return 80 + RENT_PAYER_LEN;
  return null;
}

const rentPayerDecoder = getAddressDecoder();

/**
 * The account that paid an authority's or a session's rent, as it records it
 * (layout revision 2), or `null` for an account that records none: revision
 * 1, a v1 account, or any other type. Closing a recording account refunds
 * only to this address; one that records none closes wherever its closer
 * says.
 */
export function recordedRentPayer(data: ReadonlyUint8Array): Address | null {
  if (data.length < 5) return null;
  let at: number | null = null;
  if (data[0] === ACCOUNT_DISCRIMINATOR.SESSION && data[2] === RENT_PAYER_LAYOUT_VERSION) {
    at = 80;
  } else if (data[0] === ACCOUNT_DISCRIMINATOR.AUTHORITY && data[4] === RENT_PAYER_LAYOUT_VERSION) {
    at = authorityKeyEnd(data[1]!);
  }
  if (at === null || data.length < at + RENT_PAYER_LEN) return null;
  return rentPayerDecoder.decode(data.slice(at, at + RENT_PAYER_LEN));
}

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
//   [12..14] policyLen:     u16 LE
//   [14..16] _padding:      [u8; 2]
//   [16..48] wallet:        Pubkey   (32 bytes)
//
// Then the key material (Ed25519 pubkey to 80; a passkey's credential hash,
// compressed key and rpIdHash to 145), from layout revision 2 the 32-byte
// rent payer, then `policyLen` bytes of policy.

export interface AuthorityAccountData {
  discriminator: number;
  authorityType: number;
  role: number;
  bump: number;
  version: number;
  counter: number;
  /** Bytes of spending policy after the key material. 0 = unbounded. */
  policyLen: number;
  /** Convenience: does this authority carry a spending policy? */
  isBounded: boolean;
  wallet: Address;
  /**
   * The account that paid this authority's rent, which RemoveAuthority and
   * TransferOwnership refund to (layout revision 2); `null` before it.
   */
  rentPayer: Address | null;
  /** Where the policy starts in the account data (`null`: unknown layout). */
  policyOffset: number | null;
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
  ['policyLen', getU16Decoder()],
  // 2 bytes pad to align Pubkey on offset 16
  ['_padLo', fixDecoderSize(getBytesDecoder(), 2)],
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
    policyLen: decoded.policyLen,
    isBounded: decoded.policyLen > 0,
    wallet: decoded.wallet,
    rentPayer: recordedRentPayer(data),
    policyOffset: authorityPolicyOffset(decoded.authorityType, decoded.version),
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
//   [72..80] expiresAt:     u64 LE, Unix seconds (a slot in accounts written
//                           before time-based expiry: read as a time, expired)
//   [80..112] rentPayer:    Pubkey, from layout revision 2
//   [80..] or [112..] actions buffer (variable, optional)
//
// The actions buffer is parsed separately (see codecs/actions.ts for the
// per-action wire format).

export interface SessionAccountData {
  discriminator: number;
  bump: number;
  version: number;
  wallet: Address;
  sessionKey: Address;
  /** Unix time (seconds) after which the program refuses the session. */
  expiresAt: bigint;
  /**
   * The account that paid this session's rent, which RevokeSession and
   * CloseExpiredSession refund to (layout revision 2); `null` before it.
   */
  rentPayer: Address | null;
  /** The session's action buffer; empty when unrestricted. */
  actions: Uint8Array;
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
    rentPayer: recordedRentPayer(data),
    actions: (() => {
      const at = sessionActionsOffset(decoded.version);
      return at !== null && data.length > at ? new Uint8Array(data.slice(at)) : new Uint8Array();
    })(),
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
  /** Authorities on this wallet holding rank Owner. The program refuses to
   *  remove the last one, and a wallet with a single Owner is unrecoverable
   *  if that Owner's key is lost. */
  ownerCount: number;
}

export const WALLET_HEADER_SIZE = 8;

const walletHeaderDecoder = getStructDecoder([
  ['discriminator', getU8Decoder()],
  ['bump', getU8Decoder()],
  ['version', getU8Decoder()],
  // 1 byte pad to align u32 on offset 4
  ['_pad', fixDecoderSize(getBytesDecoder(), 1)],
  ['ownerCount', getU32Decoder()],
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
    ownerCount: decoded.ownerCount,
  };
}

/**
 * A close was asked to refund rent somewhere other than the account that paid
 * it. From layout revision 2 an authority and a session record that account,
 * and the program refuses any other destination with RefundDestinationMismatch
 * (3039), so the SDK refuses it first. Leave `refundDestination` out and the
 * SDK fills in the recorded payer.
 */
export class RefundDestinationMismatchError extends Error {
  /** The account being closed. */
  readonly account: Address;
  /** The rent payer it records: the only destination the program accepts. */
  readonly rentPayer: Address;
  /** The destination that was asked for. */
  readonly requested: Address;

  constructor(params: { account: Address; rentPayer: Address; requested: Address }) {
    super(
      `${params.account} records ${params.rentPayer} as the account that paid its rent, and ` +
        `the program refunds only to it (RefundDestinationMismatch, 3039); refundDestination ` +
        `was ${params.requested}. Leave refundDestination out to use the recorded payer.`,
    );
    this.name = 'RefundDestinationMismatchError';
    this.account = params.account;
    this.rentPayer = params.rentPayer;
    this.requested = params.requested;
  }
}
