import { Buffer } from 'buffer';
/**
 * Hand-written account deserializers for LazorKit on-chain accounts.
 * Replaces Solita-generated account classes.
 */
import { Connection, PublicKey } from '@solana/web3.js';
import { ACCOUNT_DISCRIMINATOR, RENT_PAYER_LAYOUT_VERSION, RENT_PAYER_LEN } from '../constants';

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

/**
 * The account that paid an authority's or a session's rent, as it records it
 * (layout revision 2), or `null` for an account that records none: revision
 * 1, a v1 account, or any other type. Closing a recording account refunds
 * only to this key; one that records none closes wherever its closer says.
 */
export function recordedRentPayer(data: Uint8Array): PublicKey | null {
  if (data.length < 5) return null;
  let at: number | null = null;
  if (data[0] === ACCOUNT_DISCRIMINATOR.SESSION && data[2] === RENT_PAYER_LAYOUT_VERSION) {
    at = 80;
  } else if (data[0] === ACCOUNT_DISCRIMINATOR.AUTHORITY && data[4] === RENT_PAYER_LAYOUT_VERSION) {
    at = authorityKeyEnd(data[1]);
  }
  if (at === null || data.length < at + RENT_PAYER_LEN) return null;
  return new PublicKey(data.subarray(at, at + RENT_PAYER_LEN));
}

// ─── Authority Account ───────────────────────────────────────────────

/**
 * AuthorityAccountHeader layout (48 bytes):
 * [discriminator: u8][authorityType: u8][role: u8][bump: u8]
 * [version: u8][padding: 3 bytes][counter: u32 LE][padding: 4 bytes]
 * [wallet: Pubkey(32)]
 */
export interface AuthorityAccountData {
  discriminator: number;
  authorityType: number;
  role: number;
  bump: number;
  version: number;
  counter: number;
  wallet: PublicKey;
}

export class AuthorityAccount implements AuthorityAccountData {
  constructor(
    public readonly discriminator: number,
    public readonly authorityType: number,
    public readonly role: number,
    public readonly bump: number,
    public readonly version: number,
    public readonly counter: number,
    public readonly wallet: PublicKey,
    /** Bytes of spending policy after the key material. 0 = unbounded. */
    public readonly policyLen: number = 0,
    /**
     * The account that paid this authority's rent, which RemoveAuthority and
     * TransferOwnership refund to (layout revision 2); `null` before it.
     */
    public readonly rentPayer: PublicKey | null = null,
    /** Where the policy starts in the account data (`null`: unknown layout). */
    public readonly policyOffset: number | null = null,
  ) {}

  /** Does this authority carry a spending policy? Rank says what it may
   *  manage, this says whether what it may *spend* is bounded. */
  get isBounded(): boolean {
    return this.policyLen > 0;
  }

  static fromBuffer(data: Buffer): AuthorityAccount {
    if (data.length < 48) throw new Error('Authority account data too short');
    const discriminator = data[0];
    const authorityType = data[1];
    const role = data[2];
    const bump = data[3];
    const version = data[4];
    // padding: 3 bytes (5..8)
    const counter = data.readUInt32LE(8);
    const policyLen = data.readUInt16LE(12);
    // padding: 2 bytes (14..16)
    const wallet = new PublicKey(data.subarray(16, 48));
    return new AuthorityAccount(
      discriminator,
      authorityType,
      role,
      bump,
      version,
      counter,
      wallet,
      policyLen,
      recordedRentPayer(data),
      authorityPolicyOffset(authorityType, version),
    );
  }

  static async fromAccountAddress(
    connection: Connection,
    address: PublicKey,
  ): Promise<AuthorityAccount> {
    const info = await connection.getAccountInfo(address);
    if (!info || !info.data) throw new Error(`Authority account not found: ${address.toBase58()}`);
    return AuthorityAccount.fromBuffer(info.data);
  }
}

// ─── Session Account ─────────────────────────────────────────────────

/**
 * SessionAccount layout (80 bytes fixed header, then from layout revision 2
 * the 32-byte rent payer, then optional actions):
 * [discriminator: u8][bump: u8][version: u8][padding: 5 bytes]
 * [wallet: Pubkey(32)][sessionKey: Pubkey(32)][expiresAt: u64 LE]
 * [rentPayer: Pubkey(32), revision 2][actions...]
 *
 * `expiresAt` is Unix time in seconds; the program refuses the session once
 * the cluster clock is past it. A session written before time-based expiry
 * holds a slot there, which as a time is long past: it is expired.
 */
export interface SessionAccountData {
  discriminator: number;
  bump: number;
  version: number;
  wallet: PublicKey;
  sessionKey: PublicKey;
  expiresAt: bigint;
}

export class SessionAccount implements SessionAccountData {
  constructor(
    public readonly discriminator: number,
    public readonly bump: number,
    public readonly version: number,
    public readonly wallet: PublicKey,
    public readonly sessionKey: PublicKey,
    public readonly expiresAt: bigint,
    /**
     * The account that paid this session's rent, which RevokeSession and
     * CloseExpiredSession refund to (layout revision 2); `null` before it.
     */
    public readonly rentPayer: PublicKey | null = null,
    /** The session's action buffer; empty when unrestricted. */
    public readonly actions: Uint8Array = new Uint8Array(),
  ) {}

  static fromBuffer(data: Buffer): SessionAccount {
    if (data.length < 80) throw new Error('Session account data too short');
    const discriminator = data[0];
    const bump = data[1];
    const version = data[2];
    const wallet = new PublicKey(data.subarray(8, 40));
    const sessionKey = new PublicKey(data.subarray(40, 72));
    const expiresAt = data.readBigUInt64LE(72);
    const actionsAt = sessionActionsOffset(version);
    const actions =
      actionsAt !== null && data.length > actionsAt
        ? new Uint8Array(data.subarray(actionsAt))
        : new Uint8Array();
    return new SessionAccount(
      discriminator,
      bump,
      version,
      wallet,
      sessionKey,
      expiresAt,
      recordedRentPayer(data),
      actions,
    );
  }

  static async fromAccountAddress(
    connection: Connection,
    address: PublicKey,
  ): Promise<SessionAccount> {
    const info = await connection.getAccountInfo(address);
    if (!info || !info.data) throw new Error(`Session account not found: ${address.toBase58()}`);
    return SessionAccount.fromBuffer(info.data);
  }
}
