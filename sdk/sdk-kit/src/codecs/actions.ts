/**
 * Session action types and serialization for LazorKit session permissions.
 *
 * Actions are optional permission rules attached to sessions at creation time.
 * They are immutable — once set, they cannot be changed. To change permissions,
 * revoke the session and create a new one.
 *
 * Times are Unix seconds: an action's `expiresAt` (0 = none of its own) and a
 * recurring limit's `windowSeconds`. The program reads both against the
 * cluster clock (`Clock::unix_timestamp`), not slots.
 *
 * A policy names what may leave the vault, and nothing it does not name may
 * (protocol v2): with no `Sol*` action the vault's SOL may not fall, rent the
 * vault pays for a new account included, and a mint with no `Token*` action
 * may not leave the vault's token accounts. Both are net over one Execute,
 * measured on the vault's own lamports and on the token accounts it owns that
 * the Execute passes writable; inflows always pass. wSOL is a mint, not SOL.
 * A program whitelist or blacklist names programs, not assets. A policy holds
 * at most 16 actions, so it can name about 15 mints. Value the vault controls
 * any other way (stake, nonce or seed-derived accounts, positions in other
 * programs, authorities it holds) is bounded only by the program whitelist.
 *
 * Wire format is byte-identical with @lazorkit/sdk-legacy and
 * program/src/state/action.rs. See tests/actions.test.ts for parity proofs.
 *
 * @example
 * ```typescript
 * import { Actions, serializeActions, address } from '@lazorkit/sdk';
 *
 * const actions = [
 *   Actions.solRecurringLimit({ limit: 1_000_000_000n, windowSeconds: 86_400n }), // 1 SOL a day
 *   Actions.programWhitelist(address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4')),
 *   Actions.solMaxPerTx(500_000_000n),
 *   // Without a Token* action no token may leave, so name each one a swap sells.
 *   Actions.tokenLimit({ mint: address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), remaining: 50_000_000n }),
 * ];
 * const buf = serializeActions(actions);
 * ```
 */
import {
  getAddressEncoder,
  getStructEncoder,
  getU64Encoder,
  type Address,
  type Encoder,
} from '@solana/kit';
import { MIN_UNIX_SECONDS } from '../time.js';

// ─── Action Type IDs (must match program/src/state/action.rs) ────────

export enum SessionActionType {
  SolLimit = 1,
  SolRecurringLimit = 2,
  SolMaxPerTx = 3,
  TokenLimit = 4,
  TokenRecurringLimit = 5,
  TokenMaxPerTx = 6,
  ProgramWhitelist = 10,
  ProgramBlacklist = 11,
}

// ─── Action Data Types ───────────────────────────────────────────────

export interface SolLimitAction {
  type: SessionActionType.SolLimit;
  /** Lifetime SOL spending cap in lamports. */
  remaining: bigint;
  /**
   * Optional expiry of this action alone, Unix seconds; 0 or unset = none (it
   * lives as long as the session or authority). An expired limit counts as
   * exhausted, an expired whitelist as deny-all, an expired blacklist entry as
   * lifted.
   */
  expiresAt?: bigint;
}

export interface SolRecurringLimitAction {
  type: SessionActionType.SolRecurringLimit;
  /** Max lamports per window. */
  limit: bigint;
  /** Window length in seconds (86_400n = a day). A window opens at the spend
   *  that finds the previous one over. */
  windowSeconds: bigint;
  expiresAt?: bigint;
}

export interface SolMaxPerTxAction {
  type: SessionActionType.SolMaxPerTx;
  /** Max lamports per single execute. */
  max: bigint;
  expiresAt?: bigint;
}

export interface TokenLimitAction {
  type: SessionActionType.TokenLimit;
  /** SPL token mint. */
  mint: Address;
  /** Lifetime token spending cap (in token base units). */
  remaining: bigint;
  expiresAt?: bigint;
}

export interface TokenRecurringLimitAction {
  type: SessionActionType.TokenRecurringLimit;
  mint: Address;
  /** Max tokens per window. */
  limit: bigint;
  /** Window length in seconds (86_400n = a day). */
  windowSeconds: bigint;
  expiresAt?: bigint;
}

export interface TokenMaxPerTxAction {
  type: SessionActionType.TokenMaxPerTx;
  mint: Address;
  /** Max tokens per single execute. */
  max: bigint;
  expiresAt?: bigint;
}

export interface ProgramWhitelistAction {
  type: SessionActionType.ProgramWhitelist;
  /** Program address to allow. */
  programId: Address;
  expiresAt?: bigint;
}

export interface ProgramBlacklistAction {
  type: SessionActionType.ProgramBlacklist;
  /** Program address to block. */
  programId: Address;
  expiresAt?: bigint;
}

/** Union of all session action types. */
export type SessionAction =
  | SolLimitAction
  | SolRecurringLimitAction
  | SolMaxPerTxAction
  | TokenLimitAction
  | TokenRecurringLimitAction
  | TokenMaxPerTxAction
  | ProgramWhitelistAction
  | ProgramBlacklistAction;

// ─── Builder Helpers ─────────────────────────────────────────────────

/**
 * Builders for each action. An asset no action names cannot leave the vault:
 * name SOL with a `sol*` action (rent the vault pays is SOL) and each mint
 * that may leave with a `token*` action.
 */
export const Actions = {
  /** Lifetime SOL spending cap. */
  solLimit: (remaining: bigint, expiresAt?: bigint): SolLimitAction => ({
    type: SessionActionType.SolLimit,
    remaining,
    expiresAt,
  }),

  /** SOL spending cap per window of `windowSeconds` seconds. */
  solRecurringLimit: (params: {
    limit: bigint;
    windowSeconds: bigint;
    expiresAt?: bigint;
  }): SolRecurringLimitAction => ({
    type: SessionActionType.SolRecurringLimit,
    ...params,
  }),

  /** Max SOL per single execute. */
  solMaxPerTx: (max: bigint, expiresAt?: bigint): SolMaxPerTxAction => ({
    type: SessionActionType.SolMaxPerTx,
    max,
    expiresAt,
  }),

  /** Lifetime token spending cap per mint. */
  tokenLimit: (params: {
    mint: Address;
    remaining: bigint;
    expiresAt?: bigint;
  }): TokenLimitAction => ({
    type: SessionActionType.TokenLimit,
    ...params,
  }),

  /** Token spending cap per window of `windowSeconds` seconds, per mint. */
  tokenRecurringLimit: (params: {
    mint: Address;
    limit: bigint;
    windowSeconds: bigint;
    expiresAt?: bigint;
  }): TokenRecurringLimitAction => ({
    type: SessionActionType.TokenRecurringLimit,
    ...params,
  }),

  /** Max tokens per single execute per mint. */
  tokenMaxPerTx: (params: {
    mint: Address;
    max: bigint;
    expiresAt?: bigint;
  }): TokenMaxPerTxAction => ({
    type: SessionActionType.TokenMaxPerTx,
    ...params,
  }),

  /** Allow CPI only to this program (repeatable). */
  programWhitelist: (
    programId: Address,
    expiresAt?: bigint,
  ): ProgramWhitelistAction => ({
    type: SessionActionType.ProgramWhitelist,
    programId,
    expiresAt,
  }),

  /** Block CPI to this program (repeatable). */
  programBlacklist: (
    programId: Address,
    expiresAt?: bigint,
  ): ProgramBlacklistAction => ({
    type: SessionActionType.ProgramBlacklist,
    programId,
    expiresAt,
  }),
};

// ─── Serialization ───────────────────────────────────────────────────
//
// Wire format per action:
//   [type: u8] [data_len: u16 LE] [expires_at: u64 LE] [data: data_len bytes]
//   ─── 11-byte header ────────────────────────────────  ─── variable ───
//
// The on-chain reader (validate_actions_buffer in
// program/src/state/action.rs) walks the buffer linearly, reading the
// header then exactly data_len bytes for each action. data_len is
// validated against the discriminator-specific expected size.
//
// Counters that the program tracks at runtime (spent, last_reset) are
// initialized to zero on the wire.

const ACTION_HEADER_SIZE = 11;

const u64LE = getU64Encoder();
const addressEncoder = getAddressEncoder();

// Inner data encoders. Each maps to an exact byte length expected by
// validate_actions_buffer:
//   SolLimit            =  8  (remaining: u64)
//   SolRecurringLimit   = 32  (limit, spent=0, window (seconds), last_reset=0; all u64)
//   SolMaxPerTx         =  8  (max: u64)
//   TokenLimit          = 40  (mint: 32 + remaining: u64)
//   TokenRecurringLimit = 64  (mint: 32 + limit, spent=0, window, last_reset=0)
//   TokenMaxPerTx       = 40  (mint: 32 + max: u64)
//   ProgramWhitelist    = 32  (program: pubkey)
//   ProgramBlacklist    = 32  (program: pubkey)

const solLimitData: Encoder<{ remaining: bigint }> = getStructEncoder([
  ['remaining', u64LE],
]);

const solRecurringLimitData: Encoder<{
  limit: bigint;
  spent: bigint;
  window: bigint;
  lastReset: bigint;
}> = getStructEncoder([
  ['limit', u64LE],
  ['spent', u64LE],
  ['window', u64LE],
  ['lastReset', u64LE],
]);

const solMaxPerTxData: Encoder<{ max: bigint }> = getStructEncoder([
  ['max', u64LE],
]);

const tokenLimitData: Encoder<{ mint: Address; remaining: bigint }> =
  getStructEncoder([
    ['mint', addressEncoder],
    ['remaining', u64LE],
  ]);

const tokenRecurringLimitData: Encoder<{
  mint: Address;
  limit: bigint;
  spent: bigint;
  window: bigint;
  lastReset: bigint;
}> = getStructEncoder([
  ['mint', addressEncoder],
  ['limit', u64LE],
  ['spent', u64LE],
  ['window', u64LE],
  ['lastReset', u64LE],
]);

const tokenMaxPerTxData: Encoder<{ mint: Address; max: bigint }> =
  getStructEncoder([
    ['mint', addressEncoder],
    ['max', u64LE],
  ]);

function encodeActionData(action: SessionAction): Uint8Array {
  switch (action.type) {
    case SessionActionType.SolLimit:
      return solLimitData.encode({ remaining: action.remaining }) as Uint8Array;
    case SessionActionType.SolRecurringLimit:
      return solRecurringLimitData.encode({
        limit: action.limit,
        spent: 0n,
        window: action.windowSeconds,
        lastReset: 0n,
      }) as Uint8Array;
    case SessionActionType.SolMaxPerTx:
      return solMaxPerTxData.encode({ max: action.max }) as Uint8Array;
    case SessionActionType.TokenLimit:
      return tokenLimitData.encode({
        mint: action.mint,
        remaining: action.remaining,
      }) as Uint8Array;
    case SessionActionType.TokenRecurringLimit:
      return tokenRecurringLimitData.encode({
        mint: action.mint,
        limit: action.limit,
        spent: 0n,
        window: action.windowSeconds,
        lastReset: 0n,
      }) as Uint8Array;
    case SessionActionType.TokenMaxPerTx:
      return tokenMaxPerTxData.encode({
        mint: action.mint,
        max: action.max,
      }) as Uint8Array;
    case SessionActionType.ProgramWhitelist:
    case SessionActionType.ProgramBlacklist:
      return addressEncoder.encode(action.programId) as Uint8Array;
  }
}

function writeU16LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

function writeU64LE(buf: Uint8Array, offset: number, value: bigint): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(
    offset,
    value,
    /* littleEndian */ true,
  );
}

/**
 * Throws when an action's times are plainly not seconds: an `expiresAt` other
 * than 0 below 2020-01-01 (a slot, what the field held before time-based
 * expiry), or a recurring window of 0. The program would store such a slot as
 * a time long past: a limit or a whitelist then denies everything, and a
 * blacklist entry stops blocking its program. Every policy goes through here,
 * a session's and a Delegate's alike.
 */
function assertActionTimes(action: SessionAction): void {
  const at = action.expiresAt ?? 0n;
  if (at !== 0n && at < MIN_UNIX_SECONDS) {
    throw new Error(
      `an action's expiresAt ${at} is not a Unix time in seconds (it looks like a slot); ` +
        'use 0 / leave it unset for no expiry of its own',
    );
  }
  if (
    (action.type === SessionActionType.SolRecurringLimit ||
      action.type === SessionActionType.TokenRecurringLimit) &&
    action.windowSeconds <= 0n
  ) {
    throw new Error('a recurring limit needs windowSeconds > 0');
  }
}

/**
 * Serialize an array of SessionActions into the flat byte buffer format
 * expected by the program. Returns an empty buffer for an empty array. Throws
 * on an expiry that is plainly a slot, or a recurring window of zero.
 */
export function serializeActions(actions: SessionAction[]): Uint8Array {
  if (actions.length === 0) return new Uint8Array(0);

  const parts: Uint8Array[] = [];
  for (const action of actions) {
    assertActionTimes(action);
    const data = encodeActionData(action);
    const header = new Uint8Array(ACTION_HEADER_SIZE);
    header[0] = action.type;
    writeU16LE(header, 1, data.length);
    writeU64LE(header, 3, action.expiresAt ?? 0n);
    parts.push(header);
    parts.push(data);
  }

  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
