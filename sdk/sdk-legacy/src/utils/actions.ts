/**
 * Session action types and serialization for LazorKit session permissions.
 *
 * Actions are optional permission rules attached to sessions at creation time.
 * They are immutable — once set, they cannot be changed. To change permissions,
 * revoke the session and create a new one.
 *
 * @example
 * ```typescript
 * import { Actions, serializeActions } from '@lazorkit/sdk-legacy';
 *
 * const actions = [
 *   Actions.solRecurringLimit({ limit: 1_000_000_000n, window: 216_000n }),
 *   Actions.programWhitelist(JUPITER_PROGRAM_ID),
 *   Actions.solMaxPerTx(500_000_000n),
 * ];
 * ```
 */
import { PublicKey } from '@solana/web3.js';

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
  /** Lifetime SOL spending cap in lamports */
  remaining: bigint;
  /** Optional per-action expiry (slot). 0 = inherit session expiry. */
  expiresAt?: bigint;
}

export interface SolRecurringLimitAction {
  type: SessionActionType.SolRecurringLimit;
  /** Max lamports per window */
  limit: bigint;
  /** Window size in slots */
  window: bigint;
  /** Optional per-action expiry (slot). 0 = inherit session expiry. */
  expiresAt?: bigint;
}

export interface SolMaxPerTxAction {
  type: SessionActionType.SolMaxPerTx;
  /** Max lamports per single execute */
  max: bigint;
  expiresAt?: bigint;
}

export interface TokenLimitAction {
  type: SessionActionType.TokenLimit;
  /** SPL token mint */
  mint: PublicKey;
  /** Lifetime token spending cap (in token base units) */
  remaining: bigint;
  expiresAt?: bigint;
}

export interface TokenRecurringLimitAction {
  type: SessionActionType.TokenRecurringLimit;
  mint: PublicKey;
  /** Max tokens per window */
  limit: bigint;
  /** Window size in slots */
  window: bigint;
  expiresAt?: bigint;
}

export interface TokenMaxPerTxAction {
  type: SessionActionType.TokenMaxPerTx;
  mint: PublicKey;
  /** Max tokens per single execute */
  max: bigint;
  expiresAt?: bigint;
}

export interface ProgramWhitelistAction {
  type: SessionActionType.ProgramWhitelist;
  /** Program ID to allow */
  programId: PublicKey;
  expiresAt?: bigint;
}

export interface ProgramBlacklistAction {
  type: SessionActionType.ProgramBlacklist;
  /** Program ID to block */
  programId: PublicKey;
  expiresAt?: bigint;
}

/** Union of all session action types */
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

export const Actions = {
  /** Lifetime SOL spending cap */
  solLimit: (remaining: bigint, expiresAt?: bigint): SolLimitAction => ({
    type: SessionActionType.SolLimit,
    remaining,
    expiresAt,
  }),

  /** SOL spending cap per time window */
  solRecurringLimit: (params: {
    limit: bigint;
    window: bigint;
    expiresAt?: bigint;
  }): SolRecurringLimitAction => ({
    type: SessionActionType.SolRecurringLimit,
    ...params,
  }),

  /** Max SOL per single execute */
  solMaxPerTx: (max: bigint, expiresAt?: bigint): SolMaxPerTxAction => ({
    type: SessionActionType.SolMaxPerTx,
    max,
    expiresAt,
  }),

  /** Lifetime token spending cap per mint */
  tokenLimit: (params: {
    mint: PublicKey;
    remaining: bigint;
    expiresAt?: bigint;
  }): TokenLimitAction => ({
    type: SessionActionType.TokenLimit,
    ...params,
  }),

  /** Token spending cap per time window per mint */
  tokenRecurringLimit: (params: {
    mint: PublicKey;
    limit: bigint;
    window: bigint;
    expiresAt?: bigint;
  }): TokenRecurringLimitAction => ({
    type: SessionActionType.TokenRecurringLimit,
    ...params,
  }),

  /** Max tokens per single execute per mint */
  tokenMaxPerTx: (params: {
    mint: PublicKey;
    max: bigint;
    expiresAt?: bigint;
  }): TokenMaxPerTxAction => ({
    type: SessionActionType.TokenMaxPerTx,
    ...params,
  }),

  /** Allow CPI only to this program (repeatable) */
  programWhitelist: (
    programId: PublicKey,
    expiresAt?: bigint,
  ): ProgramWhitelistAction => ({
    type: SessionActionType.ProgramWhitelist,
    programId,
    expiresAt,
  }),

  /** Block CPI to this program (repeatable) */
  programBlacklist: (
    programId: PublicKey,
    expiresAt?: bigint,
  ): ProgramBlacklistAction => ({
    type: SessionActionType.ProgramBlacklist,
    programId,
    expiresAt,
  }),
};

// ─── Serialization ───────────────────────────────────────────────────

/** Action header: [type: u8][data_len: u16 LE][expires_at: u64 LE] = 11 bytes */
const ACTION_HEADER_SIZE = 11;

function writeU64LE(buf: Uint8Array, offset: number, value: bigint): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setBigUint64(offset, value, true);
}

function writeU16LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

function serializeActionData(action: SessionAction): Uint8Array {
  switch (action.type) {
    case SessionActionType.SolLimit: {
      const buf = new Uint8Array(8);
      writeU64LE(buf, 0, action.remaining);
      return buf;
    }
    case SessionActionType.SolRecurringLimit: {
      const buf = new Uint8Array(32);
      writeU64LE(buf, 0, action.limit);
      writeU64LE(buf, 8, 0n); // spent = 0
      writeU64LE(buf, 16, action.window);
      writeU64LE(buf, 24, 0n); // last_reset = 0
      return buf;
    }
    case SessionActionType.SolMaxPerTx: {
      const buf = new Uint8Array(8);
      writeU64LE(buf, 0, action.max);
      return buf;
    }
    case SessionActionType.TokenLimit: {
      const buf = new Uint8Array(40);
      buf.set(action.mint.toBytes(), 0);
      writeU64LE(buf, 32, action.remaining);
      return buf;
    }
    case SessionActionType.TokenRecurringLimit: {
      const buf = new Uint8Array(64);
      buf.set(action.mint.toBytes(), 0);
      writeU64LE(buf, 32, action.limit);
      writeU64LE(buf, 40, 0n); // spent = 0
      writeU64LE(buf, 48, action.window);
      writeU64LE(buf, 56, 0n); // last_reset = 0
      return buf;
    }
    case SessionActionType.TokenMaxPerTx: {
      const buf = new Uint8Array(40);
      buf.set(action.mint.toBytes(), 0);
      writeU64LE(buf, 32, action.max);
      return buf;
    }
    case SessionActionType.ProgramWhitelist: {
      return new Uint8Array(action.programId.toBytes());
    }
    case SessionActionType.ProgramBlacklist: {
      return new Uint8Array(action.programId.toBytes());
    }
  }
}

/**
 * Serialize an array of SessionActions into the flat byte buffer format
 * expected by the program.
 *
 * Each action: [type: u8][data_len: u16 LE][expires_at: u64 LE][data...]
 */
export function serializeActions(actions: SessionAction[]): Uint8Array {
  if (actions.length === 0) return new Uint8Array(0);

  const parts: Uint8Array[] = [];
  for (const action of actions) {
    const data = serializeActionData(action);
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

// ─── Parsing (reading a policy back) ─────────────────────────────────
//
// `serializeActions` is only half the story: an operator needs to answer
// "is this delegate bounded, and how much of its allowance is left?" for a
// key that already exists on chain. The recurring/lifetime actions carry
// mutable counters the program writes on every Execute, so a parsed action
// reports both what was granted and what has been consumed.

function readU64LE(buf: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buf[offset + i]);
  return value;
}

function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

/** One action as it currently stands on chain, including its live counters. */
export interface ParsedAction {
  type: SessionActionType;
  /** Per-action expiry slot. 0 = inherit the session/authority expiry. */
  expiresAt: bigint;
  /** Lifetime or per-window cap, in lamports or token base units. */
  limit?: bigint;
  /** Consumed so far in the current window (recurring actions only). */
  spent?: bigint;
  /** Window length in slots (recurring actions only). */
  window?: bigint;
  /** Slot the current window was last reset to (recurring actions only). */
  lastReset?: bigint;
  /** The mint a Token* action applies to. */
  mint?: PublicKey;
  /** The program a ProgramWhitelist / ProgramBlacklist action names. */
  programId?: PublicKey;
  /** Raw data bytes, for a type this parser does not model. */
  raw: Uint8Array;
}

/**
 * Parse an on-chain action buffer — an authority's policy or a session's
 * actions — into its individual actions.
 *
 * Read the buffer straight off the account: it sits after the fixed header
 * and key material (80 bytes for an Ed25519 authority, 145 for Secp256r1,
 * 80 for a session), and its length is the authority's `policyLen`.
 *
 * Throws on a malformed buffer rather than returning a partial list, since a
 * short read here would silently understate what a key is allowed to do.
 */
export function parseActions(buffer: Uint8Array): ParsedAction[] {
  const out: ParsedAction[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + ACTION_HEADER_SIZE > buffer.length) {
      throw new Error(
        `Malformed action buffer: truncated header at offset ${offset} (${buffer.length} bytes total)`,
      );
    }
    const type = buffer[offset] as SessionActionType;
    const dataLen = readU16LE(buffer, offset + 1);
    const expiresAt = readU64LE(buffer, offset + 3);
    const dataStart = offset + ACTION_HEADER_SIZE;
    if (dataStart + dataLen > buffer.length) {
      throw new Error(
        `Malformed action buffer: action at offset ${offset} declares ${dataLen} data bytes, past the end`,
      );
    }
    const data = buffer.subarray(dataStart, dataStart + dataLen);
    const parsed: ParsedAction = { type, expiresAt, raw: new Uint8Array(data) };

    switch (type) {
      case SessionActionType.SolLimit:
      case SessionActionType.SolMaxPerTx:
        parsed.limit = readU64LE(data, 0);
        break;
      case SessionActionType.SolRecurringLimit:
        parsed.limit = readU64LE(data, 0);
        parsed.spent = readU64LE(data, 8);
        parsed.window = readU64LE(data, 16);
        parsed.lastReset = readU64LE(data, 24);
        break;
      case SessionActionType.TokenLimit:
      case SessionActionType.TokenMaxPerTx:
        parsed.mint = new PublicKey(data.subarray(0, 32));
        parsed.limit = readU64LE(data, 32);
        break;
      case SessionActionType.TokenRecurringLimit:
        parsed.mint = new PublicKey(data.subarray(0, 32));
        parsed.limit = readU64LE(data, 32);
        parsed.spent = readU64LE(data, 40);
        parsed.window = readU64LE(data, 48);
        parsed.lastReset = readU64LE(data, 56);
        break;
      case SessionActionType.ProgramWhitelist:
      case SessionActionType.ProgramBlacklist:
        parsed.programId = new PublicKey(data.subarray(0, 32));
        break;
      default:
        // Unknown type — the program would reject it, but report it rather
        // than dropping it, so an operator sees what is actually stored.
        break;
    }

    out.push(parsed);
    offset = dataStart + dataLen;
  }
  return out;
}
