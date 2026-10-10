// Strict decoding of a session's actions buffer.
//
// `decodeActions` accepts a buffer if and only if the program's
// `validate_actions_buffer` (program/src/state/action.rs) does, and reports
// which program error a refused one meets. What a screen shows is decoded
// from the same bytes the passkey's challenge hashes, so there is no second
// serialization that could differ.
//
// `readStoredActions` reads a buffer as it stands on chain (a live session's
// actions, an authority's policy), where recurring limits carry the counters
// the program writes on every Execute.

import { base58Encode, readU16LE, readU64LE } from './bytes';
import { ApprovalActionsError, type ActionsProgramError } from './errors';
import { MAX_ACTIONS } from './constants';

/** Action type ids (program/src/state/action.rs). */
export const ACTION_TYPE_IDS = {
  solLimit: 1,
  solRecurringLimit: 2,
  solMaxPerTx: 3,
  tokenLimit: 4,
  tokenRecurringLimit: 5,
  tokenMaxPerTx: 6,
  programWhitelist: 10,
  programBlacklist: 11,
} as const;
export type ActionTypeName = keyof typeof ACTION_TYPE_IDS;

const TYPE_BY_ID: Record<number, ActionTypeName> = {};
for (const [name, id] of Object.entries(ACTION_TYPE_IDS)) TYPE_BY_ID[id] = name as ActionTypeName;

/** Data size per type, excluding the 11-byte header. */
const DATA_SIZE: Record<ActionTypeName, number> = {
  solLimit: 8,
  solRecurringLimit: 32,
  solMaxPerTx: 8,
  tokenLimit: 40,
  tokenRecurringLimit: 64,
  tokenMaxPerTx: 40,
  programWhitelist: 32,
  programBlacklist: 32,
};

/** [type u8][data_len u16 LE][expires_at u64 LE] */
export const ACTION_HEADER_SIZE = 11;

interface ActionCommon {
  /** Unix seconds after which this action counts as expired; 0 = none of its own. */
  expiresAt: bigint;
}

/** One action of a buffer being created (counters are zero by validation). */
export type DecodedAction =
  | (ActionCommon & { type: 'solLimit'; remaining: bigint })
  | (ActionCommon & { type: 'solRecurringLimit'; limit: bigint; windowSeconds: bigint })
  | (ActionCommon & { type: 'solMaxPerTx'; max: bigint })
  | (ActionCommon & { type: 'tokenLimit'; mint: string; remaining: bigint })
  | (ActionCommon & { type: 'tokenRecurringLimit'; mint: string; limit: bigint; windowSeconds: bigint })
  | (ActionCommon & { type: 'tokenMaxPerTx'; mint: string; max: bigint })
  | (ActionCommon & { type: 'programWhitelist'; programId: string })
  | (ActionCommon & { type: 'programBlacklist'; programId: string });

/** One action as stored on chain: recurring limits add their live counters. */
export type StoredAction =
  | Exclude<DecodedAction, { type: 'solRecurringLimit' | 'tokenRecurringLimit' }>
  | (ActionCommon & {
      type: 'solRecurringLimit';
      limit: bigint;
      windowSeconds: bigint;
      spent: bigint;
      lastReset: bigint;
    })
  | (ActionCommon & {
      type: 'tokenRecurringLimit';
      mint: string;
      limit: bigint;
      windowSeconds: bigint;
      spent: bigint;
      lastReset: bigint;
    });

interface View {
  type: ActionTypeName;
  expiresAt: bigint;
  data: Uint8Array;
}

function fail(programError: ActionsProgramError, message: string): never {
  throw new ApprovalActionsError(programError, message);
}

/** `parse_actions`: walks headers, refuses unknown types, overruns and a 17th action. */
function parseViews(buf: Uint8Array): View[] {
  const out: View[] = [];
  let cursor = 0;
  while (cursor < buf.length) {
    if (cursor + ACTION_HEADER_SIZE > buf.length) {
      fail('ActionBufferInvalid', `truncated action header at byte ${cursor}`);
    }
    const type = TYPE_BY_ID[buf[cursor]];
    if (!type) fail('ActionBufferInvalid', `unknown action type ${buf[cursor]} at byte ${cursor}`);
    const dataLen = readU16LE(buf, cursor + 1);
    const expiresAt = readU64LE(buf, cursor + 3);
    const dataStart = cursor + ACTION_HEADER_SIZE;
    if (dataStart + dataLen > buf.length) {
      fail('ActionBufferInvalid', `action at byte ${cursor} runs past the end`);
    }
    out.push({ type, expiresAt, data: buf.subarray(dataStart, dataStart + dataLen) });
    cursor = dataStart + dataLen;
    if (out.length > MAX_ACTIONS) fail('ActionBufferInvalid', `more than ${MAX_ACTIONS} actions`);
  }
  return out;
}

/** Sizes, then whitelist with blacklist, then duplicates: the program's order. */
function checkStructure(views: View[]): void {
  for (const v of views) {
    if (v.data.length !== DATA_SIZE[v.type]) {
      fail('ActionBufferInvalid', `${v.type} carries ${v.data.length} data bytes, not ${DATA_SIZE[v.type]}`);
    }
  }
  if (views.some((v) => v.type === 'programWhitelist') && views.some((v) => v.type === 'programBlacklist')) {
    fail('ActionWhitelistBlacklistConflict', 'a program whitelist and a program blacklist together');
  }
  for (const t of ['solLimit', 'solRecurringLimit', 'solMaxPerTx'] as const) {
    if (views.filter((v) => v.type === t).length > 1) fail('ActionBufferInvalid', `two ${t} actions`);
  }
  for (const t of ['tokenLimit', 'tokenRecurringLimit', 'tokenMaxPerTx'] as const) {
    const mints = views.filter((v) => v.type === t).map((v) => base58Encode(v.data.subarray(0, 32)));
    if (new Set(mints).size !== mints.length) fail('ActionBufferInvalid', `two ${t} actions for one mint`);
  }
}

function toStored(v: View): StoredAction {
  const d = v.data;
  const expiresAt = v.expiresAt;
  switch (v.type) {
    case 'solLimit':
      return { type: v.type, expiresAt, remaining: readU64LE(d, 0) };
    case 'solMaxPerTx':
      return { type: v.type, expiresAt, max: readU64LE(d, 0) };
    case 'solRecurringLimit':
      return {
        type: v.type,
        expiresAt,
        limit: readU64LE(d, 0),
        spent: readU64LE(d, 8),
        windowSeconds: readU64LE(d, 16),
        lastReset: readU64LE(d, 24),
      };
    case 'tokenLimit':
      return { type: v.type, expiresAt, mint: base58Encode(d.subarray(0, 32)), remaining: readU64LE(d, 32) };
    case 'tokenMaxPerTx':
      return { type: v.type, expiresAt, mint: base58Encode(d.subarray(0, 32)), max: readU64LE(d, 32) };
    case 'tokenRecurringLimit':
      return {
        type: v.type,
        expiresAt,
        mint: base58Encode(d.subarray(0, 32)),
        limit: readU64LE(d, 32),
        spent: readU64LE(d, 40),
        windowSeconds: readU64LE(d, 48),
        lastReset: readU64LE(d, 56),
      };
    case 'programWhitelist':
    case 'programBlacklist':
      return { type: v.type, expiresAt, programId: base58Encode(d) };
  }
}

/**
 * Decodes an actions buffer for a CreateSession, refusing exactly what the
 * program refuses: trailing or truncated bytes, unknown types, wrong data
 * sizes, more than 16 actions, a whitelist with a blacklist, a repeated
 * `Sol*` type or a repeated (`Token*` type, mint) pair, and a recurring limit
 * whose `spent` or `last_reset` is not zero or whose window is zero. Throws
 * `ApprovalActionsError`. An empty buffer is no actions.
 */
export function decodeActions(buf: Uint8Array): DecodedAction[] {
  if (buf.length === 0) return [];
  const views = parseViews(buf);
  checkStructure(views);
  const out: DecodedAction[] = [];
  for (const v of views) {
    const a = toStored(v);
    if (a.type === 'solRecurringLimit' || a.type === 'tokenRecurringLimit') {
      if (a.spent !== 0n) fail('ActionBufferInvalid', `${a.type} with spent ${a.spent}`);
      if (a.windowSeconds === 0n) fail('ActionBufferInvalid', `${a.type} with a zero window`);
      if (a.lastReset !== 0n) fail('ActionBufferInvalid', `${a.type} with last_reset ${a.lastReset}`);
      const { spent: _s, lastReset: _l, ...rest } = a;
      out.push(rest as DecodedAction);
    } else {
      out.push(a);
    }
  }
  return out;
}

/**
 * Reads an actions buffer as stored on chain. Refuses what `parse_actions`
 * and the creation-time structure checks refuse (so a buffer the program
 * could not have written), but accepts the live counters of recurring limits.
 */
export function readStoredActions(buf: Uint8Array): StoredAction[] {
  if (buf.length === 0) return [];
  const views = parseViews(buf);
  checkStructure(views);
  return views.map(toStored);
}

/** The mints a buffer's `Token*` actions name, in order, without repeats. */
export function mintsNamedBy(actions: readonly (DecodedAction | StoredAction)[]): string[] {
  const out: string[] = [];
  for (const a of actions) {
    if ('mint' in a && !out.includes(a.mint)) out.push(a.mint);
  }
  return out;
}
