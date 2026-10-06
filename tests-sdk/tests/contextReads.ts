/**
 * Stubbed Connections for the SDK's pinned reads.
 *
 * The ownership and migration reads ask each RPC call for the slot it was
 * answered at (`getProgramAccounts` with `withContext`,
 * `getMultipleAccountsInfoAndContext`, `getTokenAccountsByOwner`) and pass it
 * on as the next call's `minContextSlot`, and the passkey challenge reads the
 * authority with `getAccountInfoAndContext` (whose errors keep their RPC
 * code). `contextual` lets a test state plain answers — arrays of accounts,
 * `{ value }`, `getAccountInfo` — and serves them as one node at one slot
 * would. Wrapping twice changes nothing.
 */
import { SYSVAR_CLOCK_PUBKEY, type Connection, type PublicKey } from '@solana/web3.js';

/** The slot every read of a `contextual` connection is answered at, by default. */
export const STUB_CONTEXT_SLOT = 1_000;

/**
 * The Unix time the Clock sysvar of a `contextual` connection holds:
 * 2026-10-04. v2 session expiries compare against it, deferred expiries
 * against the slot.
 */
export const STUB_UNIX_TIME = 1_791_072_000n;

/**
 * The Clock sysvar account at `slot` and `unix`: slot u64 at 0, Unix time i64
 * at 32, as the SDK's `readClusterClock` reads it.
 */
export function clockAccount(slot: number | bigint, unix: bigint = STUB_UNIX_TIME) {
  const data = Buffer.alloc(40);
  data.writeBigUInt64LE(BigInt(slot), 0);
  data.writeBigInt64LE(unix, 32);
  return { data, lamports: 1, owner: SYSVAR_CLOCK_PUBKEY, executable: false };
}

/** One `getMultipleAccountsInfoAndContext` call, as the SDK made it. */
export interface AccountsRead {
  keys: PublicKey[];
  minContextSlot?: number;
}

type Method = (...args: any[]) => Promise<any>;

export function contextual(methods: object, log?: AccountsRead[], slot = STUB_CONTEXT_SLOT): Connection {
  const m = methods as Record<string, Method>;
  const conn: Record<string, unknown> = { ...m };
  // The Clock sysvar, at the slot the stub's getSlot names (or `slot`), so
  // tests that state a slot state the clock with it. Any other account is the
  // stub's own answer.
  conn.getAccountInfo = async (key: PublicKey, config?: unknown) => {
    if (key.equals(SYSVAR_CLOCK_PUBKEY)) return clockAccount(m.getSlot ? await m.getSlot() : slot);
    return m.getAccountInfo ? m.getAccountInfo(key, config) : null;
  };
  // Late-bound, so a test that later replaces getMultipleAccountsInfo on the
  // returned object is answered by its replacement.
  conn.getMultipleAccountsInfoAndContext = async (keys: PublicKey[], config?: { minContextSlot?: number }) => {
    log?.push({ keys, minContextSlot: config?.minContextSlot });
    return { context: { slot }, value: await (conn.getMultipleAccountsInfo as Method)(keys) };
  };
  // Late-bound too, for the same reason.
  conn.getAccountInfoAndContext = async (key: PublicKey, config?: unknown) => ({
    context: { slot },
    value: await (conn.getAccountInfo as Method)(key, config),
  });
  if (m.getProgramAccounts) {
    conn.getProgramAccounts = async (programId: PublicKey, config?: { withContext?: boolean }) => {
      const result = await m.getProgramAccounts(programId, config);
      return config?.withContext && Array.isArray(result) ? { context: { slot }, value: result } : result;
    };
  }
  if (m.getTokenAccountsByOwner) {
    conn.getTokenAccountsByOwner = async (...args: unknown[]) => {
      const result = await m.getTokenAccountsByOwner(...args);
      return result && 'context' in result ? result : { context: { slot }, ...result };
    };
  }
  return conn as unknown as Connection;
}
