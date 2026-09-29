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
import type { Connection, PublicKey } from '@solana/web3.js';

/** The slot every read of a `contextual` connection is answered at, by default. */
export const STUB_CONTEXT_SLOT = 1_000;

/** One `getMultipleAccountsInfoAndContext` call, as the SDK made it. */
export interface AccountsRead {
  keys: PublicKey[];
  minContextSlot?: number;
}

type Method = (...args: any[]) => Promise<any>;

export function contextual(methods: object, log?: AccountsRead[], slot = STUB_CONTEXT_SLOT): Connection {
  const m = methods as Record<string, Method>;
  const conn: Record<string, unknown> = { ...m };
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
