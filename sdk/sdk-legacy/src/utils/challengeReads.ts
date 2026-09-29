/**
 * The reads a passkey challenge is built from — the authority's counter, the
 * slot, the authority's key — and the freshness floor they can be given.
 *
 * Internal: not re-exported from the package index. `ChallengeReadOptions` is
 * re-exported from `secp256r1.ts`, and the error lives in `errors.ts`.
 */
import { type Commitment, Connection, SolanaJSONRPCErrorCode } from '@solana/web3.js';
import { MinContextSlotNotReachedError } from './errors';

/**
 * How to read what a passkey challenge commits to: the authority's counter,
 * the slot, and the authority's key.
 *
 * The challenge signs `counter + 1`, and the program rejects any other value
 * with SignatureReused (3006). A read made right after the authority's previous
 * transaction was sent, but before a node has executed it, returns the counter
 * that transaction is about to use. The signature then fails, and it cannot be
 * repaired: it commits to the counter, so only a new passkey prompt helps.
 */
export interface ChallengeReadOptions {
  /**
   * Commitment for the reads. Default `'confirmed'`, whatever the
   * Connection's own default (a Connection built without one reads at
   * `finalized`, seconds behind).
   */
  commitment?: Commitment;
  /**
   * Answer only from a node at or past this slot: pass the slot the
   * authority's previous transaction landed in (`getSignatureStatuses` →
   * `slot`, once it is confirmed). While the node answers that it has not
   * reached it yet (-32016), the read is retried with a short backoff for up
   * to 10 s, then fails with `MinContextSlotNotReachedError`.
   */
  minContextSlot?: number;
}

/**
 * Commitment for the challenge reads when the caller names none, whatever the
 * Connection's own default. `confirmed` sees a transaction about a slot after
 * it lands; `finalized` (what a Connection built without a commitment asks
 * for) lags by seconds, and a counter read there after a send is stale.
 */
export const CHALLENGE_READ_COMMITMENT: Commitment = 'confirmed';

/**
 * How long a challenge read keeps retrying while the RPC node answers that it
 * has not reached `minContextSlot` yet (-32016), before giving up with
 * `MinContextSlotNotReachedError`.
 */
export const MIN_CONTEXT_SLOT_WAIT_MS = 10_000;

/** The web3.js read config for `opts`, with the default commitment applied. */
export function challengeReadConfig(opts?: ChallengeReadOptions): {
  commitment: Commitment;
  minContextSlot?: number;
} {
  return {
    commitment: opts?.commitment ?? CHALLENGE_READ_COMMITMENT,
    ...(opts?.minContextSlot != null ? { minContextSlot: opts.minContextSlot } : {}),
  };
}

/** Delay before retry `attempt` (1-based): 100 ms, 200 ms, … capped at 1 s. */
function backoff(attempt: number): number {
  return Math.min(100 * attempt, 1_000);
}

/**
 * The RPC's "minimum context slot has not been reached" (-32016). Also matched
 * by message, because web3.js 1.x `getAccountInfo` rethrows RPC errors as a
 * plain Error that keeps the message but drops the code.
 */
export function minContextSlotNotReached(e: unknown): boolean {
  if (typeof e !== 'object' || e === null) return false;
  if (
    (e as { code?: unknown }).code ===
    SolanaJSONRPCErrorCode.JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED
  ) {
    return true;
  }
  const message = (e as { message?: unknown }).message;
  return typeof message === 'string' && /minimum context slot has not been reached/i.test(message);
}

/**
 * `read()`, retried with a short backoff while the node has not reached
 * `minContextSlot`, for up to `MIN_CONTEXT_SLOT_WAIT_MS`. Then it throws
 * `MinContextSlotNotReachedError` rather than read older state. Any other
 * error propagates at once, and without a `minContextSlot` nothing is retried.
 */
export async function atOrAfterContextSlot<T>(
  read: () => Promise<T>,
  minContextSlot: number | undefined,
  what: string,
): Promise<T> {
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    try {
      return await read();
    } catch (e) {
      if (minContextSlot == null || !minContextSlotNotReached(e)) throw e;
      const waitedMs = Date.now() - started;
      const delay = backoff(attempt);
      if (waitedMs + delay > MIN_CONTEXT_SLOT_WAIT_MS) {
        throw new MinContextSlotNotReachedError({ minContextSlot, waitedMs, what, cause: e });
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

/**
 * The current slot, read per `opts`: the slot a passkey challenge carries.
 * Retried like the account reads while the node is behind `minContextSlot`.
 */
export async function readChallengeSlot(
  connection: Connection,
  opts?: ChallengeReadOptions,
): Promise<bigint> {
  const slot = await atOrAfterContextSlot(
    () => connection.getSlot(challengeReadConfig(opts)),
    opts?.minContextSlot,
    'the slot',
  );
  return BigInt(slot);
}
