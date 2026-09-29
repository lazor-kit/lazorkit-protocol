/**
 * The reads a passkey challenge is built from — the authority's counter, the
 * slot, the authority's key — and the freshness floor they can be given.
 *
 * Mirrors sdk-legacy/src/utils/challengeReads.ts. `ChallengeReadOptions` and
 * `MinContextSlotNotReachedError` are re-exported from `secp256r1.ts`; the
 * rest is internal.
 */
import {
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  isSolanaError,
  type Commitment,
  type GetSlotApi,
  type Rpc,
  type Slot,
} from '@solana/kit';

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
  /** Commitment for the reads. Default `'confirmed'`. */
  commitment?: Commitment;
  /**
   * Answer only from a node at or past this slot: pass the slot the
   * authority's previous transaction landed in (`getSignatureStatuses` →
   * `slot`, once it is confirmed). While the node answers that it has not
   * reached it yet (-32016), the read is retried with a short backoff for up
   * to 10 s, then fails with `MinContextSlotNotReachedError`.
   */
  minContextSlot?: Slot;
}

/**
 * The RPC node never reached the `minContextSlot` a passkey challenge read
 * asked for, within the wait (see `Secp256r1Params.minContextSlot`).
 *
 * Thrown instead of signing: a node behind that slot may not have executed the
 * authority's previous transaction yet, and the counter it holds would already
 * be spent — the program rejects such a signature with SignatureReused (3006),
 * and the signature commits to the counter, so nothing can repair it after the
 * user has approved. Retry, or read from a node that has caught up.
 */
export class MinContextSlotNotReachedError extends Error {
  /** The slot the read had to be answered at or after. */
  readonly minContextSlot: Slot;
  /** How long the reads were retried, in milliseconds. */
  readonly waitedMs: number;

  constructor(params: { minContextSlot: Slot; waitedMs: number; what: string; cause?: unknown }) {
    super(
      `RPC node has not reached slot ${params.minContextSlot} after ${params.waitedMs} ms ` +
        `(reading ${params.what} for a passkey challenge). The authority's previous ` +
        `transaction may not be visible there yet, and a challenge over the counter it ` +
        `holds would fail with SignatureReused (3006). Retry, or use an RPC endpoint that ` +
        `has caught up.`,
      params.cause !== undefined ? { cause: params.cause } : undefined,
    );
    this.name = 'MinContextSlotNotReachedError';
    this.minContextSlot = params.minContextSlot;
    this.waitedMs = params.waitedMs;
  }
}

/**
 * Commitment for the challenge reads when the caller names none. `confirmed`
 * sees a transaction about a slot after it lands; `finalized` lags by seconds,
 * and a counter read there after a send is stale.
 */
export const CHALLENGE_READ_COMMITMENT: Commitment = 'confirmed';

/**
 * How long a challenge read keeps retrying while the RPC node answers that it
 * has not reached `minContextSlot` yet (-32016), before giving up with
 * `MinContextSlotNotReachedError`.
 */
export const MIN_CONTEXT_SLOT_WAIT_MS = 10_000;

/** The kit read config for `opts`, with the default commitment applied. */
export function challengeReadConfig(opts?: ChallengeReadOptions): {
  commitment: Commitment;
  minContextSlot?: Slot;
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
 * `read()`, retried with a short backoff while the node has not reached
 * `minContextSlot`, for up to `MIN_CONTEXT_SLOT_WAIT_MS`. Then it throws
 * `MinContextSlotNotReachedError` rather than read older state. Any other
 * error propagates at once, and without a `minContextSlot` nothing is retried.
 */
export async function atOrAfterContextSlot<T>(
  read: () => Promise<T>,
  minContextSlot: Slot | undefined,
  what: string,
): Promise<T> {
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    try {
      return await read();
    } catch (e) {
      if (
        minContextSlot == null ||
        !isSolanaError(e, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED)
      ) {
        throw e;
      }
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
  rpc: Rpc<GetSlotApi>,
  opts?: ChallengeReadOptions,
): Promise<bigint> {
  const slot = await atOrAfterContextSlot(
    () => rpc.getSlot(challengeReadConfig(opts)).send(),
    opts?.minContextSlot,
    'the slot',
  );
  return BigInt(slot);
}
