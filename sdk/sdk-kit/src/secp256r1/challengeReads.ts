/**
 * The reads a passkey challenge is built from — the authority's counter, the
 * slot, the authority's key — and the freshness floor they can be given.
 *
 * Mirrors sdk-legacy/src/utils/challengeReads.ts. `ChallengeReadOptions` and
 * `MinContextSlotNotReachedError` are re-exported from `secp256r1.ts`; the
 * rest is internal, and the public `readAuthorityCounter` /
 * `readAuthorityPubkey` are thin wrappers over the readers here.
 */
import {
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  getBase64Encoder,
  isSolanaError,
  type Address,
  type Commitment,
  type GetAccountInfoApi,
  type GetSlotApi,
  type Rpc,
  type Slot,
} from '@solana/kit';
import { ACCOUNT_DISCRIMINATOR } from '../constants.js';

const base64Encoder = getBase64Encoder();

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
   * Commitment for the reads. Default `'confirmed'`, whatever the RPC's own
   * default. A caller that confirms the previous transaction only at
   * `'processed'` reads at `'processed'` too.
   *
   * With `'finalized'` and a `minContextSlot`, the reads wait until that slot
   * is finalized on the node — how long after its confirmation depends on the
   * cluster (31 slots on a local test validator, none on devnet on
   * 2026-09-30) — for up to 30 s rather than 10 s. The slot is read at the
   * same commitment, so the challenge carries a finalized slot: where
   * finalization lags, that much of the program's 150-slot window is gone
   * before the prompt (see the README).
   */
  commitment?: Commitment;
  /**
   * Answer only from a node at or past this slot, at the read's commitment:
   * pass the slot the authority's previous transaction landed in
   * (`getSignatureStatuses` → `slot`, once it is confirmed). While the node
   * answers that it has not reached it yet (-32016), the read is retried with
   * a short backoff for up to 10 s (30 s at `finalized`), then fails with
   * `MinContextSlotNotReachedError`.
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
 *
 * At `'finalized'` the floor is the slot being finalized. How long after its
 * confirmation that happens is the cluster's: 31 slots (16.5 s) on a local
 * test validator (Agave 4.2.2), none on devnet on 2026-09-30, where the
 * finalized slot was the confirmed one. The read waits up to 30 s for it
 * (10 s at the other commitments), and the message names both causes of a
 * timeout there: a slot not finalized yet, or a node that is behind.
 */
export class MinContextSlotNotReachedError extends Error {
  /** The slot the read had to be answered at or after. */
  readonly minContextSlot: Slot;
  /** How long the reads were retried, in milliseconds. */
  readonly waitedMs: number;
  /** The commitment the read was made at, when known. */
  readonly commitment?: Commitment;

  constructor(params: {
    minContextSlot: Slot;
    waitedMs: number;
    what: string;
    commitment?: Commitment;
    cause?: unknown;
  }) {
    const { minContextSlot, waitedMs, what, commitment } = params;
    super(
      commitment === 'finalized'
        ? `Slot ${minContextSlot} is not finalized on the RPC node after ${waitedMs} ms ` +
            `(reading ${what} for a passkey challenge at 'finalized'). Either the cluster ` +
            `has not finalized it yet (how long that takes after confirmation depends on ` +
            `the cluster) or this node is behind. Wait for the previous transaction to be ` +
            `finalized before preparing, read at 'confirmed' (the default) with the same ` +
            `minContextSlot, or retry on an RPC endpoint that has caught up. Reading older ` +
            `state instead would sign a counter that transaction may have spent: ` +
            `SignatureReused (3006).`
        : `RPC node has not reached slot ${minContextSlot}` +
            `${commitment ? ` at '${commitment}'` : ''} after ${waitedMs} ms ` +
            `(reading ${what} for a passkey challenge). The authority's previous ` +
            `transaction may not be visible there yet, and a challenge over the counter it ` +
            `holds would fail with SignatureReused (3006). Retry, or use an RPC endpoint that ` +
            `has caught up.`,
      params.cause !== undefined ? { cause: params.cause } : undefined,
    );
    this.name = 'MinContextSlotNotReachedError';
    this.minContextSlot = minContextSlot;
    this.waitedMs = waitedMs;
    if (commitment !== undefined) this.commitment = commitment;
  }
}

/**
 * Commitment for the challenge reads when the caller names none. `confirmed`
 * sees a transaction about a slot after it lands; `finalized` can lag by
 * seconds, and a counter read there after a send is then stale.
 */
export const CHALLENGE_READ_COMMITMENT: Commitment = 'confirmed';

/**
 * How long a challenge read keeps retrying while the RPC node answers that it
 * has not reached `minContextSlot` yet (-32016), before giving up with
 * `MinContextSlotNotReachedError`, at `processed` and `confirmed`.
 */
export const MIN_CONTEXT_SLOT_WAIT_MS = 10_000;

/**
 * The same wait at `finalized`. Where a node's finalized slot trails its
 * confirmed one by about 32 slots (a local test validator: 31 slots, 16.5 s),
 * a floor at a slot that was just confirmed — what the README tells callers to
 * pass — cannot be finalized within {@link MIN_CONTEXT_SLOT_WAIT_MS}: every
 * such read used to end in `MinContextSlotNotReachedError`. This covers that
 * lag with room for slow slots. (On devnet on 2026-09-30 the finalized slot
 * was the confirmed one, and a floor there is reached at once.)
 */
export const FINALIZED_MIN_CONTEXT_SLOT_WAIT_MS = 30_000;

/** The -32016 wait for a read at `commitment`. */
export function minContextSlotWaitMs(commitment: Commitment): number {
  return commitment === 'finalized' ? FINALIZED_MIN_CONTEXT_SLOT_WAIT_MS : MIN_CONTEXT_SLOT_WAIT_MS;
}

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

/**
 * The reads of one passkey challenge — counter, key, slot — run side by side.
 * When one of them fails, `Promise.all` rejects at once, but the others would
 * go on retrying -32016 for the rest of their wait: polling the RPC after the
 * caller has moved on (a retry of the prepare starts another set), and keeping
 * a Node process alive on their timers. A group lets them stop: {@link run}
 * stops the group when the read it wraps fails, and a read waiting for the
 * floor gives up at once (its sleep ends early) instead of polling again.
 *
 * A read that runs beside the challenge's in the same `Promise.all` goes in
 * the group too — `prepareExecute`'s protocol-fee read — so that its failure
 * stops them as well: the call rejects with it just the same.
 *
 * One group per call, created by the caller of the reads and never shared
 * between calls: the SDK keeps no state between calls.
 */
export class ChallengeReadGroup {
  private isStopped = false;
  private firstFailure: unknown;
  private readonly sleepers = new Set<() => void>();

  /** Whether a read in the group has failed. */
  get stopped(): boolean {
    return this.isStopped;
  }

  /** What the first read to fail threw, once the group has stopped. */
  get failure(): unknown {
    return this.firstFailure;
  }

  /** Stop every read in the group; one asleep between retries wakes now. */
  stop(failure: unknown): void {
    if (this.isStopped) return;
    this.isStopped = true;
    this.firstFailure = failure;
    for (const wake of [...this.sleepers]) wake();
  }

  /** `read`, stopping the group if it fails. */
  run<T>(read: Promise<T>): Promise<T> {
    return read.catch((e: unknown) => {
      this.stop(e);
      throw e;
    });
  }

  /** Resolves after `ms`, or as soon as the group stops. */
  sleep(ms: number): Promise<void> {
    if (this.isStopped) return Promise.resolve();
    return new Promise((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        this.sleepers.delete(wake);
        resolve();
      };
      const timer = setTimeout(wake, ms);
      this.sleepers.add(wake);
    });
  }
}

/** Delay before retry `attempt` (1-based): 100 ms, 200 ms, … capped at 1 s. */
function backoff(attempt: number): number {
  return Math.min(100 * attempt, 1_000);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * `read()`, retried with a short backoff while the node has not reached
 * `config.minContextSlot`, for up to {@link minContextSlotWaitMs} of
 * `config.commitment`. Then it throws `MinContextSlotNotReachedError` rather
 * than read older state. Any other error propagates at once, and without a
 * `minContextSlot` nothing is retried. In a `group`, it stops retrying once
 * the group stops, rethrowing the last -32016.
 */
export async function atOrAfterContextSlot<T>(
  read: () => Promise<T>,
  config: { commitment: Commitment; minContextSlot?: Slot },
  what: string,
  group?: ChallengeReadGroup,
): Promise<T> {
  const { commitment, minContextSlot } = config;
  const budget = minContextSlotWaitMs(commitment);
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
      // Another read of this challenge failed: its caller has the answer.
      if (group?.stopped) throw e;
      const waitedMs = Date.now() - started;
      const delay = backoff(attempt);
      if (waitedMs + delay > budget) {
        throw new MinContextSlotNotReachedError({ minContextSlot, waitedMs, what, commitment, cause: e });
      }
      await (group ? group.sleep(delay) : sleep(delay));
      if (group?.stopped) throw e;
    }
  }
}

/** One authority account, read per `opts` (see {@link ChallengeReadOptions}). */
async function readAuthorityAccountBytes(
  rpc: Rpc<GetAccountInfoApi>,
  authorityPda: Address,
  opts: ChallengeReadOptions | undefined,
  what: string,
  group?: ChallengeReadGroup,
): Promise<Uint8Array> {
  const config = challengeReadConfig(opts);
  const info = await atOrAfterContextSlot(
    () => rpc.getAccountInfo(authorityPda, { encoding: 'base64', ...config }).send(),
    config,
    what,
    group,
  );
  if (!info.value) throw new Error(`Authority account not found: ${authorityPda}`);
  return new Uint8Array(base64Encoder.encode(info.value.data[0]));
}

/**
 * The authority's odometer counter (u32 LE at offset 8 of the header), read
 * per `opts`; in `group` when it is one of a challenge's reads.
 */
export async function readChallengeCounter(
  rpc: Rpc<GetAccountInfoApi>,
  authorityPda: Address,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<number> {
  const bytes = await readAuthorityAccountBytes(rpc, authorityPda, opts, `the counter of ${authorityPda}`, group);
  if (bytes.length < 12) throw new Error('Authority account data too short');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(8, /* le */ true);
}

/**
 * The authority's compressed Secp256r1 key (33 bytes), read per `opts`; in
 * `group` when it is one of a challenge's reads. Layout:
 *   [header(48)] [credential_id_hash(32)] [compressed_pubkey(33)] ...
 */
export async function readChallengeKey(
  rpc: Rpc<GetAccountInfoApi>,
  authorityPda: Address,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<Uint8Array> {
  const bytes = await readAuthorityAccountBytes(rpc, authorityPda, opts, `the key of ${authorityPda}`, group);
  // Min size = 48 (header) + 32 (credential_id_hash) + 33 (pubkey) = 113.
  if (bytes.length < 113) throw new Error('Authority account too small for Secp256r1');
  if (bytes[0] !== ACCOUNT_DISCRIMINATOR.AUTHORITY) throw new Error('Not an Authority account');
  if (bytes[1] !== 1) throw new Error('Authority is not Secp256r1');
  return bytes.slice(80, 80 + 33);
}

/**
 * The current slot, read per `opts`: the slot a passkey challenge carries.
 * Retried like the account reads while the node is behind `minContextSlot`.
 */
export async function readChallengeSlot(
  rpc: Rpc<GetSlotApi>,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<bigint> {
  const config = challengeReadConfig(opts);
  const slot = await atOrAfterContextSlot(() => rpc.getSlot(config).send(), config, 'the slot', group);
  return BigInt(slot);
}

/**
 * What a passkey challenge is built from — the authority's key, the slot, and
 * its counter + 1 — read side by side at one commitment and floor, skipping
 * what the caller already has (`publicKeyBytes`, `slotOverride`). If one read
 * fails, the call rejects with its error and the others stop retrying at
 * once (see {@link ChallengeReadGroup}). Pass `group` when another read runs
 * beside these (`prepareExecute`'s protocol fee) and is in it too; if it has
 * already failed, nothing is read and its error is thrown again.
 */
export async function readChallengeInputs(
  rpc: Rpc<GetAccountInfoApi & GetSlotApi>,
  authorityPda: Address,
  opts: ChallengeReadOptions,
  have: { publicKeyBytes?: Uint8Array; slotOverride?: bigint } = {},
  group: ChallengeReadGroup = new ChallengeReadGroup(),
): Promise<{ publicKeyBytes: Uint8Array; slot: bigint; counter: number }> {
  // A read beside these failed while the caller was still deriving the
  // authority's address: the call has rejected already, so start no polling.
  if (group.stopped) throw group.failure;
  const [publicKeyBytes, slot, counter] = await Promise.all([
    have.publicKeyBytes
      ? Promise.resolve(have.publicKeyBytes)
      : group.run(readChallengeKey(rpc, authorityPda, opts, group)),
    have.slotOverride != null
      ? Promise.resolve(have.slotOverride)
      : group.run(readChallengeSlot(rpc, opts, group)),
    group.run(readChallengeCounter(rpc, authorityPda, opts, group)).then((c) => c + 1),
  ]);
  return { publicKeyBytes, slot, counter };
}
