/**
 * The reads a passkey challenge is built from — the authority's counter, the
 * slot, the authority's key — and the freshness floor they can be given.
 *
 * Internal: not re-exported from the package index. `ChallengeReadOptions` is
 * re-exported from `secp256r1.ts`, the error lives in `errors.ts`, and the
 * public `readAuthorityCounter` / `readAuthorityPubkey` are thin wrappers over
 * the readers here.
 */
import { type Commitment, Connection, PublicKey, SolanaJSONRPCErrorCode } from '@solana/web3.js';
import { ACCOUNT_DISCRIMINATOR } from '../constants';
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
   * Commitment for the reads. Default `'confirmed'`, or `'processed'` when
   * the Connection's own commitment is `'processed'`: never staler than the
   * Connection. A Connection built without a commitment, or at `finalized`,
   * would read seconds behind; one at `processed` confirms its sends there,
   * and a `confirmed` read right after would miss them.
   *
   * With `'finalized'` and a `minContextSlot`, the reads wait until that slot
   * is finalized on the node — about 32 slots (13 s) after it was confirmed —
   * for up to 30 s rather than 10 s.
   */
  commitment?: Commitment;
  /**
   * Answer only from a node at or past this slot, at the read's commitment:
   * pass the slot the authority's previous transaction landed in
   * (`getSignatureStatuses` → `slot`, once it is confirmed), or
   * `confirmTransaction` → `context.slot`, which is at or after it. While the
   * node answers that it has not reached it yet (-32016), the read is retried
   * with a short backoff for up to 10 s (30 s at `finalized`), then fails with
   * `MinContextSlotNotReachedError`.
   */
  minContextSlot?: number;
}

/**
 * Commitment for the challenge reads when the caller names none and the
 * Connection is not at `processed`. `confirmed` sees a transaction about a
 * slot after it lands; `finalized` (what a Connection built without a
 * commitment asks for) lags by seconds, and a counter read there after a send
 * is stale.
 */
export const CHALLENGE_READ_COMMITMENT: Commitment = 'confirmed';

/**
 * The commitment a challenge read uses when the caller names none: `'processed'`
 * on a Connection at `'processed'` (or its old alias `'recent'`), otherwise
 * {@link CHALLENGE_READ_COMMITMENT}. Never staler than the Connection: an
 * integrator whose Connection is at `processed` confirms the previous
 * transaction there, and a `confirmed` read right after it still holds the
 * counter that transaction used (3006), or no authority at all when that
 * transaction created it.
 */
export function defaultChallengeCommitment(connection: Connection): Commitment {
  const own = connection.commitment;
  return own === 'processed' || own === 'recent' ? 'processed' : CHALLENGE_READ_COMMITMENT;
}

/**
 * How long a challenge read keeps retrying while the RPC node answers that it
 * has not reached `minContextSlot` yet (-32016), before giving up with
 * `MinContextSlotNotReachedError`, at `processed` and `confirmed`.
 */
export const MIN_CONTEXT_SLOT_WAIT_MS = 10_000;

/**
 * The same wait at `finalized`. A node's finalized slot trails its confirmed
 * one by about 32 slots (13 s at 400 ms a slot), so a floor at a slot that was
 * just confirmed — what the README tells callers to pass — cannot be finalized
 * within {@link MIN_CONTEXT_SLOT_WAIT_MS}: every such read used to end in
 * `MinContextSlotNotReachedError`. This covers the lag with room for slow
 * slots.
 */
export const FINALIZED_MIN_CONTEXT_SLOT_WAIT_MS = 30_000;

/** The -32016 wait for a read at `commitment`. */
export function minContextSlotWaitMs(commitment: Commitment): number {
  return commitment === 'finalized' || commitment === 'max' || commitment === 'root'
    ? FINALIZED_MIN_CONTEXT_SLOT_WAIT_MS
    : MIN_CONTEXT_SLOT_WAIT_MS;
}

/**
 * The web3.js read config for `opts` on `connection`, with the default
 * commitment ({@link defaultChallengeCommitment}) applied.
 */
export function challengeReadConfig(
  connection: Connection,
  opts?: ChallengeReadOptions,
): {
  commitment: Commitment;
  minContextSlot?: number;
} {
  return {
    commitment: opts?.commitment ?? defaultChallengeCommitment(connection),
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
 * One group per challenge, created by the caller of the reads and never
 * shared: the SDK keeps no state between calls.
 */
export class ChallengeReadGroup {
  private isStopped = false;
  private readonly sleepers = new Set<() => void>();

  /** Whether a read in the group has failed. */
  get stopped(): boolean {
    return this.isStopped;
  }

  /** Stop every read in the group; one asleep between retries wakes now. */
  stop(): void {
    if (this.isStopped) return;
    this.isStopped = true;
    for (const wake of [...this.sleepers]) wake();
  }

  /** `read`, stopping the group if it fails. */
  run<T>(read: Promise<T>): Promise<T> {
    return read.catch((e: unknown) => {
      this.stop();
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
 * `config.minContextSlot`, for up to {@link minContextSlotWaitMs} of
 * `config.commitment`. Then it throws `MinContextSlotNotReachedError` rather
 * than read older state. Any other error propagates at once, and without a
 * `minContextSlot` nothing is retried. In a `group`, it stops retrying once
 * the group stops, rethrowing the last -32016.
 */
export async function atOrAfterContextSlot<T>(
  read: () => Promise<T>,
  config: { commitment: Commitment; minContextSlot?: number },
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
      if (minContextSlot == null || !minContextSlotNotReached(e)) throw e;
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

/**
 * One authority account, read per `opts`. `getAccountInfoAndContext` rather
 * than `getAccountInfo`: the latter rethrows RPC errors without their code.
 */
async function readAuthorityAccount(
  connection: Connection,
  authorityPda: PublicKey,
  opts: ChallengeReadOptions | undefined,
  what: string,
  group?: ChallengeReadGroup,
) {
  const config = challengeReadConfig(connection, opts);
  const { value } = await atOrAfterContextSlot(
    () => connection.getAccountInfoAndContext(authorityPda, config),
    config,
    what,
    group,
  );
  return value;
}

/**
 * The authority's odometer counter (u32 LE at offset 8 of the header), read
 * per `opts`; in `group` when it is one of a challenge's reads.
 */
export async function readChallengeCounter(
  connection: Connection,
  authorityPda: PublicKey,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<number> {
  const info = await readAuthorityAccount(
    connection,
    authorityPda,
    opts,
    `the counter of ${authorityPda.toBase58()}`,
    group,
  );
  if (!info) throw new Error(`Authority account not found: ${authorityPda.toBase58()}`);
  if (info.data.length < 12) throw new Error('Authority account data too short');
  const view = new DataView(info.data.buffer, info.data.byteOffset);
  return view.getUint32(8, true); // offset 8, little-endian, u32
}

/**
 * The authority's compressed Secp256r1 key (33 bytes), read per `opts`; in
 * `group` when it is one of a challenge's reads. Layout:
 *   [header(48)] [credential_id_hash(32)] [compressed_pubkey(33)] ...
 */
export async function readChallengeKey(
  connection: Connection,
  authorityPda: PublicKey,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<Uint8Array> {
  const info = await readAuthorityAccount(
    connection,
    authorityPda,
    opts,
    `the key of ${authorityPda.toBase58()}`,
    group,
  );
  if (!info) throw new Error(`Authority account not found: ${authorityPda.toBase58()}`);
  // Header is 48 bytes, credential_id_hash is 32 bytes, pubkey is 33 bytes.
  // Min size = 48 + 32 + 33 = 113 bytes for a Secp256r1 authority.
  if (info.data.length < 113) throw new Error('Authority account too small for Secp256r1');
  // Byte 0 is the account discriminator.
  if (info.data[0] !== ACCOUNT_DISCRIMINATOR.AUTHORITY)
    throw new Error('Not an Authority account');
  // Byte 1 is the authority_type: Secp256r1 = 1.
  if (info.data[1] !== 1) throw new Error('Authority is not Secp256r1');
  // Pubkey at offset 48 + 32 = 80, length 33.
  return new Uint8Array(info.data.slice(80, 80 + 33));
}

/**
 * The current slot, read per `opts`: the slot a passkey challenge carries.
 * Retried like the account reads while the node is behind `minContextSlot`.
 */
export async function readChallengeSlot(
  connection: Connection,
  opts?: ChallengeReadOptions,
  group?: ChallengeReadGroup,
): Promise<bigint> {
  const config = challengeReadConfig(connection, opts);
  const slot = await atOrAfterContextSlot(() => connection.getSlot(config), config, 'the slot', group);
  return BigInt(slot);
}

/**
 * What a passkey challenge is built from — the authority's key, the slot, and
 * its counter + 1 — read side by side at one commitment and floor, skipping
 * what the caller already has (`publicKeyBytes`, `slotOverride`). If one read
 * fails, the call rejects with its error and the others stop retrying at
 * once (see {@link ChallengeReadGroup}).
 */
export async function readChallengeInputs(
  connection: Connection,
  authorityPda: PublicKey,
  opts: ChallengeReadOptions,
  have: { publicKeyBytes?: Uint8Array; slotOverride?: bigint } = {},
): Promise<{ publicKeyBytes: Uint8Array; slot: bigint; counter: number }> {
  const group = new ChallengeReadGroup();
  const [publicKeyBytes, slot, counter] = await Promise.all([
    have.publicKeyBytes
      ? Promise.resolve(have.publicKeyBytes)
      : group.run(readChallengeKey(connection, authorityPda, opts, group)),
    have.slotOverride != null
      ? Promise.resolve(have.slotOverride)
      : group.run(readChallengeSlot(connection, opts, group)),
    group.run(readChallengeCounter(connection, authorityPda, opts, group)).then((c) => c + 1),
  ]);
  return { publicKeyBytes, slot, counter };
}
