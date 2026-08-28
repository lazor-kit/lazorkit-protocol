import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  sendAndConfirmTransaction,
  Transaction,
  TransactionInstruction,
  type Signer,
} from '@solana/web3.js';

// Tests run against `solana-test-validator` which loads the SBF built with
// `--features devnet`, so the on-chain program ID is the devnet vanity.
// Re-export under the legacy name so per-test files don't need to change.
import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
} from '../../sdk/sdk-legacy/src';
export const PROGRAM_ID = PROGRAM_ID_DEVNET;
export { PROGRAM_ID_DEVNET };

/** Construct a client for the local validator (devnet program ID). */
export function makeClient(connection: Connection): LazorKitClient {
  return new LazorKitClient(connection);
}

export const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8899';

// ─── Strict-fee setup (Approach A from the proposal) ─────────────────
//
// The on-chain commercial binary now rejects any disc 0/4/7 instruction
// that does not carry a valid [ProtocolConfig, FeeRecord, TreasuryShard,
// SystemProgram] suffix. Pre-init wallets fail with 4009. So every test
// suite has to ensure ProtocolConfig is initialized before its first
// CreateWallet / Execute / ExecuteDeferred — otherwise *every* test
// breaks.
//
// To keep the per-test-file `setupTest()` stable, we lift protocol init
// to the module level: the first `setupTest()` call across the entire
// vitest run creates a shared admin + treasury keypair and runs
// `initialize_protocol` + `initialize_treasury_shard × NUM_SHARDS`.
// Subsequent calls are no-ops (idempotent).
//
// Tests that need admin-only operations (UpdateProtocol, WithdrawTreasury)
// import `getProtocolAdmin()` to get the shared admin signer.

const NUM_SHARDS = 4;
const CREATION_FEE = 5_000n; // 0.000005 SOL — fits all test budgets
const EXECUTION_FEE = 2_000n;

let _initialized = false;
let _adminKp: Keypair | undefined;
let _treasuryKp: Keypair | undefined;

/**
 * Returns the shared admin keypair (call after `setupTest()` has run at
 * least once). Throws if init hasn't happened yet — tests that import
 * this MUST chain after a `setupTest()` in their `beforeAll`.
 */
export function getProtocolAdmin(): Keypair {
  if (!_adminKp) {
    throw new Error(
      'getProtocolAdmin() called before setupTest(). ' +
        'Call setupTest() in beforeAll first.',
    );
  }
  return _adminKp;
}

/**
 * Returns the shared treasury wallet keypair. Same usage rules as
 * `getProtocolAdmin()`.
 */
export function getProtocolTreasury(): Keypair {
  if (!_treasuryKp) {
    throw new Error('getProtocolTreasury() called before setupTest()');
  }
  return _treasuryKp;
}

export interface TestContext {
  connection: Connection;
  payer: Keypair;
}

export async function setupTest(): Promise<TestContext> {
  const connection = new Connection(RPC_URL, 'confirmed');

  await assertProgramDeployed(connection);

  const payer = Keypair.generate();

  const sig = await connection.requestAirdrop(payer.publicKey, 10 * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(sig, 'confirmed');

  await ensureProtocolInitialized(connection, payer);

  return { connection, payer };
}

let _preflightDone = false;

/**
 * Fail loudly and early if the program is not where the SDK expects it.
 *
 * `validator:start` loads the .so at the devnet vanity address, the same one
 * `PROGRAM_ID_DEVNET` holds. When those disagree — a stale validator, a forgotten
 * `--reset`, a hand-rolled deploy — every downstream failure surfaces as a
 * confusing error deep inside a PDA derivation or a simulate call. Check once.
 */
async function assertProgramDeployed(connection: Connection): Promise<void> {
  if (_preflightDone) return;
  _preflightDone = true;

  const info = await connection.getAccountInfo(PROGRAM_ID);
  if (!info) {
    throw new Error(
      `LazorKit program not found at ${PROGRAM_ID.toBase58()} on ${RPC_URL}.\n` +
        `Start the validator first:  npm run validator:start && npm run validator:wait`,
    );
  }
  if (!info.executable) {
    throw new Error(
      `Account ${PROGRAM_ID.toBase58()} on ${RPC_URL} exists but is not executable.`,
    );
  }
}

/**
 * Idempotent protocol initializer. Runs at most once per vitest process.
 *
 * Order of effects:
 *   1. Generate `_adminKp` + `_treasuryKp` (module-level, shared across files)
 *   2. Airdrop a small amount to the admin so it can sign
 *      `initialize_treasury_shard` (which requires admin to be a writable signer)
 *   3. Probe `ProtocolConfig` PDA via `client.getProtocolConfig()`
 *      - If null: validator is fresh → run init + shard creation
 *      - If non-null: validator carries leftover state from a previous
 *        run; rare, but tolerated. The shared admin won't be able to
 *        sign UpdateProtocol etc. against the leftover config — that's
 *        an explicit failure mode, document for users.
 */
async function ensureProtocolInitialized(
  connection: Connection,
  funderForAdmin: Keypair,
): Promise<void> {
  if (_initialized) return;
  _initialized = true; // claim the slot before any await — no double-init under concurrency

  _adminKp = Keypair.generate();
  _treasuryKp = Keypair.generate();

  // Fund the admin (it pays no rent, but it's a signer on
  // initialize_treasury_shard so it must exist on-chain to sign).
  const fundIx = (await import('@solana/web3.js')).SystemProgram.transfer({
    fromPubkey: funderForAdmin.publicKey,
    toPubkey: _adminKp.publicKey,
    lamports: 1 * LAMPORTS_PER_SOL,
  });
  const fundTx = new Transaction().add(fundIx);
  await sendAndConfirmTransaction(connection, fundTx, [funderForAdmin], {
    commitment: 'confirmed',
  });

  const client = makeClient(connection);
  const config = await client.getProtocolConfig();
  if (config && config.enabled) {
    // Already init from a previous run with a different admin key.
    // setupTest can still proceed (fee path works), but admin-only ops
    // from tests will fail. Surface this immediately for clarity.
    console.warn(
      '[tests-sdk/common.ts] ProtocolConfig already initialized on this validator. ' +
        'Admin-only tests will fail unless you --reset the validator.',
    );
    return;
  }

  // Fresh validator — initialize protocol + shards.
  const initIxs = client.initializeProtocol({
    payer: funderForAdmin.publicKey,
    admin: _adminKp.publicKey,
    treasury: _treasuryKp.publicKey,
    creationFee: CREATION_FEE,
    executionFee: EXECUTION_FEE,
    numShards: NUM_SHARDS,
  }).instructions;
  const initTx = new Transaction();
  for (const ix of initIxs) initTx.add(ix);
  await sendAndConfirmTransaction(connection, initTx, [funderForAdmin], {
    commitment: 'confirmed',
  });

  // Initialize all NUM_SHARDS shards so every shard is a valid fee
  // destination (resolveProtocolFee picks one at random per tx).
  for (let i = 0; i < NUM_SHARDS; i++) {
    const shardIxs = client.initializeTreasuryShard({
      payer: funderForAdmin.publicKey,
      admin: _adminKp.publicKey,
      shardId: i,
    }).instructions;
    const shardTx = new Transaction();
    for (const ix of shardIxs) shardTx.add(ix);
    await sendAndConfirmTransaction(
      connection,
      shardTx,
      [funderForAdmin, _adminKp],
      { commitment: 'confirmed' },
    );
  }

  // Invalidate the client's cached protocol config so the per-test
  // clients pick up the freshly-initialized config on first call.
  client.invalidateProtocolCache();
}

export async function sendTx(
  ctx: TestContext,
  instructions: TransactionInstruction[],
  signers: Signer[] = [],
): Promise<string> {
  const tx = new Transaction();
  for (const ix of instructions) tx.add(ix);
  return sendAndConfirmTransaction(ctx.connection, tx, [ctx.payer, ...signers], {
    commitment: 'confirmed',
  });
}

export async function sendTxExpectError(
  ctx: TestContext,
  instructions: TransactionInstruction[],
  signers: Signer[] = [],
  expectedErrorCode?: number,
): Promise<string> {
  try {
    const tx = new Transaction();
    for (const ix of instructions) tx.add(ix);
    await sendAndConfirmTransaction(ctx.connection, tx, [ctx.payer, ...signers], {
      commitment: 'confirmed',
    });
    throw new Error('Transaction should have failed but succeeded');
  } catch (err: any) {
    const msg = String(err);
    if (msg.includes('Transaction should have failed')) throw err;
    if (expectedErrorCode !== undefined) {
      const hexCode = expectedErrorCode.toString(16);
      if (!msg.includes(`0x${hexCode}`) && !msg.includes(`Custom(${expectedErrorCode})`)) {
        throw new Error(
          `Expected error code ${expectedErrorCode} (0x${hexCode}), got: ${msg}`,
        );
      }
    }
    return msg;
  }
}

export async function getSlot(ctx: TestContext): Promise<bigint> {
  const slot = await ctx.connection.getSlot('confirmed');
  // Use current slot directly; Clock::get() validates slot age (< 150 slots).
  return BigInt(slot);
}

/**
 * Helper for tests that build instructions via the low-level
 * `createCreateWalletIx` / `createExecuteIx` / `createExecuteDeferredIx`
 * builders (instead of going through `client.createWallet()` etc.).
 *
 * Strict-fee enforcement requires every disc 0/4/7 instruction to carry
 * the `[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]`
 * suffix. Tests that need to inject custom counter values, replay
 * scenarios, or deferred-exec edge cases bypass the high-level client
 * — they must call this helper and pass the result as `protocolFee`.
 */
export async function resolveFeeAccts(
  connection: Connection,
  payer: PublicKey,
): Promise<{
  protocolConfigPda: PublicKey;
  feeRecordPda: PublicKey;
  treasuryShardPda: PublicKey;
}> {
  const client = makeClient(connection);
  const accts = await client.resolveProtocolFee(payer);
  if (!accts) {
    throw new Error(
      'resolveFeeAccts: ProtocolConfig is not initialized or disabled. ' +
        'Did setupTest() run? Did the validator start with --reset?',
    );
  }
  return accts;
}
