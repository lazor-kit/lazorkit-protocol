/**
 * Shared E2E-test infrastructure for the kit-flavored SDK.
 *
 * Mirrors tests-sdk/tests/common.ts (the v1 / sdk-legacy harness) in
 * intent: provide setupTest / sendTx / sendTxExpectError / getSlot
 * that any test file can import. Underneath, everything is kit:
 * KeyPairSigner instead of Keypair, Address instead of PublicKey,
 * pipe(...) builder instead of `new Transaction()`.
 */
import {
  airdropFactory,
  appendTransactionMessageInstructions,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  createKeyPairSignerFromBytes,
  generateKeyPairSigner,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type Instruction,
  type KeyPairSigner,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from '@solana/kit';
import { readFileSync } from 'fs';
import { LazorKit, PROGRAM_ID_DEVNET, type LazorKitRpc } from '@lazorkit/sdk';

export const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8899';
export const RPC_WS_URL = process.env.RPC_WS_URL ?? 'ws://127.0.0.1:8900';

// Tests run against `solana-test-validator` which loads the SBF built with
// `--features devnet`, so the on-chain program ID is the devnet vanity.
export { PROGRAM_ID_DEVNET };
export const PROGRAM_ID: Address = PROGRAM_ID_DEVNET;

/** Construct a LazorKit client wired to the local validator. */
export function makeClient(rpc: LazorKitRpc): LazorKit {
  return new LazorKit(rpc, PROGRAM_ID);
}

/**
 * The keypair `initialize_protocol` now requires.
 *
 * ProtocolConfig is the root of the fee system and has no earlier on-chain
 * account to anchor trust to, so the anchor is a pubkey compiled into the
 * program (`PROTOCOL_INIT_AUTHORITY`). The devnet value is this committed test
 * key — devnet carries no value, and a shared secret would make the local
 * suites unrunnable.
 */
export async function initAuthority() {
  // vitest runs with cwd at the package root.
  const bytes = JSON.parse(
    readFileSync('../keys/devnet-init-authority.json', 'utf8'),
  ) as number[];
  return createKeyPairSignerFromBytes(Uint8Array.from(bytes));
}

export interface TestContext {
  rpc: ReturnType<typeof createSolanaRpc>;
  rpcSubscriptions: ReturnType<typeof createSolanaRpcSubscriptions>;
  payer: KeyPairSigner;
  /** Pre-built confirm-and-send factory bound to rpc + subscriptions. */
  sendAndConfirm: ReturnType<typeof sendAndConfirmTransactionFactory>;
}

// ─── Strict-fee setup (Approach A from the proposal) ─────────────────
//
// Strict-fee enforcement on the commercial binary requires every disc
// 0/4/7 instruction to carry a valid [ProtocolConfig, FeeRecord,
// TreasuryShard, SystemProgram] suffix. Pre-init wallet creation
// fails with 4009 ProtocolNotInitialized. So every test suite has to
// ensure ProtocolConfig is initialized before its first
// CreateWallet / Execute / ExecuteDeferred — otherwise *every* test
// breaks.
//
// To keep the per-test-file `setupTest()` stable, we lift protocol
// init to the module level: the first `setupTest()` call across the
// entire vitest run creates a shared admin + treasury keypair-signer
// and runs `initialize_protocol` + `initialize_treasury_shard × NUM_SHARDS`.
// Subsequent calls are no-ops.
//
// Tests that need admin-only operations (UpdateProtocol, WithdrawTreasury)
// import `getProtocolAdmin()` to get the shared admin signer.

const NUM_SHARDS = 4;
const CREATION_FEE = 5_000n; // 0.000005 SOL — fits all test budgets
const EXECUTION_FEE = 2_000n;

let _initialized = false;
let _adminSigner: KeyPairSigner | undefined;
let _treasurySigner: KeyPairSigner | undefined;

/**
 * Returns the shared admin keypair signer. Throws if init hasn't
 * happened yet — callers must chain after a `setupTest()` in their
 * `beforeAll`.
 */
export function getProtocolAdmin(): KeyPairSigner {
  if (!_adminSigner) {
    throw new Error(
      'getProtocolAdmin() called before setupTest(). ' +
        'Call setupTest() in beforeAll first.',
    );
  }
  return _adminSigner;
}

/** Returns the shared treasury keypair signer. Same usage rules. */
export function getProtocolTreasury(): KeyPairSigner {
  if (!_treasurySigner) {
    throw new Error('getProtocolTreasury() called before setupTest()');
  }
  return _treasurySigner;
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
async function assertProgramDeployed(rpc: LazorKitRpc): Promise<void> {
  if (_preflightDone) return;
  _preflightDone = true;

  const { value } = await rpc.getAccountInfo(PROGRAM_ID, { encoding: 'base64' }).send();
  if (!value) {
    throw new Error(
      `LazorKit program not found at ${PROGRAM_ID} on ${RPC_URL}.\n` +
        `Start the validator first:  npm run validator:start && npm run validator:wait`,
    );
  }
  if (!value.executable) {
    throw new Error(`Account ${PROGRAM_ID} on ${RPC_URL} exists but is not executable.`);
  }
}

export async function setupTest(): Promise<TestContext> {
  const rpc = createSolanaRpc(RPC_URL);
  const rpcSubscriptions = createSolanaRpcSubscriptions(RPC_WS_URL);

  await assertProgramDeployed(rpc);

  const payer = await generateKeyPairSigner();

  // Airdrop 10 SOL.
  const airdrop = airdropFactory({ rpc, rpcSubscriptions });
  await airdrop({
    recipientAddress: payer.address,
    lamports: lamports(10n * 1_000_000_000n),
    commitment: 'confirmed',
  });

  const sendAndConfirm = sendAndConfirmTransactionFactory({
    rpc,
    rpcSubscriptions,
  });

  const ctx: TestContext = { rpc, rpcSubscriptions, payer, sendAndConfirm };
  await ensureProtocolInitialized(ctx);
  return ctx;
}

/**
 * Idempotent protocol initializer. Runs at most once per vitest process.
 *
 * Order of effects:
 *   1. Generate `_adminSigner` + `_treasurySigner` (module-level)
 *   2. Airdrop a small amount to the admin so it can sign
 *      `initialize_treasury_shard` (which requires admin to be a writable signer)
 *   3. Probe `ProtocolConfig` PDA via `client.getProtocolConfig()`
 *      - If null: validator is fresh → run init + shard creation
 *      - If non-null: validator carries leftover state from a previous
 *        run; rare, but tolerated. The shared admin won't be able to
 *        sign UpdateProtocol etc. against the leftover config — that's
 *        an explicit failure mode, document for users.
 */
async function ensureProtocolInitialized(ctx: TestContext): Promise<void> {
  if (_initialized) return;
  _initialized = true; // claim the slot before any await — no double-init

  _adminSigner = await generateKeyPairSigner();
  _treasurySigner = await generateKeyPairSigner();

  // Fund admin so it can sign initialize_treasury_shard.
  const airdrop = airdropFactory({
    rpc: ctx.rpc as never,
    rpcSubscriptions: ctx.rpcSubscriptions as never,
  });
  await airdrop({
    recipientAddress: _adminSigner.address,
    lamports: lamports(1n * 1_000_000_000n),
    commitment: 'confirmed',
  });

  const client = makeClient(ctx.rpc as never);
  const config = await client.getProtocolConfig();
  if (config && config.enabled) {
    console.warn(
      '[tests-sdk-kit/common.ts] ProtocolConfig already initialized on this validator. ' +
        'Admin-only tests will fail unless you --reset the validator.',
    );
    return;
  }

  // Fresh validator — initialize protocol + shards.
  //
  // initialize_protocol is gated on PROTOCOL_INIT_AUTHORITY, so the random
  // per-run payer cannot do it. Fund the authority and let it pay its own rent.
  const authority = await initAuthority();
  await airdrop({
    recipientAddress: authority.address,
    lamports: lamports(1n * 1_000_000_000n),
    commitment: 'confirmed',
  });

  const init = await client.initializeProtocol({
    payer: authority.address,
    admin: _adminSigner.address,
    treasury: _treasurySigner.address,
    creationFee: CREATION_FEE,
    executionFee: EXECUTION_FEE,
    numShards: NUM_SHARDS,
  });
  await sendTx(ctx, init.instructions, [authority]);

  for (let i = 0; i < NUM_SHARDS; i++) {
    const shard = await client.initializeTreasuryShard({
      payer: ctx.payer.address,
      admin: _adminSigner.address,
      shardId: i,
    });
    await sendTx(ctx, shard.instructions, [_adminSigner]);
  }

  client.invalidateProtocolCache();
}

/**
 * Build, sign, send, and confirm a transaction.
 *
 * Always passes the test context's payer as fee payer. Additional
 * signers (Ed25519 wallet keys, session keys, etc) can be threaded
 * via the inner instructions or by wrapping addresses into TransactionSigners
 * before calling.
 */
export async function sendTx(
  ctx: TestContext,
  instructions: Instruction[],
  signers: TransactionSigner[] = [],
): Promise<string> {
  const { value: latestBlockhash } = await ctx.rpc.getLatestBlockhash().send();

  // Inject fee-payer signer at the top of the signer list — kit's
  // signTransactionMessageWithSigners discovers signers from instruction
  // accounts AND from explicit hint signers wired into the message.
  const allSigners: readonly TransactionSigner[] = [ctx.payer, ...signers];

  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(ctx.payer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
    // Attach extra signers as a no-op instruction would be ugly; instead
    // rely on instruction-embedded signers. Most non-fee-payer signers
    // are already referenced in the instruction accounts list.
    (m) => attachExtraSigners(m, allSigners),
  );

  const signed = await signTransactionMessageWithSigners(message);
  const signature = getSignatureFromTransaction(signed);
  // `sendAndConfirm`'s factory accepts blockhash-lifetime txs only; our
  // builder always sets a blockhash lifetime above so the cast is safe.
  await ctx.sendAndConfirm(signed as never, { commitment: 'confirmed' });
  return signature;
}

/**
 * Same as sendTx but expects the transaction to fail; optionally
 * verifies a specific custom error code.
 */
export async function sendTxExpectError(
  ctx: TestContext,
  instructions: Instruction[],
  signers: TransactionSigner[] = [],
  expectedErrorCode?: number,
): Promise<string> {
  try {
    await sendTx(ctx, instructions, signers);
    throw new Error('Transaction should have failed but succeeded');
  } catch (err: unknown) {
    const msg = String(err);
    if (msg.includes('Transaction should have failed')) throw err;
    if (expectedErrorCode !== undefined) {
      // kit's SolanaError wraps the on-chain custom error code inside
      // err.context.cause.context.error (an object like
      // `{ InstructionError: [0, { Custom: 3006 }] }`). Walk the cause
      // chain + serialize the whole thing to make matching robust.
      const fullDump = serializeError(err);
      const hexCode = expectedErrorCode.toString(16);
      const numStr = String(expectedErrorCode);
      const matches =
        fullDump.includes(`0x${hexCode}`) ||
        fullDump.includes(`Custom(${expectedErrorCode})`) ||
        fullDump.includes(`custom: ${expectedErrorCode}`) ||
        // kit JSON-shaped: `"Custom":3006`
        fullDump.includes(`"Custom":${numStr}`) ||
        // And: `'Custom':3006` (some serializers)
        fullDump.includes(`'Custom':${numStr}`) ||
        // kit's SolanaError stringification: `Custom program error: #3006`
        fullDump.includes(`Custom program error: #${numStr}`);
      if (!matches) {
        throw new Error(
          `Expected error code ${expectedErrorCode} (0x${hexCode}), got: ${fullDump}`,
        );
      }
    }
    return msg;
  }
}

function serializeError(err: unknown): string {
  if (err == null) return String(err);
  const seen = new WeakSet();
  const replacer = (_k: string, v: unknown) => {
    if (typeof v === 'bigint') return v.toString();
    if (typeof v === 'object' && v !== null) {
      if (seen.has(v as object)) return '[circular]';
      seen.add(v as object);
    }
    return v;
  };
  // Walk cause chain so kit's nested error structure is included.
  const chain: unknown[] = [];
  let cur: unknown = err;
  for (let i = 0; i < 8 && cur != null; i++) {
    chain.push(cur);
    cur = (cur as { cause?: unknown }).cause;
  }
  try {
    // Walk own properties manually instead of using JSON's allowlist arg
    // (TS overloads make passing both an allowlist + a replacer fn
    // ambiguous). We use the replacer-only form and inline the
    // own-properties dump for each link in the cause chain.
    const parts = chain.map((e) => {
      const obj: Record<string, unknown> = {};
      for (const k of Object.getOwnPropertyNames(e as object)) {
        obj[k] = (e as Record<string, unknown>)[k];
      }
      try {
        return JSON.stringify(obj, replacer) || String(e);
      } catch {
        return String(e);
      }
    });
    return parts.join(' || ') + ' || ' + String(err);
  } catch {
    return String(err);
  }
}

export async function getSlot(ctx: TestContext): Promise<bigint> {
  const slot = await ctx.rpc.getSlot({ commitment: 'confirmed' }).send();
  return slot;
}

/**
 * Helper for tests that bypass the high-level client and call low-level
 * builders (createCreateWalletIx / createExecuteIx /
 * createExecuteDeferredIx) directly. Strict-fee enforcement requires
 * those calls to carry the [ProtocolConfig, FeeRecord, TreasuryShard,
 * SystemProgram] suffix; resolveFeeAccts() returns the three program-
 * owned accounts (the SystemProgram one is appended by the builder
 * helper). Tests pass the result as the `protocolFee` arg.
 */
export async function resolveFeeAccts(
  rpc: LazorKitRpc,
  payer: Address,
): Promise<{
  protocolConfigPda: Address;
  feeRecordPda: Address;
  treasuryShardPda: Address;
}> {
  const client = makeClient(rpc);
  const accts = await client.resolveProtocolFee(payer);
  if (!accts) {
    throw new Error(
      'resolveFeeAccts: ProtocolConfig is not initialized or disabled. ' +
        'Did setupTest() run? Did the validator start with --reset?',
    );
  }
  return accts;
}

/**
 * Build a SystemProgram Transfer instruction where `from` is NOT a
 * regular signer (e.g. a wallet vault PDA — the on-chain LazorKit
 * program signs for it via PDA invocation). @solana-program/system's
 * getTransferSolInstruction requires `source: TransactionSigner` which
 * we don't have for PDAs, so we hand-build the layout. Wire format:
 *   data:    [u32 LE: ix_disc=2] [u64 LE: lamports]
 *   keys:    from (writable, NOT signer) → to (writable, NOT signer)
 */
export function systemTransferFromPda(
  from: import('@solana/kit').Address,
  to: import('@solana/kit').Address,
  lamports: bigint,
): Instruction {
  const data = new Uint8Array(12);
  // 4-byte discriminator (Transfer = 2)
  new DataView(data.buffer).setUint32(0, 2, /* le */ true);
  new DataView(data.buffer).setBigUint64(4, lamports, /* le */ true);
  return {
    programAddress:
      '11111111111111111111111111111111' as import('@solana/kit').Address,
    accounts: [
      { address: from, role: /* WRITABLE */ 1 },
      { address: to, role: /* WRITABLE */ 1 },
    ],
    data,
  };
}

/** Helper: get an Address's lamports balance via the RPC. */
export async function getBalance(
  ctx: TestContext,
  address: import('@solana/kit').Address,
): Promise<bigint> {
  const info = await ctx.rpc
    .getBalance(address, { commitment: 'confirmed' })
    .send();
  return info.value;
}

/** Airdrop convenience for vault funding inside tests. */
export async function airdrop(
  ctx: TestContext,
  to: import('@solana/kit').Address,
  amount: bigint,
): Promise<void> {
  const airdropFn = airdropFactory({
    rpc: ctx.rpc as never,
    rpcSubscriptions: ctx.rpcSubscriptions as never,
  });
  await airdropFn({
    recipientAddress: to,
    lamports: lamports(amount),
    commitment: 'confirmed',
  });
}

/**
 * Kit's signTransactionMessageWithSigners pulls signers from instruction
 * accounts that have a *_SIGNER role. Some of our extra signers (e.g.
 * session keys passed as remainingAccounts on Execute) might not be
 * recognised because of how we set their AccountRole. To make sure they
 * are signed, we explicitly add them to the message via the kit helper.
 */
function attachExtraSigners<TMessage extends object>(
  message: TMessage,
  signers: readonly TransactionSigner[],
): TMessage {
  // We can't import addSignersToTransactionMessage at the top because of a
  // circular import concern with how the file is organised; pull it lazily.
  // (The actual `@solana/kit` re-exports it cleanly — this is a shim that
  // makes the call site readable.)
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { addSignersToTransactionMessage } = require('@solana/kit');
  return addSignersToTransactionMessage(signers, message);
}
