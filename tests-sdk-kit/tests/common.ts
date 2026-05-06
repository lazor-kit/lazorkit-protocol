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

export interface TestContext {
  rpc: ReturnType<typeof createSolanaRpc>;
  rpcSubscriptions: ReturnType<typeof createSolanaRpcSubscriptions>;
  payer: KeyPairSigner;
  /** Pre-built confirm-and-send factory bound to rpc + subscriptions. */
  sendAndConfirm: ReturnType<typeof sendAndConfirmTransactionFactory>;
}

export async function setupTest(): Promise<TestContext> {
  const rpc = createSolanaRpc(RPC_URL);
  const rpcSubscriptions = createSolanaRpcSubscriptions(RPC_WS_URL);
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

  return { rpc, rpcSubscriptions, payer, sendAndConfirm };
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
    const parts = chain.map((e) => {
      const own = Object.getOwnPropertyNames(e as object);
      return (
        JSON.stringify(e, [...own, 'context', 'cause'], replacer) || String(e)
      );
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
