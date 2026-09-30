/**
 * Two passkey transactions from one authority, back to back, on a validator.
 * Mirrors tests-sdk/tests/19-back-to-back.test.ts.
 *
 * tx2's challenge signs the authority's counter + 1, read when tx2 is
 * prepared; read from a bank that has not executed tx1 yet, it is the counter
 * tx1 is about to use and tx2 fails with SignatureReused (3006). The floor:
 * read tx2's counter, key and slot at or after the slot tx1 landed in
 * (`minContextSlot`).
 *
 * One node stands in for a lagging one: tx1 is confirmed at `processed` only,
 * and tx2's reads are at `confirmed`, a slot or so behind. The first case is
 * the negative control (without the floor tx2 signs the spent counter); with
 * the floor, or with `commitment: 'processed'`, it lands. Also pinned against
 * a real node: a floor it has not reached yet is waited for (-32016), one it
 * never reaches ends in MinContextSlotNotReachedError, not in a stale read, and
 * a floor read at `finalized` waits for that slot to finalize (about 32 slots
 * after it was confirmed, longer than the 10 s the other commitments wait).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  generateKeyPairSigner,
  isSolanaError,
  signature as toSignature,
  type Address,
} from '@solana/kit';
import { LazorKit, MinContextSlotNotReachedError, secp256r1 } from '@lazorkit/sdk';
import {
  airdrop,
  makeClient,
  sendTx,
  setupTest,
  systemTransferFromPda,
  type TestContext,
} from './common.js';
import { createMockSigner, generateMockSecp256r1Key } from './secp256r1Utils.js';

/** SignatureReused anywhere in a send's error chain (preflight or landed). */
function isSpentCounter(err: unknown): boolean {
  for (let e = err, i = 0; e != null && i < 8; e = (e as { cause?: unknown }).cause, i++) {
    if (isSolanaError(e, SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM) && e.context.code === 3006) return true;
  }
  return false;
}

describe('back-to-back passkey transactions (validator)', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let walletPda: Address;
  let vaultPda: Address;
  let authorityPda: Address;
  let signer: ReturnType<typeof createMockSigner>;
  let sink: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    const key = await generateMockSecp256r1Key();
    signer = createMockSigner(key);
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: {
        type: 'secp256r1',
        credentialIdHash: key.credentialIdHash,
        compressedPubkey: key.publicKeyBytes,
        rpId: key.rpId,
      },
    });
    await sendTx(ctx, created.instructions);
    ({ walletPda, vaultPda, authorityPda } = created);
    await airdrop(ctx, vaultPda, 1_000_000_000n);
    sink = (await generateKeyPairSigner()).address;
    await airdrop(ctx, sink, 1_000_000n);
  });

  /**
   * One lamport out of the vault, signed by the passkey, with `floor` on its
   * reads; sent and waited for at `commitment`.
   */
  async function payOut(
    floor?: { minContextSlot?: bigint; commitment?: 'processed' | 'confirmed' | 'finalized' },
    commitment: 'processed' | 'confirmed' = 'confirmed',
  ) {
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: secp256r1(signer, floor),
      instructions: [systemTransferFromPda(vaultPda, sink, 1n)],
    });
    return sendTx(ctx, instructions, [], ctx.payer, commitment);
  }

  /** How tx2 ends: `null` once confirmed without error, else its error. */
  async function outcome(send: () => Promise<string>): Promise<unknown> {
    try {
      await send();
      return null;
    } catch (e) {
      return e;
    }
  }

  /** tx1, confirmed at 'processed' only; returns the slot it landed in. */
  async function tx1AtProcessed(): Promise<bigint> {
    const sig1 = await payOut(undefined, 'processed');
    const {
      value: [status1],
    } = await ctx.rpc.getSignatureStatuses([toSignature(sig1)]).send();
    expect(status1?.err).toBeNull();
    return status1!.slot;
  }

  it('negative control: without a floor, tx2 read right after tx1 is processed signs the spent counter (3006)', async () => {
    let spent = 0;
    for (let round = 0; round < 3; round++) {
      const landed = await tx1AtProcessed();
      // No floor: the reads are at 'confirmed', which has not seen tx1 yet.
      const err2 = await outcome(() => payOut());
      if (err2 !== null) {
        expect(isSpentCounter(err2), String(err2)).toBe(true);
        spent++;
      }
      // The next round starts from a counter every bank agrees on.
      await client.readCounter(authorityPda, { minContextSlot: landed });
    }
    expect(spent).toBeGreaterThan(0);
  });

  it("tx2 floored at tx1's landing slot lands, though tx1 was only seen processed", async () => {
    const before = await client.readCounter(authorityPda);
    for (let round = 0; round < 3; round++) {
      const landed = await tx1AtProcessed();
      expect(await outcome(() => payOut({ minContextSlot: landed }))).toBeNull();
    }
    expect(await client.readCounter(authorityPda)).toBe(before + 6);
  });

  // A caller that confirms at 'processed' reads there too (a 'confirmed'
  // preflight would reject tx2 the same way, so it sends there as well).
  it("a caller at 'processed' throughout: tx2 read right after tx1 lands", async () => {
    const atProcessed = { commitment: 'processed' as const };
    const before = await client.readCounter(authorityPda, atProcessed);
    for (let round = 0; round < 3; round++) {
      await payOut(atProcessed, 'processed');
      expect(await outcome(() => payOut(atProcessed, 'processed'))).toBeNull();
    }
    expect(await client.readCounter(authorityPda, atProcessed)).toBe(before + 6);
  });

  it('waits for a node that has not reached the floor yet, then reads', async () => {
    const floor = (await ctx.rpc.getSlot({ commitment: 'confirmed' }).send()) + 6n;
    const counter = await client.readCounter(authorityPda, { minContextSlot: floor });
    expect(counter).toBeGreaterThanOrEqual(2);
    expect(await ctx.rpc.getSlot({ commitment: 'confirmed' }).send()).toBeGreaterThanOrEqual(floor);
  });

  // What the README tells a caller to pass (the slot tx1 landed in, once it
  // is confirmed), with the reads at 'finalized': that slot is finalized about
  // 32 slots later. The reads used to give up after 10 s, always.
  it("at 'finalized', floored at a just-confirmed tx1, tx2 waits for finalization and lands", async () => {
    const before = await client.readCounter(authorityPda);
    const sig1 = await payOut(); // confirmed
    const {
      value: [status1],
    } = await ctx.rpc.getSignatureStatuses([toSignature(sig1)]).send();
    expect(status1?.err).toBeNull();
    const landed = status1!.slot;
    // Not finalized yet: the reads have to wait for it.
    expect(await ctx.rpc.getSlot({ commitment: 'finalized' }).send()).toBeLessThan(landed);

    const started = Date.now();
    expect(await outcome(() => payOut({ minContextSlot: landed, commitment: 'finalized' }))).toBeNull();
    expect(await ctx.rpc.getSlot({ commitment: 'finalized' }).send()).toBeGreaterThanOrEqual(landed);
    expect(Date.now() - started).toBeLessThan(30_000);
    expect(await client.readCounter(authorityPda)).toBe(before + 2);
  }, 60_000);

  it('gives up with MinContextSlotNotReachedError on a floor the node never reaches', async () => {
    const floor = (await ctx.rpc.getSlot({ commitment: 'confirmed' }).send()) + 1_000_000n;
    const error = await client.readCounter(authorityPda, { minContextSlot: floor }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(MinContextSlotNotReachedError);
    expect((error as MinContextSlotNotReachedError).minContextSlot).toBe(floor);
  }, 30_000);
});
