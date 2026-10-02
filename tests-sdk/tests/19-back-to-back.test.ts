/**
 * Two passkey transactions from one authority, back to back, on a validator.
 *
 * tx2's challenge signs the authority's counter + 1, read when tx2 is
 * prepared. Read from a bank that has not executed tx1 yet, that is the
 * counter tx1 is about to use, and tx2 fails with SignatureReused (3006) —
 * three pairs out of three on devnet with a wallet and relayer that answer
 * before confirming. The floor: read tx2's counter, key and slot at or after
 * the slot tx1 landed in (`minContextSlot`).
 *
 * One node stands in for a lagging one here: tx1 is confirmed at `processed`
 * only, and tx2's reads are at `confirmed`, a slot or so behind. The first case
 * is the negative control: without the floor tx2 signs the spent counter, so
 * this setup reproduces the bug. With the floor it lands (an SDK that ignored
 * the floor fails that case). Also pinned against a real node: a floor it has
 * not reached yet is waited for (-32016 comes back with its code through
 * web3.js), one it never reaches ends in MinContextSlotNotReachedError, not in
 * a stale read, a floor read at `finalized` waits for that slot to finalize
 * (about 32 slots after it was confirmed, longer than the 10 s the other
 * commitments wait), and a Connection at `processed` keeps reading there by
 * default (1.2.0 read at the Connection's commitment).
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  SystemProgram,
  Transaction,
  type PublicKey,
  type TransactionError,
} from '@solana/web3.js';
import * as crypto from 'crypto';

import {
  LazorKitClient,
  MinContextSlotNotReachedError,
  secp256r1,
} from '../../sdk/sdk-legacy/src';
import { RPC_URL, setupTest, sendTx, makeClient, type TestContext } from './common';
import { createMockRawSigner, generateMockSecp256r1Key } from './secp256r1Utils';

type Sent = { signature: string; blockhash: string; lastValidBlockHeight: number };

/** SignatureReused, from a preflight error or a landed `{ InstructionError: [i, { Custom }] }`. */
function isSpentCounter(err: unknown): boolean {
  const text =
    err instanceof Error
      ? `${err.message} ${(err as { logs?: string[] }).logs ?? ''}`
      : JSON.stringify(err);
  return /"Custom":3006\b/.test(text) || /custom program error: 0xbbe\b/i.test(text);
}

describe('back-to-back passkey transactions', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let walletPda: PublicKey;
  let vaultPda: PublicKey;
  let authorityPda: PublicKey;
  let signer: ReturnType<typeof createMockRawSigner>;
  const sink = Keypair.generate().publicKey;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.connection);
    const key = await generateMockSecp256r1Key();
    signer = createMockRawSigner(key);
    const created = await client.createWallet({
      payer: ctx.payer.publicKey,
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
    const sig = await ctx.connection.requestAirdrop(vaultPda, LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig, 'confirmed');
    // Rent for the sink, so a 1-lamport transfer to it is allowed.
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: sink, lamports: 1_000_000 }),
    ]);
  });

  /**
   * One lamport out of the vault, signed by the passkey through `lk`, with
   * `floor` on its reads. Answers as soon as the RPC accepts it, as the wallet
   * and relayer did; preflight runs at the Connection's commitment.
   */
  async function payOut(
    floor?: { minContextSlot?: number; commitment?: 'processed' | 'confirmed' | 'finalized' },
    lk: LazorKitClient = client,
    connection: Connection = ctx.connection,
  ): Promise<Sent> {
    const { instructions } = await lk.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: secp256r1(signer, floor),
      instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: sink, lamports: 1 })],
    });
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    const tx = new Transaction({ feePayer: ctx.payer.publicKey, blockhash, lastValidBlockHeight }).add(
      ...instructions,
    );
    tx.sign(ctx.payer);
    const signature = await connection.sendRawTransaction(tx.serialize());
    return { signature, blockhash, lastValidBlockHeight };
  }

  /** How tx2 ends: `null` once confirmed without error, else its error (preflight or landed). */
  async function outcome(
    send: () => Promise<Sent>,
    connection: Connection = ctx.connection,
  ): Promise<TransactionError | Error | null> {
    let sent: Sent;
    try {
      sent = await send();
    } catch (e) {
      return e as Error;
    }
    return (await connection.confirmTransaction(sent, 'confirmed')).value.err;
  }

  it('negative control: without a floor, tx2 read right after tx1 is processed signs the spent counter (3006)', async () => {
    let spent = 0;
    for (let round = 0; round < 3; round++) {
      const tx1 = await payOut();
      expect((await ctx.connection.confirmTransaction(tx1, 'processed')).value.err).toBeNull();

      // No floor: the reads are at 'confirmed', which has not seen tx1 yet.
      const err2 = await outcome(() => payOut());
      if (err2 === null) continue; // the confirmed bank caught up first: no stale read this round
      expect(isSpentCounter(err2), JSON.stringify(err2)).toBe(true);
      spent++;

      // The next round starts from a counter every bank agrees on.
      await ctx.connection.confirmTransaction(tx1, 'confirmed');
    }
    expect(spent).toBeGreaterThan(0);
  });

  it("tx2 floored at tx1's slot lands, though tx1 was only seen processed", async () => {
    const before = await client.readCounter(authorityPda);

    for (let round = 0; round < 3; round++) {
      const tx1 = await payOut();
      const confirmed1 = await ctx.connection.confirmTransaction(tx1, 'processed');
      expect(confirmed1.value.err).toBeNull();
      const {
        value: [status1],
      } = await ctx.connection.getSignatureStatuses([tx1.signature]);
      // confirmTransaction's context slot is at or after the slot tx1 landed
      // in, so either is a floor; the README uses the former.
      expect(confirmed1.context.slot).toBeGreaterThanOrEqual(status1!.slot);
      const floor = round % 2 === 0 ? status1!.slot : confirmed1.context.slot;

      const err2 = await outcome(() => payOut({ minContextSlot: floor }));
      expect(err2).toBeNull();
    }
    expect(await client.readCounter(authorityPda)).toBe(before + 6);
  });

  it('waits for a node that has not reached the floor yet, then reads', async () => {
    const floor = (await ctx.connection.getSlot('confirmed')) + 6;
    const reads = vi.spyOn(ctx.connection, 'getAccountInfoAndContext');
    try {
      const counter = await client.readCounter(authorityPda, { minContextSlot: floor });
      expect(counter).toBeGreaterThanOrEqual(2);
      // At least one -32016 from the node, recognised and retried.
      expect(reads.mock.calls.length).toBeGreaterThan(1);
      expect(await ctx.connection.getSlot('confirmed')).toBeGreaterThanOrEqual(floor);
    } finally {
      reads.mockRestore();
    }
  });

  // What the README tells a caller to pass (the slot tx1 landed in, once it
  // is confirmed), with the reads at 'finalized': that slot is finalized about
  // 32 slots later. The reads used to give up after 10 s, always, with an
  // error that blamed the RPC endpoint.
  it("at 'finalized', floored at a just-confirmed tx1, tx2 waits for finalization and lands", async () => {
    const before = await client.readCounter(authorityPda);
    const tx1 = await payOut();
    expect((await ctx.connection.confirmTransaction(tx1, 'confirmed')).value.err).toBeNull();
    const {
      value: [status1],
    } = await ctx.connection.getSignatureStatuses([tx1.signature]);
    const landed = status1!.slot;
    // Not finalized yet: the reads have to wait for it.
    expect(await ctx.connection.getSlot('finalized')).toBeLessThan(landed);

    const started = Date.now();
    const err2 = await outcome(() => payOut({ minContextSlot: landed, commitment: 'finalized' }));
    expect(err2).toBeNull();
    // It waited for the node's finalized bank, not for 10 s and an error.
    expect(await ctx.connection.getSlot('finalized')).toBeGreaterThanOrEqual(landed);
    expect(Date.now() - started).toBeLessThan(30_000);
    expect(await client.readCounter(authorityPda)).toBe(before + 2);
  }, 60_000);

  it('gives up with MinContextSlotNotReachedError on a floor the node never reaches', async () => {
    const floor = (await ctx.connection.getSlot('confirmed')) + 1_000_000;
    const error = await client.readCounter(authorityPda, { minContextSlot: floor }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(MinContextSlotNotReachedError);
    expect((error as MinContextSlotNotReachedError).minContextSlot).toBe(floor);
  }, 30_000);

  // 1.2.0 read the challenge at the Connection's own commitment. An integrator
  // whose Connection is at 'processed' confirms each send there and prepares
  // the next one straight away; a 'confirmed' default would sign the spent
  // counter every time, and not find a wallet it had just created.
  describe("on a Connection at 'processed', with no options", () => {
    let processed: Connection;
    let lk: LazorKitClient;

    beforeAll(() => {
      processed = new Connection(RPC_URL, 'processed');
      lk = makeClient(processed);
    });

    it('tx2 prepared right after tx1 confirms at processed lands', async () => {
      const before = await client.readCounter(authorityPda, { commitment: 'processed' });

      for (let round = 0; round < 3; round++) {
        const tx1 = await payOut(undefined, lk, processed);
        expect((await processed.confirmTransaction(tx1, 'processed')).value.err).toBeNull();

        const tx2 = await payOut(undefined, lk, processed);
        expect((await processed.confirmTransaction(tx2, 'processed')).value.err).toBeNull();
      }
      expect(await lk.readCounter(authorityPda)).toBe(before + 6);
    });

    it('a passkey wallet confirmed at processed is read right away', async () => {
      const key = await generateMockSecp256r1Key();
      const created = await lk.createWallet({
        payer: ctx.payer.publicKey,
        userSeed: crypto.randomBytes(32),
        owner: {
          type: 'secp256r1',
          credentialIdHash: key.credentialIdHash,
          compressedPubkey: key.publicKeyBytes,
          rpId: key.rpId,
        },
      });
      const { blockhash, lastValidBlockHeight } = await processed.getLatestBlockhash();
      const tx = new Transaction({ feePayer: ctx.payer.publicKey, blockhash, lastValidBlockHeight }).add(
        ...created.instructions,
      );
      tx.sign(ctx.payer);
      const signature = await processed.sendRawTransaction(tx.serialize());
      const confirmed = await processed.confirmTransaction(
        { signature, blockhash, lastValidBlockHeight },
        'processed',
      );
      expect(confirmed.value.err).toBeNull();

      // Straight away: the counter and the key, as the next prepare reads them.
      expect(await lk.readCounter(created.authorityPda)).toBe(0);
      const { instructions } = await lk.execute({
        payer: ctx.payer.publicKey,
        walletPda: created.walletPda,
        signer: secp256r1(createMockRawSigner(key)),
        instructions: [SystemProgram.transfer({ fromPubkey: created.vaultPda, toPubkey: sink, lamports: 1 })],
      });
      expect(instructions.length).toBeGreaterThan(0);
    });
  });
});
