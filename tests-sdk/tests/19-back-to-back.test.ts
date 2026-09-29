/**
 * Two passkey transactions from one authority, back to back, on a validator.
 *
 * tx2's challenge signs the authority's counter + 1, read when tx2 is
 * prepared. Sent before tx1 has executed, that read returns the counter tx1 is
 * about to use and tx2 fails with SignatureReused (3006) — three pairs out of
 * three on devnet with a wallet and relayer that answer before confirming. The
 * floor: confirm tx1, and read tx2's counter, key and slot at or after the
 * slot tx1 landed in (`minContextSlot`). Also pinned here, against a real
 * node: a floor the node has not reached yet is waited for (-32016 comes back
 * with its code through web3.js), and one it never reaches ends in
 * MinContextSlotNotReachedError, not in a stale read.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { Keypair, LAMPORTS_PER_SOL, SystemProgram, Transaction, type PublicKey } from '@solana/web3.js';
import * as crypto from 'crypto';

import {
  LazorKitClient,
  MinContextSlotNotReachedError,
  secp256r1,
} from '../../sdk/sdk-legacy/src';
import { setupTest, sendTx, makeClient, type TestContext } from './common';
import { createMockRawSigner, generateMockSecp256r1Key } from './secp256r1Utils';

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

  /** One lamport out of the vault, signed by the passkey, with `floor` on its reads. */
  async function payOut(floor?: { minContextSlot?: number }) {
    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: secp256r1(signer, floor),
      instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: sink, lamports: 1 })],
    });
    const { blockhash, lastValidBlockHeight } = await ctx.connection.getLatestBlockhash('confirmed');
    const tx = new Transaction({ feePayer: ctx.payer.publicKey, blockhash, lastValidBlockHeight }).add(
      ...instructions,
    );
    tx.sign(ctx.payer);
    // Answer as soon as the RPC accepts it, as the wallet and relayer do.
    const signature = await ctx.connection.sendRawTransaction(tx.serialize());
    return { signature, blockhash, lastValidBlockHeight };
  }

  it("tx2 prepared at tx1's landing slot signs the next counter and lands", async () => {
    const before = await client.readCounter(authorityPda);

    const tx1 = await payOut();
    // What the fix asks of the caller: confirm tx1, then floor tx2's reads at its slot.
    await ctx.connection.confirmTransaction(tx1, 'confirmed');
    const {
      value: [status1],
    } = await ctx.connection.getSignatureStatuses([tx1.signature]);
    expect(status1?.err).toBeNull();

    const tx2 = await payOut({ minContextSlot: status1!.slot });
    const confirmed2 = await ctx.connection.confirmTransaction(tx2, 'confirmed');
    expect(confirmed2.value.err).toBeNull();
    expect(await client.readCounter(authorityPda)).toBe(before + 2);
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

  it('gives up with MinContextSlotNotReachedError on a floor the node never reaches', async () => {
    const floor = (await ctx.connection.getSlot('confirmed')) + 1_000_000;
    const error = await client.readCounter(authorityPda, { minContextSlot: floor }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(MinContextSlotNotReachedError);
    expect((error as MinContextSlotNotReachedError).minContextSlot).toBe(floor);
  }, 30_000);
});
