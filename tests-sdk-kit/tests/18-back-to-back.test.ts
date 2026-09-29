/**
 * Two passkey transactions from one authority, back to back, on a validator.
 * Mirrors tests-sdk/tests/19-back-to-back.test.ts.
 *
 * tx2's challenge signs the authority's counter + 1, read when tx2 is
 * prepared; read before tx1 has executed, it is the counter tx1 is about to
 * use and tx2 fails with SignatureReused (3006). The floor: read tx2's
 * counter, key and slot at or after the slot tx1 landed in
 * (`minContextSlot`). Also pinned against a real node: a floor it has not
 * reached yet is waited for (-32016), and one it never reaches ends in
 * MinContextSlotNotReachedError, not in a stale read.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import { generateKeyPairSigner, signature as toSignature, type Address } from '@solana/kit';
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

  /** One lamport out of the vault, signed by the passkey, with `floor` on its reads. */
  async function payOut(floor?: { minContextSlot?: bigint }) {
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: secp256r1(signer, floor),
      instructions: [systemTransferFromPda(vaultPda, sink, 1n)],
    });
    return sendTx(ctx, instructions);
  }

  it("tx2 prepared at tx1's landing slot signs the next counter and lands", async () => {
    const before = await client.readCounter(authorityPda);

    const sig1 = await payOut();
    const {
      value: [status1],
    } = await ctx.rpc.getSignatureStatuses([toSignature(sig1)]).send();
    expect(status1?.err).toBeNull();

    await payOut({ minContextSlot: status1!.slot });
    expect(await client.readCounter(authorityPda)).toBe(before + 2);
  });

  it('waits for a node that has not reached the floor yet, then reads', async () => {
    const floor = (await ctx.rpc.getSlot({ commitment: 'confirmed' }).send()) + 6n;
    const counter = await client.readCounter(authorityPda, { minContextSlot: floor });
    expect(counter).toBeGreaterThanOrEqual(2);
    expect(await ctx.rpc.getSlot({ commitment: 'confirmed' }).send()).toBeGreaterThanOrEqual(floor);
  });

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
