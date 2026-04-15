import { describe, it, expect, beforeAll } from 'vitest';
import { Keypair, LAMPORTS_PER_SOL } from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTx, sendTxExpectError, type TestContext } from './common';
import {
  LazorKitClient,
  PROGRAM_ID,
} from '../../sdk/sdk-legacy/src';

const NUM_SHARDS = 4;

describe('Protocol Fees', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let adminKp: Keypair;
  let treasuryKp: Keypair;
  const CREATION_FEE = 5000n;
  const EXECUTION_FEE = 2000n;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    adminKp = Keypair.generate();
    treasuryKp = Keypair.generate();

    const sig = await ctx.connection.requestAirdrop(adminKp.publicKey, 2 * LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig, 'confirmed');
  });

  it('initializes protocol config', async () => {
    const { instructions, protocolConfigPda } = client.initializeProtocol({
      payer: ctx.payer.publicKey,
      admin: adminKp.publicKey,
      treasury: treasuryKp.publicKey,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      numShards: NUM_SHARDS,
    });

    await sendTx(ctx, instructions);

    const info = await ctx.connection.getAccountInfo(protocolConfigPda);
    expect(info).not.toBeNull();
    expect(info!.data[0]).toBe(5);
    expect(info!.data[3]).toBe(1); // enabled
    expect(info!.data[4]).toBe(NUM_SHARDS);
  });

  it('rejects double initialization', async () => {
    const { instructions } = client.initializeProtocol({
      payer: ctx.payer.publicKey,
      admin: adminKp.publicKey,
      treasury: treasuryKp.publicKey,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      numShards: NUM_SHARDS,
    });
    await sendTxExpectError(ctx, instructions, [], 4001);
  });

  it('initializes treasury shards', async () => {
    for (let i = 0; i < NUM_SHARDS; i++) {
      const { instructions, treasuryShardPda } = client.initializeTreasuryShard({
        payer: ctx.payer.publicKey,
        admin: adminKp.publicKey,
        shardId: i,
      });
      await sendTx(ctx, instructions, [adminKp]);

      const info = await ctx.connection.getAccountInfo(treasuryShardPda);
      expect(info).not.toBeNull();
      expect(info!.data[0]).toBe(7);
      expect(info!.data[2]).toBe(i);
    }
  });

  it('updates protocol config', async () => {
    const { instructions } = client.updateProtocol({
      admin: adminKp.publicKey,
      creationFee: 10000n,
      executionFee: 5000n,
      enabled: true,
      newTreasury: treasuryKp.publicKey,
    });
    await sendTx(ctx, instructions, [adminKp]);

    // Revert + invalidate cache
    const { instructions: revertIxs } = client.updateProtocol({
      admin: adminKp.publicKey,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      enabled: true,
      newTreasury: treasuryKp.publicKey,
    });
    await sendTx(ctx, revertIxs, [adminKp]);
    client.invalidateProtocolCache();
  });

  it('rejects update from non-admin', async () => {
    const fakeAdmin = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(fakeAdmin.publicKey, LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig, 'confirmed');

    const { instructions } = client.updateProtocol({
      admin: fakeAdmin.publicKey,
      creationFee: 0n,
      executionFee: 0n,
      enabled: false,
      newTreasury: fakeAdmin.publicKey,
    });
    await sendTxExpectError(ctx, instructions, [fakeAdmin], 4002);
  });

  it('registers a payer', async () => {
    const { instructions, feeRecordPda } = client.registerPayer({
      payer: ctx.payer.publicKey,
      admin: adminKp.publicKey,
      targetPayer: ctx.payer.publicKey,
    });
    await sendTx(ctx, instructions, [adminKp]);

    const info = await ctx.connection.getAccountInfo(feeRecordPda);
    expect(info).not.toBeNull();
    expect(info!.data[0]).toBe(6);
  });

  it('rejects duplicate payer registration', async () => {
    const { instructions } = client.registerPayer({
      payer: ctx.payer.publicKey,
      admin: adminKp.publicKey,
      targetPayer: ctx.payer.publicKey,
    });
    await sendTxExpectError(ctx, instructions, [adminKp], 4006);
  });

  it('auto-detects payer and collects fee on CreateWallet', async () => {
    const ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);

    let shardBalanceBefore = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      shardBalanceBefore += await ctx.connection.getBalance(shardPda);
    }

    // Just call createWallet — SDK auto-detects fee record + picks shard
    const { instructions } = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });

    await sendTx(ctx, instructions);

    let shardBalanceAfter = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      shardBalanceAfter += await ctx.connection.getBalance(shardPda);
    }
    expect(shardBalanceAfter - shardBalanceBefore).toBe(Number(CREATION_FEE));

    // Verify fee record wallet_count
    const [feeRecordPda] = client.findFeeRecord(ctx.payer.publicKey);
    const info = await ctx.connection.getAccountInfo(feeRecordPda);
    const walletCount = info!.data.readUInt32LE(20);
    expect(walletCount).toBe(1);
  });

  it('auto-detects payer and collects fee on Execute', async () => {
    const ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);
    const recipient = Keypair.generate().publicKey;

    // Create wallet (will also collect fee since payer is registered)
    const { instructions: createIxs, walletPda } = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });
    await sendTx(ctx, createIxs);

    const [vaultPda] = client.findVault(walletPda);
    const fundSig = await ctx.connection.requestAirdrop(vaultPda, 2 * LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(fundSig, 'confirmed');

    let shardBalanceBefore = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      shardBalanceBefore += await ctx.connection.getBalance(shardPda);
    }

    const { SystemProgram } = await import('@solana/web3.js');
    const { instructions: execIxs } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: { type: 'ed25519', publicKey: ownerKp.publicKey },
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
    });

    await sendTx(ctx, execIxs, [ownerKp]);

    let shardBalanceAfter = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      shardBalanceAfter += await ctx.connection.getBalance(shardPda);
    }
    expect(shardBalanceAfter - shardBalanceBefore).toBe(Number(EXECUTION_FEE));
  });

  it('skips fee for unregistered payer (no extra config needed)', async () => {
    const newPayer = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(newPayer.publicKey, 5 * LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig, 'confirmed');

    const newClient = new LazorKitClient(ctx.connection);
    const newCtx = { ...ctx, payer: newPayer };

    // resolveProtocolFee returns undefined for unregistered payer
    const protocolFee = await newClient.resolveProtocolFee(newPayer.publicKey);
    expect(protocolFee).toBeUndefined();

    // createWallet works fine — no fee, no extra accounts
    const ownerKp = Keypair.generate();
    const { instructions } = await newClient.createWallet({
      payer: newPayer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });
    await sendTx(newCtx, instructions);
  });

  it('withdraws fees from treasury shards', async () => {
    const fundSig = await ctx.connection.requestAirdrop(treasuryKp.publicKey, LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(fundSig, 'confirmed');

    const treasuryBefore = await ctx.connection.getBalance(treasuryKp.publicKey);
    let totalSwept = 0;

    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      const shardBalance = await ctx.connection.getBalance(shardPda);
      // Rent-exempt for 8 bytes is ~946560 lamports; anything above that is sweepable
      if (shardBalance > 946560) {
        const { instructions } = client.withdrawTreasury({
          admin: adminKp.publicKey,
          shardId: i,
          treasury: treasuryKp.publicKey,
        });
        await sendTx(ctx, instructions, [adminKp]);
        const shardAfter = await ctx.connection.getBalance(shardPda);
        totalSwept += shardBalance - shardAfter;
      }
    }

    const treasuryAfter = await ctx.connection.getBalance(treasuryKp.publicKey);
    expect(treasuryAfter - treasuryBefore).toBe(totalSwept);
    expect(totalSwept).toBeGreaterThan(0);
  });
});
