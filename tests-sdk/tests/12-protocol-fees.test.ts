import { describe, it, expect, beforeAll } from 'vitest';
import { Keypair, LAMPORTS_PER_SOL } from '@solana/web3.js';
import * as crypto from 'crypto';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  getProtocolAdmin,
  getProtocolTreasury,
  type TestContext,
} from './common';
import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  AUTH_TYPE_ED25519,
  createCreateWalletIx,
  createWithdrawTreasuryIx,
  createUpdateProtocolIx,
} from '../../sdk/sdk-legacy/src';

// These values match what `setupTest()` uses for the global init.
// If the constants in `common.ts` ever change, this test file's
// expected fee values must move in lockstep.
const NUM_SHARDS = 4;
const CREATION_FEE = 5_000n;
const EXECUTION_FEE = 2_000n;

describe('Protocol Fees', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let adminKp: Keypair;
  let treasuryKp: Keypair;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    adminKp = getProtocolAdmin();
    treasuryKp = getProtocolTreasury();
  });

  // Note: the prior "initializes protocol config" + "initializes treasury
  // shards" tests are now redundant — setupTest() does both globally on
  // the first call across the suite. We keep "rejects double
  // initialization" because it asserts on-chain idempotency.

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

  it('protocol config is initialized + valid', async () => {
    // Sanity: setupTest() should have left this account in place.
    const [protocolConfigPda] = client.findProtocolConfig();
    const info = await ctx.connection.getAccountInfo(protocolConfigPda);
    expect(info).not.toBeNull();
    expect(info!.data[0]).toBe(5);
    expect(info!.data[3]).toBe(1); // enabled
    expect(info!.data[4]).toBe(NUM_SHARDS);
  });

  it('treasury shards are initialized', async () => {
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = client.findTreasuryShard(i);
      const info = await ctx.connection.getAccountInfo(shardPda);
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

    // Revert + invalidate cache so subsequent tests see the original fees.
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
    const sig = await ctx.connection.requestAirdrop(
      fakeAdmin.publicKey,
      LAMPORTS_PER_SOL,
    );
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

  // Note: under strict-fee enforcement, RegisterPayer is no longer
  // strictly required — the entrypoint auto-creates the FeeRecord PDA
  // on first use. But the standalone instruction is preserved for
  // backward compat, so we still test it.

  it('registers a payer (permissionless self-registration)', async () => {
    const standalonePayer = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(
      standalonePayer.publicKey,
      LAMPORTS_PER_SOL,
    );
    await ctx.connection.confirmTransaction(sig, 'confirmed');

    const { instructions, feeRecordPda } = client.registerPayer({
      payer: standalonePayer.publicKey,
    });
    // Send with the standalonePayer as fee payer (signer of the ix).
    await sendTx(
      { ...ctx, payer: standalonePayer },
      instructions,
    );

    const info = await ctx.connection.getAccountInfo(feeRecordPda);
    expect(info).not.toBeNull();
    expect(info!.data[0]).toBe(6);
  });

  it('rejects duplicate payer registration', async () => {
    // ctx.payer's FeeRecord was auto-created by the inline path on
    // its first fee-paying tx earlier in this test suite. Calling
    // RegisterPayer for the same payer must now fail with 4006.
    // Note: depending on test ordering, this may also catch a payer
    // that's been auto-registered via prior CreateWallet / Execute.
    // Trigger one more fee-paying tx first to guarantee FeeRecord
    // exists, then attempt re-register.
    await sendTx(
      ctx,
      (await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed: crypto.randomBytes(32),
        owner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
      })).instructions,
    );

    const { instructions } = client.registerPayer({
      payer: ctx.payer.publicKey,
    });
    await sendTxExpectError(ctx, instructions, [], 4006);
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

    // Verify fee record wallet_count > 0 (we don't assert exact value because
    // earlier tests in the suite have already incremented it).
    const [feeRecordPda] = client.findFeeRecord(ctx.payer.publicKey);
    const info = await ctx.connection.getAccountInfo(feeRecordPda);
    const walletCount = info!.data.readUInt32LE(20);
    expect(walletCount).toBeGreaterThan(0);
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
    const fundSig = await ctx.connection.requestAirdrop(
      vaultPda,
      2 * LAMPORTS_PER_SOL,
    );
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

  it('auto-creates FeeRecord inline for first-time unregistered payer', async () => {
    // Strict mode replaced the pre-strict "skip counter update" path
    // with inline auto-create. This test verifies the new behaviour:
    // an unregistered payer making their first fee-paying tx gets a
    // FeeRecord auto-created by the entrypoint, and the counters are
    // bumped (not skipped).
    const newPayer = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(
      newPayer.publicKey,
      5 * LAMPORTS_PER_SOL,
    );
    await ctx.connection.confirmTransaction(sig, 'confirmed');

    const newClient = new LazorKitClient(ctx.connection);

    const protocolFee = await newClient.resolveProtocolFee(newPayer.publicKey);
    expect(protocolFee).toBeDefined();
    const [expectedFeeRecordPda] = newClient.findFeeRecord(newPayer.publicKey);
    expect(protocolFee!.feeRecordPda.toBase58()).toBe(
      expectedFeeRecordPda.toBase58(),
    );

    const feeRecordInfoBefore = await ctx.connection.getAccountInfo(
      protocolFee!.feeRecordPda,
    );
    expect(feeRecordInfoBefore).toBeNull();

    let shardBalanceBefore = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = newClient.findTreasuryShard(i);
      shardBalanceBefore += await ctx.connection.getBalance(shardPda);
    }

    // Build createWallet instruction MANUALLY via the low-level builder
    // — same approach as the pre-strict version of this test, but the
    // expected post-state is now different: FeeRecord MUST exist
    // post-tx (auto-created), and wallet_count == 1.
    const ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);
    const [walletPda] = newClient.findWallet(userSeed);
    const [vaultPda] = newClient.findVault(walletPda);
    const [authorityPda, authBump] = newClient.findAuthority(
      walletPda,
      ownerKp.publicKey.toBytes(),
    );

    const ix = createCreateWalletIx({
      payer: newPayer.publicKey,
      walletPda,
      vaultPda,
      authorityPda,
      userSeed,
      authType: AUTH_TYPE_ED25519,
      authBump,
      credentialOrPubkey: ownerKp.publicKey.toBytes(),
      protocolFee,
      programId: PROGRAM_ID_DEVNET,
    });

    await sendTx({ ...ctx, payer: newPayer }, [ix]);

    let shardBalanceAfter = 0;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = newClient.findTreasuryShard(i);
      shardBalanceAfter += await ctx.connection.getBalance(shardPda);
    }
    expect(shardBalanceAfter - shardBalanceBefore).toBe(Number(CREATION_FEE));

    // Strict mode change: FeeRecord MUST now exist, and counter is 1.
    const feeRecordAfter = await ctx.connection.getAccountInfo(
      protocolFee!.feeRecordPda,
    );
    expect(feeRecordAfter).not.toBeNull();
    expect(feeRecordAfter!.data[0]).toBe(6); // FeeRecord discriminator
    const walletCount = feeRecordAfter!.data.readUInt32LE(20);
    expect(walletCount).toBe(1);
  });

  it('withdraws fees from treasury shards', async () => {
    const fundSig = await ctx.connection.requestAirdrop(
      treasuryKp.publicKey,
      LAMPORTS_PER_SOL,
    );
    await ctx.connection.confirmTransaction(fundSig, 'confirmed');

    const treasuryBefore = await ctx.connection.getBalance(
      treasuryKp.publicKey,
    );
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

  // ── H2 — admin instructions must verify config_pda / shard_pda ownership ──
  // Pre-fix, withdraw_treasury read config_pda without checking its owner.
  // An attacker could supply a fake config (owned by their own program) with
  // attacker-controlled `admin`/`treasury` fields, hand in the real LazorKit
  // shard as `shard_pda`, and drain it. Post-fix, any non-program-owned
  // config_pda or shard_pda is rejected with IllegalOwner before any writes.

  it('H2: rejects WithdrawTreasury with fake (non-program-owned) config_pda', async () => {
    const [shard0] = client.findTreasuryShard(0);
    const fakeConfig = Keypair.generate().publicKey; // System-owned → owner check fails

    const ix = createWithdrawTreasuryIx({
      admin: adminKp.publicKey,
      protocolConfigPda: fakeConfig,
      treasuryShardPda: shard0,
      treasury: treasuryKp.publicKey,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminKp]);
  });

  it('H2: rejects WithdrawTreasury with fake (non-program-owned) shard_pda', async () => {
    const [protocolConfigPda] = client.findProtocolConfig();
    const fakeShard = Keypair.generate().publicKey;

    const ix = createWithdrawTreasuryIx({
      admin: adminKp.publicKey,
      protocolConfigPda,
      treasuryShardPda: fakeShard,
      treasury: treasuryKp.publicKey,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminKp]);
  });

  it('H2: rejects UpdateProtocol with fake config_pda', async () => {
    const fakeConfig = Keypair.generate().publicKey;

    const ix = createUpdateProtocolIx({
      admin: adminKp.publicKey,
      protocolConfigPda: fakeConfig,
      creationFee: 9999n,
      executionFee: 9999n,
      enabled: true,
      newTreasury: treasuryKp.publicKey,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminKp]);
  });
});
