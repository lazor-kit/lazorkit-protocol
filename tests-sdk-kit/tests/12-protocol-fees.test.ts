/**
 * Port of tests-sdk/tests/12-protocol-fees.test.ts.
 *
 * Exercises the commercial-binary admin path: ProtocolConfig +
 * TreasuryShard initialization, fee-record self-registration,
 * auto-fee on CreateWallet/Execute, withdraw, and the H2 audit-fix
 * coverage (admin instructions verify config_pda / shard_pda owners).
 *
 * Setup quirk: this whole suite assumes a freshly-initialized
 * ProtocolConfig. The validator must be started cleanly (no leftover
 * state from previous protocol-fee runs). All other test files are
 * order-independent because they don't touch ProtocolConfig.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  airdropFactory,
  generateKeyPairSigner,
  getAddressEncoder,
  lamports,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import {
  AUTH_TYPE_ED25519,
  LazorKit,
  PROGRAM_ID_DEVNET,
  createCreateWalletIx,
  createUpdateProtocolIx,
  createWithdrawTreasuryIx,
  ed25519,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';

const NUM_SHARDS = 4;
const LAMPORTS_PER_SOL = 1_000_000_000n;
const RENT_EXEMPT_8B = 946_560n; // ~rent-exempt threshold for 8-byte account

const addressEncoder = getAddressEncoder();

async function getBalance(
  ctx: TestContext,
  addr: Address,
): Promise<bigint> {
  const r = await ctx.rpc.getBalance(addr, { commitment: 'confirmed' }).send();
  return r.value;
}

describe('Protocol Fees', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let adminSigner: KeyPairSigner;
  let treasurySigner: KeyPairSigner;
  const CREATION_FEE = 5_000n;
  const EXECUTION_FEE = 2_000n;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    adminSigner = await generateKeyPairSigner();
    treasurySigner = await generateKeyPairSigner();

    // Fund the admin so it can pay tx fees on UpdateProtocol etc.
    const airdropFn = airdropFactory({
      rpc: ctx.rpc as never,
      rpcSubscriptions: ctx.rpcSubscriptions as never,
    });
    await airdropFn({
      recipientAddress: adminSigner.address,
      lamports: lamports(2n * LAMPORTS_PER_SOL),
      commitment: 'confirmed',
    });
  });

  it('initializes protocol config', async () => {
    const { instructions, protocolConfigPda } = await client.initializeProtocol({
      payer: ctx.payer.address,
      admin: adminSigner.address,
      treasury: treasurySigner.address,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      numShards: NUM_SHARDS,
    });
    await sendTx(ctx, instructions);

    const info = await ctx.rpc
      .getAccountInfo(protocolConfigPda, { encoding: 'base64' })
      .send();
    expect(info.value).not.toBeNull();
    const data = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
    expect(data[0]).toBe(5); // ProtocolConfig discriminator
    expect(data[3]).toBe(1); // enabled
    expect(data[4]).toBe(NUM_SHARDS);
  });

  it('rejects double initialization', async () => {
    const { instructions } = await client.initializeProtocol({
      payer: ctx.payer.address,
      admin: adminSigner.address,
      treasury: treasurySigner.address,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      numShards: NUM_SHARDS,
    });
    await sendTxExpectError(ctx, instructions, [], 4001);
  });

  it('initializes treasury shards', async () => {
    for (let i = 0; i < NUM_SHARDS; i++) {
      const { instructions, treasuryShardPda } = await client.initializeTreasuryShard({
        payer: ctx.payer.address,
        admin: adminSigner.address,
        shardId: i,
      });
      await sendTx(ctx, instructions, [adminSigner]);

      const info = await ctx.rpc
        .getAccountInfo(treasuryShardPda, { encoding: 'base64' })
        .send();
      expect(info.value).not.toBeNull();
      const data = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
      expect(data[0]).toBe(7); // TreasuryShard discriminator
      expect(data[2]).toBe(i);
    }
  });

  it('updates protocol config', async () => {
    const update = await client.updateProtocol({
      admin: adminSigner.address,
      creationFee: 10_000n,
      executionFee: 5_000n,
      enabled: true,
      newTreasury: treasurySigner.address,
    });
    await sendTx(ctx, update.instructions, [adminSigner]);

    // Revert to baseline so subsequent tests still see CREATION_FEE.
    const revert = await client.updateProtocol({
      admin: adminSigner.address,
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      enabled: true,
      newTreasury: treasurySigner.address,
    });
    await sendTx(ctx, revert.instructions, [adminSigner]);
    client.invalidateProtocolCache();
  });

  it('rejects update from non-admin', async () => {
    const fakeAdmin = await generateKeyPairSigner();
    await airdrop(ctx, fakeAdmin.address, LAMPORTS_PER_SOL);

    const update = await client.updateProtocol({
      admin: fakeAdmin.address,
      creationFee: 0n,
      executionFee: 0n,
      enabled: false,
      newTreasury: fakeAdmin.address,
    });
    await sendTxExpectError(ctx, update.instructions, [fakeAdmin], 4002);
  });

  it('registers a payer (permissionless self-registration)', async () => {
    const { instructions, feeRecordPda } = await client.registerPayer({
      payer: ctx.payer.address,
    });
    await sendTx(ctx, instructions);

    const info = await ctx.rpc
      .getAccountInfo(feeRecordPda, { encoding: 'base64' })
      .send();
    expect(info.value).not.toBeNull();
    const data = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
    expect(data[0]).toBe(6); // FeeRecord discriminator
  });

  it('rejects duplicate payer registration', async () => {
    const { instructions } = await client.registerPayer({
      payer: ctx.payer.address,
    });
    await sendTxExpectError(ctx, instructions, [], 4006);
  });

  async function sumShardBalances(): Promise<bigint> {
    let total = 0n;
    for (let i = 0; i < NUM_SHARDS; i++) {
      const [pda] = await client.findTreasuryShard(i);
      total += await getBalance(ctx, pda);
    }
    return total;
  }

  it('auto-detects payer and collects fee on CreateWallet', async () => {
    const ownerSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);

    const before = await sumShardBalances();

    const { instructions } = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });
    await sendTx(ctx, instructions);

    const after = await sumShardBalances();
    expect(after - before).toBe(CREATION_FEE);

    // Verify wallet_count incremented in FeeRecord (offset 20 = u32 LE).
    const [feeRecordPda] = await client.findFeeRecord(ctx.payer.address);
    const info = await ctx.rpc
      .getAccountInfo(feeRecordPda, { encoding: 'base64' })
      .send();
    const data = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
    const walletCount = new DataView(data.buffer, data.byteOffset).getUint32(
      20,
      true,
    );
    expect(walletCount).toBe(1);
  });

  it('auto-detects payer and collects fee on Execute', async () => {
    const ownerSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);

    const { instructions: createIxs, walletPda, vaultPda } = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });
    await sendTx(ctx, createIxs);
    await airdrop(ctx, vaultPda, 2n * LAMPORTS_PER_SOL);

    const before = await sumShardBalances();

    const recipient = (await generateKeyPairSigner()).address;
    const { instructions: execIxs } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: ed25519(ownerSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
    });
    await sendTx(ctx, execIxs, [ownerSigner]);

    const after = await sumShardBalances();
    expect(after - before).toBe(EXECUTION_FEE);
  });

  it('charges fee for unregistered payer but skips FeeRecord counter update', async () => {
    // Use a fresh payer that has not yet self-registered. The high-level
    // createWallet auto-prepends RegisterPayer for first-time payers, so
    // we go through the low-level builder to bypass that.
    const newPayer = await generateKeyPairSigner();
    await airdrop(ctx, newPayer.address, 5n * LAMPORTS_PER_SOL);

    // resolveProtocolFee returns 4 fee accounts even for an unregistered
    // payer — the on-chain entrypoint detects the missing FeeRecord and
    // adapts (charges fee, skips counter bump).
    const protocolFee = await client.resolveProtocolFee(newPayer.address);
    expect(protocolFee).toBeDefined();
    const [expectedFeeRecordPda] = await client.findFeeRecord(newPayer.address);
    expect(protocolFee!.feeRecordPda).toBe(expectedFeeRecordPda);

    const feeRecordInfoBefore = await ctx.rpc
      .getAccountInfo(protocolFee!.feeRecordPda, { encoding: 'base64' })
      .send();
    expect(feeRecordInfoBefore.value).toBeNull();

    const before = await sumShardBalances();

    const ownerSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);
    const [walletPda] = await client.findWallet(userSeed);
    const [vaultPda] = await client.findVault(walletPda);
    const ownerPubkeyBytes = addressEncoder.encode(ownerSigner.address) as Uint8Array;
    const [authorityPda, authBump] = await client.findAuthority(
      walletPda,
      ownerPubkeyBytes,
    );

    const ix = createCreateWalletIx({
      payer: newPayer.address,
      walletPda,
      vaultPda,
      authorityPda,
      userSeed,
      authType: AUTH_TYPE_ED25519,
      authBump,
      credentialOrPubkey: ownerPubkeyBytes,
      protocolFee,
      programId: PROGRAM_ID_DEVNET,
    });

    // Send with the new payer as fee payer.
    await sendTx({ ...ctx, payer: newPayer }, [ix]);

    const after = await sumShardBalances();
    expect(after - before).toBe(CREATION_FEE);

    // FeeRecord PDA still doesn't exist.
    const feeRecordInfoAfter = await ctx.rpc
      .getAccountInfo(protocolFee!.feeRecordPda, { encoding: 'base64' })
      .send();
    expect(feeRecordInfoAfter.value).toBeNull();
  });

  it('withdraws fees from treasury shards', async () => {
    // Pre-fund treasury so the SOL transfer (rent-exempt destination)
    // lands cleanly.
    await airdrop(ctx, treasurySigner.address, LAMPORTS_PER_SOL);

    const treasuryBefore = await getBalance(ctx, treasurySigner.address);
    let totalSwept = 0n;

    for (let i = 0; i < NUM_SHARDS; i++) {
      const [shardPda] = await client.findTreasuryShard(i);
      const shardBefore = await getBalance(ctx, shardPda);
      // Sweep only if there's something above rent-exempt.
      if (shardBefore > RENT_EXEMPT_8B) {
        const { instructions } = await client.withdrawTreasury({
          admin: adminSigner.address,
          shardId: i,
          treasury: treasurySigner.address,
        });
        await sendTx(ctx, instructions, [adminSigner]);
        const shardAfter = await getBalance(ctx, shardPda);
        totalSwept += shardBefore - shardAfter;
      }
    }

    const treasuryAfter = await getBalance(ctx, treasurySigner.address);
    expect(treasuryAfter - treasuryBefore).toBe(totalSwept);
    expect(totalSwept).toBeGreaterThan(0n);
  });

  // ── H2 — admin instructions must verify config_pda / shard_pda ownership ──
  // Pre-fix, withdraw_treasury read config_pda without checking its owner.
  // An attacker could supply a fake config (owned by their own program)
  // with attacker-controlled `admin`/`treasury` fields, hand in the real
  // LazorKit shard as `shard_pda`, and drain it. Post-fix, any non-program-
  // owned config_pda or shard_pda is rejected with IllegalOwner.

  it('H2: rejects WithdrawTreasury with fake (non-program-owned) config_pda', async () => {
    const [shard0] = await client.findTreasuryShard(0);
    const fakeConfig = (await generateKeyPairSigner()).address;
    const ix = createWithdrawTreasuryIx({
      admin: adminSigner.address,
      protocolConfigPda: fakeConfig,
      treasuryShardPda: shard0,
      treasury: treasurySigner.address,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminSigner]);
  });

  it('H2: rejects WithdrawTreasury with fake (non-program-owned) shard_pda', async () => {
    const [protocolConfigPda] = await client.findProtocolConfig();
    const fakeShard = (await generateKeyPairSigner()).address;
    const ix = createWithdrawTreasuryIx({
      admin: adminSigner.address,
      protocolConfigPda,
      treasuryShardPda: fakeShard,
      treasury: treasurySigner.address,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminSigner]);
  });

  it('H2: rejects UpdateProtocol with fake config_pda', async () => {
    const fakeConfig = (await generateKeyPairSigner()).address;
    const ix = createUpdateProtocolIx({
      admin: adminSigner.address,
      protocolConfigPda: fakeConfig,
      creationFee: 9_999n,
      executionFee: 9_999n,
      enabled: true,
      newTreasury: treasurySigner.address,
      programId: PROGRAM_ID_DEVNET,
    });
    await sendTxExpectError(ctx, [ix], [adminSigner]);
  });
});
