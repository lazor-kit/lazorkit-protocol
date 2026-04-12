import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  type AccountMeta,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTx, sendTxExpectError, getSlot, type TestContext } from './common';
import { generateMockSecp256r1Key, signSecp256r1 } from './secp256r1Utils';
import {
  findWalletPda,
  findVaultPda,
  findAuthorityPda,
  createCreateWalletIx,
  createExecuteIx,
  packCompactInstructions,
  computeAccountsHash,
  AUTH_TYPE_SECP256R1,
  DISC_EXECUTE,
} from '../../sdk/solita-client/src';

describe('Replay Prevention (Odometer)', () => {
  let ctx: TestContext;
  let walletPda: PublicKey;
  let vaultPda: PublicKey;
  let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
  let ownerAuthorityPda: PublicKey;

  // Helper to build a simple transfer execute instruction
  const compactIxDef = [{
    programIdIndex: 6,
    accountIndexes: [3, 7],
    data: new Uint8Array((() => {
      const d = Buffer.alloc(12);
      d.writeUInt32LE(2, 0);
      d.writeBigUInt64LE(1_000_000n, 4);
      return d;
    })()),
  }];

  function buildTransferPacked() {
    return packCompactInstructions(compactIxDef);
  }

  async function buildExecuteIx(counter: bigint, packed: Uint8Array) {
    const slot = await getSlot(ctx);
    const recipient = Keypair.generate().publicKey;

    // On-chain extends: signed_payload = compact_bytes + accounts_hash
    const allAccountMetas = [
      { pubkey: ctx.payer.publicKey, isSigner: true, isWritable: false },
      { pubkey: walletPda, isSigner: false, isWritable: false },
      { pubkey: ownerAuthorityPda, isSigner: false, isWritable: true },
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: PublicKey.default, isSigner: false, isWritable: false },
      { pubkey: PublicKey.default, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: recipient, isSigner: false, isWritable: true },
    ];
    const accountsHash = computeAccountsHash(allAccountMetas, compactIxDef);
    const signedPayload = Buffer.concat([packed, accountsHash]);

    const { authPayload, precompileIx } = await signSecp256r1({
      key: ownerKey,
      discriminator: new Uint8Array([DISC_EXECUTE]),
      signedPayload,
      slot,
      counter,
      payer: ctx.payer.publicKey,
      sysvarIxIndex: 4,
      sysvarSlotHashesIndex: 5,
    });

    const ix = createExecuteIx({
      payer: ctx.payer.publicKey,
      walletPda,
      authorityPda: ownerAuthorityPda,
      vaultPda,
      packedInstructions: packed,
      authPayload,
      remainingAccounts: [
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: recipient, isSigner: false, isWritable: true },
      ],
    });

    return { precompileIx, ix };
  }

  beforeAll(async () => {
    ctx = await setupTest();

    ownerKey = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    [walletPda] = findWalletPda(userSeed);
    [vaultPda] = findVaultPda(walletPda);
    const [authPda, authBump] = findAuthorityPda(walletPda, ownerKey.credentialIdHash);
    ownerAuthorityPda = authPda;

    await sendTx(ctx, [createCreateWalletIx({
      payer: ctx.payer.publicKey,
      walletPda,
      vaultPda,
      authorityPda: authPda,
      userSeed,
      authType: AUTH_TYPE_SECP256R1,
      authBump,
      credentialOrPubkey: ownerKey.credentialIdHash,
      secp256r1Pubkey: ownerKey.publicKeyBytes,
    })]);

    // Fund vault
    const sig = await ctx.connection.requestAirdrop(vaultPda, 5 * LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig, 'confirmed');
  });

  it('accepts counter=1 for fresh authority (stored=0)', async () => {
    const packed = buildTransferPacked();
    const { precompileIx, ix } = await buildExecuteIx(1n, packed);
    await sendTx(ctx, [precompileIx, ix]);

    // Verify counter is now 1
    const info = await ctx.connection.getAccountInfo(ownerAuthorityPda);
    const view = new DataView(info!.data.buffer, info!.data.byteOffset);
    expect(view.getBigUint64(8, true)).toBe(1n);
  });

  it('rejects same counter=1 replay (SignatureReused 3006)', async () => {
    const packed = buildTransferPacked();
    // Counter is now 1 on-chain, submitting 1 again should fail
    await sendTxExpectError(
      ctx,
      [(await buildExecuteIx(1n, packed)).precompileIx, (await buildExecuteIx(1n, packed)).ix],
      [],
      3006, // SignatureReused
    );
  });

  it('rejects counter=0 (behind stored)', async () => {
    const packed = buildTransferPacked();
    await sendTxExpectError(
      ctx,
      [(await buildExecuteIx(0n, packed)).precompileIx, (await buildExecuteIx(0n, packed)).ix],
      [],
      3006,
    );
  });

  it('rejects counter=5 (skipping ahead)', async () => {
    const packed = buildTransferPacked();
    // Stored counter is 1, expected next is 2, submitting 5 should fail
    await sendTxExpectError(
      ctx,
      [(await buildExecuteIx(5n, packed)).precompileIx, (await buildExecuteIx(5n, packed)).ix],
      [],
      3006,
    );
  });

  it('accepts sequential counter 2, 3, 4', async () => {
    for (const c of [2n, 3n, 4n]) {
      const packed = buildTransferPacked();
      const { precompileIx, ix } = await buildExecuteIx(c, packed);
      await sendTx(ctx, [precompileIx, ix]);
    }

    // Verify counter is now 4
    const info = await ctx.connection.getAccountInfo(ownerAuthorityPda);
    const view = new DataView(info!.data.buffer, info!.data.byteOffset);
    expect(view.getBigUint64(8, true)).toBe(4n);
  });

  it('rejects stale counter after sequential ops', async () => {
    const packed = buildTransferPacked();
    // Counter is 4, submitting 3 should fail
    await sendTxExpectError(
      ctx,
      [(await buildExecuteIx(3n, packed)).precompileIx, (await buildExecuteIx(3n, packed)).ix],
      [],
      3006,
    );
  });
});
