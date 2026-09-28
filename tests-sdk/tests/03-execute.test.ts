import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTx, type TestContext } from './common';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils';
import { LazorKitClient, ed25519 } from '../../sdk/sdk-legacy/src';

describe('Execute', () => {
  let ctx: TestContext;
  let client: LazorKitClient;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
  });

  describe('Ed25519 Execute', () => {
    let walletPda: PublicKey;
    let vaultPda: PublicKey;
    let ownerKp: Keypair;
    let ownerAuthorityPda: PublicKey;

    beforeAll(async () => {
      ownerKp = Keypair.generate();
      const userSeed = crypto.randomBytes(32);

      const result = await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed,
        owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
      });

      await sendTx(ctx, result.instructions);

      // === User comes back — find wallet by pubkey ===
      const [found] = await client.findWalletsByAuthority(
        ownerKp.publicKey.toBytes(),
        'ed25519',
      );
      walletPda = found.walletPda;
      vaultPda = found.vaultPda;
      ownerAuthorityPda = found.authorityPda;

      // Fund the vault so it can transfer SOL
      const sig = await ctx.connection.requestAirdrop(
        vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sig, 'confirmed');
    });

    it('executes a SOL transfer via execute()', async () => {
      const recipient = Keypair.generate().publicKey;

      const { instructions } = await client.execute({
        payer: ctx.payer.publicKey,
        walletPda,
        signer: ed25519(ownerKp.publicKey, ownerAuthorityPda),
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: 1_000_000,
          }),
        ],
      });

      const balanceBefore = await ctx.connection.getBalance(recipient);
      await sendTx(ctx, instructions, [ownerKp]);
      const balanceAfter = await ctx.connection.getBalance(recipient);

      expect(balanceAfter - balanceBefore).toBe(1_000_000);
    });
  });

  describe('Secp256r1 Execute', () => {
    let walletPda: PublicKey;
    let vaultPda: PublicKey;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthorityPda: PublicKey;

    beforeAll(async () => {
      ownerKey = await generateMockSecp256r1Key();
      const userSeed = crypto.randomBytes(32);

      const result = await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: ownerKey.credentialIdHash,
          compressedPubkey: ownerKey.publicKeyBytes,
          rpId: ownerKey.rpId,
        },
      });

      await sendTx(ctx, result.instructions);

      // === User comes back — only has credentialIdHash ===
      const [found] = await client.findWalletsByAuthority(
        ownerKey.credentialIdHash,
      );
      walletPda = found.walletPda;
      vaultPda = found.vaultPda;
      ownerAuthorityPda = found.authorityPda;

      // Fund the vault
      const sig = await ctx.connection.requestAirdrop(
        vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sig, 'confirmed');
    });

    it('executes a SOL transfer via execute()', async () => {
      const recipient = Keypair.generate().publicKey;

      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: 1_000_000,
          }),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);

      const balanceBefore = await ctx.connection.getBalance(recipient);
      await sendTx(ctx, instructions);
      const balanceAfter = await ctx.connection.getBalance(recipient);

      expect(balanceAfter - balanceBefore).toBe(1_000_000);
    });

    it('executes a SOL transfer with transferSol() equivalent', async () => {
      const recipient = Keypair.generate().publicKey;

      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: 1_000_000,
          }),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);

      const balanceBefore = await ctx.connection.getBalance(recipient);
      await sendTx(ctx, instructions);
      const balanceAfter = await ctx.connection.getBalance(recipient);

      expect(balanceAfter - balanceBefore).toBe(1_000_000);
    });

    it('executes arbitrary instructions with execute()', async () => {
      const recipient = Keypair.generate().publicKey;

      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: 1_000_000,
          }),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);

      const balanceBefore = await ctx.connection.getBalance(recipient);
      await sendTx(ctx, instructions);
      const balanceAfter = await ctx.connection.getBalance(recipient);

      expect(balanceAfter - balanceBefore).toBe(1_000_000);
    });

    it('increments counter after successful execute', async () => {
      const recipient = Keypair.generate().publicKey;

      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: 1_000_000,
          }),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);

      await sendTx(ctx, instructions);

      // Verify counter is now 4 (three Secp256r1 executes above + this one)
      const authority = await ctx.connection.getAccountInfo(ownerAuthorityPda);
      const view = new DataView(
        authority!.data.buffer,
        authority!.data.byteOffset,
      );
      const counter = view.getUint32(8, true);
      expect(counter).toBe(4);
    });

    // Repaying the payer from the vault is how a sponsored call settles up,
    // and it is the one inner account whose flags the SDK has to predict: the
    // accounts hash binds the flags the runtime reports, and the runtime
    // reports the fee payer as a writable signer. Declared read-only, this
    // failed with InvalidMessageHash (3005).
    const repayPayer = async () => {
      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: ctx.payer.publicKey,
            lamports: 1_000_000,
          }),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      return client.finalizeExecute(prepared, response).instructions;
    };

    it('executes an inner transfer to the payer', async () => {
      const instructions = await repayPayer();

      const vaultBefore = await ctx.connection.getBalance(vaultPda);
      await sendTx(ctx, instructions);
      const vaultAfter = await ctx.connection.getBalance(vaultPda);

      expect(vaultBefore - vaultAfter).toBe(1_000_000);
    });

    // Another key pays the transaction fee. The Execute payer is then a signer
    // only because the instruction says so, and must still be writable to be
    // repaid (and to pay the execution fee).
    it('executes an inner transfer to the payer when another key pays the fee', async () => {
      const feePayer = Keypair.generate();
      const sig = await ctx.connection.requestAirdrop(feePayer.publicKey, LAMPORTS_PER_SOL);
      await ctx.connection.confirmTransaction(sig, 'confirmed');
      const instructions = await repayPayer();

      const vaultBefore = await ctx.connection.getBalance(vaultPda);
      const payerBefore = await ctx.connection.getBalance(ctx.payer.publicKey);
      const tx = new Transaction();
      for (const ix of instructions) tx.add(ix);
      tx.feePayer = feePayer.publicKey;
      await sendAndConfirmTransaction(ctx.connection, tx, [feePayer, ctx.payer], {
        commitment: 'confirmed',
      });

      expect(vaultBefore - (await ctx.connection.getBalance(vaultPda))).toBe(1_000_000);
      // Repaid in full, less the execution fee; the signature fee was the fee payer's.
      const payerDelta = (await ctx.connection.getBalance(ctx.payer.publicKey)) - payerBefore;
      expect(payerDelta).toBeGreaterThan(0);
      expect(payerDelta).toBeLessThanOrEqual(1_000_000);
    });
  });
});
