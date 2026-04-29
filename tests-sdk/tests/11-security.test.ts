/**
 * Security-focused tests for edge cases and attack vectors.
 *
 * Tests:
 * - Counter increment verification on admin operations (Secp256r1)
 * - Self-reentrancy prevention
 * - Cross-wallet authority usage (wrong wallet)
 * - Accounts hash mismatch in Execute
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  getSlot,
  PROGRAM_ID_DEVNET,
  type TestContext,
} from './common';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils';
import {
  prepareSecp256r1 as prepareSecp256r1Low,
  finalizeSecp256r1 as finalizeSecp256r1Low,
  concatParts,
} from '../../sdk/sdk-legacy/src/utils/signing';
import {
  LazorKitClient,
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  ROLE_ADMIN,
  ROLE_SPENDER,
  ed25519,
  findWalletPda,
  findVaultPda,
  findAuthorityPda,
  createExecuteIx,
  packCompactInstructions,
  computeAccountsHash,
  DISC_EXECUTE,
} from '../../sdk/sdk-legacy/src';

describe('Security', () => {
  let ctx: TestContext;
  let client: LazorKitClient;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
  });

  // ─── Counter increment verification ─────────────────────────────

  describe('Counter increments on admin operations', () => {
    let walletPda: PublicKey;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthPda: PublicKey;

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
      walletPda = result.walletPda;
      ownerAuthPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
    });

    it('counter increments after addAuthority', async () => {
      const counterBefore = await client.readCounter(ownerAuthPda);
      expect(counterBefore).toBe(0);

      const adminKp = Keypair.generate();

      const prepared = await client.prepareAddAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
        role: ROLE_ADMIN,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeAddAuthority(prepared, response);
      await sendTx(ctx, instructions);

      const counterAfter = await client.readCounter(ownerAuthPda);
      expect(counterAfter).toBe(1);
    });

    it('counter increments after createSession', async () => {
      const counterBefore = await client.readCounter(ownerAuthPda);

      const sessionKp = Keypair.generate();
      const currentSlot = await getSlot(ctx);

      const prepared = await client.prepareCreateSession({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        sessionKey: sessionKp.publicKey,
        expiresAt: currentSlot + 9000n,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeCreateSession(prepared, response);
      await sendTx(ctx, instructions);

      const counterAfter = await client.readCounter(ownerAuthPda);
      expect(counterAfter).toBe(counterBefore + 1);
    });

    it('counter increments after removeAuthority', async () => {
      // First add a spender to remove
      const spenderKp = Keypair.generate();

      const addPrepared = await client.prepareAddAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        newAuthority: { type: 'ed25519', publicKey: spenderKp.publicKey },
        role: ROLE_SPENDER,
      });
      const addResponse = await fakeWebAuthnSign(
        ownerKey,
        addPrepared.challenge,
      );
      const addResult = client.finalizeAddAuthority(addPrepared, addResponse);
      await sendTx(ctx, addResult.instructions);

      const counterBefore = await client.readCounter(ownerAuthPda);

      const prepared = await client.prepareRemoveAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        targetAuthorityPda: addPrepared.newAuthorityPda,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeRemoveAuthority(
        prepared,
        response,
      );
      await sendTx(ctx, instructions);

      const counterAfter = await client.readCounter(ownerAuthPda);
      expect(counterAfter).toBe(counterBefore + 1);
    });
  });

  // ─── Self-reentrancy prevention ─────────────────────────────────

  describe('Self-reentrancy', () => {
    it('rejects CPI back into own program via execute', async () => {
      const ownerKp = Keypair.generate();
      const userSeed = crypto.randomBytes(32);

      const result = await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed,
        owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
      });
      await sendTx(ctx, result.instructions);

      // Fund the vault
      const sig = await ctx.connection.requestAirdrop(
        result.vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sig, 'confirmed');

      // Try to execute an instruction that calls back into the LazorKit program
      // We'll craft a fake instruction targeting the program
      const selfCallIx = new TransactionInstruction({
        programId: PROGRAM_ID_DEVNET,
        keys: [
          { pubkey: ctx.payer.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0xff]), // Invalid instruction
      });

      const { instructions } = await client.execute({
        payer: ctx.payer.publicKey,
        walletPda: result.walletPda,
        signer: ed25519(ownerKp.publicKey, result.authorityPda),
        instructions: [selfCallIx],
      });

      // Error 3013 = SelfReentrancyNotAllowed
      await sendTxExpectError(ctx, instructions, [ownerKp], 3013);
    });
  });

  // ─── Cross-wallet authority usage ───────────────────────────────

  describe('Cross-wallet authority isolation', () => {
    it('authority from wallet A cannot execute on wallet B', async () => {
      // Create wallet A
      const ownerA = Keypair.generate();
      const seedA = crypto.randomBytes(32);
      const resultA = await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed: seedA,
        owner: { type: 'ed25519', publicKey: ownerA.publicKey },
      });
      await sendTx(ctx, resultA.instructions);
      const sigA = await ctx.connection.requestAirdrop(
        resultA.vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sigA, 'confirmed');

      // Create wallet B
      const ownerB = Keypair.generate();
      const seedB = crypto.randomBytes(32);
      const resultB = await client.createWallet({
        payer: ctx.payer.publicKey,
        userSeed: seedB,
        owner: { type: 'ed25519', publicKey: ownerB.publicKey },
      });
      await sendTx(ctx, resultB.instructions);
      const sigB = await ctx.connection.requestAirdrop(
        resultB.vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sigB, 'confirmed');

      // Try to use ownerA's authority to add authority on walletB
      // We manually set the authorityPda to ownerA's auth but target walletB
      const newKp = Keypair.generate();
      const { instructions } = await client.addAuthority({
        payer: ctx.payer.publicKey,
        walletPda: resultB.walletPda,
        adminSigner: ed25519(ownerA.publicKey, resultA.authorityPda),
        newAuthority: { type: 'ed25519', publicKey: newKp.publicKey },
        role: ROLE_SPENDER,
      });

      // Should fail — authority doesn't belong to walletB
      await sendTxExpectError(ctx, instructions, [ownerA]);
    });
  });

  // ─── Accounts hash mismatch ─────────────────────────────────────

  describe('Accounts hash binding', () => {
    it('rejects execute with swapped recipient accounts', async () => {
      const ownerKey = await generateMockSecp256r1Key();
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

      const sig = await ctx.connection.requestAirdrop(
        result.vaultPda,
        2 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sig, 'confirmed');

      const recipientA = Keypair.generate().publicKey;
      const recipientB = Keypair.generate().publicKey;

      // Sign for transfer to recipientA
      const prepared = await client.prepareExecute({
        payer: ctx.payer.publicKey,
        walletPda: result.walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: result.authorityPda,
        },
        instructions: [
          SystemProgram.transfer({
            fromPubkey: result.vaultPda,
            toPubkey: recipientA,
            lamports: 1_000_000,
          }),
        ],
      });
      const execResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: goodIxs } = client.finalizeExecute(
        prepared,
        execResponse,
      );

      // Verify the legitimate transaction works
      const balanceBefore = await ctx.connection.getBalance(recipientA);
      await sendTx(ctx, goodIxs);
      const balanceAfter = await ctx.connection.getBalance(recipientA);
      expect(balanceAfter - balanceBefore).toBe(1_000_000);

      // Now attempt to sign for recipientA but execute with recipientB
      // Build compact instructions pointing to recipientA
      const authorityPda = result.authorityPda;
      const slot = await getSlot(ctx);
      const counter = (await client.readCounter(authorityPda)) + 1;

      const transferIx = SystemProgram.transfer({
        fromPubkey: result.vaultPda,
        toPubkey: recipientA, // Sign for A
        lamports: 1_000_000,
      });

      // Build layout with recipientA
      const fixedAccounts = [
        ctx.payer.publicKey,
        result.walletPda,
        authorityPda,
        result.vaultPda,
        SYSVAR_INSTRUCTIONS_PUBKEY,
      ];
      const { compactInstructions, remainingAccounts } = (
        await import('../../sdk/sdk-legacy/src/utils/compact')
      ).buildCompactLayout(fixedAccounts, [transferIx]);
      const packed = packCompactInstructions(compactInstructions);

      // Compute accounts hash with recipientA (the one we sign)
      const allAccountMetas = [
        { pubkey: ctx.payer.publicKey, isSigner: true, isWritable: false },
        { pubkey: result.walletPda, isSigner: false, isWritable: false },
        { pubkey: authorityPda, isSigner: false, isWritable: true },
        { pubkey: result.vaultPda, isSigner: false, isWritable: true },
        {
          pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
          isSigner: false,
          isWritable: false,
        },
        ...remainingAccounts,
      ];
      const accountsHash = computeAccountsHash(
        allAccountMetas,
        compactInstructions,
      );

      const signedPayload = concatParts([packed, accountsHash]);

      // Sign with the correct data (recipientA in accounts hash)
      const tamperedPrepared = prepareSecp256r1Low({
        discriminator: new Uint8Array([DISC_EXECUTE]),
        signedPayload,
        sysvarIxIndex: 4,
        slot,
        counter,
        payer: ctx.payer.publicKey,
        programId: PROGRAM_ID_DEVNET,
        publicKeyBytes: ownerKey.publicKeyBytes,
      });
      const tamperedResponse = await fakeWebAuthnSign(
        ownerKey,
        tamperedPrepared.challenge,
      );
      const { authPayload, precompileIx } = finalizeSecp256r1Low(
        tamperedPrepared,
        tamperedResponse,
      );

      // Now build the TAMPERED instruction with recipientB swapped in
      const tamperedRemaining = remainingAccounts.map((acc) => {
        if (acc.pubkey.equals(recipientA)) {
          return { ...acc, pubkey: recipientB };
        }
        return acc;
      });

      const tamperedIx = createExecuteIx({
        payer: ctx.payer.publicKey,
        walletPda: result.walletPda,
        authorityPda,
        vaultPda: result.vaultPda,
        packedInstructions: packed,
        authPayload,
        remainingAccounts: tamperedRemaining,
        programId: PROGRAM_ID_DEVNET,

      });

      // Should fail — accounts hash won't match
      await sendTxExpectError(ctx, [precompileIx, tamperedIx]);
    });
  });
});
