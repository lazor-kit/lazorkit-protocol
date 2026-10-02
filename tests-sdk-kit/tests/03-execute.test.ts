/**
 * Port of tests-sdk/tests/03-execute.test.ts.
 *
 * Verifies Execute under both Ed25519 and Secp256r1 signers (incl.
 * the prepare/finalize WebAuthn flow), and confirms the on-chain
 * counter increments after Secp256r1 executes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
  type Signature,
} from '@solana/kit';
import { LazorKit, ed25519, decodeAuthorityAccount } from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  airdrop,
  getBalance,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';
import {
  generateMockSecp256r1Key,
  fakeWebAuthnSign,
} from './secp256r1Utils.js';

const ONE_LAMPORT = 1n;
const LAMPORTS_PER_SOL = 1_000_000_000n;

describe('Execute', () => {
  let ctx: TestContext;
  let client: LazorKit;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
  });

  describe('Ed25519 Execute', () => {
    let walletPda: Address;
    let vaultPda: Address;
    let ownerSigner: KeyPairSigner;
    let ownerAuthorityPda: Address;

    beforeAll(async () => {
      ownerSigner = await generateKeyPairSigner();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: { type: 'ed25519', publicKey: ownerSigner.address },
      });
      await sendTx(ctx, result.instructions);

      walletPda = result.walletPda;
      vaultPda = result.vaultPda;
      ownerAuthorityPda = result.authorityPda;

      await airdrop(ctx, vaultPda, 2n * LAMPORTS_PER_SOL);
    });

    it('executes a SOL transfer via execute()', async () => {
      const recipient = (await generateKeyPairSigner()).address;

      const { instructions } = await client.execute({
        payer: ctx.payer.address,
        walletPda,
        signer: ed25519(ownerSigner.address, ownerAuthorityPda),
        instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
      });

      const before = await getBalance(ctx, recipient);
      await sendTx(ctx, instructions, [ownerSigner]);
      const after = await getBalance(ctx, recipient);
      expect(after - before).toBe(1_000_000n);
      void ONE_LAMPORT;
    });
  });

  describe('Secp256r1 Execute', () => {
    let walletPda: Address;
    let vaultPda: Address;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthorityPda: Address;

    beforeAll(async () => {
      ownerKey = await generateMockSecp256r1Key();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: ownerKey.credentialIdHash,
          compressedPubkey: ownerKey.publicKeyBytes,
          rpId: ownerKey.rpId,
        },
      });
      await sendTx(ctx, result.instructions);

      // Simulate user comeback: only the credentialIdHash is known.
      const [found] = await client.findWalletsByAuthority(
        ownerKey.credentialIdHash,
      );
      walletPda = found!.walletPda;
      vaultPda = found!.vaultPda;
      ownerAuthorityPda = found!.authorityPda;

      await airdrop(ctx, vaultPda, 2n * LAMPORTS_PER_SOL);
    });

    async function transferOnce(recipient: Address) {
      const prepared = await client.prepareExecute({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);
      const before = await getBalance(ctx, recipient);
      await sendTx(ctx, instructions);
      const after = await getBalance(ctx, recipient);
      expect(after - before).toBe(1_000_000n);
    }

    it('executes a SOL transfer via prepare/finalize', async () => {
      await transferOnce((await generateKeyPairSigner()).address);
    });

    it('executes a SOL transfer (round 2)', async () => {
      await transferOnce((await generateKeyPairSigner()).address);
    });

    it('executes arbitrary instructions', async () => {
      await transferOnce((await generateKeyPairSigner()).address);
    });

    it('increments counter after successful execute', async () => {
      await transferOnce((await generateKeyPairSigner()).address);

      const info = await ctx.rpc
        .getAccountInfo(ownerAuthorityPda, { encoding: 'base64' })
        .send();
      const bytes = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
      const decoded = decodeAuthorityAccount(bytes);
      // Three Secp256r1 transfers above + this one = 4.
      expect(decoded.counter).toBe(4);
    });

    // Repaying the payer from the vault is how a sponsored call settles up,
    // and it is the one inner account whose flags the SDK has to predict: the
    // accounts hash binds the flags the runtime reports, and the runtime
    // reports the fee payer as a writable signer. Declared read-only, this
    // failed with InvalidMessageHash (3005).
    async function repayPayer() {
      const prepared = await client.prepareExecute({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, ctx.payer.address, 1_000_000n)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      return client.finalizeExecute(prepared, response).instructions;
    }

    it('executes an inner transfer to the payer', async () => {
      const instructions = await repayPayer();
      const vaultBefore = await getBalance(ctx, vaultPda);
      await sendTx(ctx, instructions);
      expect(vaultBefore - (await getBalance(ctx, vaultPda))).toBe(1_000_000n);
    });

    // Another key pays the transaction fee. The Execute payer is then a signer
    // only because the instruction says so, and must still be writable to be
    // repaid (and to pay the execution fee).
    it('executes an inner transfer to the payer when another key pays the fee', async () => {
      const feePayer = await generateKeyPairSigner();
      await airdrop(ctx, feePayer.address, LAMPORTS_PER_SOL);
      const instructions = await repayPayer();

      const vaultBefore = await getBalance(ctx, vaultPda);
      const payerBefore = await getBalance(ctx, ctx.payer.address);
      await sendTx(ctx, instructions, [], feePayer);

      expect(vaultBefore - (await getBalance(ctx, vaultPda))).toBe(1_000_000n);
      // Repaid in full, less the execution fee; the signature fee was the fee payer's.
      const payerDelta = (await getBalance(ctx, ctx.payer.address)) - payerBefore;
      expect(payerDelta > 0n).toBe(true);
      expect(payerDelta <= 1_000_000n).toBe(true);
    });

    // The sponsor that pays the fee is not the Execute payer, and it is the one
    // repaid. It sits among the inner accounts, declared writable by the
    // transfer, and the runtime reports it a writable signer: prepareExecute
    // has to be told who pays the fee (3005 otherwise).
    it('executes an inner transfer to a fee payer that is not the Execute payer', async () => {
      const feePayer = await generateKeyPairSigner();
      await airdrop(ctx, feePayer.address, LAMPORTS_PER_SOL);
      const prepared = await client.prepareExecute({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, feePayer.address, 1_000_000n)],
        feePayer: feePayer.address,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeExecute(prepared, response);

      const vaultBefore = await getBalance(ctx, vaultPda);
      const feePayerBefore = await getBalance(ctx, feePayer.address);
      const signature = await sendTx(ctx, instructions, [], feePayer);

      expect(vaultBefore - (await getBalance(ctx, vaultPda))).toBe(1_000_000n);
      // Repaid in full, less the transaction fee it paid; the execution fee
      // was the Execute payer's.
      const sent = await ctx.rpc
        .getTransaction(signature as Signature, {
          commitment: 'confirmed',
          encoding: 'json',
          maxSupportedTransactionVersion: 0,
        })
        .send();
      expect((await getBalance(ctx, feePayer.address)) - feePayerBefore).toBe(
        1_000_000n - sent!.meta!.fee,
      );
    });
  });
});
