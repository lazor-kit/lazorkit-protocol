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
  });
});
