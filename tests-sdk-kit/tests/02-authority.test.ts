/**
 * Port of tests-sdk/tests/02-authority.test.ts.
 *
 * Covers AddAuthority + RemoveAuthority under both Ed25519 and
 * Secp256r1 admin paths.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  LazorKit,
  ROLE_ADMIN,
  ROLE_SPENDER,
  decodeAuthorityAccount,
  ed25519,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  type TestContext,
  makeClient,
} from './common.js';
import {
  generateMockSecp256r1Key,
  fakeWebAuthnSign,
} from './secp256r1Utils.js';

async function loadAuthority(ctx: TestContext, pda: Address) {
  const info = await ctx.rpc.getAccountInfo(pda, { encoding: 'base64' }).send();
  if (!info.value) throw new Error(`Authority ${pda} not found`);
  return decodeAuthorityAccount(
    new Uint8Array(Buffer.from(info.value.data[0], 'base64')),
  );
}

describe('Authority Management', () => {
  let ctx: TestContext;
  let client: LazorKit;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
  });

  describe('Ed25519 admin flow', () => {
    let walletPda: Address;
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
      walletPda = result.walletPda;
      ownerAuthorityPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
    });

    it('adds an Ed25519 admin authority', async () => {
      const adminSigner = await generateKeyPairSigner();
      const { instructions, newAuthorityPda } = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthorityPda),
        newAuthority: { type: 'ed25519', publicKey: adminSigner.address },
        role: ROLE_ADMIN,
      });

      await sendTx(ctx, instructions, [ownerSigner]);

      const authority = await loadAuthority(ctx, newAuthorityPda);
      expect(authority.authorityType).toBe(AUTH_TYPE_ED25519);
      expect(authority.role).toBe(ROLE_ADMIN);
      expect(authority.counter).toBe(0);
    });

    it('adds a Secp256r1 spender authority', async () => {
      const key = await generateMockSecp256r1Key();
      const { instructions, newAuthorityPda } = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthorityPda),
        newAuthority: {
          type: 'secp256r1',
          credentialIdHash: key.credentialIdHash,
          compressedPubkey: key.publicKeyBytes,
          rpId: key.rpId,
        },
        role: ROLE_SPENDER,
      });

      await sendTx(ctx, instructions, [ownerSigner]);

      const authority = await loadAuthority(ctx, newAuthorityPda);
      expect(authority.authorityType).toBe(AUTH_TYPE_SECP256R1);
      expect(authority.role).toBe(ROLE_SPENDER);
    });

    it('removes an authority via Ed25519 admin', async () => {
      const spenderSigner = await generateKeyPairSigner();
      const { instructions: addIxs, newAuthorityPda: spenderAuthPda } =
        await client.addAuthority({
          payer: ctx.payer.address,
          walletPda,
          adminSigner: ed25519(ownerSigner.address, ownerAuthorityPda),
          newAuthority: { type: 'ed25519', publicKey: spenderSigner.address },
          role: ROLE_SPENDER,
        });
      await sendTx(ctx, addIxs, [ownerSigner]);

      const { instructions: removeIxs } = await client.removeAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthorityPda),
        targetAuthorityPda: spenderAuthPda,
      });
      await sendTx(ctx, removeIxs, [ownerSigner]);

      const info = await ctx.rpc
        .getAccountInfo(spenderAuthPda, { encoding: 'base64' })
        .send();
      expect(info.value).toBeNull();
    });

    it('rejects add from non-admin signer', async () => {
      const randomSigner = await generateKeyPairSigner();
      const newSigner = await generateKeyPairSigner();
      const { instructions } = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(randomSigner.address, ownerAuthorityPda),
        newAuthority: { type: 'ed25519', publicKey: newSigner.address },
        role: ROLE_SPENDER,
      });
      await sendTxExpectError(ctx, instructions, [randomSigner]);
    });
  });

  describe('Secp256r1 admin flow', () => {
    let walletPda: Address;
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
      walletPda = result.walletPda;
      ownerAuthorityPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
    });

    it('adds an Ed25519 admin via Secp256r1 owner', async () => {
      const adminSigner = await generateKeyPairSigner();
      const prepared = await client.prepareAddAuthority({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        newAuthority: { type: 'ed25519', publicKey: adminSigner.address },
        role: ROLE_ADMIN,
      });

      const webauthnResponse = await fakeWebAuthnSign(
        ownerKey,
        prepared.challenge,
      );
      const { instructions } = client.finalizeAddAuthority(
        prepared,
        webauthnResponse,
      );

      await sendTx(ctx, instructions);

      const authority = await loadAuthority(ctx, prepared.newAuthorityPda);
      expect(authority.authorityType).toBe(AUTH_TYPE_ED25519);
      expect(authority.role).toBe(ROLE_ADMIN);
    });
  });
});
