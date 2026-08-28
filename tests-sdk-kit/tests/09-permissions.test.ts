/**
 * Port of tests-sdk/tests/09-permissions.test.ts.
 *
 * Permission-boundary tests — verifies on-chain role enforcement.
 * Spender cannot add authorities / create sessions; admin cannot
 * remove owner / remove other admin / self-remove / add admin
 * (only owner can add admin); etc.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  getAddressEncoder,
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import {
  AUTH_TYPE_ED25519,
  LazorKit,
  ROLE_ADMIN,
  ROLE_OWNER,
  ROLE_SPENDER,
  ed25519,
} from '@lazorkit/sdk';
import {
  delegatePolicy,
  setupTest,
  sendTx,
  sendTxExpectError,
  getSlot,
  type TestContext,
  makeClient,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';
import { createAddAuthorityIx } from '../../sdk/sdk-kit/src/instructions/builders.js';

const addressEncoder = getAddressEncoder();

describe('Permission Boundaries', () => {
  let ctx: TestContext;
  let client: LazorKit;

  let walletPda: Address;
  let ownerSigner: KeyPairSigner;
  let ownerAuthPda: Address;

  let adminSigner: KeyPairSigner;
  let adminAuthPda: Address;

  let spenderSigner: KeyPairSigner;
  let spenderAuthPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);

    ownerSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);
    const walletResult = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });
    walletPda = walletResult.walletPda;
    ownerAuthPda = walletResult.authorityPda;
    await sendTx(ctx, walletResult.instructions);

    adminSigner = await generateKeyPairSigner();
    const addAdminResult = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      newAuthority: { type: 'ed25519', publicKey: adminSigner.address },
      role: ROLE_ADMIN,
    });
    adminAuthPda = addAdminResult.newAuthorityPda;
    await sendTx(ctx, addAdminResult.instructions, [ownerSigner]);

    spenderSigner = await generateKeyPairSigner();
    const addSpenderResult = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      newAuthority: { type: 'ed25519', publicKey: spenderSigner.address },
      role: ROLE_SPENDER,
      policy: delegatePolicy(),
    });
    spenderAuthPda = addSpenderResult.newAuthorityPda;
    await sendTx(ctx, addSpenderResult.instructions, [adminSigner]);
  });

  it('spender cannot add authority', async () => {
    const newSigner = await generateKeyPairSigner();
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(spenderSigner.address, spenderAuthPda),
      newAuthority: { type: 'ed25519', publicKey: newSigner.address },
      role: ROLE_SPENDER,
      policy: delegatePolicy(),
    });
    await sendTxExpectError(ctx, instructions, [spenderSigner], 3002);
  });

  it('admin cannot add admin (only spender)', async () => {
    const newSigner = await generateKeyPairSigner();
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      newAuthority: { type: 'ed25519', publicKey: newSigner.address },
      role: ROLE_ADMIN,
    });
    await sendTxExpectError(ctx, instructions, [adminSigner], 3002);
  });

  it('owner can add admin', async () => {
    const newSigner = await generateKeyPairSigner();
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      newAuthority: { type: 'ed25519', publicKey: newSigner.address },
      role: ROLE_ADMIN,
    });
    await sendTx(ctx, instructions, [ownerSigner]);
  });

  it('owner cannot add another owner through AddAuthority', async () => {
    const newOwnerSigner = await generateKeyPairSigner();
    const newOwnerKey = addressEncoder.encode(newOwnerSigner.address) as Uint8Array;
    const [newOwnerAuthPda] = await client.findAuthority(walletPda, newOwnerKey);
    const ix = createAddAuthorityIx({
      payer: ctx.payer.address,
      walletPda,
      adminAuthorityPda: ownerAuthPda,
      newAuthorityPda: newOwnerAuthPda,
      newType: AUTH_TYPE_ED25519,
      newRole: ROLE_OWNER,
      credentialOrPubkey: newOwnerKey,
      authorizerSigner: ownerSigner.address,
      programId: client.programId,
    });

    await sendTxExpectError(ctx, [ix], [ownerSigner], 3002);
  });

  it('admin cannot remove owner', async () => {
    const { instructions } = await client.removeAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      targetAuthorityPda: ownerAuthPda,
    });
    await sendTxExpectError(ctx, instructions, [adminSigner], 3002);
  });

  it('admin cannot remove another admin', async () => {
    const admin2Signer = await generateKeyPairSigner();
    const addResult = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      newAuthority: { type: 'ed25519', publicKey: admin2Signer.address },
      role: ROLE_ADMIN,
    });
    await sendTx(ctx, addResult.instructions, [ownerSigner]);

    const { instructions } = await client.removeAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      targetAuthorityPda: addResult.newAuthorityPda,
    });
    await sendTxExpectError(ctx, instructions, [adminSigner], 3002);

    const cleanup = await client.removeAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      targetAuthorityPda: addResult.newAuthorityPda,
    });
    await sendTx(ctx, cleanup.instructions, [ownerSigner]);
  });

  it('admin cannot self-remove', async () => {
    const { instructions } = await client.removeAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      targetAuthorityPda: adminAuthPda,
    });
    await sendTxExpectError(ctx, instructions, [adminSigner], 3002);
  });

  it('spender cannot create session', async () => {
    const sessionSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const { instructions } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(spenderSigner.address, spenderAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt: currentSlot + 9000n,
    });
    await sendTxExpectError(ctx, instructions, [spenderSigner], 3002);
  });

  describe('Secp256r1 spender boundaries', () => {
    let secpWalletPda: Address;
    let secpOwnerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let secpOwnerAuthPda: Address;
    let secpSpenderKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let secpSpenderAuthPda: Address;

    beforeAll(async () => {
      secpOwnerKey = await generateMockSecp256r1Key();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: secpOwnerKey.credentialIdHash,
          compressedPubkey: secpOwnerKey.publicKeyBytes,
          rpId: secpOwnerKey.rpId,
        },
      });
      secpWalletPda = result.walletPda;
      secpOwnerAuthPda = result.authorityPda;
      await sendTx(ctx, result.instructions);

      secpSpenderKey = await generateMockSecp256r1Key();
      const prepared = await client.prepareAddAuthority({
        payer: ctx.payer.address,
        walletPda: secpWalletPda,
        secp256r1: {
          credentialIdHash: secpOwnerKey.credentialIdHash,
          publicKeyBytes: secpOwnerKey.publicKeyBytes,
          authorityPda: secpOwnerAuthPda,
        },
        newAuthority: {
          type: 'secp256r1',
          credentialIdHash: secpSpenderKey.credentialIdHash,
          compressedPubkey: secpSpenderKey.publicKeyBytes,
          rpId: secpSpenderKey.rpId,
        },
        role: ROLE_SPENDER,
        policy: delegatePolicy(),
      });
      const response = await fakeWebAuthnSign(secpOwnerKey, prepared.challenge);
      const addResult = client.finalizeAddAuthority(prepared, response);
      secpSpenderAuthPda = addResult.newAuthorityPda;
      await sendTx(ctx, addResult.instructions);
    });

    it('secp256r1 spender cannot add authority', async () => {
      const newSigner = await generateKeyPairSigner();
      const prepared = await client.prepareAddAuthority({
        payer: ctx.payer.address,
        walletPda: secpWalletPda,
        secp256r1: {
          credentialIdHash: secpSpenderKey.credentialIdHash,
          publicKeyBytes: secpSpenderKey.publicKeyBytes,
          authorityPda: secpSpenderAuthPda,
        },
        newAuthority: { type: 'ed25519', publicKey: newSigner.address },
        role: ROLE_SPENDER,
        policy: delegatePolicy(),
      });
      const response = await fakeWebAuthnSign(secpSpenderKey, prepared.challenge);
      const { instructions } = client.finalizeAddAuthority(prepared, response);
      await sendTxExpectError(ctx, instructions, [], 3002);
    });

    it('secp256r1 spender cannot create session', async () => {
      const sessionSigner = await generateKeyPairSigner();
      const currentSlot = await getSlot(ctx);

      const prepared = await client.prepareCreateSession({
        payer: ctx.payer.address,
        walletPda: secpWalletPda,
        secp256r1: {
          credentialIdHash: secpSpenderKey.credentialIdHash,
          publicKeyBytes: secpSpenderKey.publicKeyBytes,
          authorityPda: secpSpenderAuthPda,
        },
        sessionKey: sessionSigner.address,
        expiresAt: currentSlot + 9000n,
      });
      const response = await fakeWebAuthnSign(secpSpenderKey, prepared.challenge);
      const { instructions } = client.finalizeCreateSession(prepared, response);
      await sendTxExpectError(ctx, instructions, [], 3002);
    });
  });
});
