/**
 * Port of tests-sdk/tests/07-e2e.test.ts.
 *
 * Realistic 9-step company workflow:
 *   1. CEO creates wallet with Secp256r1 passkey
 *   2. CEO comes back via credentialIdHash
 *   3. CEO adds Admin (Ed25519)
 *   4. Admin adds Spender (Secp256r1)
 *   5. Spender comes back via credentialIdHash
 *   6. Spender executes SOL transfer
 *   7. Admin creates Session
 *   8. Admin removes Spender
 *   9. CEO transfers ownership to new passkey
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
  delegatePolicy,
  setupTest,
  sendTx,
  airdrop,
  getBalance,
  getSlot,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';

async function loadAuthority(ctx: TestContext, pda: Address) {
  const info = await ctx.rpc.getAccountInfo(pda, { encoding: 'base64' }).send();
  return decodeAuthorityAccount(
    new Uint8Array(Buffer.from(info.value!.data[0], 'base64')),
  );
}

describe('E2E Company Workflow', () => {
  let ctx: TestContext;
  let client: LazorKit;

  let ceoKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
  let adminSigner: KeyPairSigner;
  let spenderKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;

  let walletPda: Address;
  let vaultPda: Address;
  let ceoAuthPda: Address;
  let adminAuthPda: Address;
  let spenderAuthPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    ceoKey = await generateMockSecp256r1Key('company.com');
    adminSigner = await generateKeyPairSigner();
    spenderKey = await generateMockSecp256r1Key('company.com');
  });

  it('Step 1: CEO creates wallet with passkey', async () => {
    const userSeed = crypto.randomBytes(32);
    const result = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: ceoKey.credentialIdHash,
        compressedPubkey: ceoKey.publicKeyBytes,
        rpId: ceoKey.rpId,
      },
    });
    await sendTx(ctx, result.instructions);
    await airdrop(ctx, result.vaultPda, 5n * 1_000_000_000n);
  });

  it('Step 2: CEO comes back — finds wallet by credentialIdHash only', async () => {
    const [found] = await client.findWalletsByAuthority(ceoKey.credentialIdHash);
    expect(found).toBeDefined();
    expect(found!.authorityType).toBe(AUTH_TYPE_SECP256R1);
    expect(found!.role).toBe(0);

    walletPda = found!.walletPda;
    vaultPda = found!.vaultPda;
    ceoAuthPda = found!.authorityPda;

    const auth = await loadAuthority(ctx, ceoAuthPda);
    expect(auth.role).toBe(0);
    expect(auth.authorityType).toBe(AUTH_TYPE_SECP256R1);
  });

  it('Step 3: CEO adds Admin (Ed25519)', async () => {
    const prepared = await client.prepareAddAuthority({
      payer: ctx.payer.address,
      walletPda,
      secp256r1: {
        credentialIdHash: ceoKey.credentialIdHash,
        publicKeyBytes: ceoKey.publicKeyBytes,
        authorityPda: ceoAuthPda,
      },
      newAuthority: { type: 'ed25519', publicKey: adminSigner.address },
      role: ROLE_ADMIN,
    });
    const response = await fakeWebAuthnSign(ceoKey, prepared.challenge);
    const { instructions, newAuthorityPda } = client.finalizeAddAuthority(
      prepared,
      response,
    );
    adminAuthPda = newAuthorityPda;

    await sendTx(ctx, instructions);
    const auth = await loadAuthority(ctx, adminAuthPda);
    expect(auth.role).toBe(ROLE_ADMIN);
    expect(auth.authorityType).toBe(AUTH_TYPE_ED25519);
  });

  it('Step 4: Admin adds Spender (Secp256r1)', async () => {
    const { instructions, newAuthorityPda } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      newAuthority: {
        type: 'secp256r1',
        credentialIdHash: spenderKey.credentialIdHash,
        compressedPubkey: spenderKey.publicKeyBytes,
        rpId: spenderKey.rpId,
      },
      role: ROLE_SPENDER,
      policy: delegatePolicy(),
    });
    spenderAuthPda = newAuthorityPda;

    await sendTx(ctx, instructions, [adminSigner]);

    const auth = await loadAuthority(ctx, spenderAuthPda);
    expect(auth.role).toBe(ROLE_SPENDER);
    expect(auth.authorityType).toBe(AUTH_TYPE_SECP256R1);
  });

  it('Step 5: Spender comes back — finds their wallet by credentialIdHash', async () => {
    const wallets = await client.findWalletsByAuthority(spenderKey.credentialIdHash);
    expect(wallets).toHaveLength(1);
    expect(wallets[0]!.walletPda).toBe(walletPda);
    expect(wallets[0]!.role).toBe(ROLE_SPENDER);
    spenderAuthPda = wallets[0]!.authorityPda;
  });

  it('Step 6: Spender executes SOL transfer', async () => {
    const recipient = (await generateKeyPairSigner()).address;

    const prepared = await client.prepareExecute({
      payer: ctx.payer.address,
      walletPda,
      secp256r1: {
        credentialIdHash: spenderKey.credentialIdHash,
        publicKeyBytes: spenderKey.publicKeyBytes,
        authorityPda: spenderAuthPda,
      },
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
    });
    const response = await fakeWebAuthnSign(spenderKey, prepared.challenge);
    const { instructions } = client.finalizeExecute(prepared, response);

    const before = await getBalance(ctx, recipient);
    await sendTx(ctx, instructions);
    const after = await getBalance(ctx, recipient);
    expect(after - before).toBe(1_000_000n);
  });

  it('Step 7: Admin creates Session', async () => {
    const sessionKey = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 9000n;
    const { instructions } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      sessionKey: sessionKey.address,
      expiresAt,
    });
    await sendTx(ctx, instructions, [adminSigner]);
  });

  it('Step 8: Admin removes Spender', async () => {
    const { instructions } = await client.removeAuthority({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(adminSigner.address, adminAuthPda),
      targetAuthorityPda: spenderAuthPda,
    });
    await sendTx(ctx, instructions, [adminSigner]);

    const info = await ctx.rpc.getAccountInfo(spenderAuthPda, { encoding: 'base64' }).send();
    expect(info.value).toBeNull();

    const wallets = await client.findWalletsByAuthority(spenderKey.credentialIdHash);
    expect(wallets).toHaveLength(0);
  });

  it('Step 9: CEO transfers ownership to new passkey', async () => {
    const newCeoKey = await generateMockSecp256r1Key('company.com');

    const prepared = await client.prepareTransferOwnership({
      payer: ctx.payer.address,
      walletPda,
      secp256r1: {
        credentialIdHash: ceoKey.credentialIdHash,
        publicKeyBytes: ceoKey.publicKeyBytes,
        authorityPda: ceoAuthPda,
      },
      newOwner: {
        type: 'secp256r1',
        credentialIdHash: newCeoKey.credentialIdHash,
        compressedPubkey: newCeoKey.publicKeyBytes,
        rpId: newCeoKey.rpId,
      },
    });
    const response = await fakeWebAuthnSign(ceoKey, prepared.challenge);
    const { instructions } = client.finalizeTransferOwnership(prepared, response);

    await sendTx(ctx, instructions);

    const oldWallets = await client.findWalletsByAuthority(ceoKey.credentialIdHash);
    expect(oldWallets).toHaveLength(0);

    const [newCeoWallet] = await client.findWalletsByAuthority(newCeoKey.credentialIdHash);
    expect(newCeoWallet).toBeDefined();
    expect(newCeoWallet!.walletPda).toBe(walletPda);
    expect(newCeoWallet!.role).toBe(0);
  });
});
