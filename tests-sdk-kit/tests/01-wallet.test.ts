/**
 * Port of tests-sdk/tests/01-wallet.test.ts to the kit-flavored SDK.
 *
 * Verifies the most fundamental flow:
 *   - createWallet (Ed25519 + Secp256r1 owners)
 *   - findWalletsByAuthority (round-trip through getProgramAccounts)
 *   - duplicate-wallet rejection
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  getAddressEncoder,
  type KeyPairSigner,
} from '@solana/kit';
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  LazorKit,
  PROGRAM_ID_DEVNET,
  decodeAuthorityAccount,
} from '@lazorkit/sdk';
import { setupTest, sendTx, type TestContext, makeClient } from './common.js';
import { generateMockSecp256r1Key } from './secp256r1Utils.js';

const addressEncoder = getAddressEncoder();

describe('CreateWallet', () => {
  let ctx: TestContext;
  let client: LazorKit;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
  });

  it('creates a wallet with Ed25519 owner and finds it back', async () => {
    const ownerSigner: KeyPairSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);

    const { instructions, walletPda, authorityPda } = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });

    await sendTx(ctx, instructions);

    // Verify wallet account exists + is owned by the program.
    const walletInfo = await ctx.rpc
      .getAccountInfo(walletPda, { encoding: 'base64' })
      .send();
    expect(walletInfo.value).not.toBeNull();
    expect(walletInfo.value!.owner).toBe(PROGRAM_ID_DEVNET);

    // Verify authority account decodes correctly.
    const authInfo = await ctx.rpc
      .getAccountInfo(authorityPda, { encoding: 'base64' })
      .send();
    expect(authInfo.value).not.toBeNull();
    const authBytes = new Uint8Array(
      Buffer.from(authInfo.value!.data[0], 'base64'),
    );
    const authority = decodeAuthorityAccount(authBytes);
    expect(authority.authorityType).toBe(AUTH_TYPE_ED25519);
    expect(authority.role).toBe(0); // Owner
    expect(authority.counter).toBe(0);
    expect(authority.wallet).toBe(walletPda);

    // === Simulate "user comes back" — find wallet by pubkey ===
    const ownerBytes = addressEncoder.encode(ownerSigner.address) as Uint8Array;
    const found = await client.findWalletsByAuthority(ownerBytes, 'ed25519');
    expect(found.length).toBeGreaterThanOrEqual(1);
    const hit = found[0]!;
    expect(hit.walletPda).toBe(walletPda);
    expect(hit.authorityPda).toBe(authorityPda);
    expect(hit.authorityType).toBe(AUTH_TYPE_ED25519);
    expect(hit.role).toBe(0);
  });

  it('creates a wallet with Secp256r1 owner and finds it back', async () => {
    const key = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    const { instructions, walletPda, authorityPda } = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: key.credentialIdHash,
        compressedPubkey: key.publicKeyBytes,
        rpId: key.rpId,
      },
    });

    await sendTx(ctx, instructions);

    // Verify authority account.
    const authInfo = await ctx.rpc
      .getAccountInfo(authorityPda, { encoding: 'base64' })
      .send();
    const authBytes = new Uint8Array(
      Buffer.from(authInfo.value!.data[0], 'base64'),
    );
    const authority = decodeAuthorityAccount(authBytes);
    expect(authority.authorityType).toBe(AUTH_TYPE_SECP256R1);
    expect(authority.role).toBe(0);
    expect(authority.counter).toBe(0);

    // === Simulate "user comes back" — only has credentialIdHash ===
    const found = await client.findWalletsByAuthority(key.credentialIdHash);
    expect(found.length).toBeGreaterThanOrEqual(1);
    const hit = found[0]!;
    expect(hit.walletPda).toBe(walletPda);
    expect(hit.authorityPda).toBe(authorityPda);
    expect(hit.authorityType).toBe(AUTH_TYPE_SECP256R1);
  });

  it('returns empty array for unknown credential', async () => {
    const unknown = crypto.randomBytes(32);
    const results = await client.findWalletsByAuthority(unknown);
    expect(results).toHaveLength(0);
  });

  it('rejects duplicate wallet creation', async () => {
    const ownerSigner = await generateKeyPairSigner();
    const userSeed = crypto.randomBytes(32);

    const { instructions } = await client.createWallet({
      payer: ctx.payer.address,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });

    await sendTx(ctx, instructions);

    try {
      await sendTx(ctx, instructions);
      expect.unreachable('Should have failed');
    } catch (err) {
      // kit surfaces "Transaction simulation failed" at the outer level;
      // the on-chain "already in use" is in the cause/logs. Either way,
      // the second send must fail.
      expect(err).toBeDefined();
      const all = JSON.stringify(err, Object.getOwnPropertyNames(err)) + String(err);
      expect(all).toMatch(/already in use|0x0|uninitialized|simulation failed/i);
    }
  });
});
