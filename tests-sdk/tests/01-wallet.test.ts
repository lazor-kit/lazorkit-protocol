import { describe, it, expect, beforeAll } from 'vitest';
import { Keypair } from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTx, type TestContext } from './common';
import { generateMockSecp256r1Key } from './secp256r1Utils';
import {
  LazorKitClient,
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  PROGRAM_ID,
} from '../../sdk/sdk-legacy/src';
import { AuthorityAccount } from '../../sdk/sdk-legacy/src/utils/accounts';

describe('CreateWallet', () => {
  let ctx: TestContext;
  let client: LazorKitClient;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
  });

  it('creates a wallet with Ed25519 owner and finds it back', async () => {
    const ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);

    const { instructions, walletPda, authorityPda } = await client.createWallet(
      {
        payer: ctx.payer.publicKey,
        userSeed,
        owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
      },
    );

    await sendTx(ctx, instructions);

    // Verify wallet account exists
    const walletInfo = await ctx.connection.getAccountInfo(walletPda);
    expect(walletInfo).not.toBeNull();
    expect(walletInfo!.owner.equals(PROGRAM_ID)).toBe(true);

    // Verify authority account
    const authority = await AuthorityAccount.fromAccountAddress(
      ctx.connection,
      authorityPda,
    );
    expect(authority.authorityType).toBe(AUTH_TYPE_ED25519);
    expect(authority.role).toBe(0); // Owner
    expect(Number(authority.counter)).toBe(0);
    expect(authority.wallet.equals(walletPda)).toBe(true);

    // === Simulate "user comes back" — find wallet by pubkey ===
    const [found] = await client.findWalletsByAuthority(
      ownerKp.publicKey.toBytes(),
      'ed25519',
    );
    expect(found).toBeDefined();
    expect(found.walletPda.equals(walletPda)).toBe(true);
    expect(found.authorityPda.equals(authorityPda)).toBe(true);
    expect(found.authorityType).toBe(AUTH_TYPE_ED25519);
    expect(found.role).toBe(0);
  });

  it('creates a wallet with Secp256r1 owner and finds it back', async () => {
    const key = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    const { instructions, walletPda, authorityPda } = await client.createWallet(
      {
        payer: ctx.payer.publicKey,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: key.credentialIdHash,
          compressedPubkey: key.publicKeyBytes,
          rpId: key.rpId,
        },
      },
    );

    await sendTx(ctx, instructions);

    // Verify authority account
    const authority = await AuthorityAccount.fromAccountAddress(
      ctx.connection,
      authorityPda,
    );
    expect(authority.authorityType).toBe(AUTH_TYPE_SECP256R1);
    expect(authority.role).toBe(0); // Owner
    expect(Number(authority.counter)).toBe(0);

    // === Simulate "user comes back" — only has credentialIdHash ===
    const [found] = await client.findWalletsByAuthority(key.credentialIdHash);
    expect(found).toBeDefined();
    expect(found.walletPda.equals(walletPda)).toBe(true);
    expect(found.authorityPda.equals(authorityPda)).toBe(true);
    expect(found.authorityType).toBe(AUTH_TYPE_SECP256R1);
  });

  it('returns empty array for unknown credential', async () => {
    const unknownCred = crypto.randomBytes(32);
    const results = await client.findWalletsByAuthority(unknownCred);
    expect(results).toHaveLength(0);
  });

  it('rejects duplicate wallet creation', async () => {
    const ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);

    const { instructions } = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });

    // First creation succeeds
    await sendTx(ctx, instructions);

    // Second creation should fail
    try {
      await sendTx(ctx, instructions);
      expect.unreachable('Should have failed');
    } catch (err: any) {
      expect(String(err)).toMatch(/already in use|0x0|uninitialized account/);
    }
  });
});
