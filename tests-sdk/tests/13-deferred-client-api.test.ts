import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTx, type TestContext } from './common';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils';
import {
  LazorKitClient,
  serializeDeferredPayload,
  deserializeDeferredPayload,
  readAuthorityPubkey,
  type DeferredPayload,
} from '../../sdk/sdk-legacy/src';

describe('Deferred Client API ergonomics', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
  let walletPda: PublicKey;
  let vaultPda: PublicKey;
  let authorityPda: PublicKey;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    ownerKey = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    const wallet = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: ownerKey.credentialIdHash,
        compressedPubkey: ownerKey.publicKeyBytes,
        rpId: ownerKey.rpId,
      },
    });
    walletPda = wallet.walletPda;
    vaultPda = wallet.vaultPda;
    authorityPda = wallet.authorityPda;
    await sendTx(ctx, wallet.instructions);

    const sig = await ctx.connection.requestAirdrop(
      vaultPda,
      10 * LAMPORTS_PER_SOL,
    );
    await ctx.connection.confirmTransaction(sig, 'confirmed');
  });

  // ── readAuthorityPubkey helper ───────────────────────────────────────

  it('readAuthorityPubkey returns the stored compressed pubkey', async () => {
    const fetched = await readAuthorityPubkey(ctx.connection, authorityPda);
    expect(fetched).toHaveLength(33);
    expect(Buffer.from(fetched).equals(Buffer.from(ownerKey.publicKeyBytes)))
      .toBe(true);
  });

  // ── publicKeyBytes auto-fetch ────────────────────────────────────────

  it('prepareAuthorize works without passing publicKeyBytes', async () => {
    const recipient = Keypair.generate().publicKey;

    // Note: publicKeyBytes omitted — SDK must read it from authority account
    const prepared = await client.prepareAuthorize({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: {
        credentialIdHash: ownerKey.credentialIdHash,
        authorityPda,
      },
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipient,
          lamports: LAMPORTS_PER_SOL,
        }),
      ],
      expiryOffset: 300,
    });

    const webauthnResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
    const { instructions, deferredPayload } = client.finalizeAuthorize(
      prepared,
      webauthnResponse,
    );
    await sendTx(ctx, instructions);

    // Verify deferred account created
    const info = await ctx.connection.getAccountInfo(deferredPayload.deferredExecPda);
    expect(info).not.toBeNull();

    // Clean up — execute TX2
    const tx2 = await client.executeDeferredFromPayload({
      payer: ctx.payer.publicKey,
      deferredPayload,
    });
    await sendTx(ctx, tx2.instructions);
  });

  // ── serialize / deserialize round-trip ───────────────────────────────

  it('serialize then deserialize preserves DeferredPayload exactly', () => {
    // Pure in-memory round-trip — no chain state needed.
    const deferredPayload: DeferredPayload = {
      walletPda: new PublicKey('HoG2C1pp3LwV5sfLvx8tJkBRhvXcG6LMmX4LrLkrpPVx'),
      deferredExecPda: new PublicKey('9aTKR5D7fcYkXKgq4a2DrrL3Vx7L3GpAeCNuvz1yJf4K'),
      compactInstructions: [
        {
          programIdIndex: 5,
          accountIndexes: [2, 6],
          data: new Uint8Array([2, 0, 0, 0, 0xff, 0xfe, 0xfd, 0xfc, 0x00, 0x00, 0x00, 0x00]),
        },
      ],
      remainingAccounts: [
        {
          pubkey: new PublicKey('11111111111111111111111111111111'),
          isSigner: false,
          isWritable: false,
        },
        {
          pubkey: new PublicKey('So11111111111111111111111111111111111111112'),
          isSigner: false,
          isWritable: true,
        },
      ],
    };

    // Serialize → string → parse back
    const wire = serializeDeferredPayload(deferredPayload);
    expect(typeof wire).toBe('string');
    const roundtripped = deserializeDeferredPayload(wire);

    // Structural equality
    expect(roundtripped.walletPda.toBase58()).toBe(deferredPayload.walletPda.toBase58());
    expect(roundtripped.deferredExecPda.toBase58()).toBe(
      deferredPayload.deferredExecPda.toBase58(),
    );
    expect(roundtripped.compactInstructions).toHaveLength(
      deferredPayload.compactInstructions.length,
    );
    for (let i = 0; i < deferredPayload.compactInstructions.length; i++) {
      const a = deferredPayload.compactInstructions[i];
      const b = roundtripped.compactInstructions[i];
      expect(b.programIdIndex).toBe(a.programIdIndex);
      expect(b.accountIndexes).toEqual(a.accountIndexes);
      expect(Buffer.from(b.data).equals(Buffer.from(a.data))).toBe(true);
    }
    expect(roundtripped.remainingAccounts).toHaveLength(
      deferredPayload.remainingAccounts.length,
    );
    for (let i = 0; i < deferredPayload.remainingAccounts.length; i++) {
      const a = deferredPayload.remainingAccounts[i];
      const b = roundtripped.remainingAccounts[i];
      expect(b.pubkey.toBase58()).toBe(a.pubkey.toBase58());
      expect(b.isSigner).toBe(a.isSigner);
      expect(b.isWritable).toBe(a.isWritable);
    }
  });

  it('deserialized payload submits TX2 successfully', async () => {
    const recipient = Keypair.generate().publicKey;

    // TX1: authorize a transfer on original client
    const prepared = await client.prepareAuthorize({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: { credentialIdHash: ownerKey.credentialIdHash, authorityPda },
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipient,
          lamports: LAMPORTS_PER_SOL, // >= rent-exempt minimum
        }),
      ],
    });
    const webauthnResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
    const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
      prepared,
      webauthnResponse,
    );
    await sendTx(ctx, authIxs);

    // Simulate sending `deferredPayload` over the wire
    const wire = serializeDeferredPayload(deferredPayload);

    // "Relayer" deserializes and submits TX2 using a fresh client instance
    const relayerClient = new LazorKitClient(ctx.connection);
    const reconstructed: DeferredPayload = deserializeDeferredPayload(wire);
    const tx2 = await relayerClient.executeDeferredFromPayload({
      payer: ctx.payer.publicKey,
      deferredPayload: reconstructed,
    });

    const balBefore = await ctx.connection.getBalance(recipient);
    await sendTx(ctx, tx2.instructions);
    const balAfter = await ctx.connection.getBalance(recipient);

    expect(balAfter - balBefore).toBe(LAMPORTS_PER_SOL);
  });

  // ── deserialize error handling ───────────────────────────────────────

  it('deserialize rejects malformed JSON', () => {
    expect(() => deserializeDeferredPayload('not json')).toThrow();
    expect(() => deserializeDeferredPayload('{}')).toThrow(
      /Invalid DeferredPayload JSON shape/,
    );
    expect(() =>
      deserializeDeferredPayload(JSON.stringify({ walletPda: 'x' })),
    ).toThrow(/Invalid DeferredPayload JSON shape/);
  });
});
