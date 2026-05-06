/**
 * Port of tests-sdk/tests/13-deferred-client-api.test.ts.
 *
 * Deferred-execution client ergonomics:
 *   - readAuthorityPubkey from-account fetch
 *   - prepareAuthorize works with publicKeyBytes auto-fetched
 *   - serialize → wire → deserialize round-trip preserves DeferredPayload
 *   - relayer submits TX2 from a deserialized payload
 *   - deserialize rejects malformed input
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AccountRole,
  address,
  generateKeyPairSigner,
  type Address,
} from '@solana/kit';
import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  deserializeDeferredPayload,
  readAuthorityPubkey,
  serializeDeferredPayload,
  type DeferredPayload,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  airdrop,
  getBalance,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';

describe('Deferred Client API ergonomics', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
  let walletPda: Address;
  let vaultPda: Address;
  let authorityPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    ownerKey = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);
    const wallet = await client.createWallet({
      payer: ctx.payer.address,
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
    await airdrop(ctx, vaultPda, 10n * 1_000_000_000n);
  });

  it('readAuthorityPubkey returns the stored compressed pubkey', async () => {
    const fetched = await readAuthorityPubkey(ctx.rpc as never, authorityPda);
    expect(fetched).toHaveLength(33);
    expect(Buffer.from(fetched).equals(Buffer.from(ownerKey.publicKeyBytes))).toBe(true);
  });

  it('prepareAuthorize works without passing publicKeyBytes', async () => {
    const recipient = (await generateKeyPairSigner()).address;
    // publicKeyBytes omitted — SDK reads it from the authority account.
    const prepared = await client.prepareAuthorize({
      payer: ctx.payer.address,
      walletPda,
      secp256r1: {
        credentialIdHash: ownerKey.credentialIdHash,
        authorityPda,
      },
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000_000n)],
      expiryOffset: 300,
    });
    const webauthnResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
    const { instructions, deferredPayload } = client.finalizeAuthorize(prepared, webauthnResponse);
    await sendTx(ctx, instructions);

    const info = await ctx.rpc
      .getAccountInfo(deferredPayload.deferredExecPda, { encoding: 'base64' })
      .send();
    expect(info.value).not.toBeNull();

    const tx2 = await client.executeDeferredFromPayload({
      payer: ctx.payer.address,
      deferredPayload,
    });
    await sendTx(ctx, tx2.instructions);
  });

  it('serialize then deserialize preserves DeferredPayload exactly', () => {
    const deferredPayload: DeferredPayload = {
      walletPda: address('HoG2C1pp3LwV5sfLvx8tJkBRhvXcG6LMmX4LrLkrpPVx'),
      deferredExecPda: address('9aTKR5D7fcYkXKgq4a2DrrL3Vx7L3GpAeCNuvz1yJf4K'),
      compactInstructions: [
        {
          programIdIndex: 5,
          accountIndexes: [2, 6],
          data: new Uint8Array([
            2, 0, 0, 0, 0xff, 0xfe, 0xfd, 0xfc, 0x00, 0x00, 0x00, 0x00,
          ]),
        },
      ],
      remainingAccounts: [
        {
          address: address('11111111111111111111111111111111'),
          role: AccountRole.READONLY,
        },
        {
          address: address('So11111111111111111111111111111111111111112'),
          role: AccountRole.WRITABLE,
        },
      ],
    };

    const wire = serializeDeferredPayload(deferredPayload);
    expect(typeof wire).toBe('string');

    const roundtripped = deserializeDeferredPayload(wire);
    expect(roundtripped.walletPda).toBe(deferredPayload.walletPda);
    expect(roundtripped.deferredExecPda).toBe(deferredPayload.deferredExecPda);
    expect(roundtripped.compactInstructions).toHaveLength(deferredPayload.compactInstructions.length);
    for (let i = 0; i < deferredPayload.compactInstructions.length; i++) {
      const a = deferredPayload.compactInstructions[i]!;
      const b = roundtripped.compactInstructions[i]!;
      expect(b.programIdIndex).toBe(a.programIdIndex);
      expect(b.accountIndexes).toEqual(a.accountIndexes);
      expect(Buffer.from(b.data).equals(Buffer.from(a.data))).toBe(true);
    }
    expect(roundtripped.remainingAccounts).toHaveLength(deferredPayload.remainingAccounts.length);
    for (let i = 0; i < deferredPayload.remainingAccounts.length; i++) {
      const a = deferredPayload.remainingAccounts[i]!;
      const b = roundtripped.remainingAccounts[i]!;
      expect(b.address).toBe(a.address);
      expect(b.role).toBe(a.role);
    }
  });

  it('deserialized payload submits TX2 successfully', async () => {
    const recipient = (await generateKeyPairSigner()).address;
    const prepared = await client.prepareAuthorize({
      payer: ctx.payer.address,
      walletPda,
      secp256r1: { credentialIdHash: ownerKey.credentialIdHash, authorityPda },
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000_000n)],
    });
    const webauthnResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
    const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
      prepared,
      webauthnResponse,
    );
    await sendTx(ctx, authIxs);

    const wire = serializeDeferredPayload(deferredPayload);

    // "Relayer" — fresh client instance + reconstructed payload.
    const relayer = new LazorKit(ctx.rpc as never, PROGRAM_ID_DEVNET);
    const reconstructed = deserializeDeferredPayload(wire);
    const tx2 = await relayer.executeDeferredFromPayload({
      payer: ctx.payer.address,
      deferredPayload: reconstructed,
    });

    const before = await getBalance(ctx, recipient);
    await sendTx(ctx, tx2.instructions);
    const after = await getBalance(ctx, recipient);
    expect(after - before).toBe(1_000_000_000n);
  });

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
