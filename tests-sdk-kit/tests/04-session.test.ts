/**
 * Port of tests-sdk/tests/04-session.test.ts.
 *
 * Covers CreateSession (Ed25519 admin) + unauthorized rejection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import { LazorKit, decodeSessionAccount, ed25519 } from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  getSlot,
  type TestContext,
  makeClient,
} from './common.js';

describe('CreateSession', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let walletPda: Address;
  let ownerSigner: KeyPairSigner;
  let ownerAuthorityPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);

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

  it('creates a session with Ed25519 admin', async () => {
    const sessionKey = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 9000n;

    const { instructions, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthorityPda),
      sessionKey: sessionKey.address,
      expiresAt,
      // Deliberately unrestricted: this test exercises the actionless session.
      unrestricted: true,
    });

    await sendTx(ctx, instructions, [ownerSigner]);

    const info = await ctx.rpc
      .getAccountInfo(sessionPda, { encoding: 'base64' })
      .send();
    expect(info.value).not.toBeNull();
    const session = decodeSessionAccount(
      new Uint8Array(Buffer.from(info.value!.data[0], 'base64')),
    );
    expect(session.wallet).toBe(walletPda);
    expect(session.sessionKey).toBe(sessionKey.address);
    expect(session.expiresAt).toBe(expiresAt);
  });

  it('rejects session creation from unauthorized signer', async () => {
    const randomSigner = await generateKeyPairSigner();
    const sessionKey = await generateKeyPairSigner();
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const { instructions } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(randomSigner.address, ownerAuthorityPda),
      sessionKey: sessionKey.address,
      expiresAt,
      // Deliberately unrestricted: this test exercises the actionless session.
      unrestricted: true,
    });

    await sendTxExpectError(ctx, instructions, [randomSigner]);
  });
});
