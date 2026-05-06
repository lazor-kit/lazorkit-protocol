/**
 * Port of tests-sdk/tests/10-session-execute.test.ts.
 *
 * Session-based execute paths: happy path, wrong session key rejection,
 * session expiry. transferSol convenience helper from sdk-legacy is
 * skipped — every test in this file uses execute() directly with a
 * systemTransferFromPda inner instruction.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import { LazorKit, ed25519, session } from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  getBalance,
  getSlot,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';

describe('Session Execute', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let walletPda: Address;
  let vaultPda: Address;
  let ownerSigner: KeyPairSigner;
  let ownerAuthPda: Address;

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
    vaultPda = result.vaultPda;
    ownerAuthPda = result.authorityPda;
    await sendTx(ctx, result.instructions);
    await airdrop(ctx, vaultPda, 5n * 1_000_000_000n);
  });

  it('executes SOL transfer via session key', async () => {
    const sessionSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 9000n;

    const { instructions: createIxs, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt,
    });
    await sendTx(ctx, createIxs, [ownerSigner]);

    const recipient = (await generateKeyPairSigner()).address;
    const { instructions: execIxs } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
    });

    const before = await getBalance(ctx, recipient);
    await sendTx(ctx, execIxs, [sessionSigner]);
    const after = await getBalance(ctx, recipient);
    expect(after - before).toBe(1_000_000n);
  });

  it('rejects execution with wrong session key', async () => {
    const sessionSigner = await generateKeyPairSigner();
    const wrongSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);

    const { instructions: createIxs, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt: currentSlot + 9000n,
    });
    await sendTx(ctx, createIxs, [ownerSigner]);

    const recipient = (await generateKeyPairSigner()).address;
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, wrongSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
    });
    await sendTxExpectError(ctx, instructions, [wrongSigner]);
  });

  it('rejects execution with expired session', async () => {
    const sessionSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 10n;

    const { instructions: createIxs, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt,
    });
    await sendTx(ctx, createIxs, [ownerSigner]);

    // Wait for session to expire (~4s at ~2.5 slots/sec).
    await new Promise((r) => setTimeout(r, 5000));

    const recipient = (await generateKeyPairSigner()).address;
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
    });
    // Error 3009 = SessionExpired
    await sendTxExpectError(ctx, instructions, [sessionSigner], 3009);
  });
});
