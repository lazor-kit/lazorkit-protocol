/**
 * Port of tests-sdk/tests/12-session-actions.test.ts.
 *
 * Comprehensive session-action enforcement tests:
 *   - Backwards compatibility (no actions / undefined actions)
 *   - ProgramWhitelist (allow, reject non-whitelisted, multiple whitelisted)
 *   - ProgramBlacklist (block listed, allow non-listed)
 *   - SolMaxPerTx (under, exact, over, no accumulation across txs)
 *   - SolLimit lifetime cap (depletion, single-tx-over, post-deplete block)
 *   - SolRecurringLimit (window enforcement)
 *   - Combined actions (whitelist+limits, stricter wins)
 *   - Whitelist+Blacklist conflict at creation
 *   - Session isolation (two sessions independent)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
  type KeyPairSigner,
} from '@solana/kit';
import {
  Actions,
  LazorKit,
  SYSTEM_PROGRAM_ADDRESS,
  ed25519,
  session,
  type SessionAction,
} from '@lazorkit/sdk';
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

const LAMPORTS_PER_SOL = 1_000_000_000n;

describe('Session Actions', () => {
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

    // Multiple airdrops — generous funding for the cumulative tests below.
    for (let i = 0; i < 3; i++) {
      await airdrop(ctx, vaultPda, 10n * LAMPORTS_PER_SOL);
    }
  });

  async function createSessionWith(actions: SessionAction[]) {
    const sessionSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 50_000n;

    const { instructions: createIxs, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt,
      actions,
    });
    await sendTx(ctx, createIxs, [ownerSigner]);
    return { sessionSigner, sessionPda };
  }

  async function transferIxs(
    sessionSigner: KeyPairSigner,
    sessionPda: Address,
    recipient: Address,
    lamports: bigint,
  ) {
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, lamports)],
    });
    return instructions;
  }

  describe('Backwards Compatibility', () => {
    it('no actions — fully open session works', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('undefined actions — same as no actions', async () => {
      const sessionSigner = await generateKeyPairSigner();
      const currentSlot = await getSlot(ctx);
      const { instructions: createIxs, sessionPda } = await client.createSession({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
        sessionKey: sessionSigner.address,
        expiresAt: currentSlot + 50_000n,
      });
      await sendTx(ctx, createIxs, [ownerSigner]);

      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 2_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(2_000_000n);
    });
  });

  describe('ProgramWhitelist', () => {
    it('allows whitelisted program (SystemProgram)', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('rejects non-whitelisted program', async () => {
      const random = (await generateKeyPairSigner()).address;
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(random),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
        3021,
      );
    });

    it('multiple whitelisted programs — both work', async () => {
      const extra = (await generateKeyPairSigner()).address;
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
        Actions.programWhitelist(extra),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });
  });

  describe('ProgramBlacklist', () => {
    it('blocks blacklisted program', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programBlacklist(SYSTEM_PROGRAM_ADDRESS),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
        3022,
      );
    });

    it('allows non-blacklisted program', async () => {
      const random = (await generateKeyPairSigner()).address;
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programBlacklist(random),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });
  });

  describe('SolMaxPerTx', () => {
    it('allows under limit', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(2_000_000n),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('rejects over limit', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(500_000n),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
        3023,
      );
    });

    it('allows exact limit', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(1_000_000n),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('does not accumulate across txs — each tx independent', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(1_500_000n),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;
      const r3 = (await generateKeyPairSigner()).address;

      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r1, 1_000_000n), [sessionSigner]);
      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r2, 1_000_000n), [sessionSigner]);
      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r3, 1_500_000n), [sessionSigner]);

      expect(await getBalance(ctx, r1)).toBe(1_000_000n);
      expect(await getBalance(ctx, r2)).toBe(1_000_000n);
      expect(await getBalance(ctx, r3)).toBe(1_500_000n);
    });
  });

  describe('SolLimit', () => {
    it('depletes across multiple transactions', async () => {
      const limit = 3n * LAMPORTS_PER_SOL;
      const { sessionSigner, sessionPda } = await createSessionWith([Actions.solLimit(limit)]);
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;
      const r3 = (await generateKeyPairSigner()).address;

      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r1, LAMPORTS_PER_SOL), [sessionSigner]);
      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r2, LAMPORTS_PER_SOL), [sessionSigner]);
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r3, 2n * LAMPORTS_PER_SOL),
        [sessionSigner],
        3024,
      );
      expect(await getBalance(ctx, r1)).toBe(LAMPORTS_PER_SOL);
      expect(await getBalance(ctx, r2)).toBe(LAMPORTS_PER_SOL);
    });

    it('rejects single tx exceeding total limit', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solLimit(LAMPORTS_PER_SOL / 2n),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, LAMPORTS_PER_SOL),
        [sessionSigner],
        3024,
      );
    });

    it('fully depleted session blocks further spending', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solLimit(LAMPORTS_PER_SOL),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;

      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r1, LAMPORTS_PER_SOL), [sessionSigner]);
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r2, LAMPORTS_PER_SOL),
        [sessionSigner],
        3024,
      );
    });
  });

  describe('SolRecurringLimit', () => {
    it('enforces limit within window', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solRecurringLimit({
          limit: 2n * LAMPORTS_PER_SOL,
          window: 50_000n,
        }),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;

      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r1, (3n * LAMPORTS_PER_SOL) / 2n),
        [sessionSigner],
      );
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r2, LAMPORTS_PER_SOL),
        [sessionSigner],
        3025,
      );
      expect(await getBalance(ctx, r1)).toBe((3n * LAMPORTS_PER_SOL) / 2n);
    });
  });

  describe('Combined Actions', () => {
    it('whitelist + SolMaxPerTx — both enforced (under)', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
        Actions.solMaxPerTx(2_000_000n),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r1, 1_000_000n), [sessionSigner]);
      expect(await getBalance(ctx, r1)).toBe(1_000_000n);
    });

    it('whitelist + SolMaxPerTx — per-tx exceeded', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
        Actions.solMaxPerTx(500_000n),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r1, 1_000_000n),
        [sessionSigner],
        3023,
      );
    });

    it('whitelist + SolLimit — lifetime enforced', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
        Actions.solLimit(1_500_000n),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;
      await sendTx(ctx, await transferIxs(sessionSigner, sessionPda, r1, 1_000_000n), [sessionSigner]);
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r2, 1_000_000n),
        [sessionSigner],
        3024,
      );
    });

    it('SolLimit + SolMaxPerTx — stricter wins', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.solLimit(5n * LAMPORTS_PER_SOL),
        Actions.solMaxPerTx(LAMPORTS_PER_SOL / 2n),
      ]);
      const r1 = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, r1, LAMPORTS_PER_SOL),
        [sessionSigner],
        3023,
      );
    });
  });

  describe('Creation Validation', () => {
    it('whitelist + blacklist conflict rejected at creation', async () => {
      const sessionSigner = await generateKeyPairSigner();
      const currentSlot = await getSlot(ctx);
      const random = (await generateKeyPairSigner()).address;
      const { instructions: createIxs } = await client.createSession({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
        sessionKey: sessionSigner.address,
        expiresAt: currentSlot + 50_000n,
        actions: [
          Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
          Actions.programBlacklist(random),
        ],
      });
      await sendTxExpectError(ctx, createIxs, [ownerSigner], 3028);
    });
  });

  describe('Session Isolation', () => {
    it('two sessions with different limits are independent', async () => {
      const a = await createSessionWith([Actions.solLimit(1_000_000n)]);
      const b = await createSessionWith([Actions.solLimit(5_000_000n)]);

      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;

      // Deplete A.
      await sendTx(ctx, await transferIxs(a.sessionSigner, a.sessionPda, r1, 1_000_000n), [a.sessionSigner]);
      // A blocked.
      await sendTxExpectError(
        ctx,
        await transferIxs(a.sessionSigner, a.sessionPda, r1, 1n),
        [a.sessionSigner],
        3024,
      );
      // B works.
      await sendTx(ctx, await transferIxs(b.sessionSigner, b.sessionPda, r2, 3_000_000n), [b.sessionSigner]);
      expect(await getBalance(ctx, r2)).toBe(3_000_000n);
    });
  });
});
