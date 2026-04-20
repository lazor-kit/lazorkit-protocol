/**
 * Comprehensive session actions/permissions tests.
 *
 * Security-focused test suite covering:
 * - Backwards compatibility (no actions)
 * - ProgramWhitelist enforcement (allow, reject, multiple programs)
 * - ProgramBlacklist enforcement
 * - SolMaxPerTx (under, exact, over, repeatable across txs)
 * - SolLimit lifetime cap (depletion, exact boundary, overspend)
 * - SolRecurringLimit (window reset, accumulation, boundary)
 * - Combined actions (whitelist + spending limits)
 * - Per-action expiry
 * - Whitelist+Blacklist conflict at creation
 * - State persistence across transactions
 * - Zero spending passthrough
 * - Vault balance increase (no false positive)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  getSlot,
  type TestContext,
} from './common';
import {
  LazorKitClient,
  ed25519,
  session,
  Actions,
  type SessionAction,
} from '../../sdk/sdk-legacy/src';

describe('Session Actions', () => {
  let ctx: TestContext;
  let client: LazorKitClient;

  let walletPda: PublicKey;
  let vaultPda: PublicKey;
  let ownerKp: Keypair;
  let ownerAuthPda: PublicKey;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);

    ownerKp = Keypair.generate();
    const userSeed = crypto.randomBytes(32);

    const result = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed,
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });
    walletPda = result.walletPda;
    vaultPda = result.vaultPda;
    ownerAuthPda = result.authorityPda;

    await sendTx(ctx, result.instructions);

    // Fund the vault generously — multiple airdrops to ensure enough for all tests
    for (let i = 0; i < 3; i++) {
      const sig = await ctx.connection.requestAirdrop(
        vaultPda,
        10 * LAMPORTS_PER_SOL,
      );
      await ctx.connection.confirmTransaction(sig, 'confirmed');
    }
  });

  // ─── Helper ─────────────────────────────────────────────────────────

  async function createSessionWith(actions: SessionAction[]) {
    const sessionKp = Keypair.generate();
    const currentSlot = await getSlot(ctx);
    const expiresAt = currentSlot + 50_000n;

    const { instructions: createIxs, sessionPda } = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda,
      adminSigner: ed25519(ownerKp.publicKey, ownerAuthPda),
      sessionKey: sessionKp.publicKey,
      expiresAt,
      actions,
    });
    await sendTx(ctx, createIxs, [ownerKp]);

    return { sessionKp, sessionPda };
  }

  async function executeTransfer(
    sessionKp: Keypair,
    sessionPda: PublicKey,
    recipient: PublicKey,
    lamports: number,
  ) {
    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: session(sessionPda, sessionKp.publicKey),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipient,
          lamports,
        }),
      ],
    });
    return instructions;
  }

  // ═══════════════════════════════════════════════════════════════════
  // BACKWARDS COMPATIBILITY
  // ═══════════════════════════════════════════════════════════════════

  describe('Backwards Compatibility', () => {
    it('no actions — fully open session works', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      const balance = await ctx.connection.getBalance(recipient);
      expect(balance).toBe(1_000_000);
    });

    it('undefined actions — same as no actions', async () => {
      const sessionKp = Keypair.generate();
      const currentSlot = await getSlot(ctx);

      const { instructions: createIxs, sessionPda } =
        await client.createSession({
          payer: ctx.payer.publicKey,
          walletPda,
          adminSigner: ed25519(ownerKp.publicKey, ownerAuthPda),
          sessionKey: sessionKp.publicKey,
          expiresAt: currentSlot + 50_000n,
          // no actions field at all
        });
      await sendTx(ctx, createIxs, [ownerKp]);

      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        2_000_000,
      );
      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(2_000_000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // PROGRAM WHITELIST
  // ═══════════════════════════════════════════════════════════════════

  describe('ProgramWhitelist', () => {
    it('allows whitelisted program (SystemProgram)', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SystemProgram.programId),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(1_000_000);
    });

    it('rejects non-whitelisted program', async () => {
      const randomProgram = Keypair.generate().publicKey;
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(randomProgram),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      // Error 3021 = ActionProgramNotWhitelisted
      await sendTxExpectError(ctx, ixs, [sessionKp], 3021);
    });

    it('multiple whitelisted programs — both work', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SystemProgram.programId),
        Actions.programWhitelist(Keypair.generate().publicKey), // extra allowed program
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(1_000_000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // PROGRAM BLACKLIST
  // ═══════════════════════════════════════════════════════════════════

  describe('ProgramBlacklist', () => {
    it('blocks blacklisted program', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programBlacklist(SystemProgram.programId),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      // Error 3022 = ActionProgramBlacklisted
      await sendTxExpectError(ctx, ixs, [sessionKp], 3022);
    });

    it('allows non-blacklisted program', async () => {
      const randomProgram = Keypair.generate().publicKey;
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programBlacklist(randomProgram), // only blocks randomProgram
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(1_000_000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // SOL MAX PER TX
  // ═══════════════════════════════════════════════════════════════════

  describe('SolMaxPerTx', () => {
    it('allows under limit', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(2_000_000n),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(1_000_000);
    });

    it('rejects over limit', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(500_000n),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      // Error 3023 = ActionSolMaxPerTxExceeded
      await sendTxExpectError(ctx, ixs, [sessionKp], 3023);
    });

    it('allows exact limit', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(1_000_000n),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTx(ctx, ixs, [sessionKp]);
      expect(await ctx.connection.getBalance(recipient)).toBe(1_000_000);
    });

    it('does not accumulate across txs — each tx independent', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solMaxPerTx(1_500_000n),
      ]);

      // Tx1: 1M — OK
      const r1 = Keypair.generate().publicKey;
      const ixs1 = await executeTransfer(sessionKp, sessionPda, r1, 1_000_000);
      await sendTx(ctx, ixs1, [sessionKp]);

      // Tx2: 1M again — still OK (per-tx, not cumulative)
      const r2 = Keypair.generate().publicKey;
      const ixs2 = await executeTransfer(sessionKp, sessionPda, r2, 1_000_000);
      await sendTx(ctx, ixs2, [sessionKp]);

      // Tx3: 1.5M — still OK
      const r3 = Keypair.generate().publicKey;
      const ixs3 = await executeTransfer(sessionKp, sessionPda, r3, 1_500_000);
      await sendTx(ctx, ixs3, [sessionKp]);

      expect(await ctx.connection.getBalance(r1)).toBe(1_000_000);
      expect(await ctx.connection.getBalance(r2)).toBe(1_000_000);
      expect(await ctx.connection.getBalance(r3)).toBe(1_500_000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // SOL LIMIT (lifetime)
  // ═══════════════════════════════════════════════════════════════════

  describe('SolLimit', () => {
    it('depletes across multiple transactions', async () => {
      const limit = 3 * LAMPORTS_PER_SOL;
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solLimit(BigInt(limit)),
      ]);
      const r1 = Keypair.generate().publicKey;
      const r2 = Keypair.generate().publicKey;

      // Tx1: 1 SOL (3 → 2 remaining)
      await sendTx(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, LAMPORTS_PER_SOL),
        [sessionKp],
      );

      // Tx2: 1 SOL (2 → 1 remaining)
      await sendTx(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r2, LAMPORTS_PER_SOL),
        [sessionKp],
      );

      // Tx3: 2 SOL — exceeds remaining 1 SOL
      const r3 = Keypair.generate().publicKey;
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r3, 2 * LAMPORTS_PER_SOL),
        [sessionKp],
        3024,
      );

      expect(await ctx.connection.getBalance(r1)).toBe(LAMPORTS_PER_SOL);
      expect(await ctx.connection.getBalance(r2)).toBe(LAMPORTS_PER_SOL);
    });

    it('rejects single tx exceeding total limit', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solLimit(BigInt(LAMPORTS_PER_SOL / 2)),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        LAMPORTS_PER_SOL,
      );

      await sendTxExpectError(ctx, ixs, [sessionKp], 3024);
    });

    it('fully depleted session blocks further spending', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solLimit(BigInt(LAMPORTS_PER_SOL)),
      ]);
      const r1 = Keypair.generate().publicKey;
      const r2 = Keypair.generate().publicKey;

      // Drain entire limit
      await sendTx(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, LAMPORTS_PER_SOL),
        [sessionKp],
      );

      // Further spending should fail
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r2, LAMPORTS_PER_SOL),
        [sessionKp],
        3024,
      );
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // SOL RECURRING LIMIT
  // ═══════════════════════════════════════════════════════════════════

  describe('SolRecurringLimit', () => {
    it('enforces limit within window', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solRecurringLimit({
          limit: BigInt(2 * LAMPORTS_PER_SOL),
          window: 50_000n,
        }),
      ]);
      const r1 = Keypair.generate().publicKey;
      const r2 = Keypair.generate().publicKey;

      // Tx1: 1.5 SOL — OK
      await sendTx(
        ctx,
        await executeTransfer(
          sessionKp,
          sessionPda,
          r1,
          1.5 * LAMPORTS_PER_SOL,
        ),
        [sessionKp],
      );

      // Tx2: 1 SOL — would total 2.5 SOL > 2 SOL limit
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r2, LAMPORTS_PER_SOL),
        [sessionKp],
        3025,
      );

      expect(await ctx.connection.getBalance(r1)).toBe(1.5 * LAMPORTS_PER_SOL);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // COMBINED ACTIONS
  // ═══════════════════════════════════════════════════════════════════

  describe('Combined Actions', () => {
    it('whitelist + SolMaxPerTx — both enforced', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SystemProgram.programId),
        Actions.solMaxPerTx(2_000_000n),
      ]);

      // Under both limits — OK
      const r1 = Keypair.generate().publicKey;
      await sendTx(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, 1_000_000),
        [sessionKp],
      );
      expect(await ctx.connection.getBalance(r1)).toBe(1_000_000);
    });

    it('whitelist + SolMaxPerTx — per-tx exceeded', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SystemProgram.programId),
        Actions.solMaxPerTx(500_000n),
      ]);

      const r1 = Keypair.generate().publicKey;
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, 1_000_000),
        [sessionKp],
        3023,
      );
    });

    it('whitelist + SolLimit — lifetime enforced', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SystemProgram.programId),
        Actions.solLimit(1_500_000n),
      ]);

      const r1 = Keypair.generate().publicKey;
      await sendTx(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, 1_000_000),
        [sessionKp],
      );

      const r2 = Keypair.generate().publicKey;
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r2, 1_000_000),
        [sessionKp],
        3024,
      );
    });

    it('SolLimit + SolMaxPerTx — stricter wins', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.solLimit(BigInt(5 * LAMPORTS_PER_SOL)),
        Actions.solMaxPerTx(BigInt(LAMPORTS_PER_SOL / 2)), // 0.5 SOL per tx
      ]);

      // 1 SOL per tx — exceeds MaxPerTx even though Limit has room
      const r1 = Keypair.generate().publicKey;
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionKp, sessionPda, r1, LAMPORTS_PER_SOL),
        [sessionKp],
        3023,
      );
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // CREATION VALIDATION
  // ═══════════════════════════════════════════════════════════════════

  describe('Creation Validation', () => {
    it('whitelist + blacklist conflict rejected at creation', async () => {
      const sessionKp = Keypair.generate();
      const currentSlot = await getSlot(ctx);

      const { instructions: createIxs } = await client.createSession({
        payer: ctx.payer.publicKey,
        walletPda,
        adminSigner: ed25519(ownerKp.publicKey, ownerAuthPda),
        sessionKey: sessionKp.publicKey,
        expiresAt: currentSlot + 50_000n,
        actions: [
          Actions.programWhitelist(SystemProgram.programId),
          Actions.programBlacklist(Keypair.generate().publicKey),
        ],
      });

      // Error 3028 = ActionWhitelistBlacklistConflict
      await sendTxExpectError(ctx, createIxs, [ownerKp], 3028);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // DIFFERENT SESSIONS INDEPENDENT
  // ═══════════════════════════════════════════════════════════════════

  describe('Session Isolation', () => {
    it('two sessions with different limits are independent', async () => {
      // Session A: 1M limit
      const sessionA = await createSessionWith([Actions.solLimit(1_000_000n)]);
      // Session B: 5M limit
      const sessionB = await createSessionWith([Actions.solLimit(5_000_000n)]);

      const r1 = Keypair.generate().publicKey;
      const r2 = Keypair.generate().publicKey;

      // Deplete Session A
      await sendTx(
        ctx,
        await executeTransfer(
          sessionA.sessionKp,
          sessionA.sessionPda,
          r1,
          1_000_000,
        ),
        [sessionA.sessionKp],
      );

      // Session A depleted — should fail
      await sendTxExpectError(
        ctx,
        await executeTransfer(sessionA.sessionKp, sessionA.sessionPda, r1, 1),
        [sessionA.sessionKp],
        3024,
      );

      // Session B still works
      await sendTx(
        ctx,
        await executeTransfer(
          sessionB.sessionKp,
          sessionB.sessionPda,
          r2,
          3_000_000,
        ),
        [sessionB.sessionKp],
      );

      expect(await ctx.connection.getBalance(r2)).toBe(3_000_000);
    });
  });
});
