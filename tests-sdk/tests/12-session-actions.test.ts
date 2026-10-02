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
 * - Unlisted assets (D13): a policy with no Sol* action moves no SOL (3037),
 *   a mint no Token* action names may not leave (3038), inflows always pass
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
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
  ROLE_SPENDER,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentIx,
  ed25519,
  getAssociatedTokenAddress,
  serializeActions,
  session,
  Actions,
  type SessionAction,
} from '../../sdk/sdk-legacy/src';

/** `ActionUnlistedSolOutflow`: SOL left and no Sol* action names it. */
const ERR_UNLISTED_SOL = 3037;
/** `ActionUnlistedTokenOutflow`: a mint left and no Token* action names it. */
const ERR_UNLISTED_TOKEN = 3038;

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
      // Deliberately unrestricted: this test exercises the actionless session.
      unrestricted: true,
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
          // Deliberately unrestricted: this test exercises the actionless session.
          unrestricted: true,
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
        // A whitelist names programs, not assets: SOL needs its own action.
        Actions.solLimit(BigInt(LAMPORTS_PER_SOL)),
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

    it('whitelist with no SOL action — SOL cannot leave', async () => {
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

      await sendTxExpectError(ctx, ixs, [sessionKp], ERR_UNLISTED_SOL);
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
        Actions.solLimit(BigInt(LAMPORTS_PER_SOL)),
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
        Actions.solLimit(BigInt(LAMPORTS_PER_SOL)),
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

    it('blacklist with no SOL action — SOL cannot leave', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.programBlacklist(Keypair.generate().publicKey),
      ]);
      const recipient = Keypair.generate().publicKey;
      const ixs = await executeTransfer(
        sessionKp,
        sessionPda,
        recipient,
        1_000_000,
      );

      await sendTxExpectError(ctx, ixs, [sessionKp], ERR_UNLISTED_SOL);
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

  // ═══════════════════════════════════════════════════════════════════
  // UNLISTED ASSETS (D13)
  // ═══════════════════════════════════════════════════════════════════

  describe('Unlisted assets', () => {
    let mintA: PublicKey;
    let mintB: PublicKey;
    let vaultA: PublicKey;
    let vaultB: PublicKey;
    let outsiderB: PublicKey;

    // SPL Token instructions, by hand: sdk-legacy has no spl-token dependency.
    function initializeMint2Ix(mint: PublicKey, authority: PublicKey): TransactionInstruction {
      const data = Buffer.alloc(35);
      data[0] = 20; // InitializeMint2
      data[1] = 0; // decimals
      authority.toBuffer().copy(data, 2);
      data[34] = 0; // no freeze authority
      return new TransactionInstruction({
        programId: TOKEN_PROGRAM_ID,
        keys: [{ pubkey: mint, isSigner: false, isWritable: true }],
        data,
      });
    }

    function amountIx(
      tag: number,
      first: PublicKey,
      second: PublicKey,
      authority: PublicKey,
      amount: bigint,
    ): TransactionInstruction {
      const data = Buffer.alloc(9);
      data[0] = tag;
      data.writeBigUInt64LE(amount, 1);
      return new TransactionInstruction({
        programId: TOKEN_PROGRAM_ID,
        keys: [
          { pubkey: first, isSigner: false, isWritable: true },
          { pubkey: second, isSigner: false, isWritable: true },
          { pubkey: authority, isSigner: true, isWritable: false },
        ],
        data,
      });
    }
    /** `Transfer` (3): source, destination, owner. */
    const transferIx = (source: PublicKey, destination: PublicKey, owner: PublicKey, amount: bigint) =>
      amountIx(3, source, destination, owner, amount);
    /** `MintTo` (7): mint, destination, mint authority. */
    const mintToIx = (mint: PublicKey, destination: PublicKey, amount: bigint) =>
      amountIx(7, mint, destination, ctx.payer.publicKey, amount);

    async function createMint(): Promise<PublicKey> {
      const mint = Keypair.generate();
      const lamports = await ctx.connection.getMinimumBalanceForRentExemption(82);
      await sendTx(
        ctx,
        [
          SystemProgram.createAccount({
            fromPubkey: ctx.payer.publicKey,
            newAccountPubkey: mint.publicKey,
            lamports,
            space: 82,
            programId: TOKEN_PROGRAM_ID,
          }),
          initializeMint2Ix(mint.publicKey, ctx.payer.publicKey),
        ],
        [mint],
      );
      return mint.publicKey;
    }

    /** `owner`'s ATA for `mint`, created and paid by the test payer, with `amount` minted in. */
    async function fundedAta(mint: PublicKey, owner: PublicKey, amount: bigint): Promise<PublicKey> {
      const ata = getAssociatedTokenAddress(mint, owner, TOKEN_PROGRAM_ID);
      const ixs = [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.publicKey,
          ata,
          owner,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
        }),
      ];
      if (amount > 0n) ixs.push(mintToIx(mint, ata, amount));
      await sendTx(ctx, ixs);
      return ata;
    }

    async function tokenAmount(account: PublicKey): Promise<bigint> {
      const info = await ctx.connection.getAccountInfo(account, 'confirmed');
      return info!.data.readBigUInt64LE(64);
    }

    beforeAll(async () => {
      mintA = await createMint();
      mintB = await createMint();
      vaultA = await fundedAta(mintA, vaultPda, 1_000_000n);
      vaultB = await fundedAta(mintB, vaultPda, 1_000_000n);
      outsiderB = await fundedAta(mintB, Keypair.generate().publicKey, 0n);
    });

    async function executeTokenTransfer(
      signer: ReturnType<typeof session>,
      source: PublicKey,
      destination: PublicKey,
      owner: PublicKey,
      amount: bigint,
    ) {
      const { instructions } = await client.execute({
        payer: ctx.payer.publicKey,
        walletPda,
        signer,
        instructions: [transferIx(source, destination, owner, amount)],
      });
      return instructions;
    }

    it('TokenLimit(A) — moving A is charged, moving B is refused', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.tokenLimit({ mint: mintA, remaining: 1_000n }),
        Actions.programWhitelist(TOKEN_PROGRAM_ID),
      ]);
      const outsiderA = await fundedAta(mintA, Keypair.generate().publicKey, 0n);
      const signer = session(sessionPda, sessionKp.publicKey);

      await sendTx(
        ctx,
        await executeTokenTransfer(signer, vaultA, outsiderA, vaultPda, 400n),
        [sessionKp],
      );
      expect(await tokenAmount(outsiderA)).toBe(400n);

      const before = await tokenAmount(vaultB);
      await sendTxExpectError(
        ctx,
        await executeTokenTransfer(signer, vaultB, outsiderB, vaultPda, 1n),
        [sessionKp],
        ERR_UNLISTED_TOKEN,
      );
      expect(await tokenAmount(vaultB)).toBe(before);
    });

    it('an inflow of an unlisted mint passes', async () => {
      const { sessionKp, sessionPda } = await createSessionWith([
        Actions.tokenLimit({ mint: mintA, remaining: 1_000n }),
        Actions.programWhitelist(TOKEN_PROGRAM_ID),
      ]);
      const sessionB = await fundedAta(mintB, sessionKp.publicKey, 250n);
      const before = await tokenAmount(vaultB);

      // The session key signs for its own account; the vault receives.
      await sendTx(
        ctx,
        await executeTokenTransfer(
          session(sessionPda, sessionKp.publicKey),
          sessionB,
          vaultB,
          sessionKp.publicKey,
          250n,
        ),
        [sessionKp],
      );
      expect(await tokenAmount(vaultB)).toBe(before + 250n);
    });

    it('a Delegate whose policy names only SOL cannot move a token', async () => {
      const delegateKp = Keypair.generate();
      const { instructions, newAuthorityPda } = await client.addAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        adminSigner: ed25519(ownerKp.publicKey, ownerAuthPda),
        newAuthority: { type: 'ed25519', publicKey: delegateKp.publicKey },
        role: ROLE_SPENDER,
        policy: serializeActions([
          Actions.solLimit(1_000_000n),
          Actions.programWhitelist(TOKEN_PROGRAM_ID),
        ]),
      });
      await sendTx(ctx, instructions, [ownerKp]);

      const { instructions: executeIxs } = await client.execute({
        payer: ctx.payer.publicKey,
        walletPda,
        signer: ed25519(delegateKp.publicKey, newAuthorityPda),
        instructions: [transferIx(vaultB, outsiderB, vaultPda, 1n)],
      });
      await sendTxExpectError(ctx, executeIxs, [delegateKp], ERR_UNLISTED_TOKEN);
    });
  });
});
