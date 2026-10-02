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
 *   - Unlisted assets (D13): a policy with no Sol* action moves no SOL (3037),
 *     a mint no Token* action names may not leave (3038), inflows always pass
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import { getCreateAccountInstruction } from '@solana-program/system';
import {
  AccountRole,
  generateKeyPairSigner,
  getAddressEncoder,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from '@solana/kit';
import {
  Actions,
  LazorKit,
  ROLE_SPENDER,
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  createAssociatedTokenAccountIdempotentIx,
  ed25519,
  getAssociatedTokenAddress,
  serializeActions,
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

/** `ActionUnlistedSolOutflow`: SOL left and no Sol* action names it. */
const ERR_UNLISTED_SOL = 3037;
/** `ActionUnlistedTokenOutflow`: a mint left and no Token* action names it. */
const ERR_UNLISTED_TOKEN = 3038;

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
      // Deliberately unrestricted: this test exercises the actionless session.
      unrestricted: true,
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
        // Deliberately unrestricted: this test exercises the actionless session.
        unrestricted: true,
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
        // A whitelist names programs, not assets: SOL needs its own action.
        Actions.solLimit(LAMPORTS_PER_SOL),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('whitelist with no SOL action — SOL cannot leave', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
        ERR_UNLISTED_SOL,
      );
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
        Actions.solLimit(LAMPORTS_PER_SOL),
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
        Actions.solLimit(LAMPORTS_PER_SOL),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTx(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
      );
      expect(await getBalance(ctx, recipient)).toBe(1_000_000n);
    });

    it('blacklist with no SOL action — SOL cannot leave', async () => {
      const random = (await generateKeyPairSigner()).address;
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.programBlacklist(random),
      ]);
      const recipient = (await generateKeyPairSigner()).address;
      await sendTxExpectError(
        ctx,
        await transferIxs(sessionSigner, sessionPda, recipient, 1_000_000n),
        [sessionSigner],
        ERR_UNLISTED_SOL,
      );
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

  describe('Unlisted assets', () => {
    const addressEncoder = getAddressEncoder();
    let mintA: Address;
    let mintB: Address;
    let vaultA: Address;
    let vaultB: Address;
    let outsiderB: Address;

    /** SPL Token `Transfer` (3), or `MintTo` (7) with the mint first. */
    function amountIx(tag: 3 | 7, first: Address, second: Address, authority: Address, amount: bigint): Instruction {
      const data = new Uint8Array(9);
      data[0] = tag;
      new DataView(data.buffer).setBigUint64(1, amount, true);
      return {
        programAddress: TOKEN_PROGRAM_ADDRESS,
        accounts: [
          { address: first, role: AccountRole.WRITABLE },
          { address: second, role: AccountRole.WRITABLE },
          { address: authority, role: AccountRole.READONLY_SIGNER },
        ],
        data,
      };
    }
    const transferIx = (source: Address, destination: Address, owner: Address, amount: bigint) =>
      amountIx(3, source, destination, owner, amount);

    /** A fresh SPL Token mint, 0 decimals, the test payer its authority. */
    async function createMint(): Promise<Address> {
      const mint = await generateKeyPairSigner();
      const initializeMint2 = new Uint8Array(35);
      initializeMint2[0] = 20;
      initializeMint2.set(addressEncoder.encode(ctx.payer.address), 2);
      await sendTx(
        ctx,
        [
          getCreateAccountInstruction({
            payer: ctx.payer,
            newAccount: mint,
            lamports: 10_000_000n,
            space: 82n,
            programAddress: TOKEN_PROGRAM_ADDRESS,
          }),
          {
            programAddress: TOKEN_PROGRAM_ADDRESS,
            accounts: [{ address: mint.address, role: AccountRole.WRITABLE }],
            data: initializeMint2,
          },
        ],
        [mint],
      );
      return mint.address;
    }

    /** `owner`'s ATA for `mint`, created and paid by the test payer, with `amount` minted in. */
    async function fundedAta(mint: Address, owner: Address, amount: bigint): Promise<Address> {
      const ata = await getAssociatedTokenAddress(mint, owner, TOKEN_PROGRAM_ADDRESS);
      const ixs: Instruction[] = [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata,
          owner,
          mint,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
      ];
      if (amount > 0n) ixs.push(amountIx(7, mint, ata, ctx.payer.address, amount));
      await sendTx(ctx, ixs);
      return ata;
    }

    async function tokenAmount(account: Address): Promise<bigint> {
      const { value } = await ctx.rpc
        .getAccountInfo(account, { commitment: 'confirmed', encoding: 'base64' })
        .send();
      const data = Buffer.from(value!.data[0], 'base64');
      return data.readBigUInt64LE(64);
    }

    async function executeIxs(signer: Parameters<LazorKit['execute']>[0]['signer'], instructions: Instruction[]) {
      const { instructions: ixs } = await client.execute({
        payer: ctx.payer.address,
        walletPda,
        signer,
        instructions,
      });
      return ixs;
    }

    beforeAll(async () => {
      mintA = await createMint();
      mintB = await createMint();
      vaultA = await fundedAta(mintA, vaultPda, 1_000_000n);
      vaultB = await fundedAta(mintB, vaultPda, 1_000_000n);
      outsiderB = await fundedAta(mintB, (await generateKeyPairSigner()).address, 0n);
    });

    it('TokenLimit(A) — moving A is charged, moving B is refused', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.tokenLimit({ mint: mintA, remaining: 1_000n }),
        Actions.programWhitelist(TOKEN_PROGRAM_ADDRESS),
      ]);
      const outsiderA = await fundedAta(mintA, (await generateKeyPairSigner()).address, 0n);
      const signer = session(sessionPda, sessionSigner.address);

      await sendTx(ctx, await executeIxs(signer, [transferIx(vaultA, outsiderA, vaultPda, 400n)]), [sessionSigner]);
      expect(await tokenAmount(outsiderA)).toBe(400n);

      const before = await tokenAmount(vaultB);
      await sendTxExpectError(
        ctx,
        await executeIxs(signer, [transferIx(vaultB, outsiderB, vaultPda, 1n)]),
        [sessionSigner],
        ERR_UNLISTED_TOKEN,
      );
      expect(await tokenAmount(vaultB)).toBe(before);
    });

    it('an inflow of an unlisted mint passes', async () => {
      const { sessionSigner, sessionPda } = await createSessionWith([
        Actions.tokenLimit({ mint: mintA, remaining: 1_000n }),
        Actions.programWhitelist(TOKEN_PROGRAM_ADDRESS),
      ]);
      const sessionB = await fundedAta(mintB, sessionSigner.address, 250n);
      const before = await tokenAmount(vaultB);

      // The session key signs for its own account; the vault receives.
      await sendTx(
        ctx,
        await executeIxs(session(sessionPda, sessionSigner.address), [
          transferIx(sessionB, vaultB, sessionSigner.address, 250n),
        ]),
        [sessionSigner],
      );
      expect(await tokenAmount(vaultB)).toBe(before + 250n);
    });

    it('a Delegate whose policy names only SOL cannot move a token', async () => {
      const delegate = await generateKeyPairSigner();
      const added = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
        newAuthority: { type: 'ed25519', publicKey: delegate.address },
        role: ROLE_SPENDER,
        policy: serializeActions([
          Actions.solLimit(1_000_000n),
          Actions.programWhitelist(TOKEN_PROGRAM_ADDRESS),
        ]),
      });
      await sendTx(ctx, added.instructions, [ownerSigner]);

      await sendTxExpectError(
        ctx,
        await executeIxs(ed25519(delegate.address, added.newAuthorityPda), [
          transferIx(vaultB, outsiderB, vaultPda, 1n),
        ]),
        [delegate],
        ERR_UNLISTED_TOKEN,
      );
    });
  });
});
