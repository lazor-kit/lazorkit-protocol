/**
 * H1 fix coverage — session+actions vault/token invariant enforcement.
 *
 * Without this fix, a session with `ProgramWhitelist: [SystemProgram]` could
 * craft `System::Assign(vault, attacker)` via Execute. The lamport-based
 * limits wouldn't detect the zero-lamport mutation; vault's owner would
 * silently change to the attacker's program; attacker drains in a future tx.
 *
 * The program now snapshots vault.owner() and vault.data.len() before the
 * session-CPI loop and re-verifies them after. Any mutation is rejected with
 * error 3030 (SessionVaultOwnerChanged) or 3031 (SessionVaultDataLenChanged).
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
import { LazorKitClient, ed25519, session, Actions } from '../../sdk/sdk-legacy/src';

/** Builds a raw `System::Assign { new_owner }` instruction targeting `target`. */
function systemAssignIx(target: PublicKey, newOwner: PublicKey): TransactionInstruction {
  const data = Buffer.alloc(4 + 32);
  data.writeUInt32LE(1, 0); // System instruction discriminator 1 = Assign
  newOwner.toBuffer().copy(data, 4);
  return new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [{ pubkey: target, isSigner: true, isWritable: true }],
    data,
  });
}

/** Builds a raw `System::Allocate { space }` instruction targeting `target`. */
function systemAllocateIx(target: PublicKey, space: bigint): TransactionInstruction {
  const data = Buffer.alloc(4 + 8);
  data.writeUInt32LE(8, 0); // System instruction discriminator 8 = Allocate
  data.writeBigUInt64LE(space, 4);
  return new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [{ pubkey: target, isSigner: true, isWritable: true }],
    data,
  });
}

describe('H1 — Session vault invariants', () => {
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
    const result = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
    });
    walletPda = result.walletPda;
    vaultPda = result.vaultPda;
    ownerAuthPda = result.authorityPda;
    await sendTx(ctx, result.instructions);

    // Fund the vault so it's a valid System-owned account with data_len=0
    const sig = await ctx.connection.requestAirdrop(
      vaultPda,
      5 * LAMPORTS_PER_SOL,
    );
    await ctx.connection.confirmTransaction(sig, 'confirmed');
  });

  async function createLockedDownSession(): Promise<{
    sessionKp: Keypair;
    sessionPda: PublicKey;
  }> {
    const sessionKp = Keypair.generate();
    const currentSlot = await getSlot(ctx);
    const { instructions, sessionPda } = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda,
      adminSigner: ed25519(ownerKp.publicKey, ownerAuthPda),
      sessionKey: sessionKp.publicKey,
      expiresAt: currentSlot + 9000n,
      actions: [
        // Realistic "SOL-only spender" config:
        //   - Session can only call System Program
        //   - Max 0.1 SOL per tx
        //   - 1 SOL lifetime cap
        Actions.programWhitelist(SystemProgram.programId),
        Actions.solMaxPerTx(100_000_000n),
        Actions.solLimit(1_000_000_000n),
      ],
    });
    await sendTx(ctx, instructions, [ownerKp]);
    return { sessionKp, sessionPda };
  }

  // ── Baseline: legitimate transfer still works ─────────────────────

  it('allows a normal SOL transfer via the locked-down session', async () => {
    const { sessionKp, sessionPda } = await createLockedDownSession();

    const recipient = Keypair.generate().publicKey;
    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: session(sessionPda, sessionKp.publicKey),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipient,
          lamports: LAMPORTS_PER_SOL, // within the 0.1 SOL/tx... wait, 1 SOL > 100M limit
        }),
      ],
    });
    // SolMaxPerTx is 100M, so a full SOL should fail → use a smaller value
    // (reconstruct with a value under the limit + rent-exempt for the recipient)
    const underLimitIx = SystemProgram.transfer({
      fromPubkey: vaultPda,
      toPubkey: recipient,
      lamports: 90_000_000, // under 100M per-tx AND above rent-exempt
    });
    const { instructions: okIxs } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: session(sessionPda, sessionKp.publicKey),
      instructions: [underLimitIx],
    });

    const balBefore = await ctx.connection.getBalance(recipient);
    await sendTx(ctx, okIxs, [sessionKp]);
    const balAfter = await ctx.connection.getBalance(recipient);
    expect(balAfter - balBefore).toBe(90_000_000);
  });

  // ── H1 attacks must be rejected ──────────────────────────────────

  it('rejects System::Assign on vault (error 3030 SessionVaultOwnerChanged)', async () => {
    const { sessionKp, sessionPda } = await createLockedDownSession();

    // Attacker program pubkey (any non-System pubkey works; it's just the
    // target new owner to prove the mutation succeeded if unguarded).
    const attackerProgram = Keypair.generate().publicKey;

    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: session(sessionPda, sessionKp.publicKey),
      instructions: [
        // SystemProgram is in the whitelist, so the pre-action check passes.
        // This would succeed without the H1 fix.
        systemAssignIx(vaultPda, attackerProgram),
      ],
    });

    await sendTxExpectError(ctx, instructions, [sessionKp], 3030);
  });

  it('rejects System::Allocate on vault (error 3031 SessionVaultDataLenChanged)', async () => {
    const { sessionKp, sessionPda } = await createLockedDownSession();

    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: session(sessionPda, sessionKp.publicKey),
      instructions: [
        // Allocate 1 KB on the vault. Whitelist-passes (System Program) but
        // changes data_len from 0 → 1024, triggering the invariant check.
        systemAllocateIx(vaultPda, 1024n),
      ],
    });

    await sendTxExpectError(ctx, instructions, [sessionKp], 3031);
  });

  // ── Sanity: vault state is still pristine after all attack attempts ──

  it('vault owner and data_len remain unchanged after attack attempts', async () => {
    const info = await ctx.connection.getAccountInfo(vaultPda);
    expect(info).not.toBeNull();
    expect(info!.owner.toBase58()).toBe(SystemProgram.programId.toBase58());
    expect(info!.data.length).toBe(0);
  });
});
