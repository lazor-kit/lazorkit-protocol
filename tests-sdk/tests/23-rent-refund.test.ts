/**
 * Where a closed account's rent goes, on a live validator.
 *
 * An authority and a session record the account that paid their rent (layout
 * revision 2), and RevokeSession, CloseExpiredSession, RemoveAuthority and
 * TransferOwnership refund only to it — here the suite's payer, standing in
 * for a relayer that sponsored them — whoever signs or pays for the close. The
 * client fills that destination in; asked for another, it refuses, and the
 * program refuses a hand-built instruction with 3039.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { Keypair, PublicKey, Transaction, sendAndConfirmTransaction, type Signer, type TransactionInstruction } from '@solana/web3.js';
import * as crypto from 'crypto';
import { setupTest, sendTxExpectError, getUnixTime, waitForUnixTime, type TestContext } from './common';
import {
  LazorKitClient,
  RefundDestinationMismatchError,
  ROLE_ADMIN,
  ed25519,
} from '../../sdk/sdk-legacy/src';
import { createRemoveAuthorityIx } from '../../sdk/sdk-legacy/src/utils/instructions';
import { AuthorityAccount, SessionAccount } from '../../sdk/sdk-legacy/src/utils/accounts';

const ERR_REFUND_DESTINATION_MISMATCH = 3039;

/** Send with `feePayer` paying, so the sponsor's balance moves by the rent alone. */
async function sendAs(ctx: TestContext, feePayer: Keypair, ixs: TransactionInstruction[], signers: Signer[] = []) {
  const tx = new Transaction();
  for (const ix of ixs) tx.add(ix);
  return sendAndConfirmTransaction(ctx.connection, tx, [feePayer, ...signers], { commitment: 'confirmed' });
}

describe('rent refunds go back to the sponsor', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let owner: Keypair;
  let walletPda: PublicKey;
  let ownerAuthorityPda: PublicKey;

  const balance = (k: PublicKey) => ctx.connection.getBalance(k, 'confirmed');
  const gone = async (k: PublicKey) => (await ctx.connection.getAccountInfo(k, 'confirmed')) === null;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    owner = Keypair.generate();
    const created = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    walletPda = created.walletPda;
    ownerAuthorityPda = created.authorityPda;
    await sendAs(ctx, ctx.payer, created.instructions);
    const sig = await ctx.connection.requestAirdrop(owner.publicKey, 1_000_000_000);
    await ctx.connection.confirmTransaction(sig, 'confirmed');
  });

  async function sponsoredSession(secondsLeft = 3_600n): Promise<PublicKey> {
    const { instructions, sessionPda } = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda,
      adminSigner: ed25519(owner.publicKey, ownerAuthorityPda),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: (await getUnixTime(ctx)) + secondsLeft,
      unrestricted: true,
    });
    await sendAs(ctx, ctx.payer, instructions, [owner]);
    return sessionPda;
  }

  it('RevokeSession, paid for by the Owner', async () => {
    const pda = await sponsoredSession();
    const s = await SessionAccount.fromAccountAddress(ctx.connection, pda);
    expect(s.rentPayer?.equals(ctx.payer.publicKey)).toBe(true);
    const rent = await balance(pda);
    const before = await balance(ctx.payer.publicKey);

    await expect(
      client.revokeSession({
        payer: owner.publicKey,
        walletPda,
        adminSigner: ed25519(owner.publicKey, ownerAuthorityPda),
        sessionPda: pda,
        refundDestination: owner.publicKey,
      }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);

    const { instructions } = await client.revokeSession({
      payer: owner.publicKey,
      walletPda,
      adminSigner: ed25519(owner.publicKey, ownerAuthorityPda),
      sessionPda: pda,
    });
    await sendAs(ctx, owner, instructions);
    expect(await gone(pda)).toBe(true);
    expect(await balance(ctx.payer.publicKey)).toBe(before + rent);
  });

  it('CloseExpiredSession, called by a stranger', async () => {
    const pda = await sponsoredSession(2n);
    const rent = await balance(pda);
    const s = await SessionAccount.fromAccountAddress(ctx.connection, pda);
    await waitForUnixTime(ctx, s.expiresAt);
    const stranger = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(stranger.publicKey, 100_000_000);
    await ctx.connection.confirmTransaction(sig, 'confirmed');

    const before = await balance(ctx.payer.publicKey);
    const { instructions } = await client.closeExpiredSession({ caller: stranger.publicKey, sessionPda: pda });
    await sendAs(ctx, stranger, instructions);
    expect(await gone(pda)).toBe(true);
    expect(await balance(ctx.payer.publicKey)).toBe(before + rent);
  });

  it('RemoveAuthority: the client fills the sponsor in, the program refuses anyone else', async () => {
    const admin = Keypair.generate();
    const added = await client.addAuthority({
      payer: ctx.payer.publicKey,
      walletPda,
      adminSigner: ed25519(owner.publicKey, ownerAuthorityPda),
      newAuthority: { type: 'ed25519', publicKey: admin.publicKey },
      role: ROLE_ADMIN,
    });
    await sendAs(ctx, ctx.payer, added.instructions, [owner]);
    const target = added.newAuthorityPda;
    const a = await AuthorityAccount.fromAccountAddress(ctx.connection, target);
    expect(a.rentPayer?.equals(ctx.payer.publicKey)).toBe(true);

    const handBuilt = createRemoveAuthorityIx({
      payer: ctx.payer.publicKey,
      walletPda,
      adminAuthorityPda: ownerAuthorityPda,
      targetAuthorityPda: target,
      refundDestination: owner.publicKey,
      authorizerSigner: owner.publicKey,
      programId: client.programId,
    });
    await sendTxExpectError(ctx, [handBuilt], [owner], ERR_REFUND_DESTINATION_MISMATCH);

    const rent = await balance(target);
    const before = await balance(ctx.payer.publicKey);
    const { instructions } = await client.removeAuthority({
      payer: owner.publicKey,
      walletPda,
      adminSigner: ed25519(owner.publicKey, ownerAuthorityPda),
      targetAuthorityPda: target,
    });
    await sendAs(ctx, owner, instructions);
    expect(await gone(target)).toBe(true);
    expect(await balance(ctx.payer.publicKey)).toBe(before + rent);
  });

  it('TransferOwnership: the replaced Owner’s rent goes to its sponsor', async () => {
    const rent = await balance(ownerAuthorityPda);
    const before = await balance(ctx.payer.publicKey);
    const next = Keypair.generate();
    const { instructions, newOwnerAuthorityPda } = await client.transferOwnership({
      payer: owner.publicKey,
      walletPda,
      ownerSigner: ed25519(owner.publicKey, ownerAuthorityPda),
      newOwner: { type: 'ed25519', publicKey: next.publicKey },
    });
    await sendAs(ctx, owner, instructions);
    expect(await gone(ownerAuthorityPda)).toBe(true);
    expect(await balance(ctx.payer.publicKey)).toBe(before + rent);
    const n = await AuthorityAccount.fromAccountAddress(ctx.connection, newOwnerAuthorityPda);
    expect(n.rentPayer?.equals(owner.publicKey)).toBe(true);
  });
});
