/**
 * RevokeSession and CloseExpiredSession through the client, and where the rent
 * goes.
 *
 * A session records the account that paid its rent (layout revision 2) and
 * every close refunds only to it — here the suite's payer, standing in for a
 * relayer that sponsored the session — whoever signs or pays for the close.
 * The client fills that destination in; asked for another, it refuses, and
 * the program refuses a hand-built instruction with 3039.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import { generateKeyPairSigner, type Address, type KeyPairSigner } from '@solana/kit';
import {
  LazorKit,
  RefundDestinationMismatchError,
  decodeSessionAccount,
  ed25519,
  secp256r1,
} from '@lazorkit/sdk';
import { createRevokeSessionIx } from '../../sdk/sdk-kit/src/instructions/builders.js';
import {
  airdrop,
  getBalance,
  getUnixTime,
  makeClient,
  sendTx,
  sendTxExpectError,
  setupTest,
  type TestContext,
} from './common.js';
import { createMockSigner, generateMockSecp256r1Key } from './secp256r1Utils.js';

const ERR_REFUND_DESTINATION_MISMATCH = 3039;

describe('RevokeSession and CloseExpiredSession', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let owner: KeyPairSigner;
  let walletPda: Address;
  let ownerAuthorityPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    owner = await generateKeyPairSigner();
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.address },
    });
    walletPda = created.walletPda;
    ownerAuthorityPda = created.authorityPda;
    await sendTx(ctx, created.instructions);
    // The Owner pays for its own closes below, so the sponsor's balance moves
    // by the rent alone.
    await airdrop(ctx, owner.address, 1_000_000_000n);
  });

  /** A session the suite's payer pays for, authorized by the Ed25519 Owner. */
  async function sponsoredSession(secondsLeft = 3_600n): Promise<Address> {
    const sessionKey = await generateKeyPairSigner();
    const { instructions, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(owner.address, ownerAuthorityPda),
      sessionKey: sessionKey.address,
      expiresAt: (await getUnixTime(ctx)) + secondsLeft,
      unrestricted: true,
    });
    await sendTx(ctx, instructions, [owner]);
    return sessionPda;
  }

  async function sessionData(pda: Address): Promise<Uint8Array | null> {
    const info = await ctx.rpc.getAccountInfo(pda, { encoding: 'base64', commitment: 'confirmed' }).send();
    return info.value ? new Uint8Array(Buffer.from(info.value.data[0], 'base64')) : null;
  }

  it('records the sponsor as the session’s rent payer', async () => {
    const pda = await sponsoredSession();
    const session = decodeSessionAccount((await sessionData(pda))!);
    expect(session.version).toBe(2);
    expect(session.rentPayer).toBe(ctx.payer.address);
  });

  it('Ed25519 Owner revokes, paying itself: the rent goes back to the sponsor', async () => {
    const pda = await sponsoredSession();
    const rent = await getBalance(ctx, pda);
    const before = await getBalance(ctx, ctx.payer.address);

    const { instructions } = await client.revokeSession({
      payer: owner.address,
      walletPda,
      adminSigner: ed25519(owner.address, ownerAuthorityPda),
      sessionPda: pda,
    });
    await sendTx(ctx, instructions, [owner], owner);

    expect(await sessionData(pda)).toBeNull();
    expect(await getBalance(ctx, ctx.payer.address)).toBe(before + rent);
  });

  it('the client refuses another destination, and so does the program', async () => {
    const pda = await sponsoredSession();
    await expect(
      client.revokeSession({
        payer: owner.address,
        walletPda,
        adminSigner: ed25519(owner.address, ownerAuthorityPda),
        sessionPda: pda,
        refundDestination: owner.address,
      }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);

    const ix = createRevokeSessionIx({
      payer: ctx.payer.address,
      walletPda,
      adminAuthorityPda: ownerAuthorityPda,
      sessionPda: pda,
      refundDestination: owner.address,
      authorizerSigner: owner.address,
      programId: client.programId,
    });
    await sendTxExpectError(ctx, [ix], [owner], ERR_REFUND_DESTINATION_MISMATCH);
    expect(await sessionData(pda)).not.toBeNull();
  });

  it('a passkey Owner revokes with one call (prepare, sign, finalize)', async () => {
    const key = await generateMockSecp256r1Key('lazorkit.test');
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: {
        type: 'secp256r1',
        credentialIdHash: key.credentialIdHash,
        compressedPubkey: key.publicKeyBytes,
        rpId: key.rpId,
      },
    });
    await sendTx(ctx, created.instructions);
    const signer = secp256r1(createMockSigner(key));

    const sessionKey = await generateKeyPairSigner();
    const made = await client.createSession({
      payer: ctx.payer.address,
      walletPda: created.walletPda,
      adminSigner: signer,
      sessionKey: sessionKey.address,
      expiresAt: (await getUnixTime(ctx)) + 3_600n,
      unrestricted: true,
    });
    await sendTx(ctx, made.instructions);
    expect(await sessionData(made.sessionPda)).not.toBeNull();

    const { instructions } = await client.revokeSession({
      payer: ctx.payer.address,
      walletPda: created.walletPda,
      adminSigner: signer,
      sessionPda: made.sessionPda,
    });
    const revoke = instructions[instructions.length - 1]!;
    expect(revoke.accounts![4]!.address).toBe(ctx.payer.address);
    await sendTx(ctx, instructions);
    expect(await sessionData(made.sessionPda)).toBeNull();
  });

  it('anyone closes an expired session, and the rent goes to the sponsor', async () => {
    const pda = await sponsoredSession(2n);
    const rent = await getBalance(ctx, pda);
    const expiresAt = decodeSessionAccount((await sessionData(pda))!).expiresAt;
    for (let i = 0; i < 60 && (await getUnixTime(ctx)) <= expiresAt; i++) {
      await new Promise((r) => setTimeout(r, 500));
    }

    const stranger = await generateKeyPairSigner();
    await airdrop(ctx, stranger.address, 100_000_000n);
    await expect(
      client.closeExpiredSession({ caller: stranger.address, sessionPda: pda, refundDestination: stranger.address }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);

    const before = await getBalance(ctx, ctx.payer.address);
    const { instructions } = await client.closeExpiredSession({ caller: stranger.address, sessionPda: pda });
    await sendTx(ctx, instructions, [stranger], stranger);
    expect(await sessionData(pda)).toBeNull();
    expect(await getBalance(ctx, ctx.payer.address)).toBe(before + rent);
  });
});
