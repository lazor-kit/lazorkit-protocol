/**
 * Typed approval requests on a local validator (DESIGN §7.1 items 3 and 4).
 *
 * - For each kind, random cases go the whole typed way: `prepareX` gives the
 *   request; a portal stand-in checks it against the query and the chain
 *   (`checkApprovalQuery`, `describeApproval`), picks the slot and counter
 *   from its own read at "Approve", signs `approvalChallenge` with a software
 *   P-256 passkey, and replies with `typedReplyFor`; the SDK checks the reply
 *   (`verifyApprovalReply`) and finalizes with the binding. Every case lands,
 *   and the account it leaves matches the request.
 * - Tamper: after signing, one field of the request (or the binding) is
 *   changed in the transaction sent; the program refuses it, and the
 *   untampered transaction then lands. The program binds every field the
 *   screen shows.
 * - The slot is the portal's: a request prepared more than 150 slots before
 *   Approve still lands; the same signature at the prepared slot does not.
 * - Decoder differential: about 500 mutated action buffers; `decodeActions`
 *   accepts exactly those a CreateSession simulation accepts, and refuses
 *   with the program's error.
 *
 * APPROVAL_E2E_CASES sets the cases per kind (default 30).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import {
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  Transaction,
  type TransactionInstruction,
} from '@solana/web3.js';
import * as A from '../../sdk/sdk-legacy/src/approval';
import {
  LazorKitClient,
  ROLE_ADMIN,
  ROLE_OWNER,
  ROLE_SPENDER,
  secp256r1,
  buildAuthPayload,
  buildSecp256r1PrecompileIx,
  type PreparedCreateSession,
  type PreparedRevokeSession,
  type PreparedRemoveAuthority,
  type WebAuthnResponse,
} from '../../sdk/sdk-legacy/src';
import {
  createCreateSessionIx,
  createRemoveAuthorityIx,
  createRevokeSessionIx,
} from '../../sdk/sdk-legacy/src/utils/instructions';
import { setupTest, delegatePolicy, getUnixTime, type TestContext } from './common';
import { createMockRawSigner, fakeWebAuthnSign, generateMockSecp256r1Key, type MockSecp256r1Key } from './secp256r1Utils';
import { Rng, rawAction, randomValidActions, sdkActions } from './approvalFixtures';

const CASES = Number(process.env.APPROVAL_E2E_CASES ?? 30);
const FEATURES = ['wallet-bound-challenge', 'd13', 'nonowner-invariants', 'time-expiry'];
const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());

type Prepared = PreparedCreateSession | PreparedRevokeSession | PreparedRemoveAuthority;

/** The custom program error a failed simulation or send carries, if any. */
function customCode(err: unknown): number | undefined {
  const e = err as { InstructionError?: [number, { Custom?: number } | string] } | null;
  const inner = e?.InstructionError?.[1];
  return typeof inner === 'object' && inner !== null ? inner.Custom : undefined;
}

describe('typed approval requests on chain', () => {
  let ctx: TestContext;
  let client: LazorKitClient;
  let key: MockSecp256r1Key;
  let credentialId: Uint8Array;
  let walletPda: PublicKey;
  let authorityPda: PublicKey;
  /** The slot the passkey's last transaction landed in: the next reads' floor. */
  let lastSlot = 0;
  const rng = new Rng(0xe2e);

  async function send(ixs: TransactionInstruction[], signers: Keypair[] = []): Promise<void> {
    const tx = new Transaction().add(...ixs);
    tx.feePayer = ctx.payer.publicKey;
    const { blockhash, lastValidBlockHeight } = await ctx.connection.getLatestBlockhash('confirmed');
    tx.recentBlockhash = blockhash;
    tx.sign(ctx.payer, ...signers);
    const sig = await ctx.connection.sendRawTransaction(tx.serialize(), { skipPreflight: false });
    const res = await ctx.connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, 'confirmed');
    if (res.value.err) throw new Error(`transaction failed: ${JSON.stringify(res.value.err)}`);
    const status = await ctx.connection.getSignatureStatuses([sig]);
    lastSlot = Math.max(lastSlot, status.value[0]?.slot ?? 0);
  }

  /** Simulates `ixs`; returns the error (null when it would succeed). */
  async function simulate(ixs: TransactionInstruction[], signers: Keypair[] = []): Promise<unknown> {
    const tx = new Transaction().add(...ixs);
    tx.feePayer = signers[0]?.publicKey ?? ctx.payer.publicKey;
    const res = await ctx.connection.simulateTransaction(tx, signers.length ? signers : [ctx.payer]);
    return res.value.err;
  }

  const secp = () => ({
    credentialIdHash: key.credentialIdHash,
    credentialId,
    publicKeyBytes: key.publicKeyBytes,
    authorityPda,
    minContextSlot: lastSlot || undefined,
  });

  /**
   * What the portal does between load and the passkey sheet: checks the
   * query, reads, describes, and at "Approve" binds to its own read of the
   * counter and the clock. Returns the description and the binding.
   */
  async function portalApprove(prepared: Prepared, extraView: Partial<A.ApprovalChainView> = {}) {
    const req = prepared.request!;
    expect(req).toBeDefined();
    // The fragment round-trips; the query is what the SDK sends today.
    expect(A.readApprovalFragment(A.approvalFragment(req))).toEqual(req);
    expect(
      A.checkApprovalQuery(req, {
        message: Buffer.from(prepared.challenge).toString('base64url'),
        credentialId: Buffer.from(credentialId).toString('base64'),
      }),
    ).toEqual({ ok: true });

    const plan = A.approvalReadPlan(req);
    const keys = [plan.clock, plan.wallet, plan.authority, plan.session ?? plan.target ?? plan.wallet].map((k) => new PublicKey(k));
    const { context, value } = await ctx.connection.getMultipleAccountsInfoAndContext(keys, {
      commitment: 'confirmed',
      minContextSlot: req.minContextSlot,
    });
    const snap = (i: number): A.AccountSnapshot | null =>
      value[i] ? { owner: value[i]!.owner.toBase58(), lamports: BigInt(value[i]!.lamports), data: new Uint8Array(value[i]!.data) } : null;
    const view: A.ApprovalChainView = {
      clock: snap(0),
      wallet: snap(1),
      authority: snap(2),
      ...(plan.session ? { session: snap(3) } : {}),
      ...(plan.target ? { target: snap(3) } : {}),
      ...extraView,
    };
    if (req.kind === 'revokeSession' && view.session) {
      // The mints a session names are known once it is read.
      const mints = A.approvalReadPlan(req, { session: view.session }).mints;
      view.mints = Object.fromEntries(mints.map((m) => [m, null]));
    }
    const check = A.describeApproval(req, view, { features: FEATURES });
    if (!check.ok) throw new Error(`portal refused: ${check.code} ${check.reason}`);
    expect(context.slot).toBeGreaterThanOrEqual(req.minContextSlot ?? 0);

    // "Approve": the slot and counter of the portal's own read.
    const clock = A.decodeClock(view.clock!.data)!;
    const signer = A.decodeAuthorityAccount(view.authority, req.programId)!;
    const binding = { slot: clock.slot, counter: signer.counter + 1 };
    expect(binding.counter).toBeGreaterThanOrEqual(req.counter);
    return { req, description: check.description, binding };
  }

  /** The passkey signs; the portal replies; the SDK checks the reply. */
  async function signAndVerify(req: A.ApprovalRequest, binding: A.ApprovalBinding) {
    const response = await fakeWebAuthnSign(key, A.approvalChallenge(req, binding));
    const verified = A.verifyApprovalReply(req, {
      clientDataJson: response.clientDataJson,
      typed: A.parseTypedReply(JSON.parse(JSON.stringify(A.typedReplyFor(req, binding)))),
    });
    expect(verified.binding).toEqual(binding);
    return { response, binding: verified.binding };
  }

  /** The instructions a finalize builds, with the signed response, at `binding`. */
  function authPayloadFor(response: WebAuthnResponse, binding: A.ApprovalBinding, sysvarIxIndex: number) {
    return buildAuthPayload({
      slot: binding.slot,
      counter: binding.counter,
      sysvarIxIndex,
      authenticatorData: response.authenticatorData,
      clientDataJson: response.clientDataJson,
    });
  }
  function precompileFor(response: WebAuthnResponse) {
    return buildSecp256r1PrecompileIx(
      key.publicKeyBytes,
      Buffer.concat([response.authenticatorData, response.clientDataJsonHash]),
      response.signature,
    );
  }

  const sessions: PublicKey[] = [];
  const authorities: PublicKey[] = [];
  let otherPayer: Keypair;
  let otherWallet: PublicKey;

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    credentialId = new Uint8Array(randomBytes(48));
    key = await generateMockSecp256r1Key('portal.lazor.sh', sha256(credentialId));
    const created = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: randomBytes(32),
      owner: { type: 'secp256r1', credentialIdHash: key.credentialIdHash, compressedPubkey: key.publicKeyBytes, rpId: key.rpId },
    });
    await send(created.instructions);
    walletPda = created.walletPda;
    authorityPda = created.authorityPda;

    otherPayer = Keypair.generate();
    await send([
      (await import('@solana/web3.js')).SystemProgram.transfer({
        fromPubkey: ctx.payer.publicKey,
        toPubkey: otherPayer.publicKey,
        lamports: 1_000_000_000,
      }),
    ]);
    const other = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: randomBytes(32),
      owner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
    });
    await send(other.instructions);
    otherWallet = other.walletPda;
  }, 120_000);

  // ── createSession ──

  it(`createSession: ${CASES} random typed requests land and match their envelopes`, async () => {
    for (let i = 0; i < CASES; i++) {
      const now = await getUnixTime(ctx);
      const { actions, buffer } = sdkActionsFitting(rng, false);
      const sessionKey = Keypair.generate().publicKey;
      const expiresAt = now + 60n + BigInt(rng.int(Number(A.APPROVAL_MAX_SESSION_SECONDS) - 120));
      const prepared = await client.prepareCreateSession({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: secp(),
        sessionKey,
        expiresAt,
        ...(actions.length ? { actions } : { unrestricted: true }),
      });
      const { req, description, binding } = await portalApprove(prepared);
      expect(description.kind).toBe('createSession');
      const { response } = await signAndVerify(req, binding);
      const { instructions, sessionPda } = client.finalizeCreateSession(prepared, response, binding);
      await send(instructions);

      const acc = await ctx.connection.getAccountInfo(sessionPda, 'confirmed');
      const session = A.decodeSessionAccount(
        { owner: acc!.owner.toBase58(), lamports: BigInt(acc!.lamports), data: new Uint8Array(acc!.data) },
        req.programId,
      )!;
      const args = (req as A.CreateSessionRequest).args;
      expect(session.wallet).toBe(req.wallet);
      expect(session.sessionKey).toBe(args.sessionKey);
      expect(session.expiresAt.toString()).toBe(args.expiresAt);
      expect(Buffer.from(session.actions).equals(Buffer.from(buffer))).toBe(true);
      expect(A.base64urlEncode(session.actions)).toBe(args.actions);
      sessions.push(sessionPda);
    }
  }, 600_000);

  it('createSession: changing any signed field after signing is refused; the original then lands', async () => {
    const now = await getUnixTime(ctx);
    const sessionKp = Keypair.generate();
    const drawn = sdkActionsWithSome(rng);
    const prepared = await client.prepareCreateSession({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: secp(),
      sessionKey: sessionKp.publicKey,
      expiresAt: now + 3_600n,
      actions: drawn.actions,
    });
    const { req, binding } = await portalApprove(prepared);
    const { response } = await signAndVerify(req, binding);
    const args = (req as A.CreateSessionRequest).args;
    const base = {
      payer: ctx.payer.publicKey,
      walletPda,
      adminAuthorityPda: authorityPda,
      sessionKey: new PublicKey(args.sessionKey).toBytes(),
      sessionPda: client.findSession(walletPda, new PublicKey(args.sessionKey).toBytes())[0],
      expiresAt: BigInt(args.expiresAt),
      actionsBuffer: A.requestActionsBytes(req as A.CreateSessionRequest),
      programId: client.programId,
    };
    const ixFor = (over: Partial<typeof base>, b = binding) => [
      precompileFor(response),
      createCreateSessionIx({ ...base, ...over, authPayload: authPayloadFor(response, b, 6) }),
    ];
    const otherKey = Keypair.generate().publicKey.toBytes();
    // One bit of the last action's own expiry: the buffer stays valid, so
    // only the signature can refuse it.
    const flipped = new Uint8Array(base.actionsBuffer);
    flipped[actionStarts(flipped).at(-1)! + 3] ^= 1;
    const tampers: [string, TransactionInstruction[], Keypair[], number | 'any'][] = [
      ['sessionKey', ixFor({ sessionKey: otherKey, sessionPda: client.findSession(walletPda, otherKey)[0] }), [], 3005],
      ['expiresAt', ixFor({ expiresAt: base.expiresAt + 1n }), [], 3005],
      ['actions', ixFor({ actionsBuffer: flipped }), [], 3005],
      ['payer', ixFor({ payer: otherPayer.publicKey }), [otherPayer], 3005],
      ['wallet', ixFor({ walletPda: otherWallet }), [], 'any'],
      ['slot', ixFor({}, { ...binding, slot: binding.slot - 1n }), [], 3005],
      ['counter', ixFor({}, { ...binding, counter: binding.counter + 1 }), [], 3006],
    ];
    for (const [field, ixs, signers, code] of tampers) {
      const err = await simulate(ixs, signers.length ? signers : [ctx.payer]);
      expect(err, field).not.toBeNull();
      if (code !== 'any') expect(customCode(err), field).toBe(code);
    }
    await send(ixFor({}));
    sessions.push(base.sessionPda);
  }, 120_000);

  it('the slot is chosen at Approve: prepared over 150 slots earlier, it still lands; the prepared slot would not', async () => {
    const now = await getUnixTime(ctx);
    const prepared = await client.prepareCreateSession({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: secp(),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: now + 3_600n,
      actions: sdkActionsWithSome(rng).actions,
    });
    const preparedSlot = BigInt(prepared.request!.preparedSlot);
    // Wait until the prepared slot is out of the program's 150-slot window.
    for (;;) {
      const slot = BigInt(await ctx.connection.getSlot('confirmed'));
      if (slot - preparedSlot > A.MAX_SIGNATURE_AGE_SLOTS + 5n) break;
      await new Promise((r) => setTimeout(r, 2_000));
    }
    // An older SDK's flow (no typed reply): signs the prepared challenge, refused as too old.
    const stale = await fakeWebAuthnSign(key, prepared.challenge);
    const staleErr = await simulate(client.finalizeCreateSession(prepared, stale).instructions);
    expect(customCode(staleErr)).toBe(3007);
    // The typed flow: the portal binds at Approve.
    const { req, binding } = await portalApprove(prepared);
    expect(binding.slot - preparedSlot).toBeGreaterThan(A.MAX_SIGNATURE_AGE_SLOTS);
    const { response } = await signAndVerify(req, binding);
    const { instructions, sessionPda } = client.finalizeCreateSession(prepared, response, binding);
    await send(instructions);
    sessions.push(sessionPda);
  }, 180_000);

  it('a counter that moved forward between prepare and Approve: the portal signs the new one, the SDK rebinds', async () => {
    const now = await getUnixTime(ctx);
    const first = await client.prepareCreateSession({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: secp(),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: now + 3_600n,
      unrestricted: true,
    });
    // Another approval from the same passkey lands first (another tab).
    const meanwhile = await client.prepareCreateSession({
      payer: ctx.payer.publicKey,
      walletPda,
      secp256r1: secp(),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: now + 3_600n,
      unrestricted: true,
    });
    const m = await fakeWebAuthnSign(key, meanwhile.challenge);
    await send(client.finalizeCreateSession(meanwhile, m).instructions);
    sessions.push(meanwhile.sessionPda);

    const { req, binding } = await portalApprove(first, {});
    expect(binding.counter).toBe(req.counter + 1);
    const { response } = await signAndVerify(req, binding);
    await send(client.finalizeCreateSession(first, response, binding).instructions);
    sessions.push(first.sessionPda);
  }, 120_000);

  // ── revokeSession ──

  it(`revokeSession: ${CASES} random typed requests land; the session closes and its rent reaches the refund`, async () => {
    expect(sessions.length).toBeGreaterThanOrEqual(CASES);
    for (let i = 0; i < CASES; i++) {
      const sessionPda = sessions.shift()!;
      const refund = rng.bool() ? ctx.payer.publicKey : Keypair.generate().publicKey;
      const before = await ctx.connection.getBalance(refund, 'confirmed');
      const rent = await ctx.connection.getBalance(sessionPda, 'confirmed');
      const prepared = await client.prepareRevokeSession({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: secp(),
        sessionPda,
        refundDestination: refund,
      });
      const { req, description, binding } = await portalApprove(prepared);
      expect(description).toMatchObject({ kind: 'revokeSession', refundIsPayer: refund.equals(ctx.payer.publicKey) });
      const { response } = await signAndVerify(req, binding);
      await send(client.finalizeRevokeSession(prepared, response, binding).instructions);
      expect(await ctx.connection.getAccountInfo(sessionPda, 'confirmed')).toBeNull();
      if (!refund.equals(ctx.payer.publicKey)) {
        expect(await ctx.connection.getBalance(refund, 'confirmed')).toBe(before + rent);
      }
    }
  }, 600_000);

  it('revokeSession: changing the session, refund, payer, slot or counter after signing is refused', async () => {
    const [sessionPda, otherSession] = [sessions[0], sessions[1]];
    const prepared = await client.prepareRevokeSession({ payer: ctx.payer.publicKey, walletPda, secp256r1: secp(), sessionPda });
    const { req, binding } = await portalApprove(prepared);
    const { response } = await signAndVerify(req, binding);
    const base = { payer: ctx.payer.publicKey, walletPda, adminAuthorityPda: authorityPda, sessionPda, refundDestination: ctx.payer.publicKey, programId: client.programId };
    const ixFor = (over: Partial<typeof base>, b = binding) => [precompileFor(response), createRevokeSessionIx({ ...base, ...over, authPayload: authPayloadFor(response, b, 5) })];
    const tampers: [string, TransactionInstruction[], Keypair[], number][] = [
      ['session', ixFor({ sessionPda: otherSession }), [], 3005],
      ['refund', ixFor({ refundDestination: Keypair.generate().publicKey }), [], 3005],
      ['payer', ixFor({ payer: otherPayer.publicKey }), [otherPayer], 3005],
      ['slot', ixFor({}, { ...binding, slot: binding.slot - 1n }), [], 3005],
      ['counter', ixFor({}, { ...binding, counter: binding.counter + 1 }), [], 3006],
    ];
    for (const [field, ixs, signers, code] of tampers) {
      const err = await simulate(ixs, signers.length ? signers : [ctx.payer]);
      expect(customCode(err), field).toBe(code);
    }
    await send(ixFor({}));
    sessions.shift();
  }, 120_000);

  // ── removeAuthority ──

  it(`removeAuthority: ${CASES} random typed requests land; each authority closes`, async () => {
    const roles = [ROLE_OWNER, ROLE_ADMIN, ROLE_SPENDER];
    for (let i = 0; i < CASES + 2; i++) {
      const role = roles[i % 3];
      const added = await client.addAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        adminSigner: secp256r1(createMockRawSigner(key), { authorityPda, minContextSlot: lastSlot }),
        newAuthority: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
        role,
        ...(role === ROLE_SPENDER ? { policy: delegatePolicy() } : {}),
        ...(role === ROLE_OWNER ? { allowOwner: true } : {}),
      });
      await send(added.instructions);
      authorities.push(added.newAuthorityPda);
    }
    for (let i = 0; i < CASES; i++) {
      const target = authorities.shift()!;
      const prepared = await client.prepareRemoveAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        secp256r1: secp(),
        targetAuthorityPda: target,
        refundDestination: rng.bool() ? ctx.payer.publicKey : Keypair.generate().publicKey,
      });
      const { req, description, binding } = await portalApprove(prepared);
      expect(description).toMatchObject({ kind: 'removeAuthority', targetType: 'ed25519', targetRole: ['owner', 'admin', 'delegate'][i % 3] });
      const { response } = await signAndVerify(req, binding);
      await send(client.finalizeRemoveAuthority(prepared, response, binding).instructions);
      expect(await ctx.connection.getAccountInfo(target, 'confirmed')).toBeNull();
    }
  }, 900_000);

  it('removeAuthority: changing the target, refund, payer, slot or counter after signing is refused', async () => {
    const [target, otherTarget] = authorities;
    const prepared = await client.prepareRemoveAuthority({ payer: ctx.payer.publicKey, walletPda, secp256r1: secp(), targetAuthorityPda: target });
    const { req, binding } = await portalApprove(prepared);
    const { response } = await signAndVerify(req, binding);
    const base = { payer: ctx.payer.publicKey, walletPda, adminAuthorityPda: authorityPda, targetAuthorityPda: target, refundDestination: ctx.payer.publicKey, programId: client.programId };
    const ixFor = (over: Partial<typeof base>, b = binding) => [precompileFor(response), createRemoveAuthorityIx({ ...base, ...over, authPayload: authPayloadFor(response, b, 5) })];
    const tampers: [string, TransactionInstruction[], Keypair[], number][] = [
      ['target', ixFor({ targetAuthorityPda: otherTarget }), [], 3005],
      ['refund', ixFor({ refundDestination: Keypair.generate().publicKey }), [], 3005],
      ['payer', ixFor({ payer: otherPayer.publicKey }), [otherPayer], 3005],
      ['slot', ixFor({}, { ...binding, slot: binding.slot - 1n }), [], 3005],
      ['counter', ixFor({}, { ...binding, counter: binding.counter + 1 }), [], 3006],
    ];
    for (const [field, ixs, signers, code] of tampers) {
      const err = await simulate(ixs, signers.length ? signers : [ctx.payer]);
      expect(customCode(err), field).toBe(code);
    }
    await send(ixFor({}));
  }, 120_000);

  // ── Decoder differential ──

  it('decodeActions accepts exactly the buffers CreateSession accepts (about 500 mutations)', async () => {
    const owner = Keypair.generate();
    const w = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    await send(w.instructions);
    const ownerAuthority = w.authorityPda;
    const now = await getUnixTime(ctx);

    const mutants = drawMutants(new Rng(0xd1ff), 500);
    let accepted = 0;
    const tally: Record<string, number> = {};
    for (const [i, { name, buf }] of mutants.entries()) {
      const sessionKey = Keypair.generate().publicKey;
      // The Ed25519 CreateSession the client builds, with the mutant as its raw actions.
      const ix = createCreateSessionIx({
        payer: ctx.payer.publicKey,
        walletPda: w.walletPda,
        adminAuthorityPda: ownerAuthority,
        sessionPda: client.findSession(w.walletPda, sessionKey.toBytes())[0],
        sessionKey: sessionKey.toBytes(),
        expiresAt: now + 3_600n,
        actionsBuffer: buf,
        authorizerSigner: owner.publicKey,
        programId: client.programId,
      });
      const err = await simulate([ix], [ctx.payer, owner]);
      let decoded: 'ok' | number;
      try {
        A.decodeActions(buf);
        decoded = 'ok';
      } catch (e) {
        decoded = (e as A.ApprovalActionsError).programError === 'ActionWhitelistBlacklistConflict' ? 3028 : 3020;
      }
      const chain = err === null ? 'ok' : customCode(err) ?? JSON.stringify(err);
      expect(decoded, `mutant ${i} (${name}): ${Buffer.from(buf).toString('hex')}`).toBe(chain);
      if (chain === 'ok') accepted++;
      tally[`${name}:${chain}`] = (tally[`${name}:${chain}`] ?? 0) + 1;
    }
    // Both outcomes are well represented.
    expect(accepted).toBeGreaterThan(50);
    expect(mutants.length - accepted).toBeGreaterThan(200);
    console.log('decoder differential:', JSON.stringify(tally));
  }, 600_000);
});

/**
 * A passkey CreateSession must fit one legacy transaction (1,232 bytes) with
 * the precompile instruction and the WebAuthn payload beside it, which
 * leaves room for about 370 bytes of actions.
 */
const PASSKEY_ACTIONS_MAX_BYTES = 360;
/** An Ed25519 CreateSession leaves about 760. */
const ED25519_ACTIONS_MAX_BYTES = 740;

/** SDK-expressible actions that fit a passkey CreateSession; `some`: at least one. */
function sdkActionsFitting(rng: Rng, some: boolean) {
  for (;;) {
    const drawn = sdkActions(rng);
    if (drawn.buffer.length <= PASSKEY_ACTIONS_MAX_BYTES && (!some || drawn.actions.length > 0)) return drawn;
  }
}
const sdkActionsWithSome = (rng: Rng) => sdkActionsFitting(rng, true);

/** Where each action of a well-formed buffer starts. */
function actionStarts(b: Uint8Array): number[] {
  const starts: number[] = [];
  for (let o = 0; o + 11 <= b.length; o += 11 + (b[o + 1] | (b[o + 2] << 8))) starts.push(o);
  return starts;
}

/** Valid buffers, mutated in the ways DESIGN §7.1 item 3 lists. */
function drawMutants(rng: Rng, n: number): { name: string; buf: Uint8Array }[] {
  const out: { name: string; buf: Uint8Array }[] = [];
  const valid = () => {
    for (;;) {
      const b = randomValidActions(rng, 10);
      if (b.length > 0 && b.length <= ED25519_ACTIONS_MAX_BYTES - 120) return b;
    }
  };
  while (out.length < n) {
    const b = valid();
    const push = (m: { name: string; buf: Uint8Array }) => {
      if (m.buf.length <= ED25519_ACTIONS_MAX_BYTES) out.push(m);
    };
    const starts = actionStarts(b);
    switch (rng.int(9)) {
      case 0:
        push({ name: 'valid', buf: b });
        break;
      case 1: {
        const m = new Uint8Array(b);
        const at = rng.int(m.length);
        m[at] ^= 1 << rng.int(8);
        push({ name: 'bitflip', buf: m });
        break;
      }
      case 2: {
        const m = new Uint8Array(b);
        // A flip in a header (type, length) more often breaks the buffer.
        const s = rng.pick(starts);
        m[s + rng.int(3)] ^= 1 << rng.int(8);
        push({ name: 'header-flip', buf: m });
        break;
      }
      case 3:
        push({ name: 'truncate', buf: b.subarray(0, rng.int(b.length)) });
        break;
      case 4: {
        const s = rng.pick(starts);
        const len = 11 + (b[s + 1] | (b[s + 2] << 8));
        push({ name: 'duplicate', buf: Uint8Array.from(Buffer.concat([b, b.subarray(s, s + len)])) });
        break;
      }
      case 5: {
        const types = new Set(starts.map((s) => b[s]));
        const add = types.has(10) ? 11 : 10;
        push({ name: 'whitelist+blacklist', buf: Uint8Array.from(Buffer.concat([b, rawAction(add, 0n, rng.bytes(32)), rawAction(add === 10 ? 11 : 10, 0n, rng.bytes(32))])) });
        break;
      }
      case 6: {
        const d = new Uint8Array(32);
        d[0] = 1;
        d[16] = 1;
        const field = rng.pick([8, 24]); // spent or last_reset
        d[field] = 1 + rng.int(255);
        push({ name: 'recurring-nonzero', buf: Uint8Array.from(Buffer.concat([rawAction(2, 0n, d)])) });
        break;
      }
      case 7:
        push({ name: 'trailing', buf: Uint8Array.from(Buffer.concat([b, rng.bytes(1 + rng.int(10))])) });
        break;
      case 8: {
        // Past 16 actions, with program entries of the kind already there.
        const t = starts.some((s) => b[s] === 10) ? 10 : 11;
        const extra = Array.from({ length: 17 - starts.length }, () => rawAction(t, 0n, rng.bytes(32)));
        push({ name: 'seventeen', buf: Uint8Array.from(Buffer.concat([b, ...extra])) });
        break;
      }
    }
  }
  return out;
}
