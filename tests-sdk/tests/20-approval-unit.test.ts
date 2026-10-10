/**
 * Typed approval requests (`@lazorkit/sdk-legacy/approval`), off chain.
 *
 * 1. Parity: for 10,000 seeded random cases per kind, `approvalChallenge`
 *    equals the SDK's own challenge (`prepareX` through a stubbed connection,
 *    and `prepareSecp256r1`), and both equal the reference written from the
 *    program (approvalFixtures.ts). `rebindSecp256r1` lands on the same bytes.
 * 2. Codec: round trips, every non-canonical spelling refused, the caps.
 * 3. Decoder: valid buffers decode to what was written; each rule the
 *    program applies refuses (the differential against the program itself
 *    runs on a validator in 21-approval-e2e).
 * 4. Replies, the query check, finalize with a binding, PDAs, descriptions.
 * 5. Bundle: the entry point bundles for the browser and React Native with
 *    no @solana/web3.js, no buffer, no Node builtin.
 *
 * No validator needed.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import * as path from 'path';
import {
  PublicKey,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
  type AccountInfo,
} from '@solana/web3.js';
import * as A from '../../sdk/sdk-legacy/src/approval';
import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_MAINNET,
  PROGRAM_ADDRESS_DEVNET,
  PROGRAM_ADDRESS_MAINNET,
  MAX_SESSION_SECONDS,
  prepareSecp256r1,
  rebindSecp256r1,
  buildDataPayloadForSession,
  findAuthorityPda,
  findSessionPda,
  findVaultPda,
  DISC_CREATE_SESSION,
  DISC_REVOKE_SESSION,
  DISC_REMOVE_AUTHORITY,
  parseActions,
  type SessionAction,
} from '../../sdk/sdk-legacy/src';
import { contextual } from './contextReads';
import {
  Rng,
  b64url,
  rawAction,
  randomValidActions,
  referenceChallenge,
  referenceCreateSessionPayload,
  sdkActions,
} from './approvalFixtures';

const CASES = Number(process.env.APPROVAL_PARITY_CASES ?? 10_000);
const KINDS = ['createSession', 'revokeSession', 'removeAuthority'] as const;
type Kind = (typeof KINDS)[number];

const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const addr = (b: Uint8Array) => new PublicKey(b).toBase58();
const U32_MAX = 0xffff_ffff;

/** An authority account whose stored counter is `stored`: what the challenge reads see. */
function authorityAccount(stored: number): AccountInfo<Buffer> {
  const data = Buffer.alloc(145);
  data[0] = 0x22;
  data[1] = 1;
  data[4] = 1;
  data.writeUInt32LE(stored, 8);
  data[80] = 0x02;
  return { data, owner: PROGRAM_ID_DEVNET, executable: false, lamports: 1, rentEpoch: 0 };
}

/** A connection that answers every account read with an authority at `stored`. */
function stubConnection(stored: () => number) {
  return contextual({
    getAccountInfo: async () => authorityAccount(stored()),
    getSlot: async () => 1_000,
    getMultipleAccountsInfo: async (keys: PublicKey[]) => keys.map(() => null),
  });
}

interface Case {
  kind: Kind;
  programId: Uint8Array;
  wallet: Uint8Array;
  payer: Uint8Array;
  credentialId: Uint8Array;
  slot: bigint;
  counter: number;
  // createSession
  sessionKey: Uint8Array;
  expiresAt: bigint;
  actions: Uint8Array;
  // revoke / remove
  account: Uint8Array;
  refund: Uint8Array;
}

function randomCase(rng: Rng, kind: Kind, i: number): Case {
  const programId =
    i % 3 === 0 ? PROGRAM_ID_DEVNET.toBytes() : i % 3 === 1 ? PROGRAM_ID_MAINNET.toBytes() : rng.bytes(32);
  const counters = [1, 2, U32_MAX - 1, U32_MAX];
  return {
    kind,
    programId,
    wallet: rng.bytes(32),
    payer: rng.bytes(32),
    credentialId: rng.bytes(1 + (rng.bool(0.05) ? 1022 : rng.int(96))),
    slot: rng.bool(0.1) ? rng.pick([0n, (1n << 64n) - 1n]) : rng.u64(),
    counter: rng.bool(0.1) ? rng.pick(counters) : 1 + rng.int(U32_MAX),
    sessionKey: rng.bytes(32),
    expiresAt: rng.bool(0.1) ? rng.pick([0n, (1n << 63n) - 1n]) : rng.u64() >> 1n,
    actions: randomValidActions(rng),
    account: rng.bytes(32),
    refund: rng.bytes(32),
  };
}

const KIND_CONST = {
  createSession: { disc: DISC_CREATE_SESSION, sysvar: 6 },
  revokeSession: { disc: DISC_REVOKE_SESSION, sysvar: 5 },
  removeAuthority: { disc: DISC_REMOVE_AUTHORITY, sysvar: 5 },
};

function signedPayload(c: Case): Uint8Array {
  return c.kind === 'createSession'
    ? referenceCreateSessionPayload(c.sessionKey, c.expiresAt, c.actions, c.payer)
    : Buffer.concat([c.account, c.refund]);
}

function reference(c: Case, slot = c.slot, counter = c.counter): Buffer {
  return referenceChallenge({
    discriminator: KIND_CONST[c.kind].disc,
    slot,
    counter,
    sysvarIxIndex: KIND_CONST[c.kind].sysvar,
    signedPayload: signedPayload(c),
    payer: c.payer,
    wallet: c.wallet,
    programId: c.programId,
  });
}

/** The envelope for a case, written by hand from the v1 field list (not by the SDK). */
function envelopeOf(c: Case): A.ApprovalRequest {
  const base = {
    v: 1 as const,
    cluster: 'devnet' as const,
    programId: addr(c.programId),
    wallet: addr(c.wallet),
    authority: addr(sha256(c.wallet)),
    credentialId: b64url(c.credentialId),
    payer: addr(c.payer),
    counter: c.counter,
    preparedSlot: c.slot.toString(),
  };
  switch (c.kind) {
    case 'createSession':
      return {
        ...base,
        kind: 'createSession',
        args: { sessionKey: addr(c.sessionKey), expiresAt: c.expiresAt.toString(), actions: b64url(c.actions) },
      };
    case 'revokeSession':
      return { ...base, kind: 'revokeSession', args: { session: addr(c.account), refund: addr(c.refund) } };
    case 'removeAuthority':
      return { ...base, kind: 'removeAuthority', args: { target: addr(c.account), refund: addr(c.refund) } };
  }
}

// ─── 1. Parity ────────────────────────────────────────────────────

describe('approvalChallenge — parity with the SDK and the program', () => {
  for (const kind of KINDS) {
    it(`${kind}: ${CASES} random cases, module = prepareSecp256r1 = rebind = reference`, () => {
      const rng = new Rng(0x5eed_0000 + KINDS.indexOf(kind));
      for (let i = 0; i < CASES; i++) {
        const c = randomCase(rng, kind, i);
        const env = envelopeOf(c);
        const ref = reference(c);
        const mine = A.approvalChallenge(env, { slot: c.slot, counter: c.counter });
        expect(Buffer.from(mine).equals(ref), `case ${i}`).toBe(true);
        expect(Buffer.from(A.signedPayloadOf(env)).equals(Buffer.from(signedPayload(c)))).toBe(true);

        // The SDK's own low-level path, with its own payload builder.
        const sdkPayload =
          kind === 'createSession'
            ? Buffer.concat([
                buildDataPayloadForSession(c.sessionKey, c.expiresAt, c.actions.length ? c.actions : undefined),
                c.payer,
              ])
            : Buffer.concat([c.account, c.refund]);
        const other = { slot: rng.u64(), counter: rng.int(U32_MAX) };
        const preparedElsewhere = prepareSecp256r1({
          discriminator: new Uint8Array([KIND_CONST[kind].disc]),
          signedPayload: sdkPayload,
          sysvarIxIndex: KIND_CONST[kind].sysvar,
          slot: other.slot,
          counter: other.counter,
          payer: new PublicKey(c.payer),
          wallet: new PublicKey(c.wallet),
          programId: new PublicKey(c.programId),
          publicKeyBytes: new Uint8Array(33),
        });
        expect(Buffer.from(preparedElsewhere.challenge).equals(reference(c, other.slot, other.counter))).toBe(true);
        const rebound = rebindSecp256r1(preparedElsewhere, { slot: c.slot, counter: c.counter });
        expect(Buffer.from(rebound.challenge).equals(ref), `rebind case ${i}`).toBe(true);
        expect(rebound._internal.slot).toBe(c.slot);
        expect(rebound._internal.counter).toBe(c.counter);
      }
    });

    it(`${kind}: ${CASES} random cases through prepareX (stubbed reads) and its request`, async () => {
      const rng = new Rng(0xc11e_0000 + KINDS.indexOf(kind));
      let stored = 0;
      const connection = stubConnection(() => stored);
      const clients = {
        devnet: new LazorKitClient(connection, PROGRAM_ID_DEVNET),
        mainnet: new LazorKitClient(connection, PROGRAM_ID_MAINNET),
      };
      let tooLarge = 0;
      for (let i = 0; i < CASES; i++) {
        const c = randomCase(rng, kind, i);
        const cluster = i % 2 === 0 ? 'devnet' : 'mainnet';
        const client = clients[cluster];
        c.programId = client.programId.toBytes();
        stored = c.counter - 1;
        const secp256r1 = {
          credentialIdHash: sha256(c.credentialId),
          credentialId: c.credentialId,
          publicKeyBytes: new Uint8Array(33).fill(2),
          slotOverride: c.slot,
        };
        const common = { payer: new PublicKey(c.payer), walletPda: new PublicKey(c.wallet), secp256r1 };
        // The SDK writes expires_at as a signed i64 and refuses slot-like
        // values; keep the case inside what it accepts.
        let sessionActions: SessionAction[] = [];
        if (kind === 'createSession') {
          c.expiresAt = A.MIN_UNIX_SECONDS + (c.expiresAt % (1n << 62n));
          const drawn = sdkActions(rng);
          sessionActions = drawn.actions;
          c.actions = drawn.buffer;
        }
        const createArgs = {
          sessionKey: new PublicKey(c.sessionKey),
          expiresAt: c.expiresAt,
          ...(sessionActions.length ? { actions: sessionActions } : { unrestricted: true as const }),
        };
        if (kind === 'createSession' && c.actions.length > A.MAX_PASSKEY_SESSION_ACTIONS_BYTES) {
          // Too large to send once signed: refused before any request exists.
          // Without the credential id (no request) the challenge is unchanged.
          await expect(client.prepareCreateSession({ ...common, ...createArgs })).rejects.toBeInstanceOf(
            A.TransactionTooLargeError,
          );
          const bare = await client.prepareCreateSession({
            ...common,
            secp256r1: { ...secp256r1, credentialId: undefined },
            ...createArgs,
          });
          expect(bare.request).toBeUndefined();
          expect(Buffer.from(bare.challenge).equals(reference(c)), `case ${i}`).toBe(true);
          tooLarge++;
          continue;
        }
        const prepared =
          kind === 'createSession'
            ? await client.prepareCreateSession({ ...common, ...createArgs })
            : kind === 'revokeSession'
              ? await client.prepareRevokeSession({
                  ...common,
                  sessionPda: new PublicKey(c.account),
                  refundDestination: new PublicKey(c.refund),
                })
              : await client.prepareRemoveAuthority({
                  ...common,
                  targetAuthorityPda: new PublicKey(c.account),
                  refundDestination: new PublicKey(c.refund),
                });
        const req = prepared.request!;
        expect(req, `case ${i}`).toBeDefined();
        expect(A.decodeApprovalRequest(A.encodeApprovalRequest(req))).toEqual(req);
        expect(req.cluster).toBe(cluster);
        expect(req.counter).toBe(c.counter);
        expect(req.preparedSlot).toBe(c.slot.toString());
        expect(req.authority).toBe(
          findAuthorityPda(new PublicKey(c.wallet), sha256(c.credentialId), client.programId)[0].toBase58(),
        );
        const ref = reference(c);
        expect(Buffer.from(prepared.challenge).equals(ref), `case ${i}`).toBe(true);
        expect(Buffer.from(A.approvalChallenge(req, A.preparedBinding(req))).equals(ref)).toBe(true);
      }
      if (kind === 'createSession') {
        expect(tooLarge).toBeGreaterThan(CASES / 20);
        expect(tooLarge).toBeLessThan(CASES - CASES / 20);
      }
    }, 600_000);
  }

  it('matches the vectors the program suite signs with and lands (program/tests/typed_approval_vectors_tests.rs)', () => {
    const fill = (b: number) => addr(new Uint8Array(32).fill(b));
    const actions = Buffer.from(
      '0308000000000000000000' + '80841e0000000000' +
        '0428000000000000000000' + '55'.repeat(32) + '404b4c0000000000',
      'hex',
    );
    const base = {
      v: 1 as const,
      cluster: 'devnet' as const,
      programId: PROGRAM_ADDRESS_DEVNET,
      wallet: fill(0x11),
      authority: fill(0x12),
      credentialId: b64url(new Uint8Array([1, 2, 3])),
      payer: fill(0x22),
      counter: 42,
      preparedSlot: '234567890',
    };
    const vectors: [A.ApprovalRequest, string][] = [
      [
        { ...base, kind: 'createSession', args: { sessionKey: fill(0x33), expiresAt: '1791072000', actions: b64url(actions) } },
        'd1841cf56f964039a42a5a2569f3a030991cdd8d3d5b8f29387e97ca34f8333a',
      ],
      [
        { ...base, kind: 'revokeSession', args: { session: fill(0x44), refund: fill(0x22) } },
        '83051a9cb28655e7ae605e66556d085a9b32d9d9986807ef16ffc174aada6beb',
      ],
      [
        { ...base, kind: 'removeAuthority', args: { target: fill(0x77), refund: fill(0x22) } },
        '7768f9770b74d4ec77eaf3178fa2cdc712b330f66e02472cf360b36c4d912df9',
      ],
    ];
    for (const [req, hex] of vectors) {
      const decoded = A.decodeApprovalRequest(A.encodeApprovalRequest(req));
      expect(Buffer.from(A.approvalChallenge(decoded, A.preparedBinding(decoded))).toString('hex'), req.kind).toBe(hex);
    }
  });

  it('createSession: the request carries the exact buffer the SDK serialized', async () => {
    const rng = new Rng(77);
    const client = new LazorKitClient(stubConnection(() => 6), PROGRAM_ID_DEVNET);
    for (let i = 0; i < 300; i++) {
      const { actions, buffer } = sdkActions(rng);
      if (buffer.length > A.MAX_PASSKEY_SESSION_ACTIONS_BYTES) continue;
      const credentialId = rng.bytes(16);
      const prepared = await client.prepareCreateSession({
        payer: new PublicKey(rng.bytes(32)),
        walletPda: new PublicKey(rng.bytes(32)),
        secp256r1: { credentialIdHash: sha256(credentialId), credentialId, publicKeyBytes: new Uint8Array(33), slotOverride: 99n },
        sessionKey: new PublicKey(rng.bytes(32)),
        expiresAt: A.MIN_UNIX_SECONDS + BigInt(rng.int(1e9)),
        ...(actions.length ? { actions } : { unrestricted: true }),
      });
      const req = prepared.request as A.CreateSessionRequest;
      expect(Buffer.from(A.requestActionsBytes(req)).equals(Buffer.from(buffer))).toBe(true);
      expect(A.decodeActions(buffer)).toHaveLength(actions.length);
      expect(Buffer.from(A.approvalChallenge(req, A.preparedBinding(req))).equals(Buffer.from(prepared.challenge))).toBe(true);
    }
  });

  it('no request without a credential id, or for a program that is not a known v2 deployment', async () => {
    const connection = stubConnection(() => 1);
    const base = {
      payer: PROGRAM_ID_MAINNET,
      walletPda: PROGRAM_ID_DEVNET,
      sessionPda: PROGRAM_ID_DEVNET,
    };
    const credentialId = new Uint8Array([1, 2, 3]);
    const p1 = await new LazorKitClient(connection, PROGRAM_ID_DEVNET).prepareRevokeSession({
      ...base,
      secp256r1: { credentialIdHash: sha256(credentialId), publicKeyBytes: new Uint8Array(33), slotOverride: 1n },
    });
    expect(p1.request).toBeUndefined();
    const p2 = await new LazorKitClient(connection, new PublicKey(new Uint8Array(32).fill(9))).prepareRevokeSession({
      ...base,
      secp256r1: { credentialIdHash: sha256(credentialId), credentialId, publicKeyBytes: new Uint8Array(33), slotOverride: 1n },
    });
    expect(p2.request).toBeUndefined();
    await expect(
      new LazorKitClient(connection, PROGRAM_ID_DEVNET).prepareRevokeSession({
        ...base,
        secp256r1: { credentialIdHash: new Uint8Array(32), credentialId, publicKeyBytes: new Uint8Array(33), slotOverride: 1n },
      }),
    ).rejects.toThrow(/does not hash/);
    expect(A.APPROVAL_PROGRAM_ADDRESSES.devnet).toBe(PROGRAM_ADDRESS_DEVNET);
    expect(A.APPROVAL_PROGRAM_ADDRESSES.mainnet).toBe(PROGRAM_ADDRESS_MAINNET);
    expect(A.APPROVAL_MAX_SESSION_SECONDS).toBe(MAX_SESSION_SECONDS);
  });
});

// ─── 2. Codec ─────────────────────────────────────────────────────

function sampleRequest(kind: Kind = 'createSession', rng = new Rng(3)): A.ApprovalRequest {
  const c = randomCase(rng, kind, 0);
  return envelopeOf(c);
}

/** JSON text → encoded request, bypassing the encoder. */
const encodeText = (text: string) => Buffer.from(text, 'utf8').toString('base64url');
const textOf = (req: A.ApprovalRequest) => Buffer.from(A.encodeApprovalRequest(req), 'base64url').toString('utf8');

describe('envelope codec', () => {
  it('round-trips random requests of every kind, with and without minContextSlot', () => {
    const rng = new Rng(11);
    for (let i = 0; i < 1_000; i++) {
      const kind = KINDS[i % 3];
      const req = envelopeOf(randomCase(rng, kind, i));
      if (rng.bool()) req.minContextSlot = rng.int(2 ** 31);
      req.cluster = rng.bool() ? 'devnet' : 'mainnet';
      const enc = A.encodeApprovalRequest(req);
      expect(enc).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(A.decodeApprovalRequest(enc)).toEqual(req);
      expect(A.readApprovalFragment(A.approvalFragment(req))).toEqual(req);
    }
  });

  it('is canonical: keys in order, no spaces, the documented layout', () => {
    const req = sampleRequest('revokeSession');
    expect(textOf(req)).toBe(
      `{"v":1,"kind":"revokeSession","cluster":"devnet","programId":"${req.programId}","wallet":"${req.wallet}",` +
        `"authority":"${req.authority}","credentialId":"${req.credentialId}","payer":"${req.payer}",` +
        `"counter":${req.counter},"preparedSlot":"${req.preparedSlot}",` +
        `"args":{"session":"${(req as A.RevokeSessionRequest).args.session}","refund":"${(req as A.RevokeSessionRequest).args.refund}"}}`,
    );
  });

  const refusals: [string, (t: string, r: A.ApprovalRequest) => string, 'typed-malformed' | 'typed-unsupported'][] = [
    ['a space after a colon', (t) => t.replace('"v":1', '"v": 1'), 'typed-malformed'],
    ['keys reordered', (t) => t.replace('{"v":1,"kind":"createSession"', '{"kind":"createSession","v":1'), 'typed-malformed'],
    ['a duplicated key', (t) => t.replace('"v":1,', '"v":1,"v":1,'), 'typed-malformed'],
    ['counter as 7.0', (t, r) => t.replace(`"counter":${r.counter}`, `"counter":${r.counter}.0`), 'typed-malformed'],
    ['counter in exponent form', (t, r) => t.replace(`"counter":${r.counter}`, `"counter":${r.counter}e0`), 'typed-malformed'],
    ['counter as a string', (t, r) => t.replace(`"counter":${r.counter}`, `"counter":"${r.counter}"`), 'typed-malformed'],
    ['a negative counter', (t, r) => t.replace(`"counter":${r.counter}`, `"counter":-1`), 'typed-malformed'],
    ['counter above u32', (t, r) => t.replace(`"counter":${r.counter}`, `"counter":4294967296`), 'typed-malformed'],
    ['preparedSlot with a leading zero', (t, r) => t.replace(`"preparedSlot":"${r.preparedSlot}"`, `"preparedSlot":"0${r.preparedSlot}"`), 'typed-malformed'],
    ['preparedSlot above u64', (t, r) => t.replace(`"preparedSlot":"${r.preparedSlot}"`, `"preparedSlot":"18446744073709551616"`), 'typed-malformed'],
    ['preparedSlot as a number', (t, r) => t.replace(`"preparedSlot":"${r.preparedSlot}"`, `"preparedSlot":5`), 'typed-malformed'],
    ['expiresAt at 2^63', (t, r) => t.replace(`"expiresAt":"${(r as A.CreateSessionRequest).args.expiresAt}"`, `"expiresAt":"9223372036854775808"`), 'typed-malformed'],
    ['an unknown top-level key', (t) => t.replace('"v":1,', '"v":1,"x":1,'), 'typed-malformed'],
    ['an unknown args key', (t) => t.replace('"args":{', '"args":{"x":"1",'), 'typed-malformed'],
    ['a missing key', (t) => t.replace(/,"payer":"[^"]+"/, ''), 'typed-malformed'],
    ['__proto__ key', (t) => t.replace('"v":1,', '"v":1,"__proto__":{},'), 'typed-malformed'],
    ['version 2', (t) => t.replace('"v":1', '"v":2'), 'typed-unsupported'],
    ['version as a string', (t) => t.replace('"v":1', '"v":"1"'), 'typed-malformed'],
    ['kind execute', (t) => t.replace('"kind":"createSession"', '"kind":"execute"'), 'typed-unsupported'],
    ['cluster testnet', (t) => t.replace('"cluster":"devnet"', '"cluster":"testnet"'), 'typed-malformed'],
    ['an address with a leading 1 added', (t, r) => t.replace(`"payer":"${r.payer}"`, `"payer":"1${r.payer}"`), 'typed-malformed'],
    ['an address with a bad character', (t, r) => t.replace(`"payer":"${r.payer}"`, `"payer":"0${r.payer.slice(1)}"`), 'typed-malformed'],
    ['credentialId padded', (t, r) => t.replace(`"credentialId":"${r.credentialId}"`, `"credentialId":"${r.credentialId}=="`), 'typed-malformed'],
    ['credentialId in the standard alphabet', (t) => t.replace(/"credentialId":"[^"]*"/, '"credentialId":"ab+/"'), 'typed-malformed'],
    ['credentialId empty', (t) => t.replace(/"credentialId":"[^"]*"/, '"credentialId":""'), 'typed-malformed'],
    ['credentialId of 1024 bytes', (t) => t.replace(/"credentialId":"[^"]*"/, `"credentialId":"${b64url(new Uint8Array(1024))}"`), 'typed-malformed'],
    ['credentialId with non-zero trailing bits', (t) => t.replace(/"credentialId":"[^"]*"/, '"credentialId":"AB"'), 'typed-malformed'],
    ['actions not base64url', (t) => t.replace(/"actions":"[^"]*"/, '"actions":"!!"'), 'typed-malformed'],
    ['minContextSlot negative', (t) => t.replace('"preparedSlot"', '"minContextSlot":-5,"preparedSlot"'), 'typed-malformed'],
  ];

  for (const [name, mutate, code] of refusals) {
    it(`refuses ${name}`, () => {
      const req = sampleRequest('createSession');
      const text = textOf(req);
      const mutated = mutate(text, req);
      expect(mutated).not.toBe(text);
      try {
        A.decodeApprovalRequest(encodeText(mutated));
        expect.unreachable('decoded');
      } catch (e) {
        expect(e).toBeInstanceOf(A.ApprovalRequestError);
        expect((e as A.ApprovalRequestError).code).toBe(code);
      }
    });
  }

  it('refuses a non-canonical outer encoding: padding, standard alphabet, non-ASCII, trailing bits', () => {
    const enc = A.encodeApprovalRequest(sampleRequest());
    const std = Buffer.from(enc, 'base64url').toString('base64');
    expect(() => A.decodeApprovalRequest(std)).toThrow(A.ApprovalRequestError);
    expect(() => A.decodeApprovalRequest(enc + '=')).toThrow(A.ApprovalRequestError);
    expect(() => A.decodeApprovalRequest(encodeText(textOf(sampleRequest()).replace('devnet', 'dévnet')))).toThrow(
      A.ApprovalRequestError,
    );
    expect(() => A.decodeApprovalRequest('')).toThrow(A.ApprovalRequestError);
  });

  it('caps: decode refuses over 8,192 characters; encode throws TypedRequestTooLargeError, never truncates', () => {
    const big = sampleRequest() as A.CreateSessionRequest;
    big.args.actions = b64url(new Uint8Array(6_200));
    expect(() => A.approvalFragment(big)).toThrow(A.TypedRequestTooLargeError);
    expect(() => A.decodeApprovalRequest(A.encodeApprovalRequest(big))).toThrow(/over 8192/);
    const ok = sampleRequest();
    expect(() => A.withApprovalFragment('https://portal.lazor.sh/?' + 'x'.repeat(16_000), ok)).toThrow(
      A.TypedRequestTooLargeError,
    );
    expect(() => A.withApprovalFragment('https://portal.lazor.sh/#x', ok)).toThrow(/fragment/);
  });

  it('the largest valid request (16 TokenRecurringLimit, 1,023-byte credential) fits the cap', () => {
    const rng = new Rng(5);
    const actions = Buffer.concat(
      Array.from({ length: 16 }, () => {
        const d = new Uint8Array(64);
        d.set(rng.bytes(32), 0);
        d[48] = 1;
        return rawAction(5, 0n, d);
      }),
    );
    expect(A.decodeActions(actions)).toHaveLength(16);
    const req = sampleRequest() as A.CreateSessionRequest;
    req.credentialId = b64url(rng.bytes(1023));
    req.args.actions = b64url(actions);
    req.minContextSlot = Number.MAX_SAFE_INTEGER;
    const frag = A.approvalFragment(req);
    expect(frag.length).toBeLessThan(A.MAX_APPROVAL_REQUEST_CHARS);
    // With the same credential id in the query, the URL stays under 16,384.
    const url = A.withApprovalFragment(
      `https://portal.lazor.sh/?action=sign&message=${'A'.repeat(43)}&transaction=&credentialId=${encodeURIComponent(Buffer.from(rng.bytes(1023)).toString('base64'))}`,
      req,
    );
    expect(url.length).toBeLessThan(A.MAX_APPROVAL_URL_CHARS);
  });

  it('reads the fragment only in the #/?lk1= form; once lk1 appears, nothing else is accepted', () => {
    const req = sampleRequest('removeAuthority');
    const enc = A.encodeApprovalRequest(req);
    expect(A.readApprovalFragment('')).toBeNull();
    expect(A.readApprovalFragment('#/')).toBeNull();
    expect(A.readApprovalFragment('#/?open_in_browser=true')).toBeNull();
    expect(A.readApprovalFragment(`#/?lk1=${enc}`)).toEqual(req);
    expect(() => A.readApprovalFragment(`#lk1=${enc}`)).toThrow(A.ApprovalRequestError);
    expect(() => A.readApprovalFragment(`#/?lk1=${enc}&x=1`)).toThrow(A.ApprovalRequestError);
    expect(() => A.readApprovalFragment(`#/?x=1&lk1=${enc}`)).toThrow(A.ApprovalRequestError);
    expect(() => A.readApprovalFragment(`#/?lk1=${enc.slice(0, -3)}`)).toThrow(A.ApprovalRequestError);
  });
});

// ─── 3. Decoder ───────────────────────────────────────────────────

describe('decodeActions — the program’s validate_actions_buffer rules', () => {
  it('decodes 5,000 valid buffers to exactly what was written', () => {
    const rng = new Rng(21);
    for (let i = 0; i < 5_000; i++) {
      const buf = randomValidActions(rng);
      const decoded = A.decodeActions(buf);
      const parsed = parseActions(buf);
      expect(decoded).toHaveLength(parsed.length);
      decoded.forEach((d, j) => {
        expect(d.expiresAt).toBe(parsed[j].expiresAt);
        expect(A.ACTION_TYPE_IDS[d.type]).toBe(parsed[j].type);
        if ('mint' in d) expect(d.mint).toBe(parsed[j].mint!.toBase58());
      });
    }
  });

  const sol = (t: number, extra?: (d: Uint8Array) => void) => {
    const d = new Uint8Array(t === 2 ? 32 : 8);
    if (t === 2) d[16] = 1;
    extra?.(d);
    return rawAction(t, 0n, d);
  };
  const tok = (t: number, mint: number, extra?: (d: Uint8Array) => void) => {
    const d = new Uint8Array(t === 5 ? 64 : 40);
    d.fill(mint, 0, 32);
    if (t === 5) d[48] = 1;
    extra?.(d);
    return rawAction(t, 0n, d);
  };
  const prog = (t: number, id: number) => rawAction(t, 0n, new Uint8Array(32).fill(id));
  const cat = (...xs: Uint8Array[]) => Uint8Array.from(Buffer.concat(xs));

  const bad: [string, Uint8Array, A.ActionsProgramError][] = [
    ['a truncated header', cat(sol(1)).subarray(0, 5), 'ActionBufferInvalid'],
    ['trailing bytes', cat(sol(1), new Uint8Array([1])), 'ActionBufferInvalid'],
    ['data past the end', cat(sol(1)).subarray(0, 15), 'ActionBufferInvalid'],
    ['an unknown type', cat(rawAction(7, 0n, new Uint8Array(8))), 'ActionBufferInvalid'],
    ['a wrong data size', cat(rawAction(1, 0n, new Uint8Array(9))), 'ActionBufferInvalid'],
    ['17 actions', cat(...Array.from({ length: 17 }, (_, i) => prog(10, i + 1))), 'ActionBufferInvalid'],
    ['two SolLimit', cat(sol(1), sol(1)), 'ActionBufferInvalid'],
    ['two SolRecurringLimit', cat(sol(2), sol(2)), 'ActionBufferInvalid'],
    ['two SolMaxPerTx', cat(sol(3), sol(3)), 'ActionBufferInvalid'],
    ['two TokenLimit for one mint', cat(tok(4, 7), tok(4, 7)), 'ActionBufferInvalid'],
    ['two TokenMaxPerTx for one mint', cat(tok(6, 7), tok(6, 7)), 'ActionBufferInvalid'],
    ['recurring with spent', cat(sol(2, (d) => (d[8] = 1))), 'ActionBufferInvalid'],
    ['recurring with last_reset', cat(sol(2, (d) => (d[24] = 1))), 'ActionBufferInvalid'],
    ['recurring with a zero window', cat(sol(2, (d) => (d[16] = 0))), 'ActionBufferInvalid'],
    ['token recurring with spent', cat(tok(5, 3, (d) => (d[40] = 1))), 'ActionBufferInvalid'],
    ['whitelist with blacklist', cat(prog(10, 1), prog(11, 2)), 'ActionWhitelistBlacklistConflict'],
    ['whitelist with blacklist and a duplicate', cat(prog(10, 1), prog(11, 2), sol(1), sol(1)), 'ActionWhitelistBlacklistConflict'],
  ];
  for (const [name, buf, code] of bad) {
    it(`refuses ${name} (${code})`, () => {
      try {
        A.decodeActions(buf);
        expect.unreachable('decoded');
      } catch (e) {
        expect(e).toBeInstanceOf(A.ApprovalActionsError);
        expect((e as A.ApprovalActionsError).programError).toBe(code);
      }
    });
  }

  it('accepts what the program accepts: one mint across token types, 16 actions, an empty buffer', () => {
    expect(A.decodeActions(new Uint8Array())).toEqual([]);
    expect(A.decodeActions(cat(tok(4, 7), tok(5, 7), tok(6, 7)))).toHaveLength(3);
    expect(A.decodeActions(cat(...Array.from({ length: 16 }, (_, i) => prog(11, i + 1))))).toHaveLength(16);
  });

  it('readStoredActions keeps the live counters a decoder for creation refuses', () => {
    const live = cat(sol(2, (d) => { d[8] = 5; d[24] = 9; }));
    expect(() => A.decodeActions(live)).toThrow(A.ApprovalActionsError);
    const [a] = A.readStoredActions(live) as any[];
    expect(a.spent).toBe(5n);
    expect(a.lastReset).toBe(9n);
  });
});

// ─── 4. Replies, query, finalize, PDAs, encodings ─────────────────

function clientDataJson(challenge: Uint8Array | string, type = 'webauthn.get'): Uint8Array {
  const c = typeof challenge === 'string' ? challenge : b64url(challenge);
  return new Uint8Array(Buffer.from(JSON.stringify({ type, challenge: c, origin: 'https://portal.lazor.sh' })));
}

describe('replies', () => {
  const req = { ...sampleRequest('createSession'), preparedSlot: '1000', counter: 7 };
  const prepared = A.preparedBinding(req);
  const later = { slot: prepared.slot + 40n, counter: req.counter };

  it('a typed reply: the binding it names, checked against clientDataJSON', () => {
    const typed = A.typedReplyFor(req, later);
    const out = A.verifyApprovalReply(req, { clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed });
    expect(out).toEqual({ binding: later, typed: true, challenge: A.approvalChallenge(req, later) });
  });

  it('a typed reply at a later counter (another approval landed first) is accepted', () => {
    if (req.counter === U32_MAX) return;
    const fwd = { slot: later.slot, counter: req.counter + 1 };
    const out = A.verifyApprovalReply(req, {
      clientDataJson: clientDataJson(A.approvalChallenge(req, fwd)),
      typed: A.typedReplyFor(req, fwd),
    });
    expect(out.binding).toEqual(fwd);
  });

  it('an untyped reply (older portal) must carry the SDK’s own challenge', () => {
    const out = A.verifyApprovalReply(req, { clientDataJson: clientDataJson(A.approvalChallenge(req, prepared)) });
    expect(out).toMatchObject({ binding: prepared, typed: false });
    expect(() => A.verifyApprovalReply(req, { clientDataJson: clientDataJson(A.approvalChallenge(req, later)) })).toThrow(
      A.PortalReplyMismatchError,
    );
  });

  const mismatches: [string, () => Parameters<typeof A.verifyApprovalReply>[1]][] = [
    ['a challenge for other bytes', () => ({ clientDataJson: clientDataJson(new Uint8Array(32)), typed: A.typedReplyFor(req, later) })],
    ['typed slot not the one signed', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed: A.typedReplyFor(req, { ...later, slot: later.slot + 1n }) })],
    ['another kind', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed: { ...A.typedReplyFor(req, later), kind: 'revokeSession' } })],
    ['another sysvar index', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed: { ...A.typedReplyFor(req, later), sysvarIxIndex: 5 } })],
    ['a counter below the request', () => {
      const back = { slot: later.slot, counter: req.counter - 1 };
      return { clientDataJson: clientDataJson(A.approvalChallenge(req, back)), typed: A.typedReplyFor(req, back) };
    }],
    ['webauthn.create', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later), 'webauthn.create'), typed: A.typedReplyFor(req, later) })],
    ['not JSON', () => ({ clientDataJson: new Uint8Array([0x7b]), typed: A.typedReplyFor(req, later) })],
    ['typed with an extra key', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed: { ...A.typedReplyFor(req, later), extra: 1 } as any })],
    ['typed slot as a number', () => ({ clientDataJson: clientDataJson(A.approvalChallenge(req, later)), typed: { ...A.typedReplyFor(req, later), slot: 5 } as any })],
  ];
  for (const [name, reply] of mismatches) {
    it(`refuses ${name}`, () => {
      expect(() => A.verifyApprovalReply(req, reply())).toThrow(A.PortalReplyMismatchError);
    });
  }

  it('redirect parameters round-trip; some-but-not-all is refused; none is an untyped reply', () => {
    const t = A.typedReplyFor(req, later);
    const params = new URLSearchParams(A.typedReplyParams(t));
    expect(A.parseTypedReplyParams((n) => params.get(n))).toEqual(t);
    params.delete('typedSlot');
    expect(() => A.parseTypedReplyParams((n) => params.get(n))).toThrow(A.PortalReplyMismatchError);
    expect(A.parseTypedReplyParams(() => null)).toBeUndefined();
    const bad = new URLSearchParams({ ...A.typedReplyParams(t), typedCounter: '01' });
    expect(() => A.parseTypedReplyParams((n) => bad.get(n))).toThrow(A.PortalReplyMismatchError);
  });
});

describe('checkApprovalQuery (portal, before showing anything)', () => {
  const credentialId = new Uint8Array(Buffer.from('a-credential-id-of-some-length'));
  const wallet = new PublicKey(new Uint8Array(32).fill(4));
  const [authority] = findAuthorityPda(wallet, sha256(credentialId), PROGRAM_ID_DEVNET);
  const req: A.ApprovalRequest = {
    v: 1,
    kind: 'revokeSession',
    cluster: 'devnet',
    programId: PROGRAM_ADDRESS_DEVNET,
    wallet: wallet.toBase58(),
    authority: authority.toBase58(),
    credentialId: b64url(credentialId),
    payer: addr(new Uint8Array(32).fill(5)),
    counter: 3,
    preparedSlot: '1000',
    args: { session: addr(new Uint8Array(32).fill(6)), refund: addr(new Uint8Array(32).fill(5)) },
  };
  const message = b64url(A.approvalChallenge(req, A.preparedBinding(req)));
  const queryCred = Buffer.from(credentialId).toString('base64'); // what 3.4.1 puts in the query

  it('accepts the SDK’s query: base64 credential id, base64url message', () => {
    expect(A.checkApprovalQuery(req, { message, credentialId: queryCred })).toEqual({ ok: true });
    expect(A.checkApprovalQuery(req, { message: Buffer.from(message, 'base64url').toString('base64'), credentialId: b64url(credentialId) })).toEqual({ ok: true });
  });
  it('refuses another credential, an authority not derived from it, another message', () => {
    expect(A.checkApprovalQuery(req, { message, credentialId: 'AAAA' })).toMatchObject({ reason: 'credential-id-mismatch' });
    expect(A.checkApprovalQuery({ ...req, authority: req.wallet }, { message, credentialId: queryCred })).toMatchObject({ reason: 'authority-not-derived' });
    expect(A.checkApprovalQuery({ ...req, counter: 4 }, { message, credentialId: queryCred })).toMatchObject({ reason: 'message-mismatch' });
    expect(A.checkApprovalQuery(req, { message: null, credentialId: queryCred })).toMatchObject({ code: 'challenge-mismatch' });
  });
});

describe('finalize with a binding', () => {
  it('rebinds the auth payload to the portal’s slot and counter, and refuses a response for another binding', async () => {
    const connection = stubConnection(() => 10);
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const credentialId = new Uint8Array([9, 9, 9]);
    const prepared = await client.prepareRevokeSession({
      payer: new PublicKey(new Uint8Array(32).fill(1)),
      walletPda: new PublicKey(new Uint8Array(32).fill(2)),
      sessionPda: new PublicKey(new Uint8Array(32).fill(3)),
      secp256r1: { credentialIdHash: sha256(credentialId), credentialId, publicKeyBytes: new Uint8Array(33).fill(2), slotOverride: 500n },
    });
    const req = prepared.request!;
    const binding = { slot: 640n, counter: 12 };
    const response = {
      signature: new Uint8Array(64),
      authenticatorData: new Uint8Array(37),
      clientDataJson: clientDataJson(A.approvalChallenge(req, binding)),
      clientDataJsonHash: new Uint8Array(32),
    };
    const { instructions } = client.finalizeRevokeSession(prepared, response, binding);
    const data = Buffer.from(instructions[1].data);
    // [disc(1)][auth payload: slot(8) counter(4) sysvar(1) reserved(1) ...]
    expect(data.readBigUInt64LE(1)).toBe(640n);
    expect(data.readUInt32LE(9)).toBe(12);
    expect(data[13]).toBe(5);
    // The same response finalized without the binding (or with another) is refused / unbound.
    expect(() => client.finalizeRevokeSession(prepared, response, { slot: 641n, counter: 12 })).toThrow(A.PortalReplyMismatchError);
    const unbound = client.finalizeRevokeSession(prepared, response);
    expect(Buffer.from(unbound.instructions[1].data).readBigUInt64LE(1)).toBe(500n);
  });
});

describe('PDAs and encodings without web3.js', () => {
  it('match PublicKey.findProgramAddressSync on 300 random seeds', () => {
    const rng = new Rng(31);
    for (let i = 0; i < 300; i++) {
      const programId = i % 2 ? PROGRAM_ID_DEVNET : new PublicKey(rng.bytes(32));
      const wallet = new PublicKey(rng.bytes(32));
      const key = rng.bytes(32);
      expect(A.findAuthorityAddress(wallet.toBase58(), key, programId.toBase58())).toBe(findAuthorityPda(wallet, key, programId)[0].toBase58());
      expect(A.findSessionAddress(wallet.toBytes(), key, programId.toBytes())).toBe(findSessionPda(wallet, key, programId)[0].toBase58());
      expect(A.findVaultAddress(wallet.toBase58(), programId.toBase58())).toBe(findVaultPda(wallet, programId)[0].toBase58());
    }
  });

  it('base58 and base64url agree with web3.js and Buffer, and decode canonically', () => {
    const rng = new Rng(41);
    for (let i = 0; i < 2_000; i++) {
      const k = rng.bytes(32);
      if (i % 7 === 0) k.fill(0, 0, rng.int(5));
      const s = new PublicKey(k).toBase58();
      expect(A.base58Encode(k)).toBe(s);
      expect(Buffer.from(A.decodeAddress(s)!).equals(Buffer.from(k))).toBe(true);
      const b = rng.bytes(rng.int(70));
      expect(A.base64urlEncode(b)).toBe(Buffer.from(b).toString('base64url'));
      expect(Buffer.from(A.base64urlDecode(A.base64urlEncode(b))!).equals(Buffer.from(b))).toBe(true);
    }
    expect(A.decodeAddress('1' + new PublicKey(rng.bytes(32)).toBase58())).toBeUndefined();
    expect(A.decodeAddress('11111111111111111111111111111111')).toBeDefined();
  });
});

// ─── Transaction size ─────────────────────────────────────────────

describe('passkey CreateSession size', () => {
  const blockhash = new PublicKey(new Uint8Array(32).fill(0xbb)).toBase58();

  /** The transaction finalizeCreateSession gives, serialized both ways. */
  async function built(actions: SessionAction[], authData: number, clientData: number) {
    const client = new LazorKitClient(stubConnection(() => 3), PROGRAM_ID_DEVNET);
    const credentialId = new Uint8Array([9, 9, 9]);
    const payer = new PublicKey(new Uint8Array(32).fill(0x21));
    const prepared = await client.prepareCreateSession({
      payer,
      walletPda: new PublicKey(new Uint8Array(32).fill(0x31)),
      // No credential id: no request, so no size check; this measures.
      secp256r1: { credentialIdHash: sha256(credentialId), publicKeyBytes: new Uint8Array(33).fill(2), slotOverride: 5n },
      sessionKey: new PublicKey(new Uint8Array(32).fill(0x41)),
      expiresAt: A.MIN_UNIX_SECONDS + 1n,
      ...(actions.length ? { actions } : { unrestricted: true }),
    });
    const { instructions } = client.finalizeCreateSession(prepared, {
      signature: new Uint8Array(64).fill(1),
      authenticatorData: new Uint8Array(authData).fill(2),
      clientDataJsonHash: new Uint8Array(32).fill(3),
      clientDataJson: new Uint8Array(clientData).fill(0x61),
    });
    const legacy = new Transaction({ feePayer: payer, recentBlockhash: blockhash }).add(...instructions);
    const v0 = new VersionedTransaction(
      new TransactionMessage({ payerKey: payer, recentBlockhash: blockhash, instructions }).compileToV0Message(),
    );
    return { legacy: 1 + 64 + legacy.serializeMessage().length, v0: v0.serialize().length };
  }

  it('createSessionTransactionBytes is the size of the transaction the SDK builds (v0; legacy is 2 less)', async () => {
    // web3.js serializes into a buffer of about the limit, so the cases are
    // drawn to fit; the limit itself is the next test.
    const rng = new Rng(1232);
    let measured = 0;
    for (let i = 0; i < 400; i++) {
      const { actions, buffer } = sdkActions(rng);
      const authData = rng.pick([37, 37, 69, 120]);
      const clientData = rng.pick([40, 120, 180, 256, 320, 400]);
      const estimate = A.createSessionTransactionBytes(buffer.length, {
        authenticatorDataBytes: authData,
        clientDataJsonBytes: clientData,
      });
      if (estimate > A.MAX_TRANSACTION_BYTES) continue;
      const size = await built(actions, authData, clientData);
      expect(size.v0, `case ${i}`).toBe(estimate);
      expect(size.legacy, `case ${i}`).toBe(estimate - 2);
      measured++;
    }
    expect(measured).toBeGreaterThan(100);
  });

  it('the most actions that fit with the assumed WebAuthn lengths', () => {
    const max = A.MAX_PASSKEY_SESSION_ACTIONS_BYTES;
    expect(max).toBe(224);
    expect(A.createSessionFits(max)).toBe(true);
    expect(A.createSessionFits(max + 1)).toBe(false);
    expect(A.createSessionTransactionBytes(max)).toBe(A.MAX_TRANSACTION_BYTES);
  });

  it('at the limit, the transaction the SDK builds is exactly 1,232 bytes, and one more byte is over', async () => {
    // SolMaxPerTx (19 bytes) and TokenLimit (51) actions, then clientDataJSON
    // grown until the estimate is the limit: web3.js agrees byte for byte.
    const actions: SessionAction[] = [
      { type: 3, max: 1n },
      ...Array.from({ length: 3 }, (_, k): SessionAction => ({ type: 4, mint: new PublicKey(new Uint8Array(32).fill(k + 1)), remaining: 1n })),
    ];
    let clientData = 100;
    while (A.createSessionTransactionBytes(172, { clientDataJsonBytes: clientData + 1 }) <= A.MAX_TRANSACTION_BYTES) clientData++;
    expect(A.createSessionTransactionBytes(172, { clientDataJsonBytes: clientData })).toBe(A.MAX_TRANSACTION_BYTES);
    const size = await built(actions, 37, clientData);
    expect(size.v0).toBe(A.MAX_TRANSACTION_BYTES);
    expect((await built(actions, 37, clientData + 1)).v0).toBe(A.MAX_TRANSACTION_BYTES + 1);
  });

  it('prepareCreateSession refuses, with a credential id, what could not be sent once signed', async () => {
    const client = new LazorKitClient(stubConnection(() => 3), PROGRAM_ID_DEVNET);
    const credentialId = new Uint8Array([1, 2, 3]);
    const mint = (k: number) => new PublicKey(new Uint8Array(32).fill(k));
    const args = (n: number) => ({
      payer: new PublicKey(new Uint8Array(32).fill(0x21)),
      walletPda: new PublicKey(new Uint8Array(32).fill(0x31)),
      secp256r1: { credentialIdHash: sha256(credentialId), credentialId, publicKeyBytes: new Uint8Array(33).fill(2), slotOverride: 5n },
      sessionKey: new PublicKey(new Uint8Array(32).fill(0x41)),
      expiresAt: A.MIN_UNIX_SECONDS + 1n,
      // TokenLimit actions, 51 bytes each.
      actions: Array.from({ length: n }, (_, k): SessionAction => ({ type: 4, mint: mint(k + 1), remaining: 1n })),
    });
    const fits = await client.prepareCreateSession(args(4));
    expect(fits.request).toBeDefined();
    const err = await client.prepareCreateSession(args(5)).catch((e) => e);
    expect(err).toBeInstanceOf(A.TransactionTooLargeError);
    expect(err).toMatchObject({ code: 'transaction-too-large', limit: 1232, bytes: A.createSessionTransactionBytes(255) });
    // Without a credential id, nothing changes for existing callers.
    const { secp256r1, ...rest } = args(5);
    const bare = await client.prepareCreateSession({ ...rest, secp256r1: { ...secp256r1, credentialId: undefined } });
    expect(bare.request).toBeUndefined();
  });
});

// ─── describeApproval ─────────────────────────────────────────────

const PID = PROGRAM_ADDRESS_DEVNET;
const NOW = 1_791_072_000n;
const SLOT = 400_000_000n;
const FEATURES = ['wallet-bound-challenge', 'd13', 'nonowner-invariants', 'time-expiry'];
const USDC = addr(new Uint8Array(32).fill(0x55));
const OTHER = addr(new Uint8Array(32).fill(0x66));

function snap(owner: string, data: Uint8Array, lamports = 1_000_000n): A.AccountSnapshot {
  return { owner, data, lamports };
}
function clockSnap(): A.AccountSnapshot {
  const d = Buffer.alloc(40);
  d.writeBigUInt64LE(SLOT, 0);
  d.writeBigInt64LE(NOW, 32);
  return snap('Sysvar1111111111111111111111111111111111111', d);
}
function walletSnap(owners = 1): A.AccountSnapshot {
  const d = Buffer.alloc(8);
  d[0] = 0x21;
  d[2] = 1;
  d.writeUInt32LE(owners, 4);
  return snap(PID, d);
}
function authoritySnap(o: { wallet: string; role?: number; passkey?: boolean; credHash?: Uint8Array; policy?: Uint8Array; counter?: number }): A.AccountSnapshot {
  const policy = o.policy ?? new Uint8Array();
  const keyLen = o.passkey === false ? 32 : 97;
  const d = Buffer.alloc(48 + keyLen + policy.length);
  d[0] = 0x22;
  d[1] = o.passkey === false ? 0 : 1;
  d[2] = o.role ?? 0;
  d[4] = 1;
  d.writeUInt32LE(o.counter ?? 6, 8);
  d.writeUInt16LE(policy.length, 12);
  Buffer.from(new PublicKey(o.wallet).toBytes()).copy(d, 16);
  if (o.passkey === false) d.fill(7, 48, 80);
  else Buffer.from(o.credHash ?? new Uint8Array(32)).copy(d, 48);
  Buffer.from(policy).copy(d, 48 + keyLen);
  return snap(PID, d);
}
function sessionSnap(wallet: string, expiresAt: bigint, actions: Uint8Array = new Uint8Array()): A.AccountSnapshot {
  const d = Buffer.alloc(80 + actions.length);
  d[0] = 0x23;
  d[2] = 1;
  Buffer.from(new PublicKey(wallet).toBytes()).copy(d, 8);
  d.fill(8, 40, 72);
  d.writeBigUInt64LE(expiresAt, 72);
  Buffer.from(actions).copy(d, 80);
  return snap(PID, d);
}
function mintSnap(decimals: number): A.AccountSnapshot {
  const d = Buffer.alloc(82);
  d[44] = decimals;
  d[45] = 1;
  return snap(A.SPL_TOKEN_PROGRAM_ADDRESS, d);
}

describe('describeApproval', () => {
  const credentialId = new Uint8Array([1, 2, 3, 4]);
  const credHash = sha256(credentialId);
  const wallet = addr(new Uint8Array(32).fill(0x11));
  const authority = A.findAuthorityAddress(wallet, credHash, PID);
  const payer = addr(new Uint8Array(32).fill(0x22));
  const base = {
    v: 1 as const,
    cluster: 'devnet' as const,
    programId: PID,
    wallet,
    authority,
    credentialId: b64url(credentialId),
    payer,
    counter: 7,
    preparedSlot: SLOT.toString(),
  };
  const lamports = (n: bigint) => { const d = new Uint8Array(8); for (let i = 0; i < 8; i++) d[i] = Number((n >> BigInt(8 * i)) & 0xffn); return d; };
  const solLimit = (n: bigint, exp = 0n) => rawAction(1, exp, lamports(n));
  const solMax = (n: bigint) => rawAction(3, 0n, lamports(n));
  const solMaxAt = (n: bigint, exp: bigint) => rawAction(3, exp, lamports(n));
  const tokLimit = (mint: string, n: bigint) => rawAction(4, 0n, Uint8Array.from([...new PublicKey(mint).toBytes(), ...lamports(n)]));
  const tokRecurring = (mint: string, n: bigint, w: bigint) => { const d = new Uint8Array(64); d.set(new PublicKey(mint).toBytes()); d.set(lamports(n), 32); d.set(lamports(w), 48); return rawAction(5, 0n, d); };
  const whitelist = (id: string) => rawAction(10, 0n, new PublicKey(id).toBytes());
  const create = (actions: Uint8Array[], expiresAt = NOW + 3_600n): A.CreateSessionRequest => ({
    ...base,
    kind: 'createSession',
    args: { sessionKey: addr(new Uint8Array(32).fill(0x33)), expiresAt: expiresAt.toString(), actions: b64url(Buffer.concat(actions)) },
  });
  const view = (extra: Partial<A.ApprovalChainView> = {}): A.ApprovalChainView => ({
    clock: clockSnap(),
    wallet: walletSnap(),
    authority: authoritySnap({ wallet, credHash }),
    session: null,
    mints: { [USDC]: mintSnap(6), [OTHER]: mintSnap(9) },
    vault: { lamports: 1_250_000_000n, tokens: { [USDC]: 5_000_000n } },
    ...extra,
  });
  const opts = { features: FEATURES, knownMints: { [USDC]: { decimals: 6 } } };
  const ok = (c: A.ApprovalCheck) => {
    if (!c.ok) throw new Error(`refused: ${c.code} ${c.reason}`);
    return c.description;
  };

  it('the read plan names the would-be session and the mints the actions name', () => {
    const plan = A.approvalReadPlan(create([tokLimit(USDC, 5n), solLimit(1n)]));
    expect(plan.session).toBe(A.findSessionAddress(wallet, addr(new Uint8Array(32).fill(0x33)), PID));
    expect(plan.mints).toEqual([USDC]);
    expect(plan.clock).toBe(A.CLOCK_SYSVAR_ADDRESS);
    expect(plan.vault).toBe(A.findVaultAddress(wallet, PID));
  });

  it('session-create: totals for SOL and a listed token, with expiry and balances', () => {
    const d = ok(A.describeApproval(create([solLimit(20_000_000n), solMax(2_000_000n), tokLimit(USDC, 5_000_000n)]), view(), opts)) as A.CreateSessionDescription;
    expect(d.screen).toBe('session-create');
    expect(d.variant).toBe('totals');
    expect(d.secondsLeft).toBe(3_600n);
    expect(d.assets[0]).toMatchObject({ asset: { kind: 'sol' }, hasTotal: true, lifetime: { amount: 20_000_000n }, perPayment: { amount: 2_000_000n }, balance: 1_250_000_000n });
    expect(d.assets[1]).toMatchObject({ asset: { kind: 'token', mint: USDC }, token: { decimals: 6, listed: true, readable: true }, balance: 5_000_000n });
    expect(d.otherAssetsBlocked).toBe(true);
    expect(d.uncapped).toEqual([]);
  });

  it('session-no-total: a per-payment cap only', () => {
    const d = ok(A.describeApproval(create([solMax(2_000_000n)]), view(), opts)) as A.CreateSessionDescription;
    expect(d.screen).toBe('session-no-total');
    expect(d.uncapped).toEqual([{ kind: 'sol' }]);
  });

  it('session-no-limits: no actions; can give the account away only without non-owner invariants', () => {
    const d = ok(A.describeApproval(create([]), view(), opts)) as A.CreateSessionDescription;
    expect(d.screen).toBe('session-no-limits');
    expect(d.canGiveAccountAway).toBe(false);
    const old = ok(A.describeApproval(create([]), view(), { features: ['time-expiry', 'd13'] })) as A.CreateSessionDescription;
    expect(old.canGiveAccountAway).toBe(true);
  });

  it('tokens-only and no-spend variants, on a D13 binary; without D13 the unnamed assets are uncapped', () => {
    expect((ok(A.describeApproval(create([tokRecurring(USDC, 5n, 86_400n)]), view(), opts)) as A.CreateSessionDescription).variant).toBe('tokens-only');
    expect((ok(A.describeApproval(create([whitelist(OTHER)]), view(), opts)) as A.CreateSessionDescription).variant).toBe('no-spend');
    const noD13 = ok(A.describeApproval(create([whitelist(OTHER)]), view(), { features: ['time-expiry'] })) as A.CreateSessionDescription;
    expect(noD13.screen).toBe('session-no-total');
    expect(noD13.uncapped).toEqual([{ kind: 'sol' }, { kind: 'unnamed-tokens' }]);
  });

  it('an action that ends before the session, an expired one, a zero limit', () => {
    const d = ok(A.describeApproval(create([solLimit(5n, NOW + 60n), tokLimit(USDC, 0n)]), view(), opts)) as A.CreateSessionDescription;
    expect(d.assets[0].lifetime).toMatchObject({ endsBeforeSession: true, expired: false });
    expect(d.assets[1].cannotSpend).toBe(true);
    const e = ok(A.describeApproval(create([solLimit(5n, NOW - 1n)]), view(), opts)) as A.CreateSessionDescription;
    expect(e.assets[0]).toMatchObject({ cannotSpend: true, lifetime: { expired: true } });
  });

  it('an unlisted mint takes the read decimals; an unreadable one is flagged; a listed one must agree', () => {
    const d = ok(A.describeApproval(create([tokLimit(OTHER, 1n)]), view(), opts)) as A.CreateSessionDescription;
    expect(d.assets[0].token).toMatchObject({ decimals: 9, listed: false, readable: true });
    const missing = ok(A.describeApproval(create([tokLimit(OTHER, 1n)]), view({ mints: { [OTHER]: null } }), opts)) as A.CreateSessionDescription;
    expect(missing.unreadableMints).toEqual([OTHER]);
    expect(A.describeApproval(create([tokLimit(USDC, 1n)]), view({ mints: { [USDC]: mintSnap(9) } }), opts)).toMatchObject({ ok: false, reason: 'mint-decimals-mismatch' });
  });

  const refusals: [string, () => A.ApprovalCheck, string, string][] = [
    ['features unknown', () => A.describeApproval(create([]), view(), { features: null }), 'wrong-network', 'features-unknown'],
    ['no time-expiry', () => A.describeApproval(create([]), view(), { features: ['d13'] }), 'wrong-network', 'feature-missing'],
    ['expiry in the past', () => A.describeApproval(create([], NOW), view(), opts), 'request-invalid', 'expiry-not-after-now'],
    ['expiry past 30 days', () => A.describeApproval(create([], NOW + 2_592_001n), view(), opts), 'request-invalid', 'expiry-too-far'],
    ['invalid actions', () => A.describeApproval(create([solLimit(1n), solLimit(1n)]), view(), opts), 'request-invalid', 'actions-invalid'],
    ['whitelist + blacklist', () => A.describeApproval(create([whitelist(OTHER), rawAction(11, 0n, new Uint8Array(32))]), view(), opts), 'request-invalid', 'actions-whitelist-blacklist'],
    ['too large to send once signed', () => A.describeApproval(create([1, 2, 3].map((k) => tokRecurring(addr(new Uint8Array(32).fill(k)), 5n, 60n))), view(), opts), 'request-invalid', 'transaction-too-large'],
    ['session exists', () => A.describeApproval(create([]), view({ session: sessionSnap(wallet, NOW) }), opts), 'request-invalid', 'session-exists'],
    ['wallet missing', () => A.describeApproval(create([]), view({ wallet: null }), opts), 'request-invalid', 'wallet-missing'],
    ['authority missing', () => A.describeApproval(create([]), view({ authority: null }), opts), 'request-invalid', 'authority-missing'],
    ['authority ed25519', () => A.describeApproval(create([]), view({ authority: authoritySnap({ wallet, passkey: false }) }), opts), 'request-invalid', 'authority-not-passkey'],
    ['authority of another wallet', () => A.describeApproval(create([]), view({ authority: authoritySnap({ wallet: payer, credHash }) }), opts), 'request-invalid', 'authority-wrong-wallet'],
    ['authority of another credential', () => A.describeApproval(create([]), view({ authority: authoritySnap({ wallet }) }), opts), 'request-invalid', 'authority-wrong-credential'],
    ['a delegate signer', () => A.describeApproval(create([]), view({ authority: authoritySnap({ wallet, credHash, role: 2 }) }), opts), 'request-invalid', 'authority-role'],
    ['a bounded admin', () => A.describeApproval(create([]), view({ authority: authoritySnap({ wallet, credHash, role: 1, policy: solLimit(1n) }) }), opts), 'request-invalid', 'authority-has-policy'],
    ['payer is the vault', () => A.describeApproval({ ...create([]), payer: A.findVaultAddress(wallet, PID) }, view(), opts), 'request-invalid', 'payer-is-program-account'],
  ];
  for (const [name, run, code, reason] of refusals) {
    it(`createSession refuses: ${name}`, () => {
      expect(run()).toEqual({ ok: false, code, reason });
    });
  }

  describe('revokeSession', () => {
    const session = addr(new Uint8Array(32).fill(0x44));
    const revoke = (refund = payer): A.RevokeSessionRequest => ({ ...base, kind: 'revokeSession', args: { session, refund } });

    it('describes what is left, the end time in seconds, and where the deposit goes', () => {
      const live = (() => { const d = new Uint8Array(32); d.set(lamports(10n), 0); d.set(lamports(4n), 8); d.set(lamports(86_400n), 16); d.set(lamports(NOW - 100n), 24); return rawAction(2, 0n, d); })();
      const d = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, NOW + 600n, live) }), opts)) as A.RevokeSessionDescription;
      expect(d).toMatchObject({ expiresAtUnit: 'seconds', ended: false, refundIsPayer: true, unrestricted: false });
      expect(d.policy!.assets[0].recurring).toMatchObject({ amount: 10n, spent: 4n, leftInWindow: 6n });
      const ended = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, NOW - 1n) }), opts)) as A.RevokeSessionDescription;
      expect(ended.ended).toBe(true);
      const unknown = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, NOW - 1n) }), { features: null })) as A.RevokeSessionDescription;
      expect(unknown).toMatchObject({ expiresAtUnit: 'unknown', ended: undefined });
    });

    // A recurring SOL limit as stored: limit 10, spent 4, window, last reset.
    const stored = (window: bigint, lastReset: bigint, expiresAt = 0n) => {
      const d = new Uint8Array(32);
      d.set(lamports(10n), 0);
      d.set(lamports(4n), 8);
      d.set(lamports(window), 16);
      d.set(lamports(lastReset), 24);
      return rawAction(2, expiresAt, d);
    };

    it('with time-expiry, every stored time is Unix seconds: a slot an earlier build stored has ended', () => {
      const d = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, SLOT + 6_480_000n, stored(86_400n, NOW - 100n, SLOT + 1_000n)) }), opts)) as A.RevokeSessionDescription;
      expect(d).toMatchObject({ expiresAtUnit: 'seconds', ended: true });
      expect(d.policy!.timeUnit).toBe('seconds');
      expect(d.policy!.assets[0].recurring).toMatchObject({ expired: true, leftInWindow: 0n });
    });

    it('without time-expiry, the session, its actions and windows are slots, read against the clock’s slot', () => {
      const slotBinary = { features: ['wallet-bound-challenge', 'd13', 'nonowner-invariants'] };
      const live = sessionSnap(wallet, SLOT + 600n, Buffer.concat([stored(9_000n, SLOT - 100n), solMaxAt(3n, SLOT + 50n)]));
      const d = ok(A.describeApproval(revoke(), view({ session: live }), slotBinary)) as A.RevokeSessionDescription;
      expect(d).toMatchObject({ expiresAtUnit: 'slot', ended: false });
      expect(d.policy!.timeUnit).toBe('slot');
      expect(d.policy!.assets[0].recurring).toMatchObject({ expired: false, spent: 4n, leftInWindow: 6n });
      expect(d.policy!.assets[0].perPayment).toMatchObject({ amount: 3n, expired: false });
      expect(d.policy!.assets[0].cannotSpend).toBe(false);
      // A window of 50 slots opened 100 slots ago has restarted.
      const reset = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, SLOT + 600n, stored(50n, SLOT - 100n)) }), slotBinary)) as A.RevokeSessionDescription;
      expect(reset.policy!.assets[0].recurring!.leftInWindow).toBe(10n);
      const over = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, SLOT - 1n) }), slotBinary)) as A.RevokeSessionDescription;
      expect(over.ended).toBe(true);
    });

    it('with unknown features, no policy time is judged', () => {
      const d = ok(A.describeApproval(revoke(), view({ session: sessionSnap(wallet, NOW + 600n, stored(86_400n, NOW - 100n, 1n)) }), { features: null })) as A.RevokeSessionDescription;
      expect(d.policy!.timeUnit).toBe('unknown');
      expect(d.policy!.assets[0].recurring!.expired).toBe(false);
      expect(d.policy!.assets[0].recurring!.leftInWindow).toBeUndefined();
      expect(d.policy!.assets[0].cannotSpend).toBe(false);
    });
    it('refuses a missing session, another wallet’s, a refund to the session itself', () => {
      expect(A.describeApproval(revoke(), view({ session: null }), opts)).toMatchObject({ reason: 'session-missing' });
      expect(A.describeApproval(revoke(), view({ session: sessionSnap(payer, NOW) }), opts)).toMatchObject({ reason: 'session-wrong-wallet' });
      expect(A.describeApproval(revoke(session), view({ session: sessionSnap(wallet, NOW) }), opts)).toMatchObject({ reason: 'refund-is-program-account' });
    });
  });

  describe('removeAuthority', () => {
    const target = addr(new Uint8Array(32).fill(0x77));
    const remove = (t = target): A.RemoveAuthorityRequest => ({ ...base, kind: 'removeAuthority', args: { target: t, refund: payer } });

    it('describes the target and who keeps full control', () => {
      const d = ok(A.describeApproval(remove(), view({ wallet: walletSnap(2), target: authoritySnap({ wallet, credHash: new Uint8Array(32).fill(1) }) }), opts)) as A.RemoveAuthorityDescription;
      expect(d).toMatchObject({ targetType: 'passkey', targetRole: 'owner', ownerCount: 2, ownersAfter: 1 });
      const key = ok(A.describeApproval(remove(), view({ target: authoritySnap({ wallet, passkey: false, role: 2, policy: solLimit(5n) }) }), opts)) as A.RemoveAuthorityDescription;
      expect(key).toMatchObject({ targetType: 'ed25519', targetRole: 'delegate', targetPublicKey: addr(new Uint8Array(32).fill(7)) });
      expect(key.targetPolicy!.assets[0].lifetime!.amount).toBe(5n);
      expect(key.targetPolicy!.timeUnit).toBe('seconds');
    });
    it('reads the target’s policy times in the binary’s unit', () => {
      const target = authoritySnap({ wallet, passkey: false, role: 2, policy: solLimit(5n, SLOT + 50n) });
      const slotBinary = ok(A.describeApproval(remove(), view({ target }), { features: ['d13'] })) as A.RemoveAuthorityDescription;
      expect(slotBinary.targetPolicy).toMatchObject({ timeUnit: 'slot' });
      expect(slotBinary.targetPolicy!.assets[0].lifetime).toMatchObject({ amount: 5n, expired: false });
      const timeBinary = ok(A.describeApproval(remove(), view({ target }), opts)) as A.RemoveAuthorityDescription;
      expect(timeBinary.targetPolicy!.assets[0].lifetime).toMatchObject({ expired: true });
    });
    it('refuses the last owner, the signer itself, an owner by an admin, a missing target', () => {
      expect(A.describeApproval(remove(), view({ target: authoritySnap({ wallet, credHash: new Uint8Array(32).fill(1) }) }), opts)).toMatchObject({ reason: 'last-owner' });
      expect(A.describeApproval(remove(authority), view({ target: authoritySnap({ wallet, credHash }) }), opts)).toMatchObject({ reason: 'target-is-signer' });
      expect(A.describeApproval(remove(), view({ wallet: walletSnap(3), authority: authoritySnap({ wallet, credHash, role: 1 }), target: authoritySnap({ wallet, role: 0 }) }), opts)).toMatchObject({ reason: 'target-not-removable' });
      expect(A.describeApproval(remove(), view({ target: null }), opts)).toMatchObject({ reason: 'target-missing' });
    });
  });
});

// ─── 5. Bundle ────────────────────────────────────────────────────

describe('bundle: @lazorkit/sdk-legacy/approval alone', () => {
  for (const target of [
    { name: 'browser', conditionNames: ['browser', 'import', 'default'] },
    { name: 'React Native', conditionNames: ['react-native', 'browser', 'require', 'default'] },
  ]) {
    it(`bundles for ${target.name} with only @noble/hashes and @noble/curves`, async () => {
      const { rolldown } = await import('rolldown');
      const input = path.resolve(__dirname, '../../sdk/sdk-legacy/src/approval/index.ts');
      const bundle = await rolldown({
        input,
        platform: 'browser',
        resolve: {
          conditionNames: target.conditionNames,
          modules: [path.resolve(__dirname, '../../sdk/sdk-legacy/node_modules'), 'node_modules'],
        },
      });
      const { output } = await bundle.generate({ format: 'esm' });
      await bundle.close();
      const ids = output.flatMap((o) => ('moduleIds' in o ? o.moduleIds : []));
      const packages = new Set(
        ids
          .map((id) => id.match(/node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)/)?.[1]?.replace(/\\/g, '/'))
          .filter(Boolean),
      );
      expect([...packages].sort()).toEqual(['@noble/curves', '@noble/hashes']);
      const outside = ids.filter((id) => !id.includes('node_modules') && !id.includes(`${path.sep}approval${path.sep}`));
      expect(outside).toEqual([]);
      const code = output.map((o) => ('code' in o ? o.code : '')).join('\n');
      expect(code).not.toMatch(/from\s+["'](buffer|crypto|@solana\/web3\.js|node:)/);
    });
  }
});
