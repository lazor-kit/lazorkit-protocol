/**
 * Which wallet is a returning passkey's own.
 *
 * The credential-id hash is public and `CreateWallet` / `AddAuthority` take any
 * key without its consent, so a lookup by hash can return a wallet someone else
 * planted. These tests pin the rule that replaces it: a candidate counts only
 * if a fresh assertion verifies against the key stored on it, and it is adopted
 * without asking only if nothing untrusted can spend from it and it is the one
 * wallet the passkey has signed for (a wallet handed to it can hide what its
 * earlier holder did to the vault, and the passkey challenge does not name the
 * wallet, so a signature replays from one wallet onto another).
 *
 * The first half runs without a validator (pure functions and a stubbed
 * Connection); the second half runs against the one at RPC_URL.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  Connection,
  Keypair,
  PublicKey,
  SolanaJSONRPCError,
  SystemProgram,
  TransactionInstruction,
  type AccountInfo,
} from '@solana/web3.js';
import * as crypto from 'crypto';

import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  ACCOUNT_DISCRIMINATOR,
  V1_DISC_AUTHORITY,
  V1_DISC_WALLET,
  ROLE_ADMIN,
  ROLE_OWNER,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddress,
  createAssociatedTokenAccountIdempotentIx,
  Actions,
  createOwnershipChallenge,
  verifyOwnershipProof,
  pickOwnWallet,
  selectWalletByAddress,
  findVaultPda,
  findV1VaultPda,
  ed25519,
  secp256r1,
  type OwnershipProof,
  type PasskeyWalletCandidate,
  type WalletFacts,
} from '../../sdk/sdk-legacy/src';
import { setupTest, sendTx, getSlot, type TestContext } from './common';
import { contextual } from './contextReads';
import {
  generateMockSecp256r1Key,
  createMockRawSigner,
  fakeWebAuthnSign,
  type MockSecp256r1Key,
} from './secp256r1Utils';

const RP_ID = 'example.com';

const sha256 = (data: Uint8Array | string) =>
  new Uint8Array(crypto.createHash('sha256').update(data).digest());
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const randomKey = () => Keypair.generate().publicKey;

// ─── A P-256 authenticator built on node:crypto ──────────────────────────

interface TestPasskey {
  privateKey: crypto.KeyObject;
  /** 33-byte compressed public key, as the authority account stores it. */
  publicKey: Uint8Array;
}

function newPasskey(): TestPasskey {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const compressed = new Uint8Array(33);
  compressed[0] = y[y.length - 1] & 1 ? 0x03 : 0x02;
  compressed.set(x, 1);
  return { privateKey, publicKey: compressed };
}

/** What navigator.credentials.get returns, over `challenge`, as an OwnershipProof. */
function assertion(
  passkey: TestPasskey,
  challenge: Uint8Array,
  opts: {
    rpId?: string;
    type?: string;
    flags?: number;
    encoding?: 'der' | 'compact';
    clientDataJson?: Uint8Array;
  } = {},
): OwnershipProof {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(opts.rpId ?? RP_ID), 0);
  authenticatorData[32] = opts.flags ?? 0x05; // UP | UV
  const clientDataJson =
    opts.clientDataJson ??
    new Uint8Array(
      Buffer.from(
        JSON.stringify({
          type: opts.type ?? 'webauthn.get',
          challenge: b64url(challenge),
          origin: `https://${opts.rpId ?? RP_ID}`,
          crossOrigin: false,
        }),
      ),
    );
  const signed = Buffer.concat([authenticatorData, sha256(clientDataJson)]);
  const signature = crypto.sign('sha256', signed, {
    key: passkey.privateKey,
    dsaEncoding: opts.encoding === 'compact' ? 'ieee-p1363' : 'der',
  });
  return { challenge, signature: new Uint8Array(signature), authenticatorData, clientDataJson };
}

// ─── verifyOwnershipProof ────────────────────────────────────────────────

describe('verifyOwnershipProof', () => {
  const mine = newPasskey();
  const theirs = newPasskey();
  const candidates = [{ publicKey: mine.publicKey, id: 'mine' }, { publicKey: theirs.publicKey, id: 'theirs' }];

  it('keeps the candidate whose key signed, for a DER signature (what browsers return)', () => {
    const challenge = createOwnershipChallenge();
    const proof = assertion(mine, challenge, { encoding: 'der' });
    expect(proof.signature.length).not.toBe(64); // really DER
    expect(verifyOwnershipProof(candidates, proof, RP_ID).map((c) => c.id)).toEqual(['mine']);
  });

  it('accepts a 64-byte r||s signature too', () => {
    const challenge = createOwnershipChallenge();
    const proof = assertion(mine, challenge, { encoding: 'compact' });
    expect(proof.signature.length).toBe(64);
    expect(verifyOwnershipProof(candidates, proof, RP_ID).map((c) => c.id)).toEqual(['mine']);
  });

  it('createOwnershipChallenge returns 32 fresh bytes', () => {
    const a = createOwnershipChallenge();
    const b = createOwnershipChallenge();
    expect(a.length).toBe(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('rejects an assertion over another challenge', () => {
    const proof = assertion(mine, createOwnershipChallenge());
    // A replayed assertion, presented against the challenge the caller chose now.
    expect(verifyOwnershipProof(candidates, { ...proof, challenge: createOwnershipChallenge() }, RP_ID)).toEqual([]);
  });

  it('rejects a challenge shorter than 16 bytes, even when the signature is good', () => {
    const challenge = crypto.randomBytes(15);
    expect(verifyOwnershipProof(candidates, assertion(mine, challenge), RP_ID)).toEqual([]);
    expect(verifyOwnershipProof(candidates, assertion(mine, crypto.randomBytes(16)), RP_ID)).toHaveLength(1);
  });

  it('rejects an assertion made for another relying party', () => {
    const proof = assertion(mine, createOwnershipChallenge(), { rpId: 'evil.example' });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
    expect(verifyOwnershipProof(candidates, proof, 'evil.example')).toHaveLength(1);
  });

  it('rejects a registration (webauthn.create)', () => {
    const proof = assertion(mine, createOwnershipChallenge(), { type: 'webauthn.create' });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('rejects an assertion without the user-present flag', () => {
    const proof = assertion(mine, createOwnershipChallenge(), { flags: 0x04 }); // UV only
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('keeps nothing when no candidate holds the signing key', () => {
    const stranger = newPasskey();
    const proof = assertion(stranger, createOwnershipChallenge());
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('rejects clientDataJSON that is not JSON, and never throws on garbage', () => {
    const challenge = createOwnershipChallenge();
    const garbage = new Uint8Array(Buffer.from('{"type":"webauthn.get",'));
    expect(verifyOwnershipProof(candidates, assertion(mine, challenge, { clientDataJson: garbage }), RP_ID)).toEqual([]);
    const notAnObject = new Uint8Array(Buffer.from('"webauthn.get"'));
    expect(verifyOwnershipProof(candidates, assertion(mine, challenge, { clientDataJson: notAnObject }), RP_ID)).toEqual([]);

    const good = assertion(mine, challenge);
    expect(verifyOwnershipProof(candidates, { ...good, signature: new Uint8Array(3) }, RP_ID)).toEqual([]);
    expect(verifyOwnershipProof([{ publicKey: new Uint8Array(33) }], good, RP_ID)).toEqual([]);
    expect(verifyOwnershipProof(candidates, { ...good, authenticatorData: new Uint8Array(36) }, RP_ID)).toEqual([]);
    expect(verifyOwnershipProof(candidates, {} as OwnershipProof, RP_ID)).toEqual([]);
  });
});

// ─── pickOwnWallet / selectWalletByAddress ───────────────────────────────

function facts(p: Partial<WalletFacts> & { walletPda?: PublicKey }): WalletFacts {
  const walletPda = p.walletPda ?? randomKey();
  return {
    version: 2,
    programId: PROGRAM_ID_DEVNET,
    walletPda,
    vaultPda: findVaultPda(walletPda, PROGRAM_ID_DEVNET)[0],
    authorityPda: randomKey(),
    publicKey: new Uint8Array(33),
    lamports: 0,
    slot: 100n,
    otherAuthorities: [],
    liveSessions: [],
    pendingDeferred: [],
    vaultIsSystemAccount: true,
    tokenGrants: [],
    controlledAlone: true,
    signatureCount: 1,
    ...p,
  };
}

describe('pickOwnWallet', () => {
  it('adopts the one wallet signed for that only this passkey controls, over a richer shared one', () => {
    // Someone else can spend from it, and this passkey never signed for it.
    const shared = facts({ lamports: 10_000, controlledAlone: false, signatureCount: 0 });
    const alone = facts({ lamports: 1 });
    const { adopt, needsConfirmation } = pickOwnWallet([shared, alone]);
    expect(adopt).toBe(alone);
    expect(needsConfirmation).toEqual([]);
  });

  it('adopts the one wallet signed for whatever its version or balance, over unsigned ones', () => {
    const signedV2Poor = facts({ version: 2, lamports: 1 });
    const unsignedV1 = facts({ version: 1, lamports: 9_000, signatureCount: 0 });
    const unsignedRich = facts({ version: 2, lamports: 9_000, signatureCount: 0 });
    expect(pickOwnWallet([unsignedRich, unsignedV1, signedV2Poor])).toEqual({
      adopt: signedV2Poor,
      needsConfirmation: [],
    });
  });

  it('orders v1 first (not yet migrated), then by balance, then by wallet address', () => {
    const [low, high] = [randomKey(), randomKey()].sort((a, b) => (a.toBase58() < b.toBase58() ? -1 : 1));
    const v2Rich = facts({ version: 2, lamports: 9_000 });
    const v1Poor = facts({ version: 1, lamports: 1 });
    const v2TieHigh = facts({ version: 2, lamports: 500, walletPda: high });
    const v2TieLow = facts({ version: 2, lamports: 500, walletPda: low });
    const input = [v2TieHigh, v2Rich, v1Poor, v2TieLow];

    // All signed for: nothing adopted (see below), every wallet in that order.
    const signed = pickOwnWallet(input);
    expect(signed.adopt).toBeNull();
    expect(signed.needsConfirmation).toEqual([v1Poor, v2Rich, v2TieLow, v2TieHigh]);
    // The same order when none is signed for, or none is controlled alone.
    const unsigned = input.map((f) => ({ ...f, signatureCount: 0 }));
    expect(pickOwnWallet(unsigned).needsConfirmation.map((f) => f.walletPda)).toEqual(
      [v1Poor, v2Rich, v2TieLow, v2TieHigh].map((f) => f.walletPda),
    );
    const shared = input.map((f) => ({ ...f, controlledAlone: false }));
    const pick = pickOwnWallet(shared);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation.map((f) => f.walletPda.toBase58())).toEqual(
      [v1Poor, v2Rich, v2TieLow, v2TieHigh].map((f) => f.walletPda.toBase58()),
    );
    // The input is not reordered.
    expect(input[0]).toBe(v2TieHigh);
  });

  it('adopts nothing and asks nothing when there are no wallets', () => {
    expect(pickOwnWallet([])).toEqual({ adopt: null, needsConfirmation: [] });
  });

  it('never adopts a wallet this passkey has not signed for — not even the only one, however clean', () => {
    // Created and not used yet, or handed over by someone: the facts cannot
    // tell those apart, so the user does.
    const unused = facts({ signatureCount: 0, lamports: 5_000 });
    expect(pickOwnWallet([unused])).toEqual({ adopt: null, needsConfirmation: [unused] });
  });

  it('a richer wallet handed to this passkey does not outrank the one it signed for', () => {
    // A planted wallet looks spotless and costs a lamport more to rank first
    // by balance. Its passkey authority is new, so it has no signature on it.
    const mine = facts({ signatureCount: 7, lamports: 1_000_000 });
    const planted = facts({ signatureCount: 0, lamports: 1_000_001 });
    expect(pickOwnWallet([planted, mine])).toEqual({ adopt: mine, needsConfirmation: [] });

    // Neither signed for: both go to the user, and neither is picked.
    const mineUnused = { ...mine, signatureCount: 0 };
    const pick = pickOwnWallet([mineUnused, planted]);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation).toEqual([planted, mineUnused]);
  });

  // The program's passkey challenge does not name the wallet for
  // CreateSession, AddAuthority, TransferOwnership or Authorize: the
  // passkey's signature on its own wallet can be submitted again on a planted
  // one, and that wallet's counter rises too.
  it('adopts nothing when two wallets have been signed for — either count may be a replayed copy', () => {
    const mine = facts({ signatureCount: 3, lamports: 1_000_000 });
    const copied = facts({ signatureCount: 1, lamports: 1_000_001 });
    const pick = pickOwnWallet([mine, copied]);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation).toEqual([copied, mine]);
  });

  it('counts a signed-for wallet others can spend from too: the clean one beside it is not adopted', () => {
    // The user's wallet with a live session they opened; the planted copy of
    // that first signature, once its own copy of the session has expired.
    const mineWithSession = facts({ signatureCount: 1, controlledAlone: false });
    const copied = facts({ signatureCount: 1 });
    const pick = pickOwnWallet([copied, mineWithSession]);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation).toHaveLength(2);
  });

  it('lists wallets signed for first, ahead of older versions and fuller vaults', () => {
    const signedShared = facts({ version: 2, lamports: 1, signatureCount: 3, controlledAlone: false });
    const unsignedV1 = facts({ version: 1, lamports: 9_000, signatureCount: 0 });
    const unsignedRich = facts({ version: 2, lamports: 9_000, signatureCount: 0 });
    const pick = pickOwnWallet([unsignedRich, unsignedV1, signedShared]);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation).toEqual([signedShared, unsignedV1, unsignedRich]);
  });

  it('counts having signed, not how often: a busier wallet does not outrank an older version', () => {
    const busyV2 = facts({ version: 2, lamports: 1, signatureCount: 90 });
    const onceV1 = facts({ version: 1, lamports: 1, signatureCount: 1 });
    const unsigned = facts({ version: 1, lamports: 1, signatureCount: 0 });
    expect(pickOwnWallet([busyV2, unsigned, onceV1]).needsConfirmation).toEqual([onceV1, busyV2, unsigned]);
  });
});

describe('selectWalletByAddress', () => {
  const a = facts({});
  const b = facts({});

  it('matches the vault address (what users recognise) or the wallet PDA, as string or key', () => {
    expect(selectWalletByAddress([a, b], b.vaultPda.toBase58())).toBe(b);
    expect(selectWalletByAddress([a, b], b.vaultPda)).toBe(b);
    expect(selectWalletByAddress([a, b], a.walletPda.toBase58())).toBe(a);
    expect(selectWalletByAddress([a, b], a.walletPda)).toBe(a);
  });

  it('returns null for any other address', () => {
    expect(selectWalletByAddress([a, b], randomKey())).toBeNull();
    expect(selectWalletByAddress([a, b], 'not-an-address')).toBeNull();
  });
});

// ─── Chain reads against a stubbed Connection ────────────────────────────

type Filter = { memcmp: { offset: number; bytes: string } };
type Gpa = (programId: PublicKey, config: { filters: Filter[] }) => Promise<unknown[]>;

function passkeyAuthorityData(
  disc: number,
  wallet: PublicKey,
  opts: { role?: number; credentialIdHash?: Uint8Array; publicKey?: Uint8Array; rpId?: string; counter?: number } = {},
): Buffer {
  const data = Buffer.alloc(145);
  data[0] = disc;
  data[1] = 1; // Secp256r1
  data[2] = opts.role ?? 0;
  data.writeUInt32LE(opts.counter ?? 0, 8); // signatures the key has made here
  wallet.toBuffer().copy(data, 16);
  Buffer.from(opts.credentialIdHash ?? new Uint8Array(32).fill(9)).copy(data, 48);
  Buffer.from(opts.publicKey ?? new Uint8Array(33).fill(2)).copy(data, 80);
  Buffer.from(sha256(opts.rpId ?? RP_ID)).copy(data, 113);
  return data;
}

function ed25519AuthorityData(disc: number, wallet: PublicKey, key: PublicKey, role = 1): Buffer {
  const data = Buffer.alloc(80);
  data[0] = disc;
  data[1] = 0;
  data[2] = role;
  wallet.toBuffer().copy(data, 16);
  key.toBuffer().copy(data, 48);
  return data;
}

function sessionData(wallet: PublicKey, key: PublicKey, expiresAt: bigint): Buffer {
  const data = Buffer.alloc(80);
  data[0] = ACCOUNT_DISCRIMINATOR.SESSION;
  wallet.toBuffer().copy(data, 8);
  key.toBuffer().copy(data, 40);
  data.writeBigUInt64LE(expiresAt, 72);
  return data;
}

function deferredData(wallet: PublicKey, authorizedBy: PublicKey, expiresAt: bigint): Buffer {
  const data = Buffer.alloc(176);
  data[0] = ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC;
  wallet.toBuffer().copy(data, 72);
  authorizedBy.toBuffer().copy(data, 104);
  randomKey().toBuffer().copy(data, 136);
  data.writeBigUInt64LE(expiresAt, 168);
  return data;
}

/** A 165-byte SPL token account, as SPL Token and Token-2022 both lay it out. */
function tokenAccountData(
  mint: PublicKey,
  owner: PublicKey,
  opts: { delegate?: PublicKey; closeAuthority?: PublicKey } = {},
): Buffer {
  const data = Buffer.alloc(165);
  mint.toBuffer().copy(data, 0);
  owner.toBuffer().copy(data, 32);
  data.writeBigUInt64LE(1_000n, 64);
  if (opts.delegate) {
    data.writeUInt32LE(1, 72);
    opts.delegate.toBuffer().copy(data, 76);
    data.writeBigUInt64LE(1_000n, 121);
  }
  data[108] = 1; // initialized
  if (opts.closeAuthority) {
    data.writeUInt32LE(1, 129);
    opts.closeAuthority.toBuffer().copy(data, 133);
  }
  return data;
}

const account = (pubkey: PublicKey, data: Buffer) => ({ pubkey, account: { data } });

/** What getMultipleAccountsInfo returns for an account that exists. */
const info = (owner: PublicKey, data: Buffer, lamports = 1) =>
  ({ owner, data, lamports, executable: false }) as AccountInfo<Buffer>;
const liveWallet = (disc: number = ACCOUNT_DISCRIMINATOR.WALLET, programId = PROGRAM_ID_DEVNET) =>
  info(programId, Buffer.from([disc, 0, 0, 0, 0, 0, 0, 0]));

type ReadKind = 'authorities' | 'sessions' | 'deferred' | 'accounts' | 'tokenAccounts';

/** What the chain holds at one slot. */
interface ChainState {
  /** Program accounts, by program id. */
  programs: Record<string, { pubkey: PublicKey; data: Buffer }[]>;
  /** Any other account, by address. */
  accounts?: Record<string, AccountInfo<Buffer>>;
  /** Token accounts, by the owner they list. */
  tokenAccounts?: Record<string, { pubkey: PublicKey; tokenProgram: PublicKey; data: Buffer }[]>;
}

/**
 * Enough of a Connection for the ownership reads, answering from chain state
 * rather than per call: getProgramAccounts evaluates the memcmp filters for
 * real. Every read reports the slot it was served at — `slot`, or one less
 * for `before`.
 */
function chainStub(
  opts: ChainState & {
    slot?: number;
    /**
     * The chain one slot earlier, before one transaction produced the state
     * above. A lagging node serves it to every read that does not demand
     * newer state (`minContextSlot`) — except the kinds in `newest`, which it
     * serves from the newer state: the worst order for the reader.
     */
    before?: ChainState;
    /** Default `['authorities']`. */
    newest?: ReadKind[];
    /** The first this-many reads that carry a `minContextSlot` fail: the node has not reached it. */
    lagging?: number;
  },
) {
  const now = opts.slot ?? 1_000;
  const newest = opts.newest ?? ['authorities'];
  /** Every read in order, with the `minContextSlot` it asked for. */
  const order: { read: ReadKind; minContextSlot?: number }[] = [];
  let lagging = opts.lagging ?? 0;
  const serve = (kind: ReadKind, minContextSlot: number | undefined) => {
    order.push({ read: kind, minContextSlot });
    if (minContextSlot !== undefined && lagging > 0) {
      lagging--;
      throw new SolanaJSONRPCError(
        { code: -32016, message: 'Minimum context slot has not been reached', data: { contextSlot: now - 1 } },
        'failed',
      );
    }
    const stale = opts.before && !newest.includes(kind) && (minContextSlot === undefined || minContextSlot < now);
    return stale
      ? { state: opts.before!, context: { slot: now - 1 } }
      : { state: opts as ChainState, context: { slot: now } };
  };
  const kindOf = (disc: number): ReadKind =>
    disc === ACCOUNT_DISCRIMINATOR.AUTHORITY || disc === V1_DISC_AUTHORITY
      ? 'authorities'
      : disc === ACCOUNT_DISCRIMINATOR.SESSION
        ? 'sessions'
        : 'deferred';
  const connection = {
    getSlot: async () => now,
    getMultipleAccountsInfoAndContext: async (keys: PublicKey[], config?: { minContextSlot?: number }) => {
      const { state, context } = serve('accounts', config?.minContextSlot);
      return { context, value: keys.map((k) => state.accounts?.[k.toBase58()] ?? null) };
    },
    getTokenAccountsByOwner: async (
      owner: PublicKey,
      filter: { programId: PublicKey },
      config?: { minContextSlot?: number },
    ) => {
      const { state, context } = serve('tokenAccounts', config?.minContextSlot);
      const value = (state.tokenAccounts?.[owner.toBase58()] ?? [])
        .filter((t) => t.tokenProgram.equals(filter.programId))
        .map(({ pubkey, tokenProgram, data }) => ({ pubkey, account: info(tokenProgram, data) }));
      return { context, value };
    },
    getProgramAccounts: async (
      programId: PublicKey,
      config: { filters: Filter[]; withContext?: boolean; minContextSlot?: number },
    ) => {
      const { state, context } = serve(
        kindOf(Buffer.from(config.filters[0].memcmp.bytes, 'base64')[0]),
        config.minContextSlot,
      );
      const value = (state.programs[programId.toBase58()] ?? [])
        .filter(({ data }) =>
          config.filters.every(({ memcmp: { offset, bytes } }) => {
            const want = Buffer.from(bytes, 'base64');
            return data.length >= offset + want.length && data.subarray(offset, offset + want.length).equals(want);
          }),
        )
        .map(({ pubkey, data }) => ({ pubkey, account: info(programId, data) }));
      return config.withContext ? { context, value } : value;
    },
  } as unknown as Connection;
  return { connection, order };
}

describe('findPasskeyWalletCandidates (stubbed RPC)', () => {
  const credentialIdHash = new Uint8Array(32).fill(0x11);
  const v2Wallet = randomKey();
  const v1Wallet = randomKey();
  const v2Authority = randomKey();
  const v1Authority = randomKey();

  function stub(): { connection: Connection; calls: { programId: PublicKey; filters: Filter[] }[] } {
    const calls: { programId: PublicKey; filters: Filter[] }[] = [];
    const getProgramAccounts: Gpa = async (programId, config) => {
      calls.push({ programId, filters: config.filters });
      if (programId.equals(PROGRAM_ID_DEVNET)) {
        return [
          account(v2Authority, passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, v2Wallet, { credentialIdHash })),
          // The RPC cannot filter on rank; the SDK must drop these itself.
          account(randomKey(), passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, randomKey(), { credentialIdHash, role: ROLE_ADMIN })),
          account(randomKey(), passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, randomKey(), { credentialIdHash }).subarray(0, 144)),
        ];
      }
      if (programId.equals(PROGRAM_ID_DEVNET_V1)) {
        return [account(v1Authority, passkeyAuthorityData(V1_DISC_AUTHORITY, v1Wallet, { credentialIdHash }))];
      }
      throw new Error(`unexpected program ${programId.toBase58()}`);
    };
    return { connection: { getProgramAccounts } as unknown as Connection, calls };
  }

  it('returns v2 hits, then v1 hits at the paired v1 id with the bare-seed vault', async () => {
    const { connection, calls } = stub();
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const found = await client.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID });

    expect(found).toHaveLength(2);
    const [v2, v1] = found;
    expect(v2.version).toBe(2);
    expect(v2.programId.equals(PROGRAM_ID_DEVNET)).toBe(true);
    expect(v2.walletPda.equals(v2Wallet)).toBe(true);
    expect(v2.vaultPda.equals(findVaultPda(v2Wallet, PROGRAM_ID_DEVNET)[0])).toBe(true);
    expect(v2.authorityPda.equals(v2Authority)).toBe(true);
    expect(Buffer.from(v2.publicKey)).toEqual(Buffer.alloc(33, 2));

    expect(v1.version).toBe(1);
    expect(v1.programId.equals(PROGRAM_ID_DEVNET_V1)).toBe(true);
    expect(v1.walletPda.equals(v1Wallet)).toBe(true);
    expect(v1.vaultPda.equals(findV1VaultPda(v1Wallet, PROGRAM_ID_DEVNET_V1)[0])).toBe(true);
    expect(v1.vaultPda.equals(findVaultPda(v1Wallet, PROGRAM_ID_DEVNET_V1)[0])).toBe(false);
    expect(v1.authorityPda.equals(v1Authority)).toBe(true);

    // The filters are the contract with the RPC: a passkey authority of this
    // version, this credential, created under this relying party.
    expect(calls).toHaveLength(2);
    for (const { programId, filters } of calls) {
      const disc = programId.equals(PROGRAM_ID_DEVNET) ? ACCOUNT_DISCRIMINATOR.AUTHORITY : V1_DISC_AUTHORITY;
      expect(filters.map((f) => f.memcmp.offset)).toEqual([0, 48, 113]);
      expect(Buffer.from(filters[0].memcmp.bytes, 'base64')).toEqual(Buffer.from([disc, 1]));
      expect(Buffer.from(filters[1].memcmp.bytes, 'base64')).toEqual(Buffer.from(credentialIdHash));
      expect(Buffer.from(filters[2].memcmp.bytes, 'base64')).toEqual(Buffer.from(sha256(RP_ID)));
    }
  });

  it('skips the v1 deployment when includeV1 is false', async () => {
    const { connection, calls } = stub();
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const found = await client.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID, includeV1: false });
    expect(found.map((c) => c.version)).toEqual([2]);
    expect(calls).toHaveLength(1);
  });

  it('scans both discriminators at one id where v1 was upgraded in place', async () => {
    const localId = randomKey();
    const discs: number[] = [];
    const getProgramAccounts: Gpa = async (programId, config) => {
      expect(programId.equals(localId)).toBe(true);
      discs.push(Buffer.from(config.filters[0].memcmp.bytes, 'base64')[0]);
      return [];
    };
    const client = new LazorKitClient({ getProgramAccounts } as unknown as Connection, localId);
    await client.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID });
    expect(discs.sort()).toEqual([V1_DISC_AUTHORITY, ACCOUNT_DISCRIMINATOR.AUTHORITY].sort());
  });

  it('rejects a credential-id hash that is not 32 bytes', async () => {
    const client = new LazorKitClient({} as Connection, PROGRAM_ID_DEVNET);
    await expect(
      client.findPasskeyWalletCandidates({ credentialIdHash: new Uint8Array(31), rpId: RP_ID }),
    ).rejects.toThrow('32 bytes');
  });
});

describe('describeWalletCandidates (stubbed RPC)', () => {
  const SLOT = 1_000n;
  const wallet = randomKey();
  const ownAuthority = randomKey();
  const ownKey = new Uint8Array(33).fill(7);
  const candidate: PasskeyWalletCandidate = {
    version: 2,
    programId: PROGRAM_ID_DEVNET,
    walletPda: wallet,
    vaultPda: findVaultPda(wallet, PROGRAM_ID_DEVNET)[0],
    authorityPda: ownAuthority,
    publicKey: ownKey,
  };
  const backendKey = randomKey();
  const backendAuthority = randomKey();
  const sessionKey = randomKey();

  /**
   * Program accounts by discriminator; single accounts by address (the wallet
   * exists and the vault holds 42 lamports unless overridden); the vault's
   * token accounts by token program.
   */
  function stub(
    byDisc: Record<number, ReturnType<typeof account>[]>,
    opts: {
      accounts?: Record<string, AccountInfo<Buffer> | null>;
      tokens?: Record<string, ReturnType<typeof account>[]>;
    } = {},
  ): Connection {
    const accounts: Record<string, AccountInfo<Buffer> | null> = {
      [wallet.toBase58()]: liveWallet(),
      [candidate.vaultPda.toBase58()]: info(SystemProgram.programId, Buffer.alloc(0), 42),
      ...opts.accounts,
    };
    const getProgramAccounts: Gpa = async (_programId, config) =>
      byDisc[Buffer.from(config.filters[0].memcmp.bytes, 'base64')[0]] ?? [];
    return contextual({
      getSlot: async () => Number(SLOT),
      getMultipleAccountsInfo: async (keys: PublicKey[]) => keys.map((k) => accounts[k.toBase58()] ?? null),
      getTokenAccountsByOwner: async (owner: PublicKey, filter: { programId: PublicKey }) => {
        expect(owner.equals(candidate.vaultPda)).toBe(true);
        return { context: { slot: Number(SLOT) }, value: opts.tokens?.[filter.programId.toBase58()] ?? [] };
      },
      getProgramAccounts,
    });
  }
  const own = () =>
    account(ownAuthority, passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, { publicKey: ownKey, counter: 3 }));

  it('reports what else can spend, counts only what is live, and fails closed on short accounts', async () => {
    const samePasskey = randomKey();
    const otherRpPasskey = randomKey();
    const shortAuthority = randomKey();
    const liveSession = randomKey();
    const lastSlotSession = randomKey();
    const shortSession = randomKey();
    const byOwn = randomKey();
    const byStranger = randomKey();
    const lastSlotDeferred = randomKey();
    const shortDeferred = randomKey();
    const connection = stub({
      [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [
        own(),
        account(backendAuthority, ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, backendKey)),
        account(samePasskey, passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, { role: 2 })),
        account(otherRpPasskey, passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, { rpId: 'other.example' })),
        account(shortAuthority, ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, backendKey).subarray(0, 60)),
      ],
      [ACCOUNT_DISCRIMINATOR.SESSION]: [
        account(randomKey(), sessionData(wallet, randomKey(), SLOT - 1n)), // expired
        // The program refuses only once current_slot > expires_at: this one
        // can still sign in this slot.
        account(lastSlotSession, sessionData(wallet, randomKey(), SLOT)),
        account(liveSession, sessionData(wallet, sessionKey, SLOT + 1n)),
        account(shortSession, sessionData(wallet, sessionKey, SLOT + 1n).subarray(0, 79)),
      ],
      [ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC]: [
        account(byOwn, deferredData(wallet, ownAuthority, SLOT + 10n)),
        account(byStranger, deferredData(wallet, randomKey(), SLOT + 10n)),
        account(randomKey(), deferredData(wallet, randomKey(), SLOT - 1n)), // expired
        account(lastSlotDeferred, deferredData(wallet, randomKey(), SLOT)),
        account(shortDeferred, deferredData(wallet, ownAuthority, SLOT + 10n).subarray(0, 175)),
      ],
    });
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const [f] = await client.describeWalletCandidates([candidate], { trustedKeys: [backendKey.toBase58()] });

    expect(f.walletPda.equals(wallet)).toBe(true);
    expect(f.lamports).toBe(42);
    expect(f.slot).toBe(SLOT);
    expect(f.vaultIsSystemAccount).toBe(true);
    // Read off this passkey's own authority.
    expect(f.signatureCount).toBe(3);
    // The same fields, in the same order, as @lazorkit/sdk's WalletFacts.
    expect(Object.keys(f)).toEqual([
      'version', 'programId', 'walletPda', 'vaultPda', 'authorityPda', 'publicKey',
      'lamports', 'slot', 'otherAuthorities', 'liveSessions', 'pendingDeferred',
      'vaultIsSystemAccount', 'tokenGrants', 'controlledAlone', 'signatureCount',
    ]);

    const others = new Map(f.otherAuthorities.map((a) => [a.authorityPda.toBase58(), a]));
    expect(others.has(ownAuthority.toBase58())).toBe(false);
    expect(others.size).toBe(4);
    expect(others.get(backendAuthority.toBase58())).toMatchObject({ type: 'ed25519', role: 'admin', trusted: true });
    expect(others.get(backendAuthority.toBase58())!.publicKey!.equals(backendKey)).toBe(true);
    expect(others.get(samePasskey.toBase58())).toMatchObject({
      type: 'secp256r1', role: 'spender', sameRelyingParty: true, trusted: false,
    });
    expect(others.get(otherRpPasskey.toBase58())).toMatchObject({
      type: 'secp256r1', role: 'owner', sameRelyingParty: false, trusted: false,
    });
    expect(others.get(shortAuthority.toBase58())).toMatchObject({ type: 'ed25519', trusted: false, publicKey: undefined });

    expect(f.liveSessions.map((s) => s.sessionPda.toBase58()).sort()).toEqual(
      [liveSession, lastSlotSession, shortSession].map((k) => k.toBase58()).sort(),
    );
    const short = f.liveSessions.find((s) => s.sessionPda.equals(shortSession))!;
    expect(short.trusted).toBe(false);
    expect(short.expiresAtSlot > SLOT).toBe(true);
    expect(f.liveSessions.find((s) => s.sessionPda.equals(liveSession))).toMatchObject({
      expiresAtSlot: SLOT + 1n, trusted: false,
    });
    expect(f.liveSessions.find((s) => s.sessionPda.equals(lastSlotSession))!.expiresAtSlot).toBe(SLOT);

    const deferred = new Map(f.pendingDeferred.map((d) => [d.deferredPda.toBase58(), d]));
    expect(deferred.size).toBe(4);
    expect(deferred.get(byOwn.toBase58())!.authorizedBy.equals(ownAuthority)).toBe(true);
    expect(deferred.get(lastSlotDeferred.toBase58())!.expiresAtSlot).toBe(SLOT);
    // None trusted — not even the one naming this passkey's own authority.
    expect([...deferred.values()].every((d) => !d.trusted)).toBe(true);

    expect(f.controlledAlone).toBe(false);
  });

  it('is controlledAlone when every other key and session is trusted, and no deferred execution is pending', async () => {
    const authorities = [
      own(),
      account(backendAuthority, ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, backendKey)),
    ];
    const sessions = [account(randomKey(), sessionData(wallet, sessionKey, SLOT + 100n))];
    const client = new LazorKitClient(
      stub({ [ACCOUNT_DISCRIMINATOR.AUTHORITY]: authorities, [ACCOUNT_DISCRIMINATOR.SESSION]: sessions }),
      PROGRAM_ID_DEVNET,
    );
    const [trusted] = await client.describeWalletCandidates([candidate], { trustedKeys: [backendKey, sessionKey] });
    expect(trusted.controlledAlone).toBe(true);

    // Trust the session key only: the backend authority now counts against it.
    const [partly] = await client.describeWalletCandidates([candidate], { trustedKeys: [sessionKey] });
    expect(partly.controlledAlone).toBe(false);
    expect(partly.otherAuthorities.filter((a) => !a.trusted)).toHaveLength(1);
  });

  it('counts a pending deferred execution against the wallet whoever it names', async () => {
    // The authority PDA a deferred execution records does not pin the key that
    // signed it: a passkey authority's address comes from its credential-id
    // hash, so it can be closed and re-created holding another key — and that
    // hash can equal a trusted Ed25519 key's bytes, landing on its address.
    for (const authorizedBy of [ownAuthority, backendAuthority]) {
      const client = new LazorKitClient(
        stub({
          [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [
            own(),
            account(backendAuthority, ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, backendKey)),
          ],
          [ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC]: [account(randomKey(), deferredData(wallet, authorizedBy, SLOT + 10n))],
        }),
        PROGRAM_ID_DEVNET,
      );
      const [f] = await client.describeWalletCandidates([candidate], { trustedKeys: [backendKey] });
      expect(f.otherAuthorities.every((a) => a.trusted)).toBe(true);
      expect(f.pendingDeferred).toHaveLength(1);
      expect(f.pendingDeferred[0].authorizedBy.equals(authorizedBy)).toBe(true);
      expect(f.pendingDeferred[0].trusted).toBe(false);
      expect(f.controlledAlone).toBe(false);
    }
  });

  it('reports delegates and foreign close authorities on the vault token accounts, under both token programs', async () => {
    const vault = candidate.vaultPda;
    const mint = randomKey();
    const delegate = randomKey();
    const stranger = randomKey();
    const withDelegate = randomKey();
    const closableByStranger = randomKey();
    const short = randomKey();
    const client = new LazorKitClient(
      stub(
        { [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [own()] },
        {
          tokens: {
            [TOKEN_PROGRAM_ID.toBase58()]: [
              account(randomKey(), tokenAccountData(mint, vault)), // nothing granted
              account(randomKey(), tokenAccountData(mint, vault, { closeAuthority: vault, delegate: vault })),
              account(withDelegate, tokenAccountData(mint, vault, { delegate })),
            ],
            [TOKEN_2022_PROGRAM_ID.toBase58()]: [
              account(closableByStranger, tokenAccountData(mint, vault, { closeAuthority: stranger })),
              account(short, tokenAccountData(mint, vault).subarray(0, 164)),
            ],
          },
        },
      ),
      PROGRAM_ID_DEVNET,
    );

    const [f] = await client.describeWalletCandidates([candidate]);
    expect(f.otherAuthorities).toEqual([]);
    const grants = new Map(f.tokenGrants.map((g) => [g.tokenAccount.toBase58(), g]));
    expect(grants.size).toBe(3);
    expect(grants.get(withDelegate.toBase58())).toMatchObject({ kind: 'delegate', trusted: false });
    expect(grants.get(withDelegate.toBase58())!.grantee!.equals(delegate)).toBe(true);
    expect(grants.get(withDelegate.toBase58())!.tokenProgram.equals(TOKEN_PROGRAM_ID)).toBe(true);
    expect(grants.get(withDelegate.toBase58())!.mint!.equals(mint)).toBe(true);
    expect(grants.get(closableByStranger.toBase58())).toMatchObject({ kind: 'closeAuthority', trusted: false });
    expect(grants.get(closableByStranger.toBase58())!.grantee!.equals(stranger)).toBe(true);
    expect(grants.get(closableByStranger.toBase58())!.tokenProgram.equals(TOKEN_2022_PROGRAM_ID)).toBe(true);
    expect(grants.get(short.toBase58())).toMatchObject({ kind: 'unreadable', mint: null, grantee: null, trusted: false });
    expect(f.controlledAlone).toBe(false);

    // Trusting both grantees leaves only the unreadable account against it.
    const [trusting] = await client.describeWalletCandidates([candidate], { trustedKeys: [delegate, stranger] });
    expect(trusting.tokenGrants.filter((g) => !g.trusted).map((g) => g.kind)).toEqual(['unreadable']);
    expect(trusting.controlledAlone).toBe(false);
  });

  it('a vault handed to another program, or given data, is not controlled alone; a missing one is fine', async () => {
    const describeWithVault = async (vault: AccountInfo<Buffer> | null) => {
      const client = new LazorKitClient(
        stub(
          { [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [own()] },
          { accounts: { [candidate.vaultPda.toBase58()]: vault } },
        ),
        PROGRAM_ID_DEVNET,
      );
      const [f] = await client.describeWalletCandidates([candidate], { trustedKeys: [backendKey] });
      return f;
    };

    // System::Assign through an Owner's Execute: the vault keeps its lamports,
    // but another program now decides what leaves it. No trusted key helps.
    const assigned = await describeWithVault(info(randomKey(), Buffer.alloc(0), 9));
    expect(assigned.vaultIsSystemAccount).toBe(false);
    expect(assigned.lamports).toBe(9);
    expect(assigned.otherAuthorities).toEqual([]);
    expect(assigned.tokenGrants).toEqual([]);
    expect(assigned.controlledAlone).toBe(false);
    // System::Allocate (a nonce account, say): still System-owned, not plain.
    const allocated = await describeWithVault(info(SystemProgram.programId, Buffer.alloc(80), 9));
    expect(allocated.vaultIsSystemAccount).toBe(false);
    expect(allocated.controlledAlone).toBe(false);
    // Never funded: nothing there to take.
    const missing = await describeWithVault(null);
    expect(missing.vaultIsSystemAccount).toBe(true);
    expect(missing.lamports).toBe(0);
    expect(missing.controlledAlone).toBe(true);
    // The usual case: a funded system account.
    const plain = await describeWithVault(info(SystemProgram.programId, Buffer.alloc(0), 42));
    expect(plain.vaultIsSystemAccount).toBe(true);
    expect(plain.controlledAlone).toBe(true);

    // Such a wallet is only ever offered, even as the sole candidate.
    expect(pickOwnWallet([assigned])).toEqual({ adopt: null, needsConfirmation: [assigned] });
  });

  it('reports a canonical token account of a watched mint that the vault no longer owns', async () => {
    const usdc = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
    const wsol = new PublicKey('So11111111111111111111111111111111111111112');
    const usdcAta = getAssociatedTokenAddress(usdc, candidate.vaultPda, TOKEN_PROGRAM_ID);
    const wsolAta = getAssociatedTokenAddress(wsol, candidate.vaultPda, TOKEN_PROGRAM_ID);
    const newOwner = randomKey();
    const client = new LazorKitClient(
      stub(
        { [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [own()] },
        {
          accounts: {
            // Handed away with SetAuthority(AccountOwner): senders still pay here.
            [usdcAta.toBase58()]: info(TOKEN_PROGRAM_ID, tokenAccountData(usdc, newOwner)),
            // Still the vault's: fine.
            [wsolAta.toBase58()]: info(TOKEN_PROGRAM_ID, tokenAccountData(wsol, candidate.vaultPda)),
          },
        },
      ),
      PROGRAM_ID_DEVNET,
    );
    const [f] = await client.describeWalletCandidates([candidate]);
    expect(f.tokenGrants).toHaveLength(1);
    expect(f.tokenGrants[0]).toMatchObject({ kind: 'owner', trusted: false });
    expect(f.tokenGrants[0].tokenAccount.equals(usdcAta)).toBe(true);
    expect(f.tokenGrants[0].mint!.equals(usdc)).toBe(true);
    expect(f.tokenGrants[0].grantee!.equals(newOwner)).toBe(true);
    expect(f.controlledAlone).toBe(false);
  });

  it('leaves out a wallet whose account is gone, such as a migrated v1 wallet', async () => {
    // MigrateWallet closes the v1 wallet and only the authority that migrated;
    // another Owner passkey's v1 authority stays behind, alone on nothing.
    const v1Wallet = randomKey();
    const orphan: PasskeyWalletCandidate = {
      version: 1,
      programId: PROGRAM_ID_DEVNET_V1,
      walletPda: v1Wallet,
      vaultPda: findV1VaultPda(v1Wallet, PROGRAM_ID_DEVNET_V1)[0],
      authorityPda: randomKey(),
      publicKey: ownKey,
    };
    const lookalike = (w: PublicKey): PasskeyWalletCandidate => ({
      ...candidate,
      walletPda: w,
      vaultPda: findVaultPda(w, PROGRAM_ID_DEVNET)[0],
    });
    const [otherProgram, wrongDisc, v1DiscAtV2] = [lookalike(randomKey()), lookalike(randomKey()), lookalike(randomKey())];
    const all = [orphan, candidate, otherProgram, wrongDisc, v1DiscAtV2];

    const getProgramAccounts: Gpa = async (programId, config) => {
      const disc = Buffer.from(config.filters[0].memcmp.bytes, 'base64')[0];
      const walletFilter = new PublicKey(Buffer.from(config.filters[1].memcmp.bytes, 'base64'));
      if (programId.equals(PROGRAM_ID_DEVNET_V1) && disc === V1_DISC_AUTHORITY && walletFilter.equals(v1Wallet)) {
        return [account(orphan.authorityPda, passkeyAuthorityData(V1_DISC_AUTHORITY, v1Wallet, { publicKey: ownKey, counter: 5 }))];
      }
      if (disc === ACCOUNT_DISCRIMINATOR.AUTHORITY && walletFilter.equals(wallet)) return [own()];
      return [];
    };
    const accounts: Record<string, AccountInfo<Buffer> | null> = {
      [wallet.toBase58()]: liveWallet(),
      [otherProgram.walletPda.toBase58()]: info(SystemProgram.programId, Buffer.from([ACCOUNT_DISCRIMINATOR.WALLET])),
      [wrongDisc.walletPda.toBase58()]: liveWallet(ACCOUNT_DISCRIMINATOR.AUTHORITY),
      [v1DiscAtV2.walletPda.toBase58()]: liveWallet(V1_DISC_WALLET),
    };
    const connection = contextual({
      getSlot: async () => Number(SLOT),
      getMultipleAccountsInfo: async (keys: PublicKey[]) => keys.map((k) => accounts[k.toBase58()] ?? null),
      getTokenAccountsByOwner: async () => ({ context: { slot: Number(SLOT) }, value: [] }),
      getProgramAccounts,
    });

    const facts = await new LazorKitClient(connection, PROGRAM_ID_DEVNET).describeWalletCandidates(all);
    expect(facts.map((f) => f.walletPda.toBase58())).toEqual([wallet.toBase58()]);
    // Were the orphan kept, it would stand beside the live wallet — first, as
    // v1 — and nothing could ever move what was sent to it.
    expect(pickOwnWallet(facts).adopt?.walletPda.equals(wallet)).toBe(true);

    // The same orphan with its v1 wallet still there is a live candidate. Both
    // signed for, so the user chooses; the unmigrated v1 wallet comes first.
    accounts[v1Wallet.toBase58()] = liveWallet(V1_DISC_WALLET, PROGRAM_ID_DEVNET_V1);
    const withV1 = await new LazorKitClient(connection, PROGRAM_ID_DEVNET).describeWalletCandidates(all);
    expect(withV1.map((f) => f.version)).toEqual([1, 2]);
    const pick = pickOwnWallet(withV1);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation.map((f) => f.walletPda.toBase58())).toEqual([v1Wallet.toBase58(), wallet.toBase58()]);
  });

  it('is not controlledAlone once its own authority is gone, demoted, too short or holds another key', async () => {
    const describeWith = async (own: ReturnType<typeof account>[]) =>
      (await new LazorKitClient(stub({ [ACCOUNT_DISCRIMINATOR.AUTHORITY]: own }), PROGRAM_ID_DEVNET).describeWalletCandidates([candidate]))[0];
    const ownData = (o: { role?: number; publicKey?: Uint8Array } = {}) =>
      passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, { publicKey: ownKey, counter: 9, ...o });

    const intact = await describeWith([account(ownAuthority, ownData())]);
    expect(intact.controlledAlone).toBe(true);
    expect(intact.signatureCount).toBe(9);

    const gone = await describeWith([]);
    expect(gone.otherAuthorities).toEqual([]);
    expect(gone.controlledAlone).toBe(false);
    expect(gone.signatureCount).toBe(0);

    // Demoted between the candidate scan and the description: an Owner above
    // it can take it away, and its counter no longer vouches for the wallet.
    const demoted = await describeWith([account(ownAuthority, ownData({ role: ROLE_ADMIN }))]);
    expect(demoted.controlledAlone).toBe(false);
    expect(demoted.signatureCount).toBe(0);

    const short = await describeWith([account(ownAuthority, ownData().subarray(0, 144))]);
    expect(short.controlledAlone).toBe(false);
    expect(short.signatureCount).toBe(0);

    // Re-created at the same address with another key: the signatures on it
    // are that key's, not this passkey's.
    const swapped = await describeWith([account(ownAuthority, ownData({ publicKey: new Uint8Array(33).fill(8) }))]);
    expect(swapped.controlledAlone).toBe(false);
    expect(swapped.signatureCount).toBe(0);
  });

  it('reads the slot once, wallet accounts in pages of 100, and describes four candidates at a time', async () => {
    let slotCalls = 0;
    const pages: number[] = [];
    let inFlight = 0;
    let peak = 0;
    const busy = async <T>(value: T) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
      return value;
    };
    const connection = contextual(
      {
        getSlot: async () => (slotCalls++, 5),
        // Every address reads as a live v2 wallet with no lamports: the wallet
        // check passes, and the watched token addresses are no token accounts.
        getMultipleAccountsInfo: async (keys: PublicKey[]) => (
          pages.push(keys.length), keys.map(() => info(PROGRAM_ID_DEVNET, Buffer.from([ACCOUNT_DISCRIMINATOR.WALLET]), 0))
        ),
        getProgramAccounts: () => busy([]),
        getTokenAccountsByOwner: () => busy({ context: { slot: 5 }, value: [] }),
      },
      undefined,
      5,
    );
    const many = Array.from({ length: 150 }, () => {
      const w = randomKey();
      return { ...candidate, walletPda: w, vaultPda: findVaultPda(w, PROGRAM_ID_DEVNET)[0], authorityPda: randomKey() };
    });
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const out = await client.describeWalletCandidates(many);

    expect(out.map((f) => f.walletPda.toBase58())).toEqual(many.map((c) => c.walletPda.toBase58()));
    expect(out.every((f) => f.lamports === 0 && f.slot === 5n && f.tokenGrants.length === 0)).toBe(true);
    expect(slotCalls).toBe(1);
    // Every wallet account in pages of 100 (the liveness check); then six
    // accounts per candidate: wallet, vault, four watched token accounts.
    expect(pages).toEqual([100, 50, ...Array<number>(150).fill(6)]);
    // At most two reads per candidate in flight together (sessions with
    // deferred executions, or the two token programs), four candidates at a
    // time.
    expect(peak).toBeLessThanOrEqual(4 * 2);
    expect(peak).toBeGreaterThan(2);
  });

  it('refuses a trusted key that is not a public key', async () => {
    const client = new LazorKitClient(stub({}), PROGRAM_ID_DEVNET);
    await expect(client.describeWalletCandidates([candidate], { trustedKeys: ['nope'] })).rejects.toThrow();
  });

  it('refuses a malformed trusted key or watched mint even with no candidates, and reads nothing', async () => {
    let calls = 0;
    const counting = new Proxy({} as Connection, {
      get: () => async () => {
        calls++;
        return [];
      },
    });
    const client = new LazorKitClient(counting, PROGRAM_ID_DEVNET);
    await expect(client.describeWalletCandidates([], { trustedKeys: ['not-a-key'] })).rejects.toThrow();
    await expect(client.describeWalletCandidates([], { watchMints: ['not-a-mint'] })).rejects.toThrow();
    expect(await client.describeWalletCandidates([], { trustedKeys: [backendKey], watchMints: [randomKey()] })).toEqual([]);
    expect(calls).toBe(0);
  });

  it('also checks the canonical account of each mint in watchMints, once, after the four defaults', async () => {
    // An app's own mint: its canonical vault account was handed to someone else.
    const appMint = randomKey();
    const newOwner = randomKey();
    const appAta = getAssociatedTokenAddress(appMint, candidate.vaultPda, TOKEN_PROGRAM_ID);
    const connection = stub(
      { [ACCOUNT_DISCRIMINATOR.AUTHORITY]: [own()] },
      { accounts: { [appAta.toBase58()]: info(TOKEN_PROGRAM_ID, tokenAccountData(appMint, newOwner)) } },
    );
    const read: number[] = [];
    const readAccounts = connection.getMultipleAccountsInfo;
    Object.assign(connection, {
      getMultipleAccountsInfo: async (keys: PublicKey[]) => (read.push(keys.length), readAccounts(keys)),
    });
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);

    // Not asked about: out of sight.
    const [blind] = await client.describeWalletCandidates([candidate]);
    expect(blind.tokenGrants).toEqual([]);
    expect(blind.controlledAlone).toBe(true);

    const usdc = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
    const [seen] = await client.describeWalletCandidates([candidate], {
      watchMints: [appMint, appMint.toBase58(), usdc],
    });
    expect(seen.tokenGrants).toHaveLength(1);
    expect(seen.tokenGrants[0]).toMatchObject({ kind: 'owner', trusted: false });
    expect(seen.tokenGrants[0].tokenAccount.equals(appAta)).toBe(true);
    expect(seen.tokenGrants[0].tokenProgram.equals(TOKEN_PROGRAM_ID)).toBe(true);
    expect(seen.tokenGrants[0].mint!.equals(appMint)).toBe(true);
    expect(seen.tokenGrants[0].grantee!.equals(newOwner)).toBe(true);
    expect(seen.controlledAlone).toBe(false);
    // The liveness check, then wallet, vault and the four defaults; then one
    // more for the app's mint, however often it is named and though USDC is
    // named again.
    expect(read).toEqual([1, 6, 1, 7]);

    await expect(client.describeWalletCandidates([candidate], { watchMints: ['nope'] })).rejects.toThrow();
  });

  it('reads each step at or after the slot the one before it was answered at', async () => {
    const { connection, order } = chainStub({
      programs: { [PROGRAM_ID_DEVNET.toBase58()]: [{ pubkey: ownAuthority, data: own().account.data }] },
      accounts: { [wallet.toBase58()]: liveWallet() },
    });
    const [f] = await new LazorKitClient(connection, PROGRAM_ID_DEVNET).describeWalletCandidates([candidate]);
    expect(f.controlledAlone).toBe(true);
    expect(order).toEqual([
      { read: 'accounts', minContextSlot: undefined }, // the liveness check
      { read: 'authorities', minContextSlot: undefined },
      { read: 'sessions', minContextSlot: 1_000 },
      { read: 'deferred', minContextSlot: 1_000 },
      { read: 'accounts', minContextSlot: 1_000 },
      { read: 'tokenAccounts', minContextSlot: 1_000 },
      { read: 'tokenAccounts', minContextSlot: 1_000 },
    ]);
  });

  // One transaction landing while the reads are in flight must not be
  // half-seen. The stub serves the authority scan from after it and every
  // other read from before it unless told otherwise; reads made all at once
  // would see neither the co-owner nor what it left behind.
  describe('a transaction that lands mid-read is never half-seen', () => {
    const attacker = randomKey();
    const attackerAuthority = randomKey();
    const ownRow = () => ({ pubkey: ownAuthority, data: own().account.data });
    const attackerRow = () => ({
      pubkey: attackerAuthority,
      data: ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, attacker, ROLE_OWNER),
    });
    const at = (rows: { pubkey: PublicKey; data: Buffer }[]) => ({ [PROGRAM_ID_DEVNET.toBase58()]: rows });
    const walletAccounts = { [wallet.toBase58()]: liveWallet() };

    async function straddled(before: ChainState, after: ChainState, newest?: ReadKind[]) {
      const { connection } = chainStub({ ...after, before, newest });
      const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
      const [f] = await client.describeWalletCandidates([candidate]);
      return f;
    }

    it('a co-owner opening a session and removing itself in one transaction', async () => {
      const f = await straddled(
        { programs: at([ownRow(), attackerRow()]), accounts: walletAccounts },
        {
          programs: at([ownRow(), { pubkey: randomKey(), data: sessionData(wallet, sessionKey, SLOT + 50_000n) }]),
          accounts: walletAccounts,
        },
      );
      expect(f.otherAuthorities).toEqual([]);
      expect(f.liveSessions.map((s) => s.sessionKey.toBase58())).toEqual([sessionKey.toBase58()]);
      expect(f.controlledAlone).toBe(false);
    });

    it('a co-owner approving a delegate and removing itself in one transaction', async () => {
      const mint = randomKey();
      const tokenAccount = randomKey();
      const tokens = (delegate?: PublicKey) => ({
        [candidate.vaultPda.toBase58()]: [
          { pubkey: tokenAccount, tokenProgram: TOKEN_PROGRAM_ID, data: tokenAccountData(mint, candidate.vaultPda, { delegate }) },
        ],
      });
      const f = await straddled(
        { programs: at([ownRow(), attackerRow()]), accounts: walletAccounts, tokenAccounts: tokens() },
        { programs: at([ownRow()]), accounts: walletAccounts, tokenAccounts: tokens(attacker) },
      );
      expect(f.otherAuthorities).toEqual([]);
      expect(f.tokenGrants.map((g) => [g.kind, g.grantee?.toBase58()])).toEqual([['delegate', attacker.toBase58()]]);
      expect(f.controlledAlone).toBe(false);
    });

    it('a pending deferred execution that runs — closing itself — and approves a delegate', async () => {
      // ExecuteDeferred is permissionless and closes the account in the same
      // instruction as its CPIs: a deferred read after it and a token read
      // before it would each see nothing. Reading everything after the
      // authorities is not enough — here they are served from before it too.
      const mint = randomKey();
      const tokenAccount = randomKey();
      const tokens = (delegate?: PublicKey) => ({
        [candidate.vaultPda.toBase58()]: [
          { pubkey: tokenAccount, tokenProgram: TOKEN_PROGRAM_ID, data: tokenAccountData(mint, candidate.vaultPda, { delegate }) },
        ],
      });
      const f = await straddled(
        {
          programs: at([ownRow(), { pubkey: randomKey(), data: deferredData(wallet, ownAuthority, SLOT + 10n) }]),
          accounts: walletAccounts,
          tokenAccounts: tokens(),
        },
        { programs: at([ownRow()]), accounts: walletAccounts, tokenAccounts: tokens(attacker) },
        ['sessions', 'deferred'],
      );
      expect(f.pendingDeferred).toEqual([]);
      expect(f.tokenGrants.map((g) => [g.kind, g.grantee?.toBase58()])).toEqual([['delegate', attacker.toBase58()]]);
      expect(f.controlledAlone).toBe(false);
    });

    it('a sole owner assigning the vault and handing the wallet over in one transaction', async () => {
      const f = await straddled(
        // Before: the attacker is the only authority; this passkey's is not there yet.
        {
          programs: at([attackerRow()]),
          accounts: { ...walletAccounts, [candidate.vaultPda.toBase58()]: info(SystemProgram.programId, Buffer.alloc(0), 5) },
        },
        {
          programs: at([ownRow()]),
          accounts: { ...walletAccounts, [candidate.vaultPda.toBase58()]: info(randomKey(), Buffer.alloc(0), 5) },
        },
      );
      expect(f.otherAuthorities).toEqual([]);
      expect(f.vaultIsSystemAccount).toBe(false);
      expect(f.controlledAlone).toBe(false);
    });
  });

  it('asks a lagging node again rather than read older state, and gives up after five tries', async () => {
    const state = {
      programs: { [PROGRAM_ID_DEVNET.toBase58()]: [{ pubkey: ownAuthority, data: own().account.data }] },
      accounts: { [wallet.toBase58()]: liveWallet() },
    };
    const lagging = chainStub({ ...state, lagging: 3 });
    const [f] = await new LazorKitClient(lagging.connection, PROGRAM_ID_DEVNET).describeWalletCandidates([candidate]);
    expect(f.controlledAlone).toBe(true);
    // Three refusals, each asked again: both concurrent scans and one more.
    expect(lagging.order.filter((o) => o.read === 'sessions' || o.read === 'deferred').length).toBe(5);

    const stuck = chainStub({ ...state, lagging: 1_000 });
    const failure = await new LazorKitClient(stuck.connection, PROGRAM_ID_DEVNET)
      .describeWalletCandidates([candidate])
      .catch((e: unknown) => e);
    expect((failure as { code?: unknown }).code).toBe(-32016);
    // Five tries of the session scan, then it throws; nothing later is read.
    expect(stuck.order.filter((o) => o.read === 'sessions').length).toBe(5);
    expect(stuck.order.some((o) => o.read === 'tokenAccounts')).toBe(false);
  });

  it('drops a wallet whose account is gone by the time its own accounts are read', async () => {
    // Live at the liveness check (served from before), closed by the time the
    // wallet is read again with the rest (at or after the authorities' slot).
    const { connection } = chainStub({
      programs: { [PROGRAM_ID_DEVNET.toBase58()]: [{ pubkey: ownAuthority, data: own().account.data }] },
      before: {
        programs: { [PROGRAM_ID_DEVNET.toBase58()]: [{ pubkey: ownAuthority, data: own().account.data }] },
        accounts: { [wallet.toBase58()]: liveWallet() },
      },
    });
    expect(await new LazorKitClient(connection, PROGRAM_ID_DEVNET).describeWalletCandidates([candidate])).toEqual([]);
  });
});

describe('vetMigrationDestination (stubbed RPC)', () => {
  const wallet = randomKey();
  const vault = findVaultPda(wallet, PROGRAM_ID_DEVNET)[0];
  const credentialIdHash = new Uint8Array(32).fill(0x31);
  const ownKey = new Uint8Array(33).fill(3);
  const owner = { type: 'secp256r1' as const, credentialIdHash, compressedPubkey: ownKey, rpId: RP_ID };
  const ownRow = () => ({
    pubkey: randomKey(),
    data: passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, { credentialIdHash, publicKey: ownKey, counter: 2 }),
  });
  const at = (rows: { pubkey: PublicKey; data: Buffer }[]) => ({ [PROGRAM_ID_DEVNET.toBase58()]: rows });
  const walletAccounts = { [wallet.toBase58()]: liveWallet() };
  const attacker = randomKey();
  const attackerRow = () => ({
    pubkey: randomKey(),
    data: ed25519AuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, attacker, ROLE_OWNER),
  });

  it('reads in the same order as describeWalletCandidates, each step no older than the one before', async () => {
    const { connection, order } = chainStub({ programs: at([ownRow()]), accounts: walletAccounts });
    expect(await new LazorKitClient(connection, PROGRAM_ID_DEVNET).vetMigrationDestination(wallet, owner)).toBeNull();
    expect(order).toEqual([
      { read: 'authorities', minContextSlot: undefined },
      { read: 'sessions', minContextSlot: 1_000 },
      { read: 'deferred', minContextSlot: 1_000 },
      { read: 'accounts', minContextSlot: 1_000 },
      { read: 'tokenAccounts', minContextSlot: 1_000 },
      { read: 'tokenAccounts', minContextSlot: 1_000 },
    ]);
  });

  it('sees a session a co-owner opened as it removed itself in the same transaction', async () => {
    const { connection } = chainStub({
      programs: at([ownRow(), { pubkey: randomKey(), data: sessionData(wallet, randomKey(), 50_000n) }]),
      accounts: walletAccounts,
      before: { programs: at([ownRow(), attackerRow()]), accounts: walletAccounts },
    });
    expect(await new LazorKitClient(connection, PROGRAM_ID_DEVNET).vetMigrationDestination(wallet, owner)).toContain(
      'has a live session',
    );
  });

  it('sees a vault its sole owner assigned away as it handed the wallet over', async () => {
    const program = randomKey();
    const { connection } = chainStub({
      programs: at([ownRow()]),
      accounts: { ...walletAccounts, [vault.toBase58()]: info(program, Buffer.alloc(0), 5) },
      before: {
        programs: at([attackerRow()]),
        accounts: { ...walletAccounts, [vault.toBase58()]: info(SystemProgram.programId, Buffer.alloc(0), 5) },
      },
    });
    expect(await new LazorKitClient(connection, PROGRAM_ID_DEVNET).vetMigrationDestination(wallet, owner)).toContain(
      `is owned by program ${program.toBase58()}, not the System Program`,
    );
  });

  it('takes watchMints as its third argument', async () => {
    const appMint = randomKey();
    const newOwner = randomKey();
    const appAta = getAssociatedTokenAddress(appMint, vault, TOKEN_PROGRAM_ID);
    const { connection } = chainStub({
      programs: at([ownRow()]),
      accounts: { ...walletAccounts, [appAta.toBase58()]: info(TOKEN_PROGRAM_ID, tokenAccountData(appMint, newOwner)) },
    });
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    expect(await client.vetMigrationDestination(wallet, owner)).toBeNull();
    expect(await client.vetMigrationDestination(wallet, owner, { watchMints: [appMint.toBase58()] })).toContain(
      `(the vault's own account for mint ${appMint.toBase58()}) belongs to ${newOwner.toBase58()}`,
    );
    await expect(client.vetMigrationDestination(wallet, owner, { watchMints: ['nope'] })).rejects.toThrow();
  });
});

describe('findOwnPasskeyWallet (stubbed RPC)', () => {
  it('passes watchMints through to the description', async () => {
    const passkey = newPasskey();
    const credentialIdHash = new Uint8Array(32).fill(0x41);
    const wallet = randomKey();
    const vault = findVaultPda(wallet, PROGRAM_ID_DEVNET)[0];
    const appMint = randomKey();
    const newOwner = randomKey();
    const appAta = getAssociatedTokenAddress(appMint, vault, TOKEN_PROGRAM_ID);
    const { connection } = chainStub({
      programs: {
        [PROGRAM_ID_DEVNET.toBase58()]: [
          {
            pubkey: randomKey(),
            data: passkeyAuthorityData(ACCOUNT_DISCRIMINATOR.AUTHORITY, wallet, {
              credentialIdHash,
              publicKey: passkey.publicKey,
              counter: 4,
            }),
          },
        ],
      },
      accounts: {
        [wallet.toBase58()]: liveWallet(),
        [appAta.toBase58()]: info(TOKEN_PROGRAM_ID, tokenAccountData(appMint, newOwner)),
      },
    });
    const client = new LazorKitClient(connection, PROGRAM_ID_DEVNET);
    const find = (watchMints?: PublicKey[]) =>
      client.findOwnPasskeyWallet({
        credentialIdHash,
        rpId: RP_ID,
        proof: assertion(passkey, createOwnershipChallenge()),
        watchMints,
      });

    // Signed for, and nothing it can see is anyone else's: adopted.
    const blind = await find();
    expect(blind.adopt?.walletPda.equals(wallet)).toBe(true);
    expect(blind.adopt?.signatureCount).toBe(4);

    // With the app's mint named, its canonical account shows as handed away.
    const watching = await find([appMint]);
    expect(watching.adopt).toBeNull();
    expect(watching.needsConfirmation).toHaveLength(1);
    expect(watching.needsConfirmation[0].tokenGrants.map((g) => [g.kind, g.grantee?.toBase58()])).toEqual([
      ['owner', newOwner.toBase58()],
    ]);
  });
});

// ─── Against the validator ───────────────────────────────────────────────

// SPL Token instructions, by hand: sdk-legacy has no spl-token dependency.

function initializeMint2Ix(mint: PublicKey, mintAuthority: PublicKey): TransactionInstruction {
  const data = Buffer.alloc(35);
  data[0] = 20; // InitializeMint2
  data[1] = 0; // decimals
  mintAuthority.toBuffer().copy(data, 2);
  data[34] = 0; // no freeze authority
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [{ pubkey: mint, isSigner: false, isWritable: true }],
    data,
  });
}

function approveIx(tokenAccount: PublicKey, delegate: PublicKey, owner: PublicKey, amount: bigint): TransactionInstruction {
  const data = Buffer.alloc(9);
  data[0] = 4; // Approve
  data.writeBigUInt64LE(amount, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: delegate, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function mintToIx(mint: PublicKey, to: PublicKey, mintAuthority: PublicKey, amount: bigint): TransactionInstruction {
  const data = Buffer.alloc(9);
  data[0] = 7; // MintTo
  data.writeBigUInt64LE(amount, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: mint, isSigner: false, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
      { pubkey: mintAuthority, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function transferIx(source: PublicKey, destination: PublicKey, owner: PublicKey, amount: bigint): TransactionInstruction {
  const data = Buffer.alloc(9);
  data[0] = 3; // Transfer
  data.writeBigUInt64LE(amount, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function setAccountOwnerIx(tokenAccount: PublicKey, newOwner: PublicKey, owner: PublicKey): TransactionInstruction {
  const data = Buffer.alloc(35);
  data[0] = 6; // SetAuthority
  data[1] = 2; // AccountOwner
  data[2] = 1; // Some
  newOwner.toBuffer().copy(data, 3);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: tokenAccount, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

describe('passkey wallet ownership (validator)', () => {
  let ctx: TestContext;
  let client: LazorKitClient;

  async function createPasskeyWallet(key: MockSecp256r1Key, compressedPubkey = key.publicKeyBytes) {
    const result = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'secp256r1', credentialIdHash: key.credentialIdHash, compressedPubkey, rpId: key.rpId },
    });
    await sendTx(ctx, result.instructions);
    return result;
  }

  /** Receives the lamport `signOnce` moves; funded, so a single lamport is no rent problem. */
  const sink = Keypair.generate().publicKey;

  /** The passkey signs one Execute on the wallet: a lamport out of its (funded) vault. */
  async function signOnce(key: MockSecp256r1Key, walletPda: PublicKey, vaultPda: PublicKey) {
    const { instructions } = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda,
      signer: secp256r1(createMockRawSigner(key)),
      instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: sink, lamports: 1 })],
    });
    await sendTx(ctx, instructions);
  }

  /** A passkey wallet its passkey has used: funded, and signed for once. */
  async function createUsedPasskeyWallet(key: MockSecp256r1Key) {
    const created = await createPasskeyWallet(key);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: created.vaultPda, lamports: 2_000_000 }),
    ]);
    await signOnce(key, created.walletPda, created.vaultPda);
    return created;
  }

  async function proofFrom(key: MockSecp256r1Key): Promise<OwnershipProof> {
    const challenge = createOwnershipChallenge();
    const response = await fakeWebAuthnSign(key, challenge);
    return {
      challenge,
      signature: response.signature,
      authenticatorData: response.authenticatorData,
      clientDataJson: response.clientDataJson,
    };
  }

  beforeAll(async () => {
    ctx = await setupTest();
    client = new LazorKitClient(ctx.connection);
    await sendTx(ctx, [SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: sink, lamports: 1_000_000 })]);
  });

  it('a passkey opens an unrestricted session when it says so', async () => {
    // createSession used to drop `unrestricted` on the passkey path, so this threw.
    const key = await generateMockSecp256r1Key(RP_ID);
    const { walletPda } = await createPasskeyWallet(key);
    const { instructions } = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda,
      adminSigner: secp256r1(createMockRawSigner(key)),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: (await getSlot(ctx)) + 9_000n,
      unrestricted: true,
    });
    await sendTx(ctx, instructions);
    const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID });
    const [facts] = await client.describeWalletCandidates(candidates);
    expect(facts.liveSessions).toHaveLength(1);
  });

  describe('one passkey wallet, as others gain a way to spend from it', () => {
    let key: MockSecp256r1Key;
    let walletPda: PublicKey;
    let vaultPda: PublicKey;
    let authorityPda: PublicKey;
    const admin = Keypair.generate();
    const sessionKp = Keypair.generate();

    beforeAll(async () => {
      key = await generateMockSecp256r1Key(RP_ID);
      ({ walletPda, vaultPda, authorityPda } = await createPasskeyWallet(key));
      await sendTx(ctx, [
        SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: vaultPda, lamports: 25_000_000 }),
      ]);
    });

    it('finds it, verifies a real assertion against it, and adopts it once the passkey has signed for it', async () => {
      const candidates = await client.findPasskeyWalletCandidates({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
      });
      expect(candidates).toHaveLength(1);
      const [c] = candidates;
      expect(c.version).toBe(2);
      expect(c.programId.equals(client.programId)).toBe(true);
      expect(c.walletPda.equals(walletPda)).toBe(true);
      expect(c.vaultPda.equals(vaultPda)).toBe(true);
      expect(c.authorityPda.equals(authorityPda)).toBe(true);
      expect(Buffer.from(c.publicKey)).toEqual(Buffer.from(key.publicKeyBytes));

      const proof = await proofFrom(key);
      expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual(candidates);

      const [f] = await client.describeWalletCandidates(candidates);
      expect(f.controlledAlone).toBe(true);
      expect(f.otherAuthorities).toEqual([]);
      expect(f.liveSessions).toEqual([]);
      expect(f.pendingDeferred).toEqual([]);
      expect(f.vaultIsSystemAccount).toBe(true);
      expect(f.tokenGrants).toEqual([]);
      expect(f.lamports).toBe(await ctx.connection.getBalance(vaultPda));
      expect(f.slot > 0n).toBe(true);
      expect(f.signatureCount).toBe(0);

      // Created and not used yet: offered, not adopted. A wallet someone
      // handed to this passkey would look exactly the same.
      const fresh = await client.findOwnPasskeyWallet({ credentialIdHash: key.credentialIdHash, rpId: RP_ID, proof });
      expect(fresh.adopt).toBeNull();
      expect(fresh.needsConfirmation.map((x) => x.walletPda.toBase58())).toEqual([walletPda.toBase58()]);
      expect(fresh.unproven).toBe(0);

      await signOnce(key, walletPda, vaultPda);
      const own = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof: await proofFrom(key),
      });
      expect(own.adopt?.walletPda.equals(walletPda)).toBe(true);
      expect(own.adopt?.signatureCount).toBe(1);
      expect(own.needsConfirmation).toEqual([]);
      expect(own.unproven).toBe(0);
    });

    it('an Ed25519 admin makes it shared — unless the integrator trusts that key', async () => {
      const { instructions } = await client.addAuthority({
        payer: ctx.payer.publicKey,
        walletPda,
        adminSigner: secp256r1(createMockRawSigner(key)),
        newAuthority: { type: 'ed25519', publicKey: admin.publicKey },
        role: ROLE_ADMIN,
      });
      await sendTx(ctx, instructions);

      const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID });
      const [shared] = await client.describeWalletCandidates(candidates);
      expect(shared.controlledAlone).toBe(false);
      expect(shared.otherAuthorities).toHaveLength(1);
      expect(shared.otherAuthorities[0]).toMatchObject({ type: 'ed25519', role: 'admin', trusted: false });
      expect(shared.otherAuthorities[0].publicKey!.equals(admin.publicKey)).toBe(true);

      const [trusted] = await client.describeWalletCandidates(candidates, { trustedKeys: [admin.publicKey] });
      expect(trusted.controlledAlone).toBe(true);
      expect(trusted.otherAuthorities[0].trusted).toBe(true);
    });

    it('a live session makes it shared — unless its key is trusted too', async () => {
      const expiresAt = (await getSlot(ctx)) + 9_000n;
      const { instructions, sessionPda } = await client.createSession({
        payer: ctx.payer.publicKey,
        walletPda,
        adminSigner: ed25519(admin.publicKey),
        sessionKey: sessionKp.publicKey,
        expiresAt,
        actions: [Actions.solLimit(1_000_000n)],
      });
      await sendTx(ctx, instructions, [admin]);

      const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID });
      const [withSession] = await client.describeWalletCandidates(candidates, { trustedKeys: [admin.publicKey] });
      expect(withSession.liveSessions).toHaveLength(1);
      expect(withSession.liveSessions[0].sessionPda.equals(sessionPda)).toBe(true);
      expect(withSession.liveSessions[0].sessionKey.equals(sessionKp.publicKey)).toBe(true);
      expect(withSession.liveSessions[0].expiresAtSlot).toBe(expiresAt);
      expect(withSession.liveSessions[0].trusted).toBe(false);
      expect(withSession.controlledAlone).toBe(false);

      const [trusted] = await client.describeWalletCandidates(candidates, {
        trustedKeys: [admin.publicKey.toBase58(), sessionKp.publicKey.toBase58()],
      });
      expect(trusted.liveSessions[0].trusted).toBe(true);
      expect(trusted.controlledAlone).toBe(true);
    });

    it('findOwnPasskeyWallet then asks the user instead of adopting it', async () => {
      const proof = await proofFrom(key);
      const own = await client.findOwnPasskeyWallet({ credentialIdHash: key.credentialIdHash, rpId: RP_ID, proof });
      expect(own.adopt).toBeNull();
      expect(own.needsConfirmation.map((f) => f.walletPda.toBase58())).toEqual([walletPda.toBase58()]);
      expect(selectWalletByAddress(own.needsConfirmation, vaultPda.toBase58())?.walletPda.equals(walletPda)).toBe(true);

      const trusting = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof: await proofFrom(key),
        trustedKeys: [admin.publicKey, sessionKp.publicKey],
      });
      expect(trusting.adopt?.walletPda.equals(walletPda)).toBe(true);
    });
  });

  it('a passkey authority at Admin rank is not a candidate', async () => {
    const key = await generateMockSecp256r1Key(RP_ID);
    const owner = Keypair.generate();
    const created = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    await sendTx(ctx, created.instructions);
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.publicKey,
      walletPda: created.walletPda,
      adminSigner: ed25519(owner.publicKey),
      newAuthority: { type: 'secp256r1', credentialIdHash: key.credentialIdHash, compressedPubkey: key.publicKeyBytes, rpId: RP_ID },
      role: ROLE_ADMIN,
    });
    await sendTx(ctx, instructions, [owner]);

    // The raw lookup lists it; the candidate finder does not.
    const raw = await client.findWalletsByAuthority(key.credentialIdHash);
    expect(raw.map((r) => r.walletPda.toBase58())).toEqual([created.walletPda.toBase58()]);
    expect(await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID })).toEqual([]);
  });

  it('a wallet created under another relying party is not a candidate', async () => {
    const key = await generateMockSecp256r1Key('other-rp.example');
    const { walletPda } = await createPasskeyWallet(key);

    expect(await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID })).toEqual([]);
    const underItsOwn = await client.findPasskeyWalletCandidates({
      credentialIdHash: key.credentialIdHash,
      rpId: 'other-rp.example',
    });
    expect(underItsOwn.map((c) => c.walletPda.toBase58())).toEqual([walletPda.toBase58()]);
  });

  it('a wallet listing the same credential hash with another public key is found but not proven', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    // The attacker knows the victim's credential-id hash (it is public) and
    // lists it next to a key they hold. CreateWallet asks neither.
    const attacker = await generateMockSecp256r1Key(RP_ID, victim.credentialIdHash);
    const real = await createPasskeyWallet(victim);
    const planted = await createPasskeyWallet(victim, attacker.publicKeyBytes);

    const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID });
    expect(candidates.map((c) => c.walletPda.toBase58()).sort()).toEqual(
      [real.walletPda, planted.walletPda].map((k) => k.toBase58()).sort(),
    );

    const proven = verifyOwnershipProof(candidates, await proofFrom(victim), RP_ID);
    expect(proven.map((c) => c.walletPda.toBase58())).toEqual([real.walletPda.toBase58()]);
    const theirs = verifyOwnershipProof(candidates, await proofFrom(attacker), RP_ID);
    expect(theirs.map((c) => c.walletPda.toBase58())).toEqual([planted.walletPda.toBase58()]);

    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    // Only the real wallet is offered (not adopted: it has not been used yet).
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation.map((f) => f.walletPda.toBase58())).toEqual([real.walletPda.toBase58()]);
    expect(own.unproven).toBe(1);
  });

  it('with no wallet this passkey provably owns, there is nothing to adopt or confirm', async () => {
    const key = await generateMockSecp256r1Key(RP_ID);
    const own = await client.findOwnPasskeyWallet({ credentialIdHash: key.credentialIdHash, rpId: RP_ID, proof: await proofFrom(key) });
    expect(own).toEqual({ adopt: null, needsConfirmation: [], unproven: 0 });
  });

  // A wallet someone else controlled first, then handed to the victim's
  // passkey: whatever they set up while in control must still show.

  /** An Ed25519-owned wallet whose owner is about to hand it over. */
  async function walletControlledBy(owner: Keypair) {
    const created = await client.createWallet({
      payer: ctx.payer.publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    await sendTx(ctx, created.instructions);
    return created;
  }

  /** `passkey` as the owner `migrateV1Wallet` / `vetMigrationDestination` take. */
  const ownerOf = (passkey: MockSecp256r1Key) => ({
    type: 'secp256r1' as const,
    credentialIdHash: passkey.credentialIdHash,
    compressedPubkey: passkey.publicKeyBytes,
    rpId: passkey.rpId,
  });

  /** TransferOwnership to `passkey`, closing the previous owner's authority. */
  async function handOver(walletPda: PublicKey, from: Keypair, passkey: MockSecp256r1Key) {
    const handed = await client.transferOwnership({
      payer: ctx.payer.publicKey,
      walletPda,
      ownerSigner: ed25519(from.publicKey),
      newOwner: {
        type: 'secp256r1',
        credentialIdHash: passkey.credentialIdHash,
        compressedPubkey: passkey.publicKeyBytes,
        rpId: passkey.rpId,
      },
    });
    await sendTx(ctx, handed.instructions, [from]);
    return handed.newOwnerAuthorityPda;
  }

  it('a deferred execution queued at this passkey\'s authority address, by another key, is not trusted', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const real = await createUsedPasskeyWallet(victim);

    // Richer than the victim's real wallet. Never adopted (the victim's
    // passkey has not signed for it), but the user choosing must see the drain.
    const attacker = Keypair.generate();
    const bait = await walletControlledBy(attacker);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: bait.vaultPda, lamports: 200_000_000 }),
    ]);

    // 1. The attacker's own P-256 key at the victim's credential hash — the
    //    address the victim's passkey will have on this wallet — queues a drain.
    const planted = await generateMockSecp256r1Key(RP_ID, victim.credentialIdHash);
    const added = await client.addAuthority({
      payer: ctx.payer.publicKey,
      walletPda: bait.walletPda,
      adminSigner: ed25519(attacker.publicKey),
      newAuthority: { type: 'secp256r1', credentialIdHash: victim.credentialIdHash, compressedPubkey: planted.publicKeyBytes, rpId: RP_ID },
      role: ROLE_OWNER,
      allowOwner: true,
    });
    await sendTx(ctx, added.instructions, [attacker]);
    const thief = Keypair.generate().publicKey;
    const queued = await client.authorize({
      payer: ctx.payer.publicKey,
      walletPda: bait.walletPda,
      signer: secp256r1(createMockRawSigner(planted), { authorityPda: added.newAuthorityPda }),
      instructions: [SystemProgram.transfer({ fromPubkey: bait.vaultPda, toPubkey: thief, lamports: 150_000_000 })],
      expiryOffset: 9_000,
    });
    await sendTx(ctx, queued.instructions);

    // 2. That authority is removed, and the same address re-created holding
    //    the victim's real key as the only authority left.
    const removed = await client.removeAuthority({
      payer: ctx.payer.publicKey,
      walletPda: bait.walletPda,
      adminSigner: ed25519(attacker.publicKey),
      targetAuthorityPda: added.newAuthorityPda,
    });
    await sendTx(ctx, removed.instructions, [attacker]);
    const reborn = await handOver(bait.walletPda, attacker, victim);
    expect(reborn.equals(added.newAuthorityPda)).toBe(true);

    // The victim's proof holds for it — the key there is theirs now — and no
    // other authority or session remains. Only the queued drain gives it away.
    const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID });
    const proven = verifyOwnershipProof(candidates, await proofFrom(victim), RP_ID);
    const baitCandidate = proven.find((c) => c.walletPda.equals(bait.walletPda))!;
    expect(baitCandidate).toBeDefined();
    const [f] = await client.describeWalletCandidates([baitCandidate]);
    expect(f.otherAuthorities).toEqual([]);
    expect(f.liveSessions).toEqual([]);
    expect(f.pendingDeferred).toHaveLength(1);
    expect(f.pendingDeferred[0].authorizedBy.equals(baitCandidate.authorityPda)).toBe(true);
    expect(f.pendingDeferred[0].trusted).toBe(false);
    expect(f.controlledAlone).toBe(false);

    const own = await client.findOwnPasskeyWallet({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID, proof: await proofFrom(victim) });
    expect(own.adopt?.walletPda.equals(real.walletPda)).toBe(true);

    // And the threat is real: ExecuteDeferred does not ask who authorized it.
    const tx2 = await client.executeDeferredFromPayload({ payer: ctx.payer.publicKey, deferredPayload: queued.deferredPayload });
    await sendTx(ctx, tx2.instructions);
    expect(await ctx.connection.getBalance(thief)).toBe(150_000_000);
  });

  it('a token delegate an earlier controller left on the vault makes it shared — unless trusted', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const previous = Keypair.generate();
    const w = await walletControlledBy(previous);

    // Any mint: delegates are found on every token account the vault owns.
    const mint = Keypair.generate();
    const ata = getAssociatedTokenAddress(mint.publicKey, w.vaultPda, TOKEN_PROGRAM_ID);
    await sendTx(
      ctx,
      [
        SystemProgram.createAccount({
          fromPubkey: ctx.payer.publicKey,
          newAccountPubkey: mint.publicKey,
          lamports: await ctx.connection.getMinimumBalanceForRentExemption(82),
          space: 82,
          programId: TOKEN_PROGRAM_ID,
        }),
        initializeMint2Ix(mint.publicKey, ctx.payer.publicKey),
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.publicKey,
          ata,
          owner: w.vaultPda,
          mint: mint.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        }),
      ],
      [mint],
    );
    const delegate = Keypair.generate().publicKey;
    const approved = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda: w.walletPda,
      signer: ed25519(previous.publicKey),
      instructions: [approveIx(ata, delegate, w.vaultPda, 0xffff_ffff_ffff_ffffn)],
    });
    await sendTx(ctx, approved.instructions, [previous]);
    await handOver(w.walletPda, previous, victim);

    const own = await client.findOwnPasskeyWallet({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID, proof: await proofFrom(victim) });
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation).toHaveLength(1);
    const [f] = own.needsConfirmation;
    expect(f.otherAuthorities).toEqual([]);
    expect(f.tokenGrants).toHaveLength(1);
    expect(f.tokenGrants[0]).toMatchObject({ kind: 'delegate', trusted: false });
    expect(f.tokenGrants[0].tokenAccount.equals(ata)).toBe(true);
    expect(f.tokenGrants[0].tokenProgram.equals(TOKEN_PROGRAM_ID)).toBe(true);
    expect(f.tokenGrants[0].mint!.equals(mint.publicKey)).toBe(true);
    expect(f.tokenGrants[0].grantee!.equals(delegate)).toBe(true);

    // Trusting the delegate clears the facts; a wallet handed to this passkey
    // is still only offered, as it has never signed for it.
    const trusting = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
      trustedKeys: [delegate],
    });
    expect(trusting.adopt).toBeNull();
    expect(trusting.needsConfirmation).toHaveLength(1);
    expect(trusting.needsConfirmation[0]).toMatchObject({ controlledAlone: true, signatureCount: 0 });
    expect(trusting.needsConfirmation[0].walletPda.equals(w.walletPda)).toBe(true);

    // Nor may a v1 migration deliver into it: the delegate would take the tokens.
    const problem = await client.vetMigrationDestination(w.walletPda, ownerOf(victim));
    expect(problem).toContain(ata.toBase58());
    expect(problem).toContain(`has a delegate, ${delegate.toBase58()}`);
  });

  it('a canonical wSOL account handed to another owner makes it shared', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const previous = Keypair.generate();
    const w = await walletControlledBy(previous);

    const wsol = new PublicKey('So11111111111111111111111111111111111111112');
    const ata = getAssociatedTokenAddress(wsol, w.vaultPda, TOKEN_PROGRAM_ID);
    await sendTx(ctx, [
      createAssociatedTokenAccountIdempotentIx({
        payer: ctx.payer.publicKey,
        ata,
        owner: w.vaultPda,
        mint: wsol,
        tokenProgram: TOKEN_PROGRAM_ID,
      }),
    ]);
    // SPL Token lets even an associated token account change owner. It stops
    // listing as the vault's, but wSOL sent to the vault's address lands here.
    const newOwner = Keypair.generate().publicKey;
    const moved = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda: w.walletPda,
      signer: ed25519(previous.publicKey),
      instructions: [setAccountOwnerIx(ata, newOwner, w.vaultPda)],
    });
    await sendTx(ctx, moved.instructions, [previous]);
    await handOver(w.walletPda, previous, victim);

    const own = await client.findOwnPasskeyWallet({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID, proof: await proofFrom(victim) });
    expect(own.adopt).toBeNull();
    const [f] = own.needsConfirmation;
    expect(f.walletPda.equals(w.walletPda)).toBe(true);
    expect(f.otherAuthorities).toEqual([]);
    expect(f.tokenGrants).toHaveLength(1);
    expect(f.tokenGrants[0]).toMatchObject({ kind: 'owner', trusted: false });
    expect(f.tokenGrants[0].tokenAccount.equals(ata)).toBe(true);
    expect(f.tokenGrants[0].mint!.equals(wsol)).toBe(true);
    expect(f.tokenGrants[0].grantee!.equals(newOwner)).toBe(true);

    const problem = await client.vetMigrationDestination(w.walletPda, ownerOf(victim));
    expect(problem).toContain(
      `${ata.toBase58()} (the vault's own account for mint ${wsol.toBase58()}) belongs to ${newOwner.toBase58()}`,
    );
  });

  it('a vault its former owner Assigned to another program is only ever offered for confirmation', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const previous = Keypair.generate();
    const w = await walletControlledBy(previous);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: w.vaultPda, lamports: 5_000_000 }),
    ]);
    // An Owner with no policy: the vault signs the Assign through Execute, and
    // nothing checks the vault's owner after the inner instructions run.
    const newOwnerProgram = Keypair.generate().publicKey;
    const assigned = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda: w.walletPda,
      signer: ed25519(previous.publicKey),
      instructions: [SystemProgram.assign({ accountPubkey: w.vaultPda, programId: newOwnerProgram })],
    });
    await sendTx(ctx, assigned.instructions, [previous]);
    expect((await ctx.connection.getAccountInfo(w.vaultPda))!.owner.equals(newOwnerProgram)).toBe(true);
    await handOver(w.walletPda, previous, victim);

    const own = await client.findOwnPasskeyWallet({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID, proof: await proofFrom(victim) });
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation).toHaveLength(1);
    const [f] = own.needsConfirmation;
    expect(f.walletPda.equals(w.walletPda)).toBe(true);
    // Nothing else shows: no authority, session, deferred execution or grant.
    expect(f.otherAuthorities).toEqual([]);
    expect(f.liveSessions).toEqual([]);
    expect(f.pendingDeferred).toEqual([]);
    expect(f.tokenGrants).toEqual([]);
    expect(f.lamports).toBe(5_000_000);
    expect(f.vaultIsSystemAccount).toBe(false);
    expect(f.controlledAlone).toBe(false);

    // No trusted key changes that — not even the ones involved.
    const trusting = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
      trustedKeys: [previous.publicKey, newOwnerProgram],
    });
    expect(trusting.adopt).toBeNull();
    expect(trusting.needsConfirmation.map((x) => x.walletPda.toBase58())).toEqual([w.walletPda.toBase58()]);

    // And a v1 migration will not deliver into it.
    const problem = await client.vetMigrationDestination(w.walletPda, ownerOf(victim));
    expect(problem).toContain(
      `vault ${w.vaultPda.toBase58()} is owned by program ${newOwnerProgram.toBase58()}, not the System Program`,
    );
  });

  it('a wallet handed over clean is a fit migration destination; with a live session it is not', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const previous = Keypair.generate();
    const w = await walletControlledBy(previous);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: w.vaultPda, lamports: 5_000_000 }),
    ]);
    // A vault token account that is still the vault's alone does not count.
    const wsol = new PublicKey('So11111111111111111111111111111111111111112');
    await sendTx(ctx, [
      createAssociatedTokenAccountIdempotentIx({
        payer: ctx.payer.publicKey,
        ata: getAssociatedTokenAddress(wsol, w.vaultPda, TOKEN_PROGRAM_ID),
        owner: w.vaultPda,
        mint: wsol,
        tokenProgram: TOKEN_PROGRAM_ID,
      }),
    ]);
    await handOver(w.walletPda, previous, victim);
    expect(await client.vetMigrationDestination(w.walletPda, ownerOf(victim))).toBeNull();
    // Someone else's passkey is not this owner.
    expect(await client.vetMigrationDestination(w.walletPda, ownerOf(await generateMockSecp256r1Key(RP_ID)))).toContain(
      'not owned by this key alone',
    );

    // A session the victim's own passkey opens still counts: its key could be anyone's.
    const session = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda: w.walletPda,
      adminSigner: secp256r1(createMockRawSigner(victim)),
      sessionKey: Keypair.generate().publicKey,
      expiresAt: (await getSlot(ctx)) + 9_000n,
      actions: [Actions.solLimit(1_000_000n)],
    });
    await sendTx(ctx, session.instructions);
    expect(await client.vetMigrationDestination(w.walletPda, ownerOf(victim))).toContain('has a live session');
  });

  it("a wallet handed over with an unwatched mint's token account moved away looks clean, and is not adopted over the one the passkey signed for", async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const real = await createUsedPasskeyWallet(victim);
    const realBalance = await ctx.connection.getBalance(real.vaultPda);

    // An SPL Token mint other than the four watched ones (a JUP, a BONK, an
    // app's own token): its canonical vault account is moved to the attacker.
    const attacker = Keypair.generate();
    const bait = await walletControlledBy(attacker);
    const mint = Keypair.generate();
    const ata = getAssociatedTokenAddress(mint.publicKey, bait.vaultPda, TOKEN_PROGRAM_ID);
    await sendTx(
      ctx,
      [
        SystemProgram.createAccount({
          fromPubkey: ctx.payer.publicKey,
          newAccountPubkey: mint.publicKey,
          lamports: await ctx.connection.getMinimumBalanceForRentExemption(82),
          space: 82,
          programId: TOKEN_PROGRAM_ID,
        }),
        initializeMint2Ix(mint.publicKey, ctx.payer.publicKey),
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.publicKey,
          ata,
          owner: bait.vaultPda,
          mint: mint.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        }),
      ],
      [mint],
    );
    const moved = await client.execute({
      payer: ctx.payer.publicKey,
      walletPda: bait.walletPda,
      signer: ed25519(attacker.publicKey),
      instructions: [setAccountOwnerIx(ata, attacker.publicKey, bait.vaultPda)],
    });
    await sendTx(ctx, moved.instructions, [attacker]);
    // One lamport more than the victim's own vault, to rank first by balance.
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: bait.vaultPda, lamports: realBalance + 1 }),
    ]);
    await handOver(bait.walletPda, attacker, victim);

    // Nothing on chain leads back to the moved account: the facts are spotless,
    // and vetting passes it. Only the missing signature tells it apart.
    const candidates = await client.findPasskeyWalletCandidates({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID });
    const facts = await client.describeWalletCandidates(verifyOwnershipProof(candidates, await proofFrom(victim), RP_ID));
    const baitFacts = facts.find((f) => f.walletPda.equals(bait.walletPda))!;
    expect(baitFacts).toMatchObject({
      controlledAlone: true,
      vaultIsSystemAccount: true,
      tokenGrants: [],
      signatureCount: 0,
      lamports: realBalance + 1,
    });
    expect(facts.find((f) => f.walletPda.equals(real.walletPda))!.signatureCount).toBe(1);
    expect(await client.vetMigrationDestination(bait.walletPda, ownerOf(victim))).toBeNull();

    // Unless the app names the mint: then the account shows.
    const [watched] = await client.describeWalletCandidates([baitFacts], { watchMints: [mint.publicKey] });
    expect(watched.controlledAlone).toBe(false);
    expect(watched.tokenGrants).toHaveLength(1);
    expect(watched.tokenGrants[0]).toMatchObject({ kind: 'owner', trusted: false });
    expect(watched.tokenGrants[0].tokenAccount.equals(ata)).toBe(true);
    expect(watched.tokenGrants[0].grantee!.equals(attacker.publicKey)).toBe(true);
    expect(
      await client.vetMigrationDestination(bait.walletPda, ownerOf(victim), { watchMints: [mint.publicKey] }),
    ).toContain(`(the vault's own account for mint ${mint.publicKey.toBase58()}) belongs to ${attacker.publicKey.toBase58()}`);

    const own = await client.findOwnPasskeyWallet({ credentialIdHash: victim.credentialIdHash, rpId: RP_ID, proof: await proofFrom(victim) });
    expect(own.adopt?.walletPda.equals(real.walletPda)).toBe(true);
    expect(own.needsConfirmation).toEqual([]);

    // What that would have cost: tokens paid to the bait vault's address for
    // this mint land in the moved account, and the attacker alone moves them.
    const theirs = getAssociatedTokenAddress(mint.publicKey, attacker.publicKey, TOKEN_PROGRAM_ID);
    await sendTx(ctx, [mintToIx(mint.publicKey, ata, ctx.payer.publicKey, 1_000n)]);
    await sendTx(
      ctx,
      [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.publicKey,
          ata: theirs,
          owner: attacker.publicKey,
          mint: mint.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        }),
        transferIx(ata, theirs, attacker.publicKey, 1_000n),
      ],
      [attacker],
    );
    expect((await ctx.connection.getTokenAccountBalance(theirs)).value.amount).toBe('1000');
  });

  // The program's passkey challenge binds the payer, the counter and the
  // instruction's own arguments, but not the wallet, for CreateSession (and
  // AddAuthority, TransferOwnership, Authorize). So the signature from the
  // victim's first transaction on their own wallet also works on a wallet
  // planted for their passkey — through the same fee payer, which a relayer
  // lends to anyone — and raises its counter too.
  it("a planted wallet's signature count can be raised by replaying the victim's own first signature, so two signed-for wallets are never adopted", async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const real = await createPasskeyWallet(victim);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: real.vaultPda, lamports: 2_000_000 }),
    ]);
    const attacker = Keypair.generate();
    const bait = await walletControlledBy(attacker);
    const baitAuthority = await handOver(bait.walletPda, attacker, victim);

    // The victim's first passkey transaction: a session for the app's key.
    const appSessionKey = Keypair.generate().publicKey;
    const session = await client.createSession({
      payer: ctx.payer.publicKey,
      walletPda: real.walletPda,
      adminSigner: secp256r1(createMockRawSigner(victim)),
      sessionKey: appSessionKey,
      expiresAt: (await getSlot(ctx)) + 9_000n,
      actions: [Actions.solLimit(1_000_000n)],
    });
    await sendTx(ctx, session.instructions);

    // The same precompile instruction and instruction data, pointed at the
    // bait wallet, its victim authority and the session address there.
    const [baitSession] = client.findSession(bait.walletPda, appSessionKey.toBytes());
    const swap = new Map([
      [real.walletPda.toBase58(), bait.walletPda],
      [real.authorityPda.toBase58(), baitAuthority],
      [session.sessionPda.toBase58(), baitSession],
    ]);
    const replayed = session.instructions.map(
      (ix) =>
        new TransactionInstruction({
          programId: ix.programId,
          data: ix.data,
          keys: ix.keys.map((k) => ({ ...k, pubkey: swap.get(k.pubkey.toBase58()) ?? k.pubkey })),
        }),
    );
    await sendTx(ctx, replayed);
    // A lamport more than the victim's own vault, to rank first by balance.
    await sendTx(ctx, [
      SystemProgram.transfer({
        fromPubkey: ctx.payer.publicKey,
        toPubkey: bait.vaultPda,
        lamports: (await ctx.connection.getBalance(real.vaultPda)) + 1,
      }),
    ]);

    // With the app's session key trusted, both wallets are clean and both
    // signed for once: the counts cannot tell the user's wallet from the copy.
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
      trustedKeys: [appSessionKey],
    });
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation.map((f) => f.walletPda.toBase58())).toEqual(
      [bait.walletPda, real.walletPda].map((w) => w.toBase58()),
    );
    for (const f of own.needsConfirmation) {
      expect(f).toMatchObject({ controlledAlone: true, signatureCount: 1, otherAuthorities: [], tokenGrants: [] });
      expect(f.liveSessions.map((s) => s.sessionKey.toBase58())).toEqual([appSessionKey.toBase58()]);
    }
  });

  it('a wallet address holding only lamports is no wallet yet: vetting says so, and CreateWallet still takes it', async () => {
    // The v1 CreateWallet instruction made the userSeed public, so anyone can
    // fund the v2 wallet address a userSeed migration will use.
    const victim = await generateMockSecp256r1Key(RP_ID);
    const seed = crypto.randomBytes(32);
    const [walletPda] = client.findWallet(seed);
    await sendTx(ctx, [
      SystemProgram.transfer({ fromPubkey: ctx.payer.publicKey, toPubkey: walletPda, lamports: 1_000_000 }),
    ]);
    expect(await client.vetMigrationDestination(walletPda, ownerOf(victim))).toContain(
      `${walletPda.toBase58()} is not a wallet of program ${client.programId.toBase58()}`,
    );

    // So migrateV1Wallet creates the wallet there (16-v1-migration-unit), which
    // works: the program tops the balance up and takes the account.
    const created = await client.createWallet({ payer: ctx.payer.publicKey, userSeed: seed, owner: ownerOf(victim) });
    await sendTx(ctx, created.instructions);
    expect((await ctx.connection.getAccountInfo(walletPda))!.owner.equals(client.programId)).toBe(true);
    expect(await client.vetMigrationDestination(walletPda, ownerOf(victim))).toBeNull();
  });
});
