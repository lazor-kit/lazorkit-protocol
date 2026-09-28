/**
 * Which wallet a returning passkey user owns, against a stubbed RPC.
 *
 * The credential-id hash is public and `CreateWallet`/`AddAuthority` take any
 * owner without consent, so finding a wallet by hash proves nothing. These
 * tests pin the three things that do: the proof (a P-256 signature over a
 * fresh challenge, under this relying party), the description of who else can
 * spend, and the rule that turns those into "adopt" or "ask the user".
 *
 * Mirrors tests-sdk/tests/17-ownership.test.ts (unit half), the sdk-legacy twin.
 * The live-validator half is tests-sdk-kit/tests/17-ownership.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2';
import {
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  SolanaError,
  getAddressDecoder,
  isSolanaError,
  getAddressEncoder,
  type Address,
} from '@solana/kit';
import bs58lib from 'bs58';

import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_2022_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  V1_DISC_AUTHORITY,
  V1_DISC_DEFERRED_EXEC,
  V1_DISC_SESSION,
  V1_DISC_WALLET,
  createOwnershipChallenge,
  findV1VaultPda,
  findVaultPda,
  getAssociatedTokenAddress,
  pickOwnWallet,
  selectWalletByAddress,
  verifyOwnershipProof,
  type OwnershipProof,
  type PasskeyWalletCandidate,
  type WalletFacts,
} from '../src/index.js';
import { ACCOUNT_DISCRIMINATOR } from '../src/constants.js';

const RP_ID = 'portal.lazor.sh';
const utf8 = new TextEncoder();
const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const CURVE_N = p256.CURVE.n;

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const b64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bs58 = (bytes: Uint8Array): string => bs58lib.encode(bytes);
const bytesOf = (a: Address): Uint8Array => new Uint8Array(addressEncoder.encode(a));

let addrCounter = 1;
/** A distinct, valid address per call. */
function freshAddress(): Address {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(0, addrCounter++);
  bytes[31] = 0x5a;
  return addressDecoder.decode(bytes);
}

// ─── Passkeys and proofs ─────────────────────────────────────────────

function newPasskey() {
  const secretKey = p256.utils.randomPrivateKey();
  return { secretKey, publicKey: p256.getPublicKey(secretKey, true) };
}

/** An assertion as a browser would return it, with knobs to break each rule. */
function makeProof(
  secretKey: Uint8Array,
  opts: {
    challenge?: Uint8Array;
    /** The challenge written into clientDataJSON, when it should differ. */
    signedChallenge?: Uint8Array;
    rpId?: string;
    type?: string;
    flags?: number;
    format?: 'der' | 'compact';
    highS?: boolean;
    clientDataJson?: Uint8Array;
  } = {},
): OwnershipProof {
  const challenge = opts.challenge ?? createOwnershipChallenge();
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(utf8.encode(opts.rpId ?? RP_ID)), 0);
  authenticatorData[32] = opts.flags ?? 0x05; // UP | UV
  const clientDataJson =
    opts.clientDataJson ??
    utf8.encode(
      JSON.stringify({
        type: opts.type ?? 'webauthn.get',
        challenge: b64url(opts.signedChallenge ?? challenge),
        origin: `https://${RP_ID}`,
        crossOrigin: false,
      }),
    );
  const message = sha256(new Uint8Array([...authenticatorData, ...sha256(clientDataJson)]));
  const lowS = p256.sign(message, secretKey, { prehash: false, lowS: true });
  const sig = opts.highS ? new p256.Signature(lowS.r, CURVE_N - lowS.s) : lowS;
  return {
    challenge,
    signature: opts.format === 'compact' ? sig.toCompactRawBytes() : sig.toDERRawBytes(),
    authenticatorData,
    clientDataJson,
  };
}

// ─── Account fixtures ────────────────────────────────────────────────

function passkeyAuthorityData(p: {
  disc?: number;
  role?: number;
  wallet: Address;
  credentialIdHash: Uint8Array;
  publicKey: Uint8Array;
  rpId?: string;
  /** The replay counter at 8: how many times this key has signed for the wallet. */
  counter?: number;
}): Uint8Array {
  const data = new Uint8Array(145);
  data[0] = p.disc ?? ACCOUNT_DISCRIMINATOR.AUTHORITY;
  data[1] = 1;
  data[2] = p.role ?? 0;
  new DataView(data.buffer).setUint32(8, p.counter ?? 0, true);
  data.set(bytesOf(p.wallet), 16);
  data.set(p.credentialIdHash, 48);
  data.set(p.publicKey, 80);
  data.set(sha256(utf8.encode(p.rpId ?? RP_ID)), 113);
  return data;
}

function ed25519AuthorityData(wallet: Address, key: Address, role = 1): Uint8Array {
  const data = new Uint8Array(80);
  data[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
  data[1] = 0;
  data[2] = role;
  data.set(bytesOf(wallet), 16);
  data.set(bytesOf(key), 48);
  return data;
}

function sessionData(wallet: Address, sessionKey: Address, expiresAt: bigint): Uint8Array {
  const data = new Uint8Array(80);
  data[0] = ACCOUNT_DISCRIMINATOR.SESSION;
  data.set(bytesOf(wallet), 8);
  data.set(bytesOf(sessionKey), 40);
  new DataView(data.buffer).setBigUint64(72, expiresAt, true);
  return data;
}

function deferredData(wallet: Address, authority: Address, expiresAt: bigint): Uint8Array {
  const data = new Uint8Array(176);
  data[0] = ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC;
  data.set(bytesOf(wallet), 72);
  data.set(bytesOf(authority), 104);
  new DataView(data.buffer).setBigUint64(168, expiresAt, true);
  return data;
}

/** An SPL token account (the 165-byte base layout Token-2022 shares). */
function tokenAccountData(p: {
  mint: Address;
  owner: Address;
  delegate?: Address;
  closeAuthority?: Address;
}): Uint8Array {
  const data = new Uint8Array(165);
  const view = new DataView(data.buffer);
  data.set(bytesOf(p.mint), 0);
  data.set(bytesOf(p.owner), 32);
  if (p.delegate) {
    view.setUint32(72, 1, true);
    data.set(bytesOf(p.delegate), 76);
  }
  data[108] = 1; // Initialized
  if (p.closeAuthority) {
    view.setUint32(129, 1, true);
    data.set(bytesOf(p.closeAuthority), 133);
  }
  return data;
}

// ─── Stub RPC ────────────────────────────────────────────────────────

interface Memcmp {
  memcmp: { offset: bigint; bytes: string; encoding: string };
}
interface StoredAccount {
  pubkey: Address;
  data: Uint8Array;
}
interface RawAccount {
  owner: Address;
  lamports?: bigint;
  data?: Uint8Array;
}
interface TokenAccount {
  pubkey: Address;
  tokenProgram: Address;
  data: Uint8Array;
}

/** The wallet account each candidate names, as its program keeps it. */
function walletAccounts(
  ...cs: Pick<PasskeyWalletCandidate, 'version' | 'programId' | 'walletPda'>[]
): Record<string, RawAccount> {
  return Object.fromEntries(
    cs.map((c) => [
      c.walletPda,
      {
        owner: c.programId,
        data: new Uint8Array([c.version === 1 ? V1_DISC_WALLET : ACCOUNT_DISCRIMINATOR.WALLET, 0, 0, 0, 0, 0, 0, 0]),
      },
    ]),
  );
}

type ReadKind = 'authorities' | 'sessions' | 'deferred' | 'accounts' | 'tokenAccounts';

/** What the chain holds at one slot. */
interface ChainState {
  programs: Record<string, StoredAccount[]>;
  /** Vault balances: system accounts with no data. */
  lamports?: Record<string, bigint>;
  /** Any other account, by address — wallet accounts among them. */
  accounts?: Record<string, RawAccount>;
  /** Token accounts, by the owner they list. */
  tokenAccounts?: Record<string, TokenAccount[]>;
}

/**
 * Enough of an RPC for the ownership reads: getProgramAccounts evaluates the
 * memcmp filters for real, so a test states what is on chain rather than what
 * each call returns. Every read answers with the context slot it was served
 * at — `slot`, or one less for `before`.
 */
function stubRpc(
  opts: ChainState & {
    slot?: bigint;
    /**
     * The chain one slot earlier, before one transaction produced the state
     * above. A lagging node serves it to every read that does not demand
     * newer state (`minContextSlot`) — except the kinds in `newest`, which it
     * serves from the newer state: pick the worst order for the reader.
     */
    before?: ChainState;
    /** Default `['authorities']`. */
    newest?: ReadKind[];
    /** The first this-many reads that carry a `minContextSlot` fail: the node has not reached it. */
    lagging?: number;
  },
) {
  const now = opts.slot ?? 1_000n;
  const newest = opts.newest ?? ['authorities'];
  const calls = {
    getSlot: 0,
    getMultipleAccounts: [] as Address[][],
    getProgramAccounts: [] as { programId: Address; filters: Memcmp[] }[],
    getTokenAccountsByOwner: [] as { owner: Address; programId: Address; encoding: string }[],
    /** Every account read in order, with the `minContextSlot` it asked for. */
    order: [] as { read: ReadKind; minContextSlot?: bigint }[],
  };
  let lagging = opts.lagging ?? 0;
  /** The state a read is answered from, and its slot; throws while lagging. */
  const serve = (kind: ReadKind, minContextSlot: bigint | undefined) => {
    if (minContextSlot !== undefined && lagging > 0) {
      lagging--;
      throw new SolanaError(SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, {
        contextSlot: now - 1n,
      });
    }
    const stale =
      opts.before && !newest.includes(kind) && (minContextSlot === undefined || minContextSlot < now);
    return stale
      ? { state: opts.before!, context: { slot: now - 1n } }
      : { state: opts as ChainState, context: { slot: now } };
  };
  let inFlight = 0;
  let maxInFlight = 0;
  const track = async <T>(result: () => T): Promise<T> => {
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 1));
    inFlight--;
    return result();
  };
  const rpc = {
    getSlot: () => ({
      send: async () => {
        calls.getSlot++;
        return now;
      },
    }),
    getMultipleAccounts: (addresses: Address[], config: { minContextSlot?: bigint }) => ({
      send: async () => {
        calls.getMultipleAccounts.push(addresses);
        calls.order.push({ read: 'accounts', minContextSlot: config.minContextSlot });
        const { state, context } = serve('accounts', config.minContextSlot);
        return {
          context,
          value: addresses.map((a) => {
            const raw: RawAccount | undefined =
              state.accounts?.[a] ??
              (state.lamports?.[a] === undefined
                ? undefined
                : { owner: SYSTEM_PROGRAM_ADDRESS, lamports: state.lamports[a] });
            if (!raw) return null;
            return {
              owner: raw.owner,
              lamports: raw.lamports ?? 1n,
              data: [b64(raw.data ?? new Uint8Array(0)), 'base64'],
              executable: false,
            };
          }),
        };
      },
    }),
    getTokenAccountsByOwner: (
      owner: Address,
      filter: { programId: Address },
      config: { encoding: string; minContextSlot?: bigint },
    ) => ({
      send: () => {
        calls.getTokenAccountsByOwner.push({ owner, programId: filter.programId, encoding: config.encoding });
        calls.order.push({ read: 'tokenAccounts', minContextSlot: config.minContextSlot });
        return track(() => {
          const { state, context } = serve('tokenAccounts', config.minContextSlot);
          return {
            context,
            value: (state.tokenAccounts?.[owner] ?? [])
              .filter((t) => t.tokenProgram === filter.programId)
              .map(({ pubkey, tokenProgram, data }) => ({
                pubkey,
                account: { data: [b64(data), 'base64'], owner: tokenProgram, executable: false, lamports: 1n },
              })),
          };
        });
      },
    }),
    getProgramAccounts: (
      programId: Address,
      config: { filters: Memcmp[]; withContext?: boolean; minContextSlot?: bigint },
    ) => ({
      send: () => {
        calls.getProgramAccounts.push({ programId, filters: config.filters });
        const disc = bs58lib.decode(config.filters[0]!.memcmp.bytes)[0];
        const kind: ReadKind =
          disc === ACCOUNT_DISCRIMINATOR.AUTHORITY || disc === V1_DISC_AUTHORITY
            ? 'authorities'
            : disc === ACCOUNT_DISCRIMINATOR.SESSION || disc === V1_DISC_SESSION
              ? 'sessions'
              : 'deferred';
        calls.order.push({ read: kind, minContextSlot: config.minContextSlot });
        return track(() => {
          const { state, context } = serve(kind, config.minContextSlot);
          const value = (state.programs[programId] ?? [])
            .filter(({ data }) =>
              config.filters.every(({ memcmp }) => {
                const want = bs58lib.decode(memcmp.bytes);
                const off = Number(memcmp.offset);
                return data.length >= off + want.length && want.every((b, i) => data[off + i] === b);
              }),
            )
            .map(({ pubkey, data }) => ({
              pubkey,
              account: { data: [b64(data), 'base64'], executable: false, lamports: 1n },
            }));
          return config.withContext ? { context, value } : value;
        });
      },
    }),
  };
  return { rpc: rpc as never, calls, maxInFlight: () => maxInFlight };
}

function candidate(overrides: Partial<PasskeyWalletCandidate> = {}): PasskeyWalletCandidate {
  return {
    version: 2,
    programId: PROGRAM_ID_DEVNET,
    walletPda: freshAddress(),
    vaultPda: freshAddress(),
    authorityPda: freshAddress(),
    publicKey: newPasskey().publicKey,
    ...overrides,
  };
}

function facts(overrides: Partial<WalletFacts> = {}): WalletFacts {
  return {
    ...candidate(),
    lamports: 0n,
    slot: 1_000n,
    otherAuthorities: [],
    liveSessions: [],
    pendingDeferred: [],
    vaultIsSystemAccount: true,
    tokenGrants: [],
    controlledAlone: true,
    signatureCount: 1,
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('createOwnershipChallenge', () => {
  it('returns 32 fresh random bytes', () => {
    const a = createOwnershipChallenge();
    const b = createOwnershipChallenge();
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a).toHaveLength(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('verifyOwnershipProof', () => {
  const mine = newPasskey();
  const other = newPasskey();
  const candidates = [
    { id: 'mine', publicKey: mine.publicKey },
    { id: 'other', publicKey: other.publicKey },
  ];

  it('keeps the candidate whose key signed, for a DER signature', () => {
    const proven = verifyOwnershipProof(candidates, makeProof(mine.secretKey, { format: 'der' }), RP_ID);
    expect(proven.map((c) => c.id)).toEqual(['mine']);
  });

  it('keeps the candidate whose key signed, for a 64-byte r||s signature', () => {
    const proven = verifyOwnershipProof(candidates, makeProof(mine.secretKey, { format: 'compact' }), RP_ID);
    expect(proven.map((c) => c.id)).toEqual(['mine']);
  });

  it('accepts a high-S signature: authenticators produce them, and possession is still proven', () => {
    const proven = verifyOwnershipProof(
      candidates,
      makeProof(mine.secretKey, { format: 'compact', highS: true }),
      RP_ID,
    );
    expect(proven.map((c) => c.id)).toEqual(['mine']);
  });

  it('rejects an assertion over a different challenge', () => {
    // A valid signature by the right key — over some other challenge. Replaying
    // an old assertion must not prove anything today.
    const proof = makeProof(mine.secretKey, { signedChallenge: createOwnershipChallenge() });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('rejects a challenge shorter than 16 bytes', () => {
    const proof = makeProof(mine.secretKey, { challenge: new Uint8Array(15).fill(9) });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
    // 16 is enough.
    const ok = makeProof(mine.secretKey, { challenge: new Uint8Array(16).fill(9) });
    expect(verifyOwnershipProof(candidates, ok, RP_ID)).toHaveLength(1);
  });

  it('rejects an assertion made under another relying party', () => {
    const proof = makeProof(mine.secretKey, { rpId: 'evil.example' });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
    // …and the right assertion checked against the wrong rpId.
    expect(verifyOwnershipProof(candidates, makeProof(mine.secretKey), 'evil.example')).toEqual([]);
  });

  it('rejects a registration (webauthn.create) response', () => {
    const proof = makeProof(mine.secretKey, { type: 'webauthn.create' });
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('rejects an assertion without the user-present flag', () => {
    const proof = makeProof(mine.secretKey, { flags: 0x04 }); // UV without UP
    expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual([]);
  });

  it('keeps nothing when no candidate holds the signing key', () => {
    const stranger = newPasskey();
    expect(verifyOwnershipProof(candidates, makeProof(stranger.secretKey), RP_ID)).toEqual([]);
  });

  it('returns [] rather than throwing on garbage', () => {
    const garbage = makeProof(mine.secretKey, { clientDataJson: utf8.encode('{not json') });
    expect(verifyOwnershipProof(candidates, garbage, RP_ID)).toEqual([]);
    const nullJson = makeProof(mine.secretKey, { clientDataJson: utf8.encode('null') });
    expect(verifyOwnershipProof(candidates, nullJson, RP_ID)).toEqual([]);
    const shortAuthData = { ...makeProof(mine.secretKey), authenticatorData: new Uint8Array(36) };
    expect(verifyOwnershipProof(candidates, shortAuthData, RP_ID)).toEqual([]);
    const badSig = { ...makeProof(mine.secretKey), signature: new Uint8Array([1, 2, 3]) };
    expect(verifyOwnershipProof(candidates, badSig, RP_ID)).toEqual([]);
    const badKey = [{ id: 'bad', publicKey: new Uint8Array(33).fill(7) }];
    expect(verifyOwnershipProof(badKey, makeProof(mine.secretKey), RP_ID)).toEqual([]);
    expect(verifyOwnershipProof(candidates, {} as OwnershipProof, RP_ID)).toEqual([]);
  });
});

describe('pickOwnWallet', () => {
  it('adopts the one wallet signed for that only this passkey controls', () => {
    // Someone else can spend from it, and this passkey never signed for it.
    const shared = facts({ controlledAlone: false, signatureCount: 0, lamports: 10_000n });
    const alone = facts({ controlledAlone: true, lamports: 1n });
    expect(pickOwnWallet([shared, alone])).toEqual({ adopt: alone, needsConfirmation: [] });
  });

  it('adopts the one wallet signed for whatever its version or balance, over unsigned ones', () => {
    const signedV2Poor = facts({ version: 2, lamports: 1n });
    const unsignedV1 = facts({ version: 1, lamports: 9_000n, signatureCount: 0 });
    const unsignedRich = facts({ version: 2, lamports: 9_000n, signatureCount: 0 });
    expect(pickOwnWallet([unsignedRich, unsignedV1, signedV2Poor])).toEqual({
      adopt: signedV2Poor,
      needsConfirmation: [],
    });
  });

  it('lists v1 first (unmigrated funds), then the fuller vault, then the lower address', () => {
    const [lo, hi] = [freshAddress(), freshAddress()].sort();
    const v2Rich = facts({ version: 2, lamports: 9_000n });
    const v1Poor = facts({ version: 1, lamports: 1n });
    const v1Rich = facts({ version: 1, lamports: 5n });
    const v1TieHi = facts({ version: 1, lamports: 5n, walletPda: hi! });
    const v1TieLo = facts({ version: 1, lamports: 5n, walletPda: lo! });
    const input = [v2Rich, v1Poor, v1TieHi, v1Rich, v1TieLo];

    // All signed for: nothing adopted (see below), every wallet in that order.
    const { adopt, needsConfirmation } = pickOwnWallet(input);
    expect(adopt).toBeNull();
    const fives = [v1TieLo, v1Rich, v1TieHi].sort((a, b) => (a.walletPda < b.walletPda ? -1 : 1));
    expect(needsConfirmation).toEqual([...fives, v1Poor, v2Rich]);
    // The same order when none is signed for.
    const unsigned = input.map((f) => ({ ...f, signatureCount: 0 }));
    expect(pickOwnWallet(unsigned).needsConfirmation.map((f) => f.walletPda)).toEqual(
      [...fives, v1Poor, v2Rich].map((f) => f.walletPda),
    );
    // The input is not reordered.
    expect(input[0]).toBe(v2Rich);
  });

  it('with none controlled alone, adopts nothing and lists every wallet in the same order', () => {
    const [lo, hi] = [freshAddress(), freshAddress()].sort();
    const a = facts({ version: 2, lamports: 100n, controlledAlone: false });
    const b = facts({ version: 1, lamports: 1n, controlledAlone: false });
    const c = facts({ version: 2, lamports: 500n, controlledAlone: false, walletPda: hi! });
    const d = facts({ version: 2, lamports: 500n, controlledAlone: false, walletPda: lo! });

    const { adopt, needsConfirmation } = pickOwnWallet([a, b, c, d]);
    expect(adopt).toBeNull();
    expect(needsConfirmation).toEqual([b, d, c, a]);
  });

  it('adopts nothing and asks nothing when there are no facts', () => {
    expect(pickOwnWallet([])).toEqual({ adopt: null, needsConfirmation: [] });
  });

  it('never adopts a wallet this passkey has not signed for — not even the only one, however clean', () => {
    // Created and not used yet, or handed over by someone: the facts cannot
    // tell those apart, so the user does.
    const unused = facts({ signatureCount: 0, lamports: 5_000n });
    expect(pickOwnWallet([unused])).toEqual({ adopt: null, needsConfirmation: [unused] });
  });

  it('a richer wallet handed to this passkey does not outrank the one it signed for', () => {
    // A planted wallet looks spotless and costs a lamport more to rank first
    // by balance. Its passkey authority is new, so it has no signature on it.
    const mine = facts({ signatureCount: 7, lamports: 1_000_000n });
    const planted = facts({ signatureCount: 0, lamports: 1_000_001n });
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
    const mine = facts({ signatureCount: 3, lamports: 1_000_000n });
    const copied = facts({ signatureCount: 1, lamports: 1_000_001n });
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
    const signedShared = facts({ version: 2, lamports: 1n, signatureCount: 3, controlledAlone: false });
    const unsignedV1 = facts({ version: 1, lamports: 9_000n, signatureCount: 0 });
    const unsignedRich = facts({ version: 2, lamports: 9_000n, signatureCount: 0 });
    const pick = pickOwnWallet([unsignedRich, unsignedV1, signedShared]);
    expect(pick.adopt).toBeNull();
    expect(pick.needsConfirmation).toEqual([signedShared, unsignedV1, unsignedRich]);
  });

  it('counts having signed, not how often: a busier wallet does not outrank an older version', () => {
    const busyV2 = facts({ version: 2, lamports: 1n, signatureCount: 90 });
    const onceV1 = facts({ version: 1, lamports: 1n, signatureCount: 1 });
    const unsigned = facts({ version: 1, lamports: 1n, signatureCount: 0 });
    expect(pickOwnWallet([busyV2, unsigned, onceV1]).needsConfirmation).toEqual([onceV1, busyV2, unsigned]);
  });
});

describe('selectWalletByAddress', () => {
  const a = candidate();
  const b = candidate();

  it('matches the vault — the address users know', () => {
    expect(selectWalletByAddress([a, b], b.vaultPda)).toBe(b);
  });

  it('matches the wallet PDA', () => {
    expect(selectWalletByAddress([a, b], a.walletPda)).toBe(a);
    expect(selectWalletByAddress([a, b], a.walletPda as string)).toBe(a);
  });

  it('returns null for any other address', () => {
    expect(selectWalletByAddress([a, b], freshAddress())).toBeNull();
    expect(selectWalletByAddress([a, b], a.authorityPda)).toBeNull();
    expect(selectWalletByAddress([], a.vaultPda)).toBeNull();
  });
});

describe('findPasskeyWalletCandidates', () => {
  const credentialIdHash = new Uint8Array(32).fill(0x42);
  const key = newPasskey();

  it('filters on disc+type, the credential hash and the relying party, and derives each version’s vault', async () => {
    const v2Wallet = freshAddress();
    const v1Wallet = freshAddress();
    const v2Authority = freshAddress();
    const v1Authority = freshAddress();
    const { rpc, calls } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          {
            pubkey: v2Authority,
            data: passkeyAuthorityData({ wallet: v2Wallet, credentialIdHash, publicKey: key.publicKey }),
          },
        ],
        [PROGRAM_ID_DEVNET_V1]: [
          {
            pubkey: v1Authority,
            data: passkeyAuthorityData({
              disc: V1_DISC_AUTHORITY,
              wallet: v1Wallet,
              credentialIdHash,
              publicKey: key.publicKey,
            }),
          },
        ],
      },
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);

    const found = await lk.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID });

    // v2 first, then the v1 deployment paired with devnet v2.
    expect(found).toEqual([
      {
        version: 2,
        programId: PROGRAM_ID_DEVNET,
        walletPda: v2Wallet,
        vaultPda: (await findVaultPda(v2Wallet, PROGRAM_ID_DEVNET))[0],
        authorityPda: v2Authority,
        publicKey: key.publicKey,
      },
      {
        version: 1,
        programId: PROGRAM_ID_DEVNET_V1,
        walletPda: v1Wallet,
        // The bare `vault` seed: v1 predates the `lk2:` namespace.
        vaultPda: (await findV1VaultPda(v1Wallet, PROGRAM_ID_DEVNET_V1))[0],
        authorityPda: v1Authority,
        publicKey: key.publicKey,
      },
    ]);
    expect(found[1]!.vaultPda).not.toBe((await findVaultPda(v1Wallet, PROGRAM_ID_DEVNET_V1))[0]);

    // One scan per deployment, and the filters are the contract with the RPC.
    expect(calls.getProgramAccounts.map((c) => c.programId).sort()).toEqual(
      [PROGRAM_ID_DEVNET, PROGRAM_ID_DEVNET_V1].sort(),
    );
    const rpIdHash = sha256(utf8.encode(RP_ID));
    for (const { programId, filters } of calls.getProgramAccounts) {
      const disc = programId === PROGRAM_ID_DEVNET ? ACCOUNT_DISCRIMINATOR.AUTHORITY : V1_DISC_AUTHORITY;
      expect(filters.map((f) => f.memcmp.offset)).toEqual([0n, 48n, 113n]);
      expect(filters[0]!.memcmp.bytes).toBe(bs58(new Uint8Array([disc, 1])));
      expect(filters[1]!.memcmp.bytes).toBe(bs58(credentialIdHash));
      expect(filters[2]!.memcmp.bytes).toBe(bs58(rpIdHash));
    }
    expect(calls.getMultipleAccounts).toHaveLength(0);
  });

  it('keeps Owner rank only, and skips accounts too short to hold a passkey', async () => {
    const wallet = freshAddress();
    const owner = freshAddress();
    const { rpc } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          { pubkey: owner, data: passkeyAuthorityData({ wallet, credentialIdHash, publicKey: key.publicKey }) },
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet: freshAddress(), role: 1, credentialIdHash, publicKey: key.publicKey }),
          },
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet: freshAddress(), role: 2, credentialIdHash, publicKey: key.publicKey }),
          },
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet: freshAddress(), credentialIdHash, publicKey: key.publicKey }).slice(0, 144),
          },
        ],
      },
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);
    const found = await lk.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID, includeV1: false });
    expect(found.map((c) => c.authorityPda)).toEqual([owner]);
  });

  it('with includeV1: false scans only this program', async () => {
    const { rpc, calls } = stubRpc({ programs: {} });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);
    expect(await lk.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID, includeV1: false })).toEqual([]);
    expect(calls.getProgramAccounts.map((c) => c.programId)).toEqual([PROGRAM_ID_DEVNET]);
  });

  it('on an in-place layout, runs both scans against the one program id', async () => {
    const local = freshAddress();
    const v2Wallet = freshAddress();
    const v1Wallet = freshAddress();
    const { rpc, calls } = stubRpc({
      programs: {
        [local]: [
          { pubkey: freshAddress(), data: passkeyAuthorityData({ wallet: v2Wallet, credentialIdHash, publicKey: key.publicKey }) },
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ disc: V1_DISC_AUTHORITY, wallet: v1Wallet, credentialIdHash, publicKey: key.publicKey }),
          },
        ],
      },
    });
    const lk = new LazorKit(rpc, local);
    const found = await lk.findPasskeyWalletCandidates({ credentialIdHash, rpId: RP_ID });
    expect(found.map((c) => [c.version, c.programId, c.walletPda])).toEqual([
      [2, local, v2Wallet],
      [1, local, v1Wallet],
    ]);
    expect(found[1]!.vaultPda).toBe((await findV1VaultPda(v1Wallet, local))[0]);
    expect(calls.getProgramAccounts.map((c) => c.programId)).toEqual([local, local]);
  });

  it('rejects a credential hash that is not 32 bytes', async () => {
    const lk = new LazorKit({} as never, PROGRAM_ID_DEVNET);
    await expect(
      lk.findPasskeyWalletCandidates({ credentialIdHash: new Uint8Array(31), rpId: RP_ID }),
    ).rejects.toThrow('32 bytes');
  });
});

describe('describeWalletCandidates', () => {
  const SLOT = 5_000n;
  const credentialIdHash = new Uint8Array(32).fill(0x11);
  const key = newPasskey();

  /**
   * A live candidate whose own authority is on chain, plus whatever else the
   * test adds: program accounts, raw accounts (the vault, watched token
   * accounts) and token accounts the vault owns.
   */
  function setup(
    extra: (c: PasskeyWalletCandidate) => StoredAccount[],
    more: {
      /** The vault account; default a plain one holding 7 lamports, `null` for none. */
      vault?: RawAccount | null;
      accounts?: (c: PasskeyWalletCandidate) => Record<string, RawAccount>;
      tokenAccounts?: (c: PasskeyWalletCandidate) => TokenAccount[];
    } = {},
  ) {
    const c = candidate({ publicKey: key.publicKey });
    const own: StoredAccount = {
      pubkey: c.authorityPda,
      // Signed for three times.
      data: passkeyAuthorityData({ wallet: c.walletPda, credentialIdHash, publicKey: key.publicKey, counter: 3 }),
    };
    const stub = stubRpc({
      programs: { [PROGRAM_ID_DEVNET]: [own, ...extra(c)] },
      slot: SLOT,
      accounts: {
        ...walletAccounts(c),
        ...(more.vault === null
          ? {}
          : { [c.vaultPda]: more.vault ?? { owner: SYSTEM_PROGRAM_ADDRESS, lamports: 7n } }),
        ...more.accounts?.(c),
      },
      tokenAccounts: { [c.vaultPda]: more.tokenAccounts?.(c) ?? [] },
    });
    return { c, lk: new LazorKit(stub.rpc, PROGRAM_ID_DEVNET), ...stub };
  }

  it('a wallet with only this passkey is controlled alone', async () => {
    const { c, lk, calls } = setup(() => []);
    const [f] = await lk.describeWalletCandidates([c]);
    expect(f).toEqual({
      ...c,
      lamports: 7n,
      slot: SLOT,
      otherAuthorities: [],
      liveSessions: [],
      pendingDeferred: [],
      vaultIsSystemAccount: true,
      tokenGrants: [],
      controlledAlone: true,
      // Read off this passkey's own authority.
      signatureCount: 3,
    });
    // The same fields, in the same order, as @lazorkit/sdk-legacy's WalletFacts.
    expect(Object.keys(f!)).toEqual([
      'version', 'programId', 'walletPda', 'vaultPda', 'authorityPda', 'publicKey',
      'lamports', 'slot', 'otherAuthorities', 'liveSessions', 'pendingDeferred',
      'vaultIsSystemAccount', 'tokenGrants', 'controlledAlone', 'signatureCount',
    ]);
    expect(calls.getSlot).toBe(1);
    // The wallet accounts first, to drop dead candidates; then, after the
    // scans, the wallet account again, the vault, and the vault's SPL Token
    // account for each watched mint, in one call.
    const watched = await Promise.all(
      [
        'So11111111111111111111111111111111111111112',
        'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
        'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
        '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
      ].map((m) => getAssociatedTokenAddress(m as Address, c.vaultPda, TOKEN_PROGRAM_ADDRESS)),
    );
    expect(calls.getMultipleAccounts).toEqual([[c.walletPda], [c.walletPda, c.vaultPda, ...watched]]);
    // Authority, session and deferred scans, each on the candidate's wallet.
    const offsets = calls.getProgramAccounts.map((x) => [
      x.filters[0]!.memcmp.bytes,
      x.filters[1]!.memcmp.offset,
      x.filters[1]!.memcmp.bytes,
    ]);
    expect(offsets).toEqual([
      [bs58(new Uint8Array([ACCOUNT_DISCRIMINATOR.AUTHORITY])), 16n, c.walletPda],
      [bs58(new Uint8Array([ACCOUNT_DISCRIMINATOR.SESSION])), 8n, c.walletPda],
      [bs58(new Uint8Array([ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC])), 72n, c.walletPda],
    ]);
    // …and the vault's token accounts under both token programs.
    expect(calls.getTokenAccountsByOwner).toEqual([
      { owner: c.vaultPda, programId: TOKEN_PROGRAM_ADDRESS, encoding: 'base64' },
      { owner: c.vaultPda, programId: TOKEN_2022_PROGRAM_ADDRESS, encoding: 'base64' },
    ]);
  });

  it('an Ed25519 authority is untrusted unless its key is in trustedKeys', async () => {
    const backend = freshAddress();
    const pda = freshAddress();
    const { c, lk } = setup((c) => [{ pubkey: pda, data: ed25519AuthorityData(c.walletPda, backend, 1) }]);

    const [plain] = await lk.describeWalletCandidates([c]);
    expect(plain!.otherAuthorities).toEqual([
      { authorityPda: pda, type: 'ed25519', role: 'admin', publicKey: backend, trusted: false },
    ]);
    expect(plain!.controlledAlone).toBe(false);

    const [trusted] = await lk.describeWalletCandidates([c], { trustedKeys: [backend as string] });
    expect(trusted!.otherAuthorities[0]!.trusted).toBe(true);
    expect(trusted!.controlledAlone).toBe(true);
  });

  it('another passkey is never trusted, and says whether it shares the relying party', async () => {
    const other = newPasskey();
    const same = freshAddress();
    const foreign = freshAddress();
    const { c, lk } = setup((c) => [
      {
        pubkey: same,
        data: passkeyAuthorityData({ wallet: c.walletPda, role: 0, credentialIdHash: new Uint8Array(32).fill(1), publicKey: other.publicKey }),
      },
      {
        pubkey: foreign,
        data: passkeyAuthorityData({
          wallet: c.walletPda,
          role: 2,
          credentialIdHash: new Uint8Array(32).fill(2),
          publicKey: other.publicKey,
          rpId: 'elsewhere.example',
        }),
      },
    ]);
    const [f] = await lk.describeWalletCandidates([c], {
      // Listing a passkey's bytes as a trusted key changes nothing.
      trustedKeys: [addressDecoder.decode(other.publicKey.slice(1))],
    });
    expect(f!.otherAuthorities).toEqual([
      { authorityPda: same, type: 'secp256r1', role: 'owner', sameRelyingParty: true, trusted: false },
      { authorityPda: foreign, type: 'secp256r1', role: 'spender', sameRelyingParty: false, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
  });

  it('a live session counts against the wallet unless its key is trusted; an expired one is ignored', async () => {
    const liveKey = freshAddress();
    const deadKey = freshAddress();
    const livePda = freshAddress();
    const { c, lk } = setup((c) => [
      { pubkey: livePda, data: sessionData(c.walletPda, liveKey, SLOT + 1n) },
      { pubkey: freshAddress(), data: sessionData(c.walletPda, deadKey, SLOT - 1n) },
    ]);

    const [plain] = await lk.describeWalletCandidates([c]);
    expect(plain!.liveSessions).toEqual([
      { sessionPda: livePda, sessionKey: liveKey, expiresAtSlot: SLOT + 1n, trusted: false },
    ]);
    expect(plain!.controlledAlone).toBe(false);

    const [trusted] = await lk.describeWalletCandidates([c], { trustedKeys: [liveKey] });
    expect(trusted!.liveSessions[0]!.trusted).toBe(true);
    expect(trusted!.controlledAlone).toBe(true);
  });

  it('a session or deferred execution expiring at the read slot is still live, as the program sees it', async () => {
    // The program refuses only `current_slot > expires_at`: at `expires_at`
    // itself the key still signs and the deferred still executes.
    const sessionKey = freshAddress();
    const sessionPda = freshAddress();
    const deferredPda = freshAddress();
    const { c, lk } = setup((c) => [
      { pubkey: sessionPda, data: sessionData(c.walletPda, sessionKey, SLOT) },
      { pubkey: deferredPda, data: deferredData(c.walletPda, c.authorityPda, SLOT) },
    ]);
    const [f] = await lk.describeWalletCandidates([c]);
    expect(f!.liveSessions).toEqual([{ sessionPda, sessionKey, expiresAtSlot: SLOT, trusted: false }]);
    expect(f!.pendingDeferred).toEqual([
      { deferredPda, authorizedBy: c.authorityPda, expiresAtSlot: SLOT, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
  });

  it('no pending deferred is trusted — not one naming this passkey’s authority, nor a trusted Ed25519 one', async () => {
    // Its authorizer is recorded as a PDA, and a passkey authority's PDA comes
    // from the credential-id hash: the key that signed may be one that sat
    // there before, since removed. ExecuteDeferred never checks again.
    const backend = freshAddress();
    const backendPda = freshAddress();
    const own = freshAddress();
    const byBackend = freshAddress();
    const { c, lk } = setup((c) => [
      { pubkey: backendPda, data: ed25519AuthorityData(c.walletPda, backend, 1) },
      { pubkey: own, data: deferredData(c.walletPda, c.authorityPda, SLOT + 10n) },
      { pubkey: byBackend, data: deferredData(c.walletPda, backendPda, SLOT + 10n) },
      // Expired: nothing left to execute.
      { pubkey: freshAddress(), data: deferredData(c.walletPda, c.authorityPda, SLOT - 1n) },
    ]);

    const [f] = await lk.describeWalletCandidates([c], { trustedKeys: [backend] });
    expect(f!.otherAuthorities.map((a) => a.trusted)).toEqual([true]);
    expect(f!.pendingDeferred).toEqual([
      { deferredPda: own, authorizedBy: c.authorityPda, expiresAtSlot: SLOT + 10n, trusted: false },
      { deferredPda: byBackend, authorizedBy: backendPda, expiresAtSlot: SLOT + 10n, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
  });

  it('a vault handed to another program, or given data, is not controlled alone; a missing one is fine', async () => {
    const attackerProgram = freshAddress();
    const describeWithVault = async (vault: RawAccount | null) => {
      const { c, lk } = setup(() => [], { vault });
      const [f] = await lk.describeWalletCandidates([c]);
      return f!;
    };

    // System::Assign through an Owner's Execute: the vault keeps its lamports,
    // but another program now decides what leaves it.
    const assigned = await describeWithVault({ owner: attackerProgram, lamports: 9n });
    expect(assigned.vaultIsSystemAccount).toBe(false);
    expect(assigned.lamports).toBe(9n);
    expect(assigned.controlledAlone).toBe(false);
    // System::Allocate (a nonce account, say): still System-owned, not plain.
    const allocated = await describeWithVault({ owner: SYSTEM_PROGRAM_ADDRESS, data: new Uint8Array(80) });
    expect(allocated.vaultIsSystemAccount).toBe(false);
    expect(allocated.controlledAlone).toBe(false);
    // Never funded: nothing there to take.
    const missing = await describeWithVault(null);
    expect(missing.vaultIsSystemAccount).toBe(true);
    expect(missing.lamports).toBe(0n);
    expect(missing.controlledAlone).toBe(true);
  });

  it('a delegate or foreign close authority on a vault token account counts against the wallet unless trusted', async () => {
    const mint = freshAddress();
    const delegate = freshAddress();
    const closer = freshAddress();
    const splAccount = freshAddress();
    const t22Account = freshAddress();
    const cleanAccount = freshAddress();
    const { c, lk } = setup(() => [], {
      tokenAccounts: (c) => [
        { pubkey: splAccount, tokenProgram: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint, owner: c.vaultPda, delegate }) },
        {
          pubkey: t22Account,
          tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
          // Token-2022 carries extensions past the 165-byte base; the offsets hold.
          data: new Uint8Array([
            ...tokenAccountData({ mint, owner: c.vaultPda, closeAuthority: closer }),
            2, 0, 0, 0,
          ]),
        },
        // The vault as its own delegate and close authority grants nothing.
        {
          pubkey: cleanAccount,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
          data: tokenAccountData({ mint, owner: c.vaultPda, delegate: c.vaultPda, closeAuthority: c.vaultPda }),
        },
      ],
    });

    const [f] = await lk.describeWalletCandidates([c]);
    expect(f!.tokenGrants).toEqual([
      { tokenAccount: splAccount, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint, kind: 'delegate', grantee: delegate, trusted: false },
      { tokenAccount: t22Account, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, mint, kind: 'closeAuthority', grantee: closer, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);

    const [partly] = await lk.describeWalletCandidates([c], { trustedKeys: [delegate] });
    expect(partly!.tokenGrants.map((g) => g.trusted)).toEqual([true, false]);
    expect(partly!.controlledAlone).toBe(false);

    const [both] = await lk.describeWalletCandidates([c], { trustedKeys: [delegate, closer] });
    expect(both!.controlledAlone).toBe(true);
  });

  it('the vault’s canonical token account for a watched mint, handed to another owner, counts against it', async () => {
    const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' as Address;
    const WSOL = 'So11111111111111111111111111111111111111112' as Address;
    const newOwner = freshAddress();
    const vaultPda = freshAddress();
    const usdcAta = await getAssociatedTokenAddress(USDC, vaultPda, TOKEN_PROGRAM_ADDRESS);
    const wsolAta = await getAssociatedTokenAddress(WSOL, vaultPda, TOKEN_PROGRAM_ADDRESS);
    const c = candidate({ publicKey: key.publicKey, vaultPda });
    const { rpc } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          { pubkey: c.authorityPda, data: passkeyAuthorityData({ wallet: c.walletPda, credentialIdHash, publicKey: key.publicKey }) },
        ],
      },
      slot: SLOT,
      accounts: {
        ...walletAccounts(c),
        // SetAuthority(AccountOwner): no longer listed as the vault's, but a
        // sender paying the vault's USDC address pays `newOwner`.
        [usdcAta]: { owner: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint: USDC, owner: newOwner }) },
        // Still the vault's: nothing to report (it is read with the vault's own).
        [wsolAta]: { owner: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint: WSOL, owner: vaultPda }) },
      },
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);

    const [f] = await lk.describeWalletCandidates([c]);
    expect(f!.tokenGrants).toEqual([
      { tokenAccount: usdcAta, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint: USDC, kind: 'owner', grantee: newOwner, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
    const [trusted] = await lk.describeWalletCandidates([c], { trustedKeys: [newOwner] });
    expect(trusted!.controlledAlone).toBe(true);
  });

  it('a token account too short to read is an untrusted grant, not skipped', async () => {
    const short = freshAddress();
    const { c, lk } = setup(() => [], {
      tokenAccounts: () => [
        { pubkey: short, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, data: new Uint8Array(100) },
      ],
    });
    const [f] = await lk.describeWalletCandidates([c]);
    expect(f!.tokenGrants).toEqual([
      { tokenAccount: short, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, mint: null, kind: 'unreadable', grantee: null, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
  });

  it('leaves out a candidate whose wallet account is gone or is not its program’s wallet', async () => {
    // MigrateWallet closes a v1 wallet and the authority that migrated it; any
    // other authority stays behind, pointing at nothing.
    const alive = candidate();
    const closed = candidate();
    const foreign = candidate();
    const notAWallet = candidate();
    const { rpc, calls } = stubRpc({
      programs: {},
      slot: SLOT,
      accounts: {
        ...walletAccounts(alive),
        [foreign.walletPda]: { ...walletAccounts(foreign)[foreign.walletPda]!, owner: freshAddress() },
        [notAWallet.walletPda]: { owner: PROGRAM_ID_DEVNET, data: new Uint8Array([ACCOUNT_DISCRIMINATOR.AUTHORITY]) },
      },
    });
    const out = await new LazorKit(rpc, PROGRAM_ID_DEVNET).describeWalletCandidates([
      closed,
      alive,
      foreign,
      notAWallet,
    ]);
    expect(out.map((f) => f.walletPda)).toEqual([alive.walletPda]);
    // Nothing more is read for the ones left out.
    expect(calls.getProgramAccounts).toHaveLength(3);
    expect(calls.getTokenAccountsByOwner).toHaveLength(2);
  });

  it('accounts too short to read count against the wallet instead of being skipped', async () => {
    const trustedKey = freshAddress();
    const shortAuth = freshAddress();
    const shortSession = freshAddress();
    const shortDeferred = freshAddress();
    const { c, lk } = setup((c) => [
      // An Ed25519 authority cut off before its key: it cannot be matched to a trusted key.
      { pubkey: shortAuth, data: ed25519AuthorityData(c.walletPda, trustedKey, 1).slice(0, 60) },
      // A session with no expiry to read: live.
      { pubkey: shortSession, data: sessionData(c.walletPda, trustedKey, SLOT - 100n).slice(0, 72) },
      // A deferred cut off inside its authorizer, this passkey's own: no expiry, no trust.
      { pubkey: shortDeferred, data: deferredData(c.walletPda, c.authorityPda, SLOT - 100n).slice(0, 120) },
    ]);
    const [f] = await lk.describeWalletCandidates([c], { trustedKeys: [trustedKey] });
    expect(f!.otherAuthorities).toEqual([
      { authorityPda: shortAuth, type: 'ed25519', role: 'admin', publicKey: undefined, trusted: false },
    ]);
    const NONE = '11111111111111111111111111111111';
    expect(f!.liveSessions).toEqual([
      { sessionPda: shortSession, sessionKey: NONE, expiresAtSlot: 0xffff_ffff_ffff_ffffn, trusted: false },
    ]);
    expect(f!.pendingDeferred).toEqual([
      { deferredPda: shortDeferred, authorizedBy: NONE, expiresAtSlot: 0xffff_ffff_ffff_ffffn, trusted: false },
    ]);
    expect(f!.controlledAlone).toBe(false);
  });

  it('is not controlled alone once its own authority is gone, demoted or holds another key', async () => {
    const credentialIdHash = new Uint8Array(32).fill(0x33);
    const c = candidate({ publicKey: key.publicKey });
    const describeWith = async (own: StoredAccount[]) => {
      const { rpc } = stubRpc({
        programs: { [PROGRAM_ID_DEVNET]: own },
        slot: SLOT,
        accounts: walletAccounts(c),
      });
      const [f] = await new LazorKit(rpc, PROGRAM_ID_DEVNET).describeWalletCandidates([c]);
      return f!;
    };
    const ownData = (o: { role?: number; publicKey?: Uint8Array }) =>
      passkeyAuthorityData({ wallet: c.walletPda, credentialIdHash, publicKey: key.publicKey, counter: 9, ...o });

    const intact = await describeWith([{ pubkey: c.authorityPda, data: ownData({}) }]);
    expect(intact.controlledAlone).toBe(true);
    expect(intact.signatureCount).toBe(9);
    // Gone: nothing else on the wallet, and still not this passkey's alone.
    const gone = await describeWith([]);
    expect(gone.otherAuthorities).toEqual([]);
    expect(gone.controlledAlone).toBe(false);
    expect(gone.signatureCount).toBe(0);
    const demoted = await describeWith([{ pubkey: c.authorityPda, data: ownData({ role: 1 }) }]);
    expect(demoted.controlledAlone).toBe(false);
    expect(demoted.signatureCount).toBe(0);
    // Re-created at the same address with another key: the signatures on it
    // are that key's, not this passkey's.
    const swapped = await describeWith([
      { pubkey: c.authorityPda, data: ownData({ publicKey: newPasskey().publicKey }) },
    ]);
    expect(swapped.controlledAlone).toBe(false);
    expect(swapped.signatureCount).toBe(0);
    const short = await describeWith([{ pubkey: c.authorityPda, data: ownData({}).slice(0, 144) }]);
    expect(short.controlledAlone).toBe(false);
    expect(short.signatureCount).toBe(0);
  });

  it('refuses a trusted key that is not an address', async () => {
    const { c, lk } = setup(() => []);
    await expect(lk.describeWalletCandidates([c], { trustedKeys: ['not-a-key'] })).rejects.toThrow();
  });

  it('a v1 candidate is described with v1 discriminators on its own program', async () => {
    const c = candidate({ version: 1, programId: PROGRAM_ID_DEVNET_V1 });
    // v1 authorities carry the same replay counter at 8.
    const own = passkeyAuthorityData({
      disc: V1_DISC_AUTHORITY,
      wallet: c.walletPda,
      credentialIdHash,
      publicKey: c.publicKey,
      counter: 5,
    });
    const { rpc, calls } = stubRpc({
      programs: { [PROGRAM_ID_DEVNET_V1]: [{ pubkey: c.authorityPda, data: own }] },
      slot: SLOT,
      accounts: walletAccounts(c),
    });
    const [f] = await new LazorKit(rpc, PROGRAM_ID_DEVNET).describeWalletCandidates([c]);
    expect(f!.lamports).toBe(0n); // no vault account at all
    expect(f!.controlledAlone).toBe(true);
    expect(f!.signatureCount).toBe(5);
    expect(calls.getProgramAccounts.map((x) => [x.programId, x.filters[0]!.memcmp.bytes])).toEqual([
      [PROGRAM_ID_DEVNET_V1, bs58(new Uint8Array([V1_DISC_AUTHORITY]))],
      [PROGRAM_ID_DEVNET_V1, bs58(new Uint8Array([V1_DISC_SESSION]))],
      [PROGRAM_ID_DEVNET_V1, bs58(new Uint8Array([V1_DISC_DEFERRED_EXEC]))],
    ]);
  });

  it('reads accounts in pages of 100, keeps input order, and describes at most 4 candidates at once', async () => {
    const many = Array.from({ length: 205 }, () => candidate());
    const lamports = Object.fromEntries(many.map((c, i) => [c.vaultPda, BigInt(i)]));
    const { rpc, calls, maxInFlight } = stubRpc({
      programs: {},
      slot: SLOT,
      lamports,
      accounts: walletAccounts(...many),
    });
    const out = await new LazorKit(rpc, PROGRAM_ID_DEVNET).describeWalletCandidates(many);

    expect(out.map((f) => f.walletPda)).toEqual(many.map((c) => c.walletPda));
    expect(out.map((f) => f.lamports)).toEqual(many.map((_, i) => BigInt(i)));
    expect(calls.getSlot).toBe(1);
    // Every wallet account in pages of 100; then six accounts per candidate:
    // wallet, vault, four watched token accounts.
    const pages = calls.getMultipleAccounts.map((page) => page.length);
    expect(pages).toEqual([100, 100, 5, ...Array<number>(205).fill(6)]);
    expect(calls.getProgramAccounts).toHaveLength(205 * 3);
    expect(calls.getTokenAccountsByOwner).toHaveLength(205 * 2);
    // At most two scans per candidate in flight together (sessions with
    // deferred, or the two token programs), four candidates at a time.
    expect(maxInFlight()).toBeLessThanOrEqual(8);
    expect(maxInFlight()).toBeGreaterThan(2);
  });

  it('reads each step at or after the slot the one before it was answered at', async () => {
    const { c, lk, calls } = setup(() => []);
    await lk.describeWalletCandidates([c]);
    expect(calls.order).toEqual([
      { read: 'accounts', minContextSlot: undefined }, // the liveness pre-check
      { read: 'authorities', minContextSlot: undefined },
      { read: 'sessions', minContextSlot: SLOT },
      { read: 'deferred', minContextSlot: SLOT },
      { read: 'accounts', minContextSlot: SLOT },
      { read: 'tokenAccounts', minContextSlot: SLOT },
      { read: 'tokenAccounts', minContextSlot: SLOT },
    ]);
  });

  // One attacker transaction, landing while the reads are in flight, must not
  // be half-seen. The stub serves the authority scan from after it and every
  // other read from before it unless told otherwise — reads made all at once
  // would see neither the attacker's authority nor what replaced it.
  describe('a transaction that lands mid-read is never half-seen', () => {
    const attacker = freshAddress();
    const attackerPda = freshAddress();
    const drain = freshAddress();

    function straddled(
      before: (c: PasskeyWalletCandidate, own: StoredAccount) => Partial<ChainState>,
      after: (c: PasskeyWalletCandidate, own: StoredAccount) => Partial<ChainState>,
      newest?: ReadKind[],
    ) {
      const c = candidate({ publicKey: key.publicKey });
      const own: StoredAccount = {
        pubkey: c.authorityPda,
        data: passkeyAuthorityData({ wallet: c.walletPda, credentialIdHash, publicKey: key.publicKey }),
      };
      const base = { programs: { [PROGRAM_ID_DEVNET]: [own] }, accounts: walletAccounts(c) };
      const stub = stubRpc({
        slot: SLOT,
        ...base,
        ...after(c, own),
        before: { ...base, ...before(c, own) },
        newest,
      });
      return { c, lk: new LazorKit(stub.rpc, PROGRAM_ID_DEVNET) };
    }

    it('a co-owner opening a session and removing itself in one transaction', async () => {
      const sessionKey = freshAddress();
      const { c, lk } = straddled(
        (c, own) => ({
          programs: { [PROGRAM_ID_DEVNET]: [own, { pubkey: attackerPda, data: ed25519AuthorityData(c.walletPda, attacker, 0) }] },
        }),
        (c, own) => ({
          programs: {
            [PROGRAM_ID_DEVNET]: [own, { pubkey: drain, data: sessionData(c.walletPda, sessionKey, SLOT + 50_000n) }],
          },
        }),
      );
      const [f] = await lk.describeWalletCandidates([c]);
      expect(f!.otherAuthorities).toEqual([]);
      expect(f!.liveSessions.map((s) => s.sessionKey)).toEqual([sessionKey]);
      expect(f!.controlledAlone).toBe(false);
    });

    it('a co-owner approving a delegate and removing itself in one transaction', async () => {
      const mint = freshAddress();
      const tokenAccount = freshAddress();
      const { c, lk } = straddled(
        (c, own) => ({
          programs: { [PROGRAM_ID_DEVNET]: [own, { pubkey: attackerPda, data: ed25519AuthorityData(c.walletPda, attacker, 0) }] },
          tokenAccounts: {
            [c.vaultPda]: [{ pubkey: tokenAccount, tokenProgram: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint, owner: c.vaultPda }) }],
          },
        }),
        (c) => ({
          tokenAccounts: {
            [c.vaultPda]: [
              { pubkey: tokenAccount, tokenProgram: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint, owner: c.vaultPda, delegate: attacker }) },
            ],
          },
        }),
      );
      const [f] = await lk.describeWalletCandidates([c]);
      expect(f!.tokenGrants.map((g) => [g.kind, g.grantee])).toEqual([['delegate', attacker]]);
      expect(f!.controlledAlone).toBe(false);
    });

    it('a pending deferred execution that runs — closing itself — and approves a delegate', async () => {
      // ExecuteDeferred is permissionless and closes the account in the same
      // instruction as its CPIs: a deferred read after it and a token read
      // before it would each see nothing. Reading everything after the
      // authorities is not enough — here they come from before it too.
      const mint = freshAddress();
      const tokenAccount = freshAddress();
      const account = (c: PasskeyWalletCandidate, delegate?: Address) => ({
        [c.vaultPda]: [
          { pubkey: tokenAccount, tokenProgram: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint, owner: c.vaultPda, delegate }) },
        ],
      });
      const { c, lk } = straddled(
        (c, own) => ({
          programs: { [PROGRAM_ID_DEVNET]: [own, { pubkey: drain, data: deferredData(c.walletPda, c.authorityPda, SLOT + 10n) }] },
          tokenAccounts: account(c),
        }),
        (c) => ({ tokenAccounts: account(c, attacker) }),
        ['sessions', 'deferred'],
      );
      const [f] = await lk.describeWalletCandidates([c]);
      expect(f!.tokenGrants.map((g) => [g.kind, g.grantee])).toEqual([['delegate', attacker]]);
      expect(f!.controlledAlone).toBe(false);
    });

    it('a sole owner assigning the vault and handing the wallet over in one transaction', async () => {
      const attackerProgram = freshAddress();
      const { c, lk } = straddled(
        (c) => ({
          // Before: the attacker is the only authority; the victim's is not there yet.
          programs: { [PROGRAM_ID_DEVNET]: [{ pubkey: attackerPda, data: ed25519AuthorityData(c.walletPda, attacker, 0) }] },
          lamports: { [c.vaultPda]: 5n },
        }),
        (c) => ({ accounts: { ...walletAccounts(c), [c.vaultPda]: { owner: attackerProgram, lamports: 5n } } }),
      );
      const [f] = await lk.describeWalletCandidates([c]);
      expect(f!.vaultIsSystemAccount).toBe(false);
      expect(f!.controlledAlone).toBe(false);
    });
  });

  it('asks a lagging node again rather than read older state, and gives up after five tries', async () => {
    const ok = setup(() => [], {});
    const lagging = stubRpc({
      programs: { [PROGRAM_ID_DEVNET]: [] },
      slot: SLOT,
      accounts: walletAccounts(ok.c),
      lagging: 3,
    });
    const [f] = await new LazorKit(lagging.rpc, PROGRAM_ID_DEVNET).describeWalletCandidates([ok.c]);
    expect(f!.walletPda).toBe(ok.c.walletPda);
    // Three refusals, each retried: both concurrent scans and one more.
    expect(lagging.calls.order.filter((o) => o.read === 'sessions' || o.read === 'deferred').length).toBeGreaterThan(2);

    const stuck = stubRpc({
      programs: { [PROGRAM_ID_DEVNET]: [] },
      slot: SLOT,
      accounts: walletAccounts(ok.c),
      lagging: 1_000,
    });
    const failure = await new LazorKit(stuck.rpc, PROGRAM_ID_DEVNET)
      .describeWalletCandidates([ok.c])
      .catch((e: unknown) => e);
    expect(isSolanaError(failure, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED)).toBe(true);
    // Five tries of each of the two concurrent scans, then nothing more.
    expect(stuck.calls.order.filter((o) => o.read === 'sessions').length).toBe(5);
    expect(stuck.calls.order.some((o) => o.read === 'tokenAccounts')).toBe(false);
  });

  it('checks the canonical account of each mint in watchMints too, and reads them in pages of 100', async () => {
    const extra = Array.from({ length: 150 }, () => freshAddress());
    const newOwner = freshAddress();
    const c = candidate({ publicKey: key.publicKey });
    const handed = await getAssociatedTokenAddress(extra[120]!, c.vaultPda, TOKEN_PROGRAM_ADDRESS);
    const { rpc, calls } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          { pubkey: c.authorityPda, data: passkeyAuthorityData({ wallet: c.walletPda, credentialIdHash, publicKey: key.publicKey }) },
        ],
      },
      slot: SLOT,
      accounts: {
        ...walletAccounts(c),
        [handed]: { owner: TOKEN_PROGRAM_ADDRESS, data: tokenAccountData({ mint: extra[120]!, owner: newOwner }) },
      },
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);

    // Outside the watched mints, the chain cannot say: nothing points back.
    const [unwatched] = await lk.describeWalletCandidates([c]);
    expect(unwatched!.tokenGrants).toEqual([]);
    expect(unwatched!.controlledAlone).toBe(true);

    calls.getMultipleAccounts.length = 0;
    const [watched] = await lk.describeWalletCandidates([c], {
      // A default mint listed again is not checked twice.
      watchMints: ['So11111111111111111111111111111111111111112', ...extra],
    });
    expect(watched!.tokenGrants).toEqual([
      { tokenAccount: handed, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint: extra[120], kind: 'owner', grantee: newOwner, trusted: false },
    ]);
    expect(watched!.controlledAlone).toBe(false);
    // wallet + vault + 4 default + 150 extra = 156 accounts, in two pages.
    expect(calls.getMultipleAccounts.map((p) => p.length)).toEqual([1, 100, 56]);

    await expect(lk.describeWalletCandidates([c], { watchMints: ['not-a-mint'] })).rejects.toThrow();
  });

  it('makes no calls for no candidates', async () => {
    const { rpc, calls } = stubRpc({ programs: {} });
    expect(await new LazorKit(rpc, PROGRAM_ID_DEVNET).describeWalletCandidates([])).toEqual([]);
    expect(calls.getSlot).toBe(0);
  });

  it('refuses a malformed trusted key or watched mint even with no candidates, and reads nothing', async () => {
    const { rpc, calls } = stubRpc({ programs: {} });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);
    await expect(lk.describeWalletCandidates([], { trustedKeys: ['not-a-key'] })).rejects.toThrow();
    await expect(lk.describeWalletCandidates([], { watchMints: ['not-a-mint'] })).rejects.toThrow();
    expect(
      await lk.describeWalletCandidates([], { trustedKeys: [freshAddress()], watchMints: [freshAddress()] }),
    ).toEqual([]);
    expect(calls.getSlot).toBe(0);
    expect(calls.getMultipleAccounts).toEqual([]);
  });
});

describe('findOwnPasskeyWallet', () => {
  const credentialIdHash = new Uint8Array(32).fill(0x77);
  const mine = newPasskey();
  const planted = newPasskey();

  it('adopts the proven wallet, drops the planted one and counts it as unproven', async () => {
    const myWallet = freshAddress();
    const plantedWallet = freshAddress();
    const myAuthority = freshAddress();
    const { rpc } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          {
            pubkey: myAuthority,
            data: passkeyAuthorityData({ wallet: myWallet, credentialIdHash, publicKey: mine.publicKey, counter: 2 }),
          },
          // Someone else's wallet listing this credential with their own key.
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet: plantedWallet, credentialIdHash, publicKey: planted.publicKey }),
          },
        ],
      },
      accounts: walletAccounts(
        { version: 2, programId: PROGRAM_ID_DEVNET, walletPda: myWallet },
        { version: 2, programId: PROGRAM_ID_DEVNET, walletPda: plantedWallet },
      ),
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);

    const result = await lk.findOwnPasskeyWallet({
      credentialIdHash,
      rpId: RP_ID,
      proof: makeProof(mine.secretKey),
    });
    expect(result.adopt?.walletPda).toBe(myWallet);
    expect(result.adopt?.authorityPda).toBe(myAuthority);
    expect(result.adopt?.signatureCount).toBe(2);
    expect(result.needsConfirmation).toEqual([]);
    expect(result.unproven).toBe(1);
  });

  it('offers — never adopts — a proven, clean wallet this passkey has never signed for, whatever is trusted', async () => {
    // The user's own new wallet reads exactly like one someone handed to them.
    const wallet = freshAddress();
    const { rpc } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          { pubkey: freshAddress(), data: passkeyAuthorityData({ wallet, credentialIdHash, publicKey: mine.publicKey }) },
        ],
      },
      accounts: walletAccounts({ version: 2, programId: PROGRAM_ID_DEVNET, walletPda: wallet }),
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);
    for (const trustedKeys of [undefined, [freshAddress()]]) {
      const result = await lk.findOwnPasskeyWallet({
        credentialIdHash,
        rpId: RP_ID,
        proof: makeProof(mine.secretKey),
        trustedKeys,
      });
      expect(result.adopt).toBeNull();
      expect(result.needsConfirmation.map((f) => [f.walletPda, f.controlledAlone, f.signatureCount])).toEqual([
        [wallet, true, 0],
      ]);
      expect(result.unproven).toBe(0);
    }
  });

  it('asks the user about a proven wallet someone else can also spend from', async () => {
    const wallet = freshAddress();
    const backend = freshAddress();
    const { rpc } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet, credentialIdHash, publicKey: mine.publicKey, counter: 1 }),
          },
          { pubkey: freshAddress(), data: ed25519AuthorityData(wallet, backend, 0) },
        ],
      },
      accounts: walletAccounts({ version: 2, programId: PROGRAM_ID_DEVNET, walletPda: wallet }),
    });
    const lk = new LazorKit(rpc, PROGRAM_ID_DEVNET);
    const proof = makeProof(mine.secretKey);

    const asked = await lk.findOwnPasskeyWallet({ credentialIdHash, rpId: RP_ID, proof });
    expect(asked.adopt).toBeNull();
    expect(asked.needsConfirmation.map((f) => f.walletPda)).toEqual([wallet]);
    expect(asked.unproven).toBe(0);

    const trusted = await lk.findOwnPasskeyWallet({ credentialIdHash, rpId: RP_ID, proof, trustedKeys: [backend] });
    expect(trusted.adopt?.walletPda).toBe(wallet);
  });

  it('with nothing proven, adopts nothing and asks nothing: the caller creates a wallet', async () => {
    const { rpc, calls } = stubRpc({
      programs: {
        [PROGRAM_ID_DEVNET]: [
          {
            pubkey: freshAddress(),
            data: passkeyAuthorityData({ wallet: freshAddress(), credentialIdHash, publicKey: planted.publicKey }),
          },
        ],
      },
    });
    const result = await new LazorKit(rpc, PROGRAM_ID_DEVNET).findOwnPasskeyWallet({
      credentialIdHash,
      rpId: RP_ID,
      proof: makeProof(mine.secretKey),
    });
    expect(result).toEqual({ adopt: null, needsConfirmation: [], unproven: 1 });
    // Nothing unproven is described.
    expect(calls.getSlot).toBe(0);
  });
});
