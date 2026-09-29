import { Buffer } from 'buffer';
import {
  AccountInfo,
  Connection,
  PublicKey,
  SolanaJSONRPCErrorCode,
  SystemProgram,
} from '@solana/web3.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { ACCOUNT_DISCRIMINATOR, legacyProgramIdFor } from '../constants';
import { concatBytes } from './bytes';
import { findVaultPda } from './pdas';
import { getAssociatedTokenAddress, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from './spl';
import {
  findV1VaultPda,
  V1_DISC_AUTHORITY,
  V1_DISC_DEFERRED_EXEC,
  V1_DISC_SESSION,
  V1_DISC_WALLET,
} from './v1';
import { AUTH_TYPE_ED25519, AUTH_TYPE_SECP256R1, ROLE_OWNER } from './instructions';

// Which wallet is a returning passkey's own?
//
// Not "any wallet that lists its credential-id hash". The hash is public — it
// sits in every authority account the passkey has — and `CreateWallet` and
// `AddAuthority` take any key without its consent. So anyone can create a
// wallet listing a victim's hash next to their own public key, or add the
// victim's real passkey to a wallet they control, and a lookup by hash returns
// it. A wallet is adopted without asking only when
//   1. this passkey's authority on it is Owner rank, under this relying party,
//      and stores the key the passkey has just PROVEN it holds (a P-256
//      signature over a fresh challenge the caller chose),
//   2. nothing untrusted can spend from it: no other authority, no live
//      session, no pending deferred execution, no delegate or foreign close
//      authority on the vault's token accounts, no vault handed to another
//      program — except keys the integrator declared trusted, and
//   3. this passkey has signed for it before, and for no other wallet it
//      owns. `TransferOwnership` and `AddAuthority` hand a wallet to a
//      passkey without asking it, and what the earlier holder did through the
//      vault is not all readable — an SPL Token account moved off the vault
//      for any mint but a few watched ones cannot be found. Only a wallet the
//      user already chose is past that. But a counter raised before the
//      passkey challenge named the wallet may hold a signature replayed from
//      another wallet (see `pickOwnWallet`), so two wallets signed for mean
//      asking.
// Anything else goes to the user to confirm. A wallet whose account is gone (a
// migrated v1 wallet leaves its other authorities behind) is no candidate.

export interface PasskeyWalletCandidate {
  /** 1 = the v1 deployment paired with this client's program (a pre-v2 wallet); 2 = this client's program. */
  version: 1 | 2;
  programId: PublicKey;
  walletPda: PublicKey;
  vaultPda: PublicKey;
  /** This passkey's authority on the wallet. */
  authorityPda: PublicKey;
  /** The 33-byte compressed P-256 key stored on that authority. */
  publicKey: Uint8Array;
}

/** A WebAuthn assertion over a challenge the caller chose. */
export interface OwnershipProof {
  /** Fresh random bytes the caller generated for this proof (>= 16 bytes; use createOwnershipChallenge()). */
  challenge: Uint8Array;
  /** DER or 64-byte r||s. */
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
}

export type AuthorityRoleName = 'owner' | 'admin' | 'spender' | 'unknown';

export interface WalletFacts extends PasskeyWalletCandidate {
  /** Vault balance, lamports. */
  lamports: number;
  /** Slot the reads were made at; expiry slots compare against it. */
  slot: bigint;
  /** Every authority on the wallet except this passkey's. */
  otherAuthorities: {
    authorityPda: PublicKey;
    type: 'ed25519' | 'secp256r1';
    role: AuthorityRoleName;
    /** Ed25519 only: the key. */
    publicKey?: PublicKey;
    /** Secp256r1 only: created under the same relying party as this passkey. */
    sameRelyingParty?: boolean;
    /** Ed25519 key listed in trustedKeys. Secp256r1 is never trusted. */
    trusted: boolean;
  }[];
  /** Sessions the program still accepts: expiry at or after `slot`. */
  liveSessions: {
    sessionPda: PublicKey;
    sessionKey: PublicKey;
    expiresAtSlot: bigint;
    trusted: boolean;
  }[];
  /** Deferred executions the program still accepts: expiry at or after `slot`. */
  pendingDeferred: {
    deferredPda: PublicKey;
    /** The authority PDA that authorized it. */
    authorizedBy: PublicKey;
    expiresAtSlot: bigint;
    /**
     * Always `false`. `ExecuteDeferred` never re-checks who authorized it, and
     * the PDA recorded here may since have been closed and re-created holding
     * another key — a passkey authority's address comes from its credential-id
     * hash, not its key, and that seed can equal an Ed25519 key's bytes. So
     * the name proves nothing about who signed.
     */
    trusted: boolean;
  }[];
  /**
   * The vault is a plain system account: owned by the System Program with no
   * data, or not created yet. An Owner's `Execute` can `Assign` it to another
   * program or `Allocate` it data; after that the new owner program, not
   * LazorKit, decides what leaves it.
   */
  vaultIsSystemAccount: boolean;
  /**
   * Rights over the vault's SPL Token / Token-2022 accounts, which outlive
   * every LazorKit authority: a delegate, a close authority other than the
   * vault, or the vault's canonical SPL Token account for a watched mint —
   * wSOL, USDC, USDT, devnet USDC, and any passed as `watchMints` — handed to
   * another owner (senders still pay into it).
   *
   * Not complete, and cannot be: a canonical SPL Token account for any other
   * mint that an earlier holder of the wallet handed to someone else no longer
   * lists as the vault's, and nothing on chain leads back to it. That is why a
   * wallet this passkey has never signed for is not adopted
   * (`signatureCount`), and why an app should pass the mints it receives as
   * `watchMints`.
   */
  tokenGrants: {
    tokenAccount: PublicKey;
    tokenProgram: PublicKey;
    /** `null` when the account is too short to read. */
    mint: PublicKey | null;
    kind: 'delegate' | 'closeAuthority' | 'owner' | 'unreadable';
    /** Who holds the right; `null` when the account is too short to read. */
    grantee: PublicKey | null;
    /** `grantee` is listed in trustedKeys. */
    trusted: boolean;
  }[];
  /** Nothing but this passkey and trusted keys can spend from the wallet. */
  controlledAlone: boolean;
  /**
   * How many times this passkey has signed for the wallet: the replay counter
   * on its authority account. Every authority starts at 0, however it was
   * created, and only a signature verified against the key it stores advances
   * it. 0 means this passkey never has — true of a wallet it created and has
   * not used yet, and of a wallet someone else handed to it. Read only while
   * its authority is intact; 0 otherwise.
   *
   * On v1, and on v2 before the program named the wallet in the passkey
   * challenge, the signature need not have been made for this wallet: one
   * made on another wallet for `CreateSession`, `AddAuthority`,
   * `TransferOwnership` or `Authorize` could be submitted here again, within
   * about 150 slots, through the same fee payer. See {@link pickOwnWallet}.
   */
  signatureCount: number;
}

// ─── Layouts ──────────────────────────────────────────────────────────────
//
// v1 and v2 accounts share every offset; only the discriminators and the PDA
// seeds differ.

interface VersionLayout {
  wallet: number;
  authority: number;
  session: number;
  deferred: number;
  vault(walletPda: PublicKey, programId: PublicKey): PublicKey;
}

const LAYOUTS: Record<1 | 2, VersionLayout> = {
  2: {
    wallet: ACCOUNT_DISCRIMINATOR.WALLET,
    authority: ACCOUNT_DISCRIMINATOR.AUTHORITY,
    session: ACCOUNT_DISCRIMINATOR.SESSION,
    deferred: ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC,
    vault: (wallet, programId) => findVaultPda(wallet, programId)[0],
  },
  1: {
    wallet: V1_DISC_WALLET,
    authority: V1_DISC_AUTHORITY,
    session: V1_DISC_SESSION,
    deferred: V1_DISC_DEFERRED_EXEC,
    vault: (wallet, programId) => findV1VaultPda(wallet, programId)[0],
  },
};

// Authority: disc | type | role | .. | counter 8..12 | .. | wallet 16..48 |
// key material from 48. Secp256r1 key material: credential-id hash 48..80,
// compressed key 80..113, rpId hash 113..145.
const AUTHORITY_COUNTER = 8;
const AUTHORITY_WALLET = 16;
const AUTHORITY_KEY = 48;
const AUTHORITY_ED25519_LEN = 80;
const AUTHORITY_P256_KEY = 80;
const AUTHORITY_RP_ID_HASH = 113;
const AUTHORITY_SECP256R1_LEN = 145;
// Session: disc .. | wallet 8..40 | session key 40..72 | expires_at 72..80.
const SESSION_WALLET = 8;
const SESSION_KEY = 40;
const SESSION_EXPIRES_AT = 72;
// DeferredExec: disc .. | wallet 72..104 | authority 104..136 | payer 136..168
// | expires_at 168..176.
const DEFERRED_WALLET = 72;
const DEFERRED_AUTHORITY = 104;
const DEFERRED_EXPIRES_AT = 168;
// SPL token account, the same base layout in Token-2022: mint 0..32 | owner
// 32..64 | amount | delegate COption 72..108 | state | is_native |
// delegated_amount | close_authority COption 129..165.
const TOKEN_OWNER = 32;
const TOKEN_DELEGATE = 72;
const TOKEN_CLOSE_AUTHORITY = 129;
const TOKEN_ACCOUNT_LEN = 165;

/**
 * Mints whose canonical vault token account is always checked for a changed
 * owner: wSOL, USDC, USDT, and devnet USDC. SPL Token lets `SetAuthority` hand
 * even an associated token account to someone else, after which it no longer
 * lists as the vault's but senders still pay into it — and nothing on chain
 * points from it back to the vault, so only a mint named in advance can be
 * checked. Callers add their own with `watchMints`. Token-2022 ones are created
 * immutable, so only SPL Token is checked. Every other mint's account is out of
 * sight — no list closes that; see `WalletFacts.signatureCount`.
 */
const WATCHED_MINTS = [
  'So11111111111111111111111111111111111111112',
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
].map((m) => new PublicKey(m));

/** Stands in for an expiry that cannot be read: such an account counts as live. */
const UNREADABLE_EXPIRY = 0xffff_ffff_ffff_ffffn;

/** Candidates described at once; each costs three getProgramAccounts calls and two getTokenAccountsByOwner. */
const DESCRIBE_CONCURRENCY = 4;

/** Tries of a read the RPC answers "minimum context slot not reached", before giving up. */
const MIN_CONTEXT_SLOT_TRIES = 5;

// ─── Pure helpers ─────────────────────────────────────────────────────────

/** 32 random bytes from crypto.getRandomValues. */
export function createOwnershipChallenge(): Uint8Array {
  return randomBytes(32);
}

/**
 * Pure. The candidates whose stored key produced this proof.
 *
 * The assertion must be a `webauthn.get` over exactly `proof.challenge`, made
 * under `rpId` with the user present. Returns `[]` when any of that fails;
 * never throws. Freshness is the caller's part: generate the challenge with
 * {@link createOwnershipChallenge} for each proof and never reuse one.
 */
export function verifyOwnershipProof<T extends { publicKey: Uint8Array }>(
  candidates: T[],
  proof: OwnershipProof,
  rpId: string,
): T[] {
  try {
    const digest = assertionDigest(proof, rpId);
    if (!digest) return [];
    return candidates.filter((c) => p256Verifies(proof.signature, digest, c.publicKey));
  } catch {
    return [];
  }
}

/**
 * Pure. Every public key this proof verifies against — its signer's among
 * them — as 33-byte compressed keys, each once.
 *
 * A WebAuthn assertion carries no public key, but an ECDSA signature names
 * its signer up to a few candidates: the recovery ids 0..3 each give at most
 * one (2 and 3 only in the rare case r + n < p), so almost always two. One
 * assertion does not say which; {@link resolvePasskeyPublicKey} pins it with a
 * second. The proof is checked exactly as {@link verifyOwnershipProof} checks
 * it — a `webauthn.get` over exactly `proof.challenge` (>= 16 bytes), made
 * under `rpId` with the user present — and every key returned passes
 * `verifyOwnershipProof` for it. Returns `[]` when any check fails; never
 * throws. The signature may be DER or 64-byte r||s, high-S or low-S, as
 * `verifyOwnershipProof` accepts it.
 */
export function recoverPasskeyPublicKeys(proof: OwnershipProof, rpId: string): Uint8Array[] {
  try {
    const digest = assertionDigest(proof, rpId);
    if (!digest) return [];
    const keys: Uint8Array[] = [];
    for (const format of SIGNATURE_FORMATS) {
      let signature: ReturnType<typeof p256.Signature.fromBytes>;
      try {
        signature = p256.Signature.fromBytes(proof.signature, format);
      } catch {
        continue; // not this encoding
      }
      for (let recovery = 0; recovery < 4; recovery++) {
        let key: Uint8Array;
        try {
          key = signature.addRecoveryBit(recovery).recoverPublicKey(digest).toBytes(true);
        } catch {
          continue; // no point for this id: r + n is not below p, or no curve point has that x
        }
        if (key.length !== 33) continue;
        if (!p256Verifies(proof.signature, digest, key)) continue;
        if (!keys.some((k) => bytesEqual(k, key))) keys.push(key);
      }
    }
    return keys;
  } catch {
    return [];
  }
}

/**
 * Pure. The one public key that produced every proof, or `null`.
 *
 * For a passkey whose key you do not hold — one registered on another device,
 * or by another app under the same `rpId` — when it has no wallet yet: collect
 * two assertions from it, each over its own fresh challenge
 * ({@link createOwnershipChallenge}), and pass them here; then create the
 * wallet with the key this returns. Each proof leaves a few candidates
 * ({@link recoverPasskeyPublicKeys}); only the signer's is common to both.
 *
 * `null` unless there are at least two proofs, no two over the same challenge,
 * each passes the checks of {@link verifyOwnershipProof} under `rpId`, and
 * exactly one key is common to all of them — so assertions from two different
 * passkeys give `null`. Never throws.
 *
 * The key is the one that signed these assertions, and nothing more: the
 * credential it belongs to is whichever produced them. Take both from
 * `navigator.credentials.get` calls you made, the second with
 * `allowCredentials` set to the first one's `rawId`, check the two `rawId`s
 * match, and hash that `rawId` for the wallet's `credentialIdHash`.
 */
export function resolvePasskeyPublicKey(proofs: OwnershipProof[], rpId: string): Uint8Array | null {
  try {
    if (!Array.isArray(proofs) || proofs.length < 2) return null;
    for (let i = 0; i < proofs.length; i++) {
      for (let j = i + 1; j < proofs.length; j++) {
        if (bytesEqual(proofs[i].challenge, proofs[j].challenge)) return null;
      }
    }
    let common = recoverPasskeyPublicKeys(proofs[0], rpId);
    for (const proof of proofs.slice(1)) {
      const keys = recoverPasskeyPublicKeys(proof, rpId);
      common = common.filter((c) => keys.some((k) => bytesEqual(k, c)));
    }
    return common.length === 1 ? common[0] : null;
  } catch {
    return null;
  }
}

/**
 * Pure. The rule.
 *
 * A wallet is adopted only if it is the one wallet this passkey has signed for
 * (`signatureCount > 0`) and only it (and trusted keys) can spend from it.
 *
 * Signed for is what keeps a planted wallet out. Anyone can hand a wallet to a
 * passkey with `TransferOwnership` — its key is public — after using the vault
 * as they liked, and not all of that shows: an SPL Token account moved off the
 * vault is only found for a few watched mints. Such a wallet can look
 * spotless, and funding its vault would outrank the user's own. A wallet never
 * signed for — including the user's own, created and not yet used — goes to
 * the user.
 *
 * The one: a count may hold a copied signature. The v2 program now names the
 * wallet in the passkey challenge, so a signature verifies only on the wallet
 * it was made for. v1 never did, nor did v2 before that change: there the
 * challenge bound the payer, the counter and the instruction's own arguments,
 * but not the wallet, for `CreateSession`, `AddAuthority`, `TransferOwnership`
 * and `Authorize`, and whoever planted a wallet could take the passkey's
 * signature from its first transaction on another wallet and submit it again,
 * within about 150 slots, on the planted one through the same fee payer (a
 * relayer signs for anyone) — raising that wallet's count too. Counts from
 * then are still on chain, so when two wallets have been signed for, either
 * may be the copy, and none is adopted — even when only one of them is
 * `controlledAlone`. Among those counts this cannot catch a copy of a
 * signature made where the passkey is not an Owner (an Admin seat on someone
 * else's wallet) or on an authority since closed.
 *
 * Order, for `needsConfirmation`: signed for first, then the oldest protocol
 * version (a live v1 wallet has not been migrated — its funds are still
 * there), then the fullest vault, then the wallet address. If none can be
 * adopted, every wallet goes to the user.
 */
export function pickOwnWallet(facts: WalletFacts[]): {
  adopt: WalletFacts | null;
  needsConfirmation: WalletFacts[];
} {
  const ordered = [...facts].sort(
    (a, b) =>
      Number(b.signatureCount > 0) - Number(a.signatureCount > 0) ||
      a.version - b.version ||
      b.lamports - a.lamports ||
      compareStrings(a.walletPda.toBase58(), b.walletPda.toBase58()),
  );
  const signed = ordered.filter((f) => f.signatureCount > 0);
  if (signed.length === 1 && signed[0].controlledAlone) {
    return { adopt: signed[0], needsConfirmation: [] };
  }
  return { adopt: null, needsConfirmation: ordered };
}

/**
 * Pure. The candidate whose vault OR wallet PDA equals `address` (base58
 * string or PublicKey), else null. Users recognise the vault — it is the
 * address that holds their funds — so accept either.
 */
export function selectWalletByAddress<T extends { walletPda: PublicKey; vaultPda: PublicKey }>(
  candidates: T[],
  address: string | PublicKey,
): T | null {
  const wanted = typeof address === 'string' ? address : address.toBase58();
  return (
    candidates.find(
      (c) => c.vaultPda.toBase58() === wanted || c.walletPda.toBase58() === wanted,
    ) ?? null
  );
}

// ─── Chain reads (used by LazorKitClient) ─────────────────────────────────

/**
 * Every wallet on which this credential is an Owner-rank passkey created under
 * `rpId` — on the client's program and, with `includeV1`, on the v1 deployment
 * paired with it. v2 hits first. Nothing here is proven yet: pass the result
 * through {@link verifyOwnershipProof}.
 */
export async function scanPasskeyWalletCandidates(
  connection: Connection,
  programId: PublicKey,
  params: { credentialIdHash: Uint8Array; rpId: string; includeV1?: boolean },
): Promise<PasskeyWalletCandidate[]> {
  const { credentialIdHash, rpId, includeV1 = true } = params;
  if (credentialIdHash.length !== 32) {
    throw new Error(
      `credentialIdHash must be exactly 32 bytes, got ${credentialIdHash.length}`,
    );
  }
  const rpIdHash = rpIdHashOf(rpId);
  // On a local or staging id the v1 id is the same program (in-place layout);
  // the discriminator keeps the two scans apart.
  const targets: { version: 1 | 2; programId: PublicKey }[] = [{ version: 2, programId }];
  if (includeV1) targets.push({ version: 1, programId: legacyProgramIdFor(programId) });

  const found = await Promise.all(
    targets.map(async ({ version, programId: target }) => {
      const layout = LAYOUTS[version];
      const accounts = await connection.getProgramAccounts(target, {
        encoding: 'base64',
        filters: [
          memcmp(0, Uint8Array.of(layout.authority, AUTH_TYPE_SECP256R1)),
          memcmp(AUTHORITY_KEY, credentialIdHash),
          memcmp(AUTHORITY_RP_ID_HASH, rpIdHash),
        ],
      });
      return accounts
        .filter(
          ({ account }) =>
            account.data.length >= AUTHORITY_SECP256R1_LEN && account.data[2] === ROLE_OWNER,
        )
        .map(({ pubkey, account }): PasskeyWalletCandidate => {
          const walletPda = new PublicKey(
            account.data.subarray(AUTHORITY_WALLET, AUTHORITY_WALLET + 32),
          );
          return {
            version,
            programId: target,
            walletPda,
            vaultPda: layout.vault(walletPda, target),
            authorityPda: pubkey,
            publicKey: new Uint8Array(
              account.data.subarray(AUTHORITY_P256_KEY, AUTHORITY_RP_ID_HASH),
            ),
          };
        });
    }),
  );
  return found.flat();
}

/**
 * Who else can spend from each candidate. Reads the slot once, then every
 * candidate's wallet account in pages of 100; then per remaining candidate,
 * four at a time, in the order power flows between these accounts: its
 * authorities; then its sessions and deferred executions; then its wallet
 * account, vault, the vault's SPL Token account for each watched mint (the
 * four defaults, then `watchMints`) and the vault's token accounts under both
 * token programs. Each step asks the RPC for state at least as new as the one
 * before (`minContextSlot`), so a transaction that lands mid-read cannot be
 * half-seen; see {@link readSpendingState}. Reads are at the connection's
 * commitment.
 *
 * A candidate whose wallet account is gone, or is not a wallet of its
 * program, is left out: MigrateWallet closes a v1 wallet and only the
 * authority that migrated it, and nothing can ever move funds sent to what is
 * left. A lookup that fails throws; nothing is guessed.
 *
 * Fails closed: an account too short to read is an untrusted authority, or a
 * live and untrusted session / deferred execution / token grant — never
 * skipped. A wallet on which this passkey's own authority is no longer the
 * Owner-rank key it was found with is not `controlledAlone` either (and its
 * `signatureCount` is 0), and nor is one whose vault is no longer a plain
 * system account: no trusted key makes that one safe.
 */
export async function describePasskeyWallets(
  connection: Connection,
  candidates: PasskeyWalletCandidate[],
  options: { trustedKeys?: (PublicKey | string)[]; watchMints?: (PublicKey | string)[] } = {},
): Promise<WalletFacts[]> {
  // Both throw on a malformed key rather than silently trusting or watching less.
  const trusted = new Set(
    (options.trustedKeys ?? []).map((k) => new PublicKey(k).toBase58()),
  );
  const mints = watchedMints(options.watchMints);
  if (candidates.length === 0) return [];

  // The slot first: one older than the reads can only count more things live.
  const slot = BigInt(await connection.getSlot());

  // Drop candidates whose wallet is gone before scanning anything for them.
  // Each survivor's wallet is read again, in order with the rest.
  const { infos: wallets } = await readAccounts(connection, candidates.map((c) => c.walletPda));
  const live = candidates.filter((c, i) => isLiveWallet(c, wallets[i]));
  const described = await mapBounded(live, DESCRIBE_CONCURRENCY, (c) =>
    describeCandidate(connection, c, slot, trusted, mints),
  );
  return described.filter((f): f is WalletFacts => f !== null);
}

/** `info` is a wallet account of the candidate's program and version. */
function isLiveWallet(
  c: Pick<PasskeyWalletCandidate, 'programId' | 'version'>,
  info: AccountInfo<Buffer> | null | undefined,
): boolean {
  return (
    !!info &&
    info.owner.equals(c.programId) &&
    info.data.length > 0 &&
    info.data[0] === LAYOUTS[c.version].wallet
  );
}

async function describeCandidate(
  connection: Connection,
  c: PasskeyWalletCandidate,
  slot: bigint,
  trusted: ReadonlySet<string>,
  mints: PublicKey[],
): Promise<WalletFacts | null> {
  const watched = watchedTokenAccounts(c.vaultPda, mints);
  const {
    authorities,
    sessions,
    deferred,
    infos: [walletInfo, vaultInfo, ...watchedInfos],
    ownedTokens,
  } = await readSpendingState(connection, c.programId, c.walletPda, c.vaultPda, LAYOUTS[c.version], [
    c.walletPda,
    c.vaultPda,
    ...watched.map((w) => w.address),
  ]);

  // Gone since the first read: as dead as one that was gone then.
  if (!isLiveWallet(c, walletInfo)) return null;
  const lamports = vaultInfo?.lamports ?? 0;
  const vaultIsSystemAccount = isPlainSystemAccount(vaultInfo);
  const tokenGrants = vaultTokenGrants(
    c.vaultPda,
    ownedTokens,
    watched.map((w, i) => ({ ...w, info: watchedInfos[i] })),
    trusted,
  );

  const own = authorities.find((a) => a.pubkey.equals(c.authorityPda))?.account.data;
  const ownIntact =
    !!own &&
    own.length >= AUTHORITY_SECP256R1_LEN &&
    own[1] === AUTH_TYPE_SECP256R1 &&
    own[2] === ROLE_OWNER &&
    bytesEqual(own.subarray(AUTHORITY_P256_KEY, AUTHORITY_RP_ID_HASH), c.publicKey);
  const ownRpIdHash =
    own && own.length >= AUTHORITY_SECP256R1_LEN
      ? own.subarray(AUTHORITY_RP_ID_HASH, AUTHORITY_SECP256R1_LEN)
      : null;

  const otherAuthorities: WalletFacts['otherAuthorities'] = [];
  for (const { pubkey, account } of authorities) {
    if (pubkey.equals(c.authorityPda)) continue;
    const data = account.data;
    const role = roleName(data[2]);
    if (data[1] === AUTH_TYPE_ED25519) {
      const publicKey =
        data.length >= AUTHORITY_ED25519_LEN
          ? new PublicKey(data.subarray(AUTHORITY_KEY, AUTHORITY_ED25519_LEN))
          : undefined;
      const isTrusted = !!publicKey && trusted.has(publicKey.toBase58());
      otherAuthorities.push({ authorityPda: pubkey, type: 'ed25519', role, publicKey, trusted: isTrusted });
    } else {
      // Anything that is not Ed25519 is reported as a passkey, which is never
      // trusted: a passkey cannot be declared, only proven.
      const sameRelyingParty =
        !!ownRpIdHash &&
        data.length >= AUTHORITY_SECP256R1_LEN &&
        bytesEqual(data.subarray(AUTHORITY_RP_ID_HASH, AUTHORITY_SECP256R1_LEN), ownRpIdHash);
      otherAuthorities.push({ authorityPda: pubkey, type: 'secp256r1', role, sameRelyingParty, trusted: false });
    }
  }

  // Live through the expiry slot itself: see sessionExpiry.
  const liveSessions: WalletFacts['liveSessions'] = [];
  for (const { pubkey, account } of sessions) {
    const data = account.data;
    const expiresAtSlot = sessionExpiry(data);
    if (expiresAtSlot < slot) continue;
    const readable = data.length >= SESSION_EXPIRES_AT + 8;
    const sessionKey = readable
      ? new PublicKey(data.subarray(SESSION_KEY, SESSION_KEY + 32))
      : PublicKey.default;
    liveSessions.push({
      sessionPda: pubkey,
      sessionKey,
      expiresAtSlot,
      trusted: readable && trusted.has(sessionKey.toBase58()),
    });
  }

  // Never trusted, whoever it names: see `pendingDeferred.trusted`. A user's
  // own tx1 still waiting for its tx2 means asking once — the price of not
  // adopting a drain someone queued under this passkey's address.
  const pendingDeferred: WalletFacts['pendingDeferred'] = [];
  for (const { pubkey, account } of deferred) {
    const data = account.data;
    const expiresAtSlot = deferredExpiry(data);
    if (expiresAtSlot < slot) continue;
    const authorizedBy =
      data.length >= DEFERRED_EXPIRES_AT + 8
        ? new PublicKey(data.subarray(DEFERRED_AUTHORITY, DEFERRED_AUTHORITY + 32))
        : PublicKey.default;
    pendingDeferred.push({ deferredPda: pubkey, authorizedBy, expiresAtSlot, trusted: false });
  }

  return {
    version: c.version,
    programId: c.programId,
    walletPda: c.walletPda,
    vaultPda: c.vaultPda,
    authorityPda: c.authorityPda,
    publicKey: c.publicKey,
    lamports,
    slot,
    otherAuthorities,
    liveSessions,
    pendingDeferred,
    vaultIsSystemAccount,
    tokenGrants,
    controlledAlone:
      ownIntact &&
      vaultIsSystemAccount &&
      otherAuthorities.every((a) => a.trusted) &&
      liveSessions.every((s) => s.trusted) &&
      pendingDeferred.every((d) => d.trusted) &&
      tokenGrants.every((g) => g.trusted),
    // Only this passkey's key advances the counter of an intact authority.
    signatureCount: ownIntact ? readU32LE(own, AUTHORITY_COUNTER) : 0,
  };
}

// ─── Vault checks shared with the v1 migration ────────────────────────────
//
// `vetMigrationDestination` and `migrateV1Wallet` apply the same reading of a
// vault and its token accounts. Not exported from the package.

type TokenGrant = WalletFacts['tokenGrants'][number];

/**
 * Whether a vault is still a plain system account: not created yet, or owned
 * by the System Program with no data. A vault an Owner `Assign`ed to another
 * program, or `Allocate`d data (a nonce account, say), is not — and is no
 * longer LazorKit's to guard.
 */
export function isPlainSystemAccount(info: AccountInfo<Buffer> | null | undefined): boolean {
  return !info || (info.owner.equals(SystemProgram.programId) && info.data.length === 0);
}

/**
 * The slot through which the program still accepts a session (it refuses only
 * once `current_slot > expires_at`), or a never-passing slot when the account
 * is too short to read.
 */
export function sessionExpiry(data: Uint8Array): bigint {
  return data.length >= SESSION_EXPIRES_AT + 8 ? readU64LE(data, SESSION_EXPIRES_AT) : UNREADABLE_EXPIRY;
}

/** As {@link sessionExpiry}, for a deferred execution. */
export function deferredExpiry(data: Uint8Array): bigint {
  return data.length >= DEFERRED_EXPIRES_AT + 8 ? readU64LE(data, DEFERRED_EXPIRES_AT) : UNREADABLE_EXPIRY;
}

/** `WATCHED_MINTS`, then each of `extra` not already there. A malformed mint throws. */
export function watchedMints(extra: ReadonlyArray<PublicKey | string> = []): PublicKey[] {
  const mints = [...WATCHED_MINTS];
  for (const m of extra) {
    const mint = new PublicKey(m);
    if (!mints.some((w) => w.equals(mint))) mints.push(mint);
  }
  return mints;
}

/** The vault's SPL Token account for each of `mints` (default `WATCHED_MINTS`), in order. */
export function watchedTokenAccounts(
  vault: PublicKey,
  mints: PublicKey[] = WATCHED_MINTS,
): { address: PublicKey; mint: PublicKey }[] {
  return mints.map((mint) => ({
    address: getAssociatedTokenAddress(mint, vault, TOKEN_PROGRAM_ID),
    mint,
  }));
}

/**
 * Every right over the vault's tokens held by someone else: delegates and
 * foreign close authorities on the token accounts it owns (`owned`, as
 * {@link readSpendingState} read them), SPL Token grants first, then
 * Token-2022; then each watched canonical account (with its `info`, read by
 * the caller) whose owner is no longer the vault.
 */
export function vaultTokenGrants(
  vault: PublicKey,
  owned: { spl: ReadonlyArray<AccountRow>; token2022: ReadonlyArray<AccountRow> },
  watched: { address: PublicKey; mint: PublicKey; info: AccountInfo<Buffer> | null | undefined }[],
  trusted: ReadonlySet<string>,
): TokenGrant[] {
  const grants: TokenGrant[] = [
    ...owned.spl.flatMap(({ pubkey, account }) =>
      tokenAccountGrants(pubkey, TOKEN_PROGRAM_ID, account.data, vault, trusted),
    ),
    ...owned.token2022.flatMap(({ pubkey, account }) =>
      tokenAccountGrants(pubkey, TOKEN_2022_PROGRAM_ID, account.data, vault, trusted),
    ),
  ];
  for (const { address, mint, info } of watched) {
    // Absent, or not a token account (lamports sent to the address): nothing
    // to hand over. Owned by the vault: already read above.
    if (!info || !info.owner.equals(TOKEN_PROGRAM_ID)) continue;
    if (info.data.length < TOKEN_OWNER + 32) {
      grants.push(unreadableGrant(address, TOKEN_PROGRAM_ID));
      continue;
    }
    const owner = new PublicKey(info.data.subarray(TOKEN_OWNER, TOKEN_OWNER + 32));
    if (owner.equals(vault)) continue;
    grants.push({
      tokenAccount: address,
      tokenProgram: TOKEN_PROGRAM_ID,
      mint,
      kind: 'owner',
      grantee: owner,
      trusted: trusted.has(owner.toBase58()),
    });
  }
  return grants;
}

/**
 * Why an existing account at a migration's destination token address must not
 * receive the tokens, or `null` when it is the vault's alone: a token account
 * of `tokenProgram`, owned by the vault, with no delegate and no close
 * authority but the vault. The program checks only the owner; a delegate or a
 * close authority left on it by whoever held the wallet before would still
 * take what arrives.
 */
export function tokenAccountProblem(
  address: PublicKey,
  info: AccountInfo<Buffer>,
  vault: PublicKey,
  tokenProgram: PublicKey,
): string | null {
  if (!info.owner.equals(tokenProgram)) {
    return `is owned by program ${info.owner.toBase58()}, not ${tokenProgram.toBase58()}`;
  }
  if (info.data.length < TOKEN_ACCOUNT_LEN) return 'cannot be read as a token account';
  const owner = new PublicKey(info.data.subarray(TOKEN_OWNER, TOKEN_OWNER + 32));
  if (!owner.equals(vault)) return `belongs to ${owner.toBase58()}, not the v2 vault ${vault.toBase58()}`;
  const [grant] = tokenAccountGrants(address, tokenProgram, info.data, vault, new Set());
  return grant ? grantPhrase(grant) : null;
}

/** A token grant as the end of a sentence about its token account. */
export function grantPhrase(grant: TokenGrant): string {
  const grantee = grant.grantee?.toBase58();
  switch (grant.kind) {
    case 'delegate':
      return `has a delegate, ${grantee}`;
    case 'closeAuthority':
      return `has a close authority other than the vault, ${grantee}`;
    case 'owner':
      return `(the vault's own account for mint ${grant.mint?.toBase58()}) belongs to ${grantee}`;
    case 'unreadable':
      return 'cannot be read as a token account';
  }
}

// ─── Consistent reads (shared with the v1 migration) ──────────────────────
//
// Separate RPC reads are separate snapshots, and a load-balanced endpoint may
// answer them from different nodes. Each read below reports the slot it was
// answered at, and the next asks for state at least that new
// (`minContextSlot`).

/** A row of getProgramAccounts / getTokenAccountsByOwner. */
type AccountRow = Readonly<{ pubkey: PublicKey; account: Readonly<{ data: Buffer }> }>;

/**
 * Everything that can move `wallet`'s funds, read so that no transaction can
 * be half-seen. Reading these concurrently lets one transaction that lands in
 * between — a co-owner that opens a session or approves a delegate, and drops
 * its own authority — show as neither. They are read in the order power flows
 * instead, each step at or after the slot the previous one was answered at:
 *
 * 1. authorities — the only thing that creates authorities, sessions or
 *    deferred executions (the program refuses to call itself, and the runtime
 *    refuses reentry through another program);
 * 2. sessions and deferred executions — which, besides authorities, are all
 *    that can make the vault sign: `ExecuteDeferred` closes the account in the
 *    same instruction as its CPIs, and an expired session can be closed by
 *    anyone, so a grant they made is only ever seen after they are gone;
 * 3. `accounts` (the wallet account, the vault, its canonical token accounts)
 *    and the vault's token accounts under both token programs — none of which
 *    can create anything the earlier steps read.
 *
 * Anything that can still spend at the last step either existed at the step
 * that reads its kind, or was made later by something an earlier step saw.
 * Expiries are compared against a slot the caller read before any of this: no
 * newer than the slot the program will check them at, it only counts more
 * things live.
 */
export async function readSpendingState(
  connection: Connection,
  programId: PublicKey,
  wallet: PublicKey,
  vault: PublicKey,
  discs: { authority: number; session: number; deferred: number },
  accounts: PublicKey[],
): Promise<{
  authorities: AccountRow[];
  sessions: AccountRow[];
  deferred: AccountRow[];
  /** `accounts`, in order; `null` for one that does not exist. */
  infos: (AccountInfo<Buffer> | null)[];
  ownedTokens: { spl: AccountRow[]; token2022: AccountRow[] };
  /** The newest state any of it was read at. */
  slot: number;
}> {
  const scan = (disc: number, walletOffset: number, minContextSlot?: number) =>
    scanWalletAccounts(connection, programId, wallet, disc, walletOffset, minContextSlot);
  const authorities = await scan(discs.authority, AUTHORITY_WALLET);
  const [sessions, deferred] = await Promise.all([
    scan(discs.session, SESSION_WALLET, authorities.slot),
    scan(discs.deferred, DEFERRED_WALLET, authorities.slot),
  ]);
  const after = Math.max(sessions.slot, deferred.slot);
  const [read, ownedTokens] = await Promise.all([
    readAccounts(connection, accounts, after),
    readVaultTokenAccounts(connection, vault, after),
  ]);
  return {
    authorities: authorities.rows,
    sessions: sessions.rows,
    deferred: deferred.rows,
    infos: accounts.map((_, i) => read.infos[i] ?? null),
    ownedTokens: { spl: ownedTokens.spl, token2022: ownedTokens.token2022 },
    slot: Math.max(read.slot, ownedTokens.slot),
  };
}

/**
 * `keys` in pages of 100, in order; `null` for an account that does not
 * exist. Each page is read at or after `minContextSlot`; `slot` is the newest
 * context slot among them.
 */
export async function readAccounts(
  connection: Connection,
  keys: PublicKey[],
  minContextSlot?: number,
): Promise<{ slot: number; infos: (AccountInfo<Buffer> | null)[] }> {
  const infos: (AccountInfo<Buffer> | null)[] = [];
  let slot = minContextSlot ?? 0;
  for (let i = 0; i < keys.length; i += 100) {
    const { context, value } = await atOrAfterSlot(() =>
      connection.getMultipleAccountsInfoAndContext(keys.slice(i, i + 100), { minContextSlot }),
    );
    slot = Math.max(slot, context.slot);
    infos.push(...value);
  }
  return { slot, infos };
}

/**
 * `programId`'s accounts with discriminator `disc` that name `wallet` at
 * `walletOffset`, as of `slot` — at or after `minContextSlot`.
 */
async function scanWalletAccounts(
  connection: Connection,
  programId: PublicKey,
  wallet: PublicKey,
  disc: number,
  walletOffset: number,
  minContextSlot?: number,
): Promise<{ slot: number; rows: AccountRow[] }> {
  const { context, value } = await atOrAfterSlot(() =>
    connection.getProgramAccounts(programId, {
      encoding: 'base64',
      withContext: true,
      minContextSlot,
      filters: [memcmp(0, Uint8Array.of(disc)), memcmp(walletOffset, wallet.toBytes())],
    }),
  );
  return { slot: context.slot, rows: [...value] };
}

/**
 * The token accounts `vault` owns, under SPL Token and under Token-2022, at or
 * after `minContextSlot`. `slot` is the newer of the two reads.
 */
async function readVaultTokenAccounts(
  connection: Connection,
  vault: PublicKey,
  minContextSlot?: number,
): Promise<{ slot: number; spl: AccountRow[]; token2022: AccountRow[] }> {
  const read = (programId: PublicKey) =>
    atOrAfterSlot(() => connection.getTokenAccountsByOwner(vault, { programId }, { minContextSlot }));
  const [spl, token2022] = await Promise.all([read(TOKEN_PROGRAM_ID), read(TOKEN_2022_PROGRAM_ID)]);
  return {
    slot: Math.max(spl.context.slot, token2022.context.slot),
    spl: [...spl.value],
    token2022: [...token2022.value],
  };
}

/**
 * `read()`, retried while the RPC answers that it has not reached the
 * `minContextSlot` asked for — a node behind a load balancer a slot or two
 * behind the one that served the previous read. Gives up (throws) after five
 * tries rather than read older state.
 */
async function atOrAfterSlot<T>(read: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await read();
    } catch (e) {
      if (attempt >= MIN_CONTEXT_SLOT_TRIES || !minContextSlotNotReached(e)) throw e;
      await new Promise((r) => setTimeout(r, 100 * attempt));
    }
  }
}

/** The RPC's "minimum context slot has not been reached" (-32016). */
function minContextSlotNotReached(e: unknown): boolean {
  return (
    typeof e === 'object' &&
    e !== null &&
    (e as { code?: unknown }).code ===
      SolanaJSONRPCErrorCode.JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED
  );
}

// ─── Internals ────────────────────────────────────────────────────────────

/**
 * The delegate and the close authority on one token account, where either is
 * someone other than `vault`; one `unreadable` grant for an account too short
 * to read. A close authority can take a wSOL account's whole balance; a
 * delegate, up to its allowance of whatever arrives later.
 */
function tokenAccountGrants(
  tokenAccount: PublicKey,
  tokenProgram: PublicKey,
  data: Uint8Array,
  vault: PublicKey,
  trusted: ReadonlySet<string>,
): TokenGrant[] {
  if (data.length < TOKEN_ACCOUNT_LEN) return [unreadableGrant(tokenAccount, tokenProgram)];
  const mint = new PublicKey(data.subarray(0, 32));
  const grants: TokenGrant[] = [];
  for (const [kind, offset] of [
    ['delegate', TOKEN_DELEGATE],
    ['closeAuthority', TOKEN_CLOSE_AUTHORITY],
  ] as const) {
    // COption: a u32 tag, then the key. Any tag but None counts as set.
    if (readU32LE(data, offset) === 0) continue;
    const grantee = new PublicKey(data.subarray(offset + 4, offset + 36));
    if (grantee.equals(vault)) continue;
    grants.push({
      tokenAccount,
      tokenProgram,
      mint,
      kind,
      grantee,
      trusted: trusted.has(grantee.toBase58()),
    });
  }
  return grants;
}

function unreadableGrant(tokenAccount: PublicKey, tokenProgram: PublicKey): TokenGrant {
  return { tokenAccount, tokenProgram, mint: null, kind: 'unreadable', grantee: null, trusted: false };
}

/**
 * What a valid assertion's signature covers, or `null` when the proof fails a
 * check: a `webauthn.get` over exactly `proof.challenge` (>= 16 bytes), made
 * under `rpId` with the user present. May throw on a malformed proof; callers
 * catch.
 */
function assertionDigest(proof: OwnershipProof, rpId: string): Uint8Array | null {
  const { challenge, authenticatorData, clientDataJson } = proof;
  if (challenge.length < 16) return null;

  let clientData: unknown;
  try {
    clientData = JSON.parse(Buffer.from(clientDataJson).toString('utf8'));
  } catch {
    return null;
  }
  if (typeof clientData !== 'object' || clientData === null) return null;
  const { type, challenge: signedChallenge } = clientData as Record<string, unknown>;
  if (type !== 'webauthn.get') return null;
  if (signedChallenge !== base64UrlNoPad(challenge)) return null;

  if (authenticatorData.length < 37) return null;
  if (!bytesEqual(authenticatorData.subarray(0, 32), rpIdHashOf(rpId))) return null;
  if ((authenticatorData[32] & 0x01) === 0) return null; // user present

  // WebAuthn signs authenticatorData || sha256(clientDataJSON), hashed once.
  return sha256(concatBytes([authenticatorData, sha256(clientDataJson)]));
}

/** Browsers return DER; the SDK's own signers hand over 64-byte r||s. */
const SIGNATURE_FORMATS = ['der', 'compact'] as const;

function p256Verifies(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  // A 64-byte DER signature exists too, so try both rather than guess by length.
  for (const format of SIGNATURE_FORMATS) {
    try {
      if (p256.verify(signature, message, publicKey, { lowS: false, prehash: false, format })) {
        return true;
      }
    } catch {
      // Not this encoding, or not a point on the curve.
    }
  }
  return false;
}

function rpIdHashOf(rpId: string): Uint8Array {
  return sha256(Buffer.from(rpId, 'utf8'));
}

function roleName(role: number | undefined): AuthorityRoleName {
  switch (role) {
    case 0:
      return 'owner';
    case 1:
      return 'admin';
    case 2:
      return 'spender';
    default:
      return 'unknown';
  }
}

function memcmp(offset: number, bytes: Uint8Array) {
  return {
    memcmp: { offset, bytes: Buffer.from(bytes).toString('base64'), encoding: 'base64' as const },
  };
}

function base64UrlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function readU64LE(data: Uint8Array, offset: number): bigint {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true);
}

function readU32LE(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
}

/** Code-point order, so the result does not depend on the runtime's locale. */
function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** `fn` over `items` with at most `limit` in flight; results keep input order. */
async function mapBounded<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
