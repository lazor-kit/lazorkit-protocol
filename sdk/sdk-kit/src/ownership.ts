/**
 * Which wallet belongs to a returning passkey user.
 *
 * `CreateWallet` and `AddAuthority` take any owner without that owner's
 * consent. A passkey's credential-id hash is public — it sits in every
 * authority account the passkey has — so anyone can create a wallet listing a
 * victim's credential next to their own key, or add the victim's real passkey
 * to a wallet they control. Finding a wallet by the hash proves nothing.
 *
 * So a wallet is adopted without asking only when (1) its authority for this
 * credential is Owner rank, created under this relying party, and stores the
 * key the passkey is *proven* to hold — a P-256 signature over a fresh
 * challenge the caller chose — (2) nothing untrusted can spend from it: no
 * other authority, no live session, no pending deferred execution, no delegate
 * or foreign close authority on the vault's token accounts, no canonical token
 * account of a watched mint handed away, no vault handed to another program —
 * except keys the integrator declared trusted, and (3) this passkey has signed
 * for it before, and for no other wallet it owns. `TransferOwnership` and
 * `AddAuthority` hand a wallet to a passkey without asking it, and what the
 * earlier holder did through the vault is not all readable — an SPL Token
 * account moved off the vault for any mint but a few watched ones cannot be
 * found. Only a wallet the user already chose is past that. But a counter
 * raised before the passkey challenge named the wallet may hold a signature
 * replayed from another wallet (see `pickOwnWallet`), so two wallets signed
 * for mean asking.
 * Anything else, the user must confirm. A wallet whose account is gone (a
 * migrated v1 wallet leaves its other authorities behind) is no candidate.
 *
 * The RPC halves live on the client (`findPasskeyWalletCandidates`,
 * `describeWalletCandidates`, `findOwnPasskeyWallet`); what is here is pure.
 * Mirrors sdk-legacy/src/utils/ownership.ts: same names, same rule.
 */
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2';
import { getBase64Decoder, type Address } from '@solana/kit';

const base64Decoder = getBase64Decoder();
const utf8 = new TextEncoder();

/** A wallet this passkey is an Owner of, as the chain lists it. Not yet proven. */
export interface PasskeyWalletCandidate {
  /** 1 = the v1 deployment paired with this client's program (a pre-v2 wallet); 2 = this client's program. */
  version: 1 | 2;
  programId: Address;
  walletPda: Address;
  vaultPda: Address;
  /** This passkey's authority on the wallet. */
  authorityPda: Address;
  /** The 33-byte compressed P-256 key stored on that authority. */
  publicKey: Uint8Array;
}

/** A WebAuthn assertion over a challenge the caller chose. */
export interface OwnershipProof {
  /**
   * The challenge the caller generated for this proof, fresh: use
   * createTaggedOwnershipChallenge(). Any challenge of at least 16 bytes is
   * checked, so a proof over createOwnershipChallenge()'s 32 bytes verifies too.
   */
  challenge: Uint8Array;
  /** DER or 64-byte r||s. */
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
}

export type AuthorityRoleName = 'owner' | 'admin' | 'spender' | 'unknown';

/** A candidate and everything else that can move its funds. */
export interface WalletFacts extends PasskeyWalletCandidate {
  /** Vault balance, lamports. */
  lamports: bigint;
  /**
   * Slot of the cluster clock read before the scans; deferred-execution
   * expiries (and a v1 wallet's session expiries) compare against it.
   */
  slot: bigint;
  /**
   * Unix time (seconds) of that same clock read; a v2 wallet's session
   * expiries compare against it.
   */
  unixTimestamp: bigint;
  /** Every authority on the wallet except this passkey's. */
  otherAuthorities: {
    authorityPda: Address;
    type: 'ed25519' | 'secp256r1';
    role: AuthorityRoleName;
    /** Ed25519 only: the key. */
    publicKey?: Address;
    /** Secp256r1 only: created under the same relying party as this passkey. */
    sameRelyingParty?: boolean;
    /** Ed25519 key listed in trustedKeys. Secp256r1 is never trusted. */
    trusted: boolean;
  }[];
  /**
   * Sessions the program still accepts: expiry at or after `unixTimestamp`
   * (v2), or at or after `slot` (v1, whose sessions store a slot). A v2
   * session written before time-based expiry holds a slot (any value below
   * 2020-01-01 in seconds) and is listed while that slot has not passed.
   */
  liveSessions: {
    sessionPda: Address;
    sessionKey: Address;
    /**
     * Unix seconds for a v2 wallet's session, a slot for a v1 wallet's (and
     * for a v2 session written before time-based expiry).
     */
    expiresAt: bigint;
    trusted: boolean;
  }[];
  /** Deferred executions the program still accepts: expiry at or after `slot`. */
  pendingDeferred: {
    deferredPda: Address;
    /** The authority PDA that authorized it. */
    authorizedBy: Address;
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
    tokenAccount: Address;
    tokenProgram: Address;
    /** `null` when the account is too short to read. */
    mint: Address | null;
    kind: 'delegate' | 'closeAuthority' | 'owner' | 'unreadable';
    /** Who holds the right; `null` when the account is too short to read. */
    grantee: Address | null;
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

/** The domain tag every LazorKit ownership-proof challenge starts with (format v1). */
export const OWNERSHIP_PROOF_DOMAIN = 'LazorKit ownership proof v1';

const OWNERSHIP_PROOF_TAG = utf8.encode(OWNERSHIP_PROOF_DOMAIN);
const OWNERSHIP_PROOF_NONCE_LENGTH = 32;

/**
 * 32 fresh random bytes from crypto.getRandomValues: a nonce, and no more
 * than that. Always exactly 32 bytes, as in every release before.
 *
 * @deprecated As the challenge of an ownership proof, use
 * {@link createTaggedOwnershipChallenge}. A passkey signs whatever challenge it
 * is handed, and 32 bare random bytes look exactly like a transaction
 * challenge to whatever is asked to sign them. This function itself is
 * unchanged, and proofs over its bytes still verify.
 */
export function createOwnershipChallenge(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/**
 * A fresh challenge for an ownership proof, format v1:
 *
 *     tag       = UTF-8 "LazorKit ownership proof v1"   (27 bytes, OWNERSHIP_PROOF_DOMAIN)
 *     challenge = tag || 32 random bytes               (59 bytes)
 *
 * The random bytes come from crypto.getRandomValues. Generate one for each
 * proof and never reuse it; check the assertion with
 * {@link verifyOwnershipProof}.
 *
 * A passkey signs whatever challenge it is handed, and the LazorKit programs
 * approve a transaction by the challenge in a passkey signature: always a
 * 32-byte hash. A message challenge ({@link signedMessageChallenge}) is 58
 * bytes and starts with its own tag, and this one is 59 with another, so no
 * challenge of one kind can equal one of another, whatever the bytes. The same
 * format as sdk-legacy's `createTaggedOwnershipChallenge`, and as
 * `createOwnershipChallenge` in `@lazorkit/wallet` 3.3.1 and
 * `@lazorkit/wallet-mobile-adapter` 2.3.1, whose connect already signs it.
 */
export function createTaggedOwnershipChallenge(): Uint8Array {
  const challenge = new Uint8Array(OWNERSHIP_PROOF_TAG.length + OWNERSHIP_PROOF_NONCE_LENGTH);
  challenge.set(OWNERSHIP_PROOF_TAG, 0);
  challenge.set(
    globalThis.crypto.getRandomValues(new Uint8Array(OWNERSHIP_PROOF_NONCE_LENGTH)),
    OWNERSHIP_PROOF_TAG.length,
  );
  return challenge;
}

/**
 * Pure. The candidates whose stored key produced this proof.
 *
 * The assertion must be a `webauthn.get` over exactly `proof.challenge`, made
 * under `rpId` with the user present. A challenge the caller did not choose
 * fresh — or any old assertion the passkey once produced — would prove only
 * that someone saw a signature, not that this user holds the key now: use
 * {@link createTaggedOwnershipChallenge}. Any challenge of at least 16 bytes
 * is checked as it is — the tagged form, and the 32 bare random bytes of
 * {@link createOwnershipChallenge} — so proofs made over either verify.
 * Never throws: a malformed proof proves nothing and returns `[]`.
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
 * its signer up to a few candidates: each recovery id 0..3 gives at most one
 * (2 and 3 only in the rare case r + n < p), so almost always two. One
 * assertion does not say which; {@link resolvePasskeyPublicKey} pins it with a
 * second. The proof is checked exactly as {@link verifyOwnershipProof} checks
 * it — a `webauthn.get` over exactly `proof.challenge` (>= 16 bytes), made
 * under `rpId` with the user present — and every key returned passes
 * `verifyOwnershipProof` for it. Returns `[]` when any check fails; never
 * throws. The signature may be DER or 64-byte r||s, high-S or low-S, as
 * `verifyOwnershipProof` accepts it; a 64-byte string that reads as both
 * counts under both readings, so it can give twice as many keys (no
 * authenticator returns one).
 *
 * These checks say what the signer signed, not who it is: see
 * {@link resolvePasskeyPublicKey} for where the proof has to come from.
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
 * ({@link createTaggedOwnershipChallenge}), and pass them here; then create
 * the wallet with the key this returns. Each proof leaves a few candidates
 * ({@link recoverPasskeyPublicKeys}); only the signer's is common to both.
 * Proofs over the 32 bare random bytes of {@link createOwnershipChallenge}
 * still resolve, as they verify.
 *
 * `null` unless there are at least two proofs, no two over the same challenge,
 * each passes the checks of {@link verifyOwnershipProof} under `rpId`, and
 * exactly one key is common to all of them — so assertions from two different
 * passkeys give `null`. Never throws.
 *
 * The key is whichever key signed these assertions, and nothing more. Its
 * signature covers the rpId hash, the flags and the clientData, but under that
 * same key: anyone holding any P-256 key can make assertions over your
 * challenges that pass every check. So the key is the passkey's only when both
 * assertions come straight from `navigator.credentials.get` in your own page,
 * where the browser sets those bytes: the second call with `allowCredentials`
 * set to the first one's `rawId`; check the two `rawId`s match and hash that
 * `rawId` for the wallet's `credentialIdHash`. Assertions relayed to you — by
 * a portal, over a deep link or a redirect — prove only that whoever produced
 * them holds the key. Over a channel you do not authenticate that can be
 * whoever controls it, with a key of their own, and a wallet created with it
 * is theirs.
 */
export function resolvePasskeyPublicKey(proofs: OwnershipProof[], rpId: string): Uint8Array | null {
  try {
    if (!Array.isArray(proofs) || proofs.length < 2) return null;
    for (let i = 0; i < proofs.length; i++) {
      for (let j = i + 1; j < proofs.length; j++) {
        if (bytesEqual(proofs[i]!.challenge, proofs[j]!.challenge)) return null;
      }
    }
    let common = recoverPasskeyPublicKeys(proofs[0]!, rpId);
    for (const proof of proofs.slice(1)) {
      const keys = recoverPasskeyPublicKeys(proof, rpId);
      common = common.filter((c) => keys.some((k) => bytesEqual(k, c)));
    }
    return common.length === 1 ? common[0]! : null;
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
  const ordered = [...facts].sort(compareFacts);
  const signed = ordered.filter((f) => f.signatureCount > 0);
  if (signed.length === 1 && signed[0]!.controlledAlone) {
    return { adopt: signed[0]!, needsConfirmation: [] };
  }
  return { adopt: null, needsConfirmation: ordered };
}

/**
 * Pure. The candidate whose vault OR wallet PDA equals `address`, else null.
 * Users know their vault — it is the address they receive at — so either is
 * accepted.
 */
export function selectWalletByAddress<T extends { walletPda: Address; vaultPda: Address }>(
  candidates: T[],
  address: Address | string,
): T | null {
  return candidates.find((c) => c.vaultPda === address || c.walletPda === address) ?? null;
}

/**
 * What a valid assertion's signature covers, or `null` when the proof fails a
 * check: a `webauthn.get` over exactly `proof.challenge` (>= 16 bytes), made
 * under `rpId` with the user present. May throw on a malformed proof; callers
 * catch.
 */
function assertionDigest(proof: OwnershipProof, rpId: string): Uint8Array | null {
  if (proof.challenge.length < 16) return null;
  const clientData = JSON.parse(new TextDecoder().decode(proof.clientDataJson)) as {
    type?: unknown;
    challenge?: unknown;
  };
  if (clientData.type !== 'webauthn.get') return null;
  if (clientData.challenge !== base64UrlNoPad(proof.challenge)) return null;
  const authData = proof.authenticatorData;
  if (authData.length < 37) return null;
  if (!bytesEqual(authData.subarray(0, 32), sha256(utf8.encode(rpId)))) return null;
  if ((authData[32]! & 0x01) === 0) return null;

  // WebAuthn signs authenticatorData || sha256(clientDataJSON), hashed once.
  return sha256(concat(authData, sha256(proof.clientDataJson)));
}

/** Browsers return DER, the SDK's own signers 64-byte r||s. */
const SIGNATURE_FORMATS = ['der', 'compact'] as const;

function p256Verifies(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  // Some 64-byte strings parse as both DER and r||s — so try each format
  // rather than guess by length.
  // `prehash: false`: the message is already the digest. `lowS: false`: the
  // low-S rule belongs to the on-chain precompile, not to proving possession.
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

/** Signed for first, then version ascending, lamports descending, address in code-point order. */
function compareFacts(a: WalletFacts, b: WalletFacts): number {
  const signed = Number(b.signatureCount > 0) - Number(a.signatureCount > 0);
  if (signed !== 0) return signed;
  if (a.version !== b.version) return a.version - b.version;
  if (a.lamports !== b.lamports) return a.lamports > b.lamports ? -1 : 1;
  return a.walletPda < b.walletPda ? -1 : a.walletPda > b.walletPda ? 1 : 0;
}

function base64UrlNoPad(bytes: Uint8Array): string {
  return base64Decoder.decode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
