/**
 * High-level LazorKit client (kit / @solana/web3.js v2 flavor).
 *
 * Mirrors sdk-legacy/src/utils/client.ts in surface and semantics; the
 * differences are mechanical:
 *   - Connection      → kit Rpc<...>
 *   - PublicKey       → Address
 *   - TransactionInstruction → kit Instruction
 *   - AccountMeta {pubkey,isSigner,isWritable} → AccountMeta {address, role}
 *
 * Methods that produce a transaction return `{ instructions, ... }`
 * for the caller to assemble + sign + send. The SDK never touches
 * keypairs or signers directly (Secp256r1 signing is delegated through
 * a callback contract).
 */
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha2';
import {
  AccountRole,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  address,
  getAddressEncoder,
  getBase64Encoder,
  isSolanaError,
  type AccountMeta,
  type Address,
  type Base58EncodedBytes,
  type GetAccountInfoApi,
  type GetMultipleAccountsApi,
  type GetProgramAccountsApi,
  type GetSlotApi,
  type GetTokenAccountsByOwnerApi,
  type Commitment,
  type Instruction,
  type Rpc,
  type Slot,
} from '@solana/kit';
import { ACCOUNT_DISCRIMINATOR } from './constants.js';
import bs58 from 'bs58';

const bs58Encode = (b: Uint8Array): string => bs58.encode(b);
import {
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  PROGRAM_ID_MAINNET,
  PROGRAM_ID_MAINNET_V1,
  legacyProgramIdFor,
} from './constants.js';
import { serializeActions, type SessionAction } from './codecs/actions.js';
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  DISC_ADD_AUTHORITY,
  DISC_AUTHORIZE,
  DISC_CREATE_SESSION,
  DISC_EXECUTE,
  DISC_MIGRATE_WALLET,
  DISC_REMOVE_AUTHORITY,
  DISC_REVOKE_SESSION,
  DISC_TRANSFER_OWNERSHIP,
  ROLE_OWNER,
  ROLE_SPENDER,
  createAddAuthorityIx,
  createAuthorizeIx,
  createCreateSessionIx,
  createCreateWalletIx,
  createExecuteDeferredIx,
  createExecuteIx,
  createInitializeProtocolIx,
  createInitializeTreasuryShardIx,
  createMigrateWalletIx,
  createReclaimDeferredIx,
  createRegisterPayerIx,
  createRemoveAuthorityIx,
  createRevokeSessionIx,
  createTransferOwnershipIx,
  createUpdateProtocolIx,
  createWithdrawTreasuryIx,
  type MigrateTokenPair,
} from './instructions/builders.js';
import {
  findAuthorityPda,
  findDeferredExecPda,
  findFeeRecordPda,
  findProtocolConfigPda,
  findSessionPda,
  findTreasuryShardPda,
  findVaultPda,
  findWalletPda,
} from './pdas.js';
import {
  createAssociatedTokenAccountIdempotentIx,
  getAssociatedTokenAddress,
} from './spl.js';
import {
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_2022_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
} from './instructions/system.js';
import {
  V1_DISC_AUTHORITY,
  V1_DISC_DEFERRED_EXEC,
  V1_DISC_SESSION,
  V1_DISC_WALLET,
  classifyV1VaultTokens,
  harvestWithheldIx,
  tokenAccountFrozen,
  deriveV1Accounts,
  enumerateV1VaultTokens,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletsByOwner,
  readV1WalletState,
  type UnmovableReason,
  type V1Accounts,
  type V1VaultToken,
  type V1WalletRecord,
} from './v1.js';
import {
  pickOwnWallet,
  verifyOwnershipProof,
  type AuthorityRoleName,
  type OwnershipProof,
  type PasskeyWalletCandidate,
  type WalletFacts,
} from './ownership.js';
import {
  finalizeSecp256r1,
  prepareSecp256r1,
  buildDataPayloadForAdd,
  buildDataPayloadForSession,
  buildDataPayloadForTransfer,
  type PreparedSecp256r1,
} from './secp256r1/signing.js';
import {
  readAuthorityCounter,
  type ChallengeReadOptions,
} from './secp256r1/secp256r1.js';
import { ChallengeReadGroup, readChallengeInputs } from './secp256r1/challengeReads.js';
import {
  buildCompactLayout,
  computeAccountsHash,
  computeInstructionsHash,
  decodeAccountIndex,
  packCompactInstructions,
  type CompactInstruction,
} from './transactions/index.js';
import type {
  AdminSigner,
  CreateWalletOwner,
  DeferredPayload,
  ExecuteSigner,
  Secp256r1Params,
  Secp256r1SignerConfig,
  WebAuthnResponse,
} from './types.js';

const addressEncoder = getAddressEncoder();
const base64Encoder = getBase64Encoder();

// ─── Sysvar instruction indexes (auto-computed from account layouts) ──

const SYSVAR_IX_INDEX_ADD_AUTHORITY = 6;
const SYSVAR_IX_INDEX_REMOVE_AUTHORITY = 5;
const SYSVAR_IX_INDEX_TRANSFER_OWNERSHIP = 7;
const SYSVAR_IX_INDEX_EXECUTE = 4;
const SYSVAR_IX_INDEX_CREATE_SESSION = 6;
const SYSVAR_IX_INDEX_AUTHORIZE = 6;
const SYSVAR_IX_INDEX_REVOKE_SESSION = 5;
const SYSVAR_IX_INDEX_MIGRATE_WALLET = 7;

// ─── Prepared types (Secp256r1 prepare/finalize flow) ────────────────

interface PreparedBase {
  /** SHA-256 challenge to pass to navigator.credentials.get(): 32 bytes, approving this operation only. */
  challenge: Uint8Array;
}

export interface PreparedExecute extends PreparedBase {
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    authorityPda: Address;
    vaultPda: Address;
    packed: Uint8Array;
    remainingAccounts: AccountMeta[];
    protocolFee?: ProtocolFeeAccounts;
    registerIx?: Instruction;
    programId: Address;
  };
}

export interface PreparedAddAuthority extends PreparedBase {
  newAuthorityPda: Address;
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    adminAuthorityPda: Address;
    newAuthorityPda: Address;
    newType: number;
    newRole: number;
    policy?: Uint8Array;
    credentialOrPubkey: Uint8Array;
    secp256r1Pubkey?: Uint8Array;
    rpId?: string;
    programId: Address;
  };
}

export interface PreparedRemoveAuthority extends PreparedBase {
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    adminAuthorityPda: Address;
    targetAuthorityPda: Address;
    refundDestination: Address;
    programId: Address;
  };
}

export interface PreparedTransferOwnership extends PreparedBase {
  newOwnerAuthorityPda: Address;
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    currentOwnerAuthorityPda: Address;
    newOwnerAuthorityPda: Address;
    refundDestination: Address;
    newType: number;
    credentialOrPubkey: Uint8Array;
    secp256r1Pubkey?: Uint8Array;
    rpId?: string;
    programId: Address;
  };
}

export interface PreparedCreateSession extends PreparedBase {
  sessionPda: Address;
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    adminAuthorityPda: Address;
    sessionPda: Address;
    sessionKey: Uint8Array;
    expiresAt: bigint;
    actionsBuffer?: Uint8Array;
    programId: Address;
  };
}

export interface PreparedRevokeSession extends PreparedBase {
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    walletPda: Address;
    adminAuthorityPda: Address;
    sessionPda: Address;
    refundDestination: Address;
    programId: Address;
  };
}

export interface PreparedAuthorize extends PreparedBase {
  deferredExecPda: Address;
  counter: number;
  /** @internal */
  _internal: {
    signing: PreparedSecp256r1;
    payer: Address;
    executor: Address;
    walletPda: Address;
    authorityPda: Address;
    deferredExecPda: Address;
    instructionsHash: Uint8Array;
    accountsHash: Uint8Array;
    expiryOffset: number;
    compactInstructions: CompactInstruction[];
    remainingAccounts: AccountMeta[];
    programId: Address;
  };
}

interface ProtocolFeeAccounts {
  protocolConfigPda: Address;
  feeRecordPda: Address;
  treasuryShardPda: Address;
}

export interface WalletAuthorityRecord {
  walletPda: Address;
  authorityPda: Address;
  vaultPda: Address;
  /** Role enum: 0=Owner, 1=Admin, 2=Spender. */
  role: number;
  /** Authority type enum: 0=Ed25519, 1=Secp256r1. */
  authorityType: number;
}

// ─── Internal helpers ────────────────────────────────────────────────

function assertByteLength(value: Uint8Array, expected: number, name: string): void {
  if (value.length !== expected) {
    throw new Error(`${name} must be exactly ${expected} bytes, got ${value.length}`);
  }
}

function assertNonZeroBytes(value: Uint8Array, name: string): void {
  if (value.every((b) => b === 0)) {
    throw new Error(`${name} must not be all zero bytes`);
  }
}

function resolveOwnerFields(owner: CreateWalletOwner): {
  authType: number;
  credentialOrPubkey: Uint8Array;
  secp256r1Pubkey?: Uint8Array;
  rpId?: string;
} {
  if (owner.type === 'ed25519') {
    const publicKeyBytes = addressEncoder.encode(owner.publicKey) as Uint8Array;
    assertNonZeroBytes(publicKeyBytes, 'publicKey');
    return {
      authType: AUTH_TYPE_ED25519,
      credentialOrPubkey: publicKeyBytes,
    };
  }
  assertByteLength(owner.credentialIdHash, 32, 'credentialIdHash');
  assertByteLength(owner.compressedPubkey, 33, 'compressedPubkey');
  assertNonZeroBytes(owner.credentialIdHash, 'credentialIdHash');
  assertNonZeroBytes(owner.compressedPubkey, 'compressedPubkey');
  return {
    authType: AUTH_TYPE_SECP256R1,
    credentialOrPubkey: owner.credentialIdHash,
    secp256r1Pubkey: owner.compressedPubkey,
    rpId: owner.rpId,
  };
}

/// The program lets an Owner create another Owner — that is what makes a second
/// device able to revoke a lost first one. It stays behind an explicit opt-in
/// here because handing out ownership is not something to do by passing a `0`
/// where a `1` was meant, and because the safe default is the one most callers
/// want.
function assertAddAuthorityRole(
  role: number,
  allowOwner = false,
  policy?: Uint8Array,
): void {
  if (role === ROLE_OWNER && !allowOwner) {
    throw new Error(
      'AddAuthority creates an Owner only with allowOwner: true — an Owner can ' +
        'manage and revoke everything, including you. Use ROLE_ADMIN for a ' +
        'manager, or transferOwnership to hand ownership over.',
    );
  }
  if (role < 0 || role > 2) {
    throw new Error(
      'AddAuthority role must be ROLE_OWNER (0), ROLE_ADMIN (1) or ROLE_SPENDER (2)',
    );
  }
  // The program rejects a policy-less Delegate (DelegateRequiresPolicy, 3033).
  // Catching it here names the missing argument instead of surfacing an opaque
  // custom program error after a passkey prompt has already been spent.
  if (role === ROLE_SPENDER && (!policy || policy.length === 0)) {
    throw new Error(
      'ROLE_SPENDER (Delegate) requires a non-empty policy — rank says what an ' +
        'authority may manage, the policy says what it may spend, and a Delegate ' +
        'manages nothing. Build one with serializeActions([...]).',
    );
  }
  // …and only a Delegate may carry one (PolicyRankMismatch, 3035). A bounded
  // Owner or Admin holds powers no engine can bound — and a bounded Owner was
  // a dead end, able to remove the unbounded Owner and then widen nothing.
  if (role !== ROLE_SPENDER && policy && policy.length > 0) {
    throw new Error(
      'Only ROLE_SPENDER (Delegate) may carry a policy. A capped spender is a ' +
        'Delegate; a manager is an Admin. To give one person both, issue two ' +
        'authorities.',
    );
  }
}

/// A session with no actions is not "a session with no limits" in name only —
/// it has no spending limit at all. The action buffer is what switches on the
/// policy rules (no SOL and no mint the actions do not name leaving the
/// vault, and the limits on those they do), so an empty buffer lets the key
/// move any asset the vault holds until it expires: more than a bounded
/// Delegate can. It still cannot change who controls the vault or its token
/// accounts — the program holds every signer but an Owner to that — but
/// spending without a limit is a deliberate capability, never a default, so
/// it has to be asked for by name.
function assertSessionActions(
  actions: SessionAction[] | undefined,
  unrestricted = false,
): void {
  if ((!actions || actions.length === 0) && !unrestricted) {
    throw new Error(
      'createSession with no actions grants an UNRESTRICTED session key — it can ' +
        'move everything the vault holds, which is more than a bounded Delegate ' +
        'can. Pass actions: [Actions.solLimit(...), ...] to bound it, or ' +
        'unrestricted: true to say you meant it.',
    );
  }
}

/**
 * Discriminators the ownership scans filter on, per protocol version. v1 and
 * v2 accounts share every offset; only these bytes (and the PDA seeds) differ.
 */
const OWNERSHIP_DISCS = {
  1: {
    wallet: V1_DISC_WALLET,
    authority: V1_DISC_AUTHORITY,
    session: V1_DISC_SESSION,
    deferred: V1_DISC_DEFERRED_EXEC,
  },
  2: {
    wallet: ACCOUNT_DISCRIMINATOR.WALLET,
    authority: ACCOUNT_DISCRIMINATOR.AUTHORITY,
    session: ACCOUNT_DISCRIMINATOR.SESSION,
    deferred: ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC,
  },
} as const;

/**
 * Mints whose canonical vault token account is always checked for a changed
 * owner: wSOL, USDC, USDT, and devnet USDC. SPL Token lets `SetAuthority` hand
 * even an associated token account to someone else, after which it no longer
 * lists as the vault's but senders still pay into it — and nothing on chain
 * points from it back to the vault, so only a mint named in advance can be
 * checked. Callers add their own with `watchMints`. Token-2022 ones are
 * created immutable, so only SPL Token is checked.
 */
const WATCHED_MINTS: readonly Address[] = [
  'So11111111111111111111111111111111111111112',
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
].map((m) => address(m));

/** `WATCHED_MINTS`, then each of `extra` not already there. A malformed mint throws. */
function watchedMints(extra: ReadonlyArray<Address | string> = []): Address[] {
  const mints = [...WATCHED_MINTS];
  for (const m of extra) {
    const mint = address(m);
    if (!mints.includes(mint)) mints.push(mint);
  }
  return mints;
}

// SPL token account, the same base layout in Token-2022: mint 0..32 | owner
// 32..64 | amount | delegate COption 72..108 | state | is_native |
// delegated_amount | close_authority COption 129..165.
const TOKEN_DELEGATE = 72;
const TOKEN_CLOSE_AUTHORITY = 129;
const TOKEN_ACCOUNT_LEN = 165;

type TokenGrant = WalletFacts['tokenGrants'][number];

/**
 * The delegates and foreign close authorities on token accounts the vault
 * owns. A close authority can take a wSOL account's whole balance; a delegate,
 * up to its allowance of whatever arrives later.
 */
function grantsOn(
  accounts: ReadonlyArray<{ pubkey: Address; data: Uint8Array }>,
  tokenProgram: Address,
  vault: Address,
  trustedKeys: ReadonlySet<string>,
): TokenGrant[] {
  const grants: TokenGrant[] = [];
  for (const { pubkey, data } of accounts) {
    if (data.length < TOKEN_ACCOUNT_LEN) {
      grants.push(unreadableGrant(pubkey, tokenProgram));
      continue;
    }
    const mint = addressFromBytes(data.slice(0, 32));
    for (const [kind, offset] of [
      ['delegate', TOKEN_DELEGATE],
      ['closeAuthority', TOKEN_CLOSE_AUTHORITY],
    ] as const) {
      // COption: a u32 tag, then the key. Any tag but None counts as set.
      if (readU32(data, offset) === 0) continue;
      const grantee = addressFromBytes(data.slice(offset + 4, offset + 36));
      if (grantee === vault) continue;
      grants.push({
        tokenAccount: pubkey,
        tokenProgram,
        mint,
        kind,
        grantee,
        trusted: trustedKeys.has(grantee),
      });
    }
  }
  return grants;
}

function unreadableGrant(tokenAccount: Address, tokenProgram: Address): TokenGrant {
  return { tokenAccount, tokenProgram, mint: null, kind: 'unreadable', grantee: null, trusted: false };
}

type TokenAccountRow = { pubkey: Address; data: Uint8Array };

/** The vault's canonical SPL Token account for each of `mints`, in order. */
function watchedAtasOf(vault: Address, mints: ReadonlyArray<Address>): Promise<Address[]> {
  return Promise.all(mints.map((mint) => getAssociatedTokenAddress(mint, vault, TOKEN_PROGRAM_ADDRESS)));
}

/**
 * Every right over `vault`'s tokens that someone other than the vault holds:
 * delegates and foreign close authorities on the accounts it owns under either
 * token program, and its canonical account for a watched mint handed to
 * another owner. `watched` pairs each of {@link watchedAtasOf} with what the
 * chain holds there.
 */
function vaultTokenGrants(
  vault: Address,
  owned: { spl: ReadonlyArray<TokenAccountRow>; token2022: ReadonlyArray<TokenAccountRow> },
  watched: ReadonlyArray<{
    address: Address;
    mint: Address;
    info: { owner: Address; data: Uint8Array } | null;
  }>,
  trustedKeys: ReadonlySet<string>,
): TokenGrant[] {
  const grants: TokenGrant[] = [
    ...grantsOn(owned.spl, TOKEN_PROGRAM_ADDRESS, vault, trustedKeys),
    ...grantsOn(owned.token2022, TOKEN_2022_PROGRAM_ADDRESS, vault, trustedKeys),
  ];
  for (const { address: ata, mint, info } of watched) {
    // Absent, or not a token account (lamports sent to the address): nothing
    // to hand over. Owned by the vault: already read above.
    if (!info || info.owner !== TOKEN_PROGRAM_ADDRESS) continue;
    if (info.data.length < 64) {
      grants.push(unreadableGrant(ata, TOKEN_PROGRAM_ADDRESS));
      continue;
    }
    const owner = addressFromBytes(info.data.slice(32, 64));
    if (owner === vault) continue;
    grants.push({
      tokenAccount: ata,
      tokenProgram: TOKEN_PROGRAM_ADDRESS,
      mint,
      kind: 'owner',
      grantee: owner,
      trusted: trustedKeys.has(owner),
    });
  }
  return grants;
}

/** What a token grant lets its holder do, as the tail of an error message. */
function grantPhrase(g: TokenGrant): string {
  switch (g.kind) {
    case 'delegate':
      return `has a delegate, ${g.grantee}`;
    case 'closeAuthority':
      return `has a close authority other than the vault, ${g.grantee}`;
    case 'owner':
      return `(the vault's own account for mint ${g.mint}) belongs to ${g.grantee}`;
    case 'unreadable':
      return 'cannot be read as a token account';
  }
}

/**
 * Why an existing account at a migration's destination token address must not
 * receive the tokens, or `null`. The program checks only that it is a token
 * account of the destination vault with the same mint; a delegate or a close
 * authority left on it by whoever held the wallet before would still take
 * what arrives.
 */
function destinationTokenAccountProblem(
  dest: Address,
  info: { owner: Address; data: Uint8Array },
  tokenProgram: Address,
  vault: Address,
): string | null {
  if (info.owner !== tokenProgram) return `is owned by program ${info.owner}, not ${tokenProgram}`;
  if (info.data.length < TOKEN_ACCOUNT_LEN) return 'cannot be read as a token account';
  const owner = addressFromBytes(info.data.slice(32, 64));
  if (owner !== vault) return `belongs to ${owner}, not the v2 vault ${vault}`;
  const [grant] = grantsOn([{ pubkey: dest, data: info.data }], tokenProgram, vault, new Set());
  return grant ? grantPhrase(grant) : null;
}

/**
 * A plain system account: owned by the System Program with no data, or not
 * created yet. Anything else — a vault an Owner's `Execute` assigned to another
 * program or allocated data — is spent by rules LazorKit does not enforce.
 */
function isSystemAccount(info: { owner: Address; data: Uint8Array } | null): boolean {
  return !info || (info.owner === SYSTEM_PROGRAM_ADDRESS && info.data.length === 0);
}

/** `info` is a wallet account of the candidate's program and version. */
function isLiveWallet(
  c: Pick<PasskeyWalletCandidate, 'programId' | 'version'>,
  info: { owner: Address; data: Uint8Array } | null,
): boolean {
  return (
    !!info &&
    info.owner === c.programId &&
    info.data.length > 0 &&
    info.data[0] === OWNERSHIP_DISCS[c.version].wallet
  );
}

/** An expiry that could not be read counts as never expiring: fail closed. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function memcmpFilter(offset: bigint, bytes: Uint8Array) {
  return {
    memcmp: {
      offset,
      bytes: bs58Encode(bytes) as Base58EncodedBytes,
      encoding: 'base58' as const,
    },
  };
}

function roleName(role: number | undefined): AuthorityRoleName {
  return role === 0 ? 'owner' : role === 1 ? 'admin' : role === 2 ? 'spender' : 'unknown';
}

/** Stands in for a key an account too short to read does not have. */
const ZERO_ADDRESS = '11111111111111111111111111111111' as Address;

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
      if (attempt >= 5 || !isSolanaError(e, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED)) {
        throw e;
      }
      await new Promise((r) => setTimeout(r, 100 * attempt));
    }
  }
}

function maxSlot(...slots: bigint[]): bigint {
  return slots.reduce((a, b) => (a > b ? a : b));
}

/** `fn` over `items`, at most `limit` in flight, results in input order. */
async function mapBounded<T, R>(
  items: ReadonlyArray<T>,
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * RPC capability bag the client needs. Use kit's `createSolanaRpc(url)`, which
 * satisfies all of it.
 *
 * `GetMultipleAccountsApi` and `GetTokenAccountsByOwnerApi` are there for the
 * v1 migration path, which has to read a v1 wallet's state and enumerate its
 * token accounts before it can move anything.
 */
export type LazorKitRpc = Rpc<
  GetAccountInfoApi &
    GetMultipleAccountsApi &
    GetProgramAccountsApi &
    GetSlotApi &
    GetTokenAccountsByOwnerApi
>;

/**
 * The runtime reports an account's privileges per key, not per position: a key
 * listed twice in a message is a signer, and writable, at every position if it
 * is so at any one. The accounts hash is over those runtime flags, so a layout
 * that repeats a key has to hash the union. Authorize's can — tx2's payer is
 * index 0 (signer) and the Authorize payer is the refund destination at index
 * 4 (writable only), and `buildCompactLayout` maps an inner reference to the
 * Authorize payer onto index 4, where the program reads signer + writable when
 * the two are one key.
 *
 * What this models is this instruction's own list plus the transaction's fee
 * payer, a writable signer wherever it appears: the payer at index 0, declared
 * so for that reason, or `feePayer` when another key pays. The rest of the
 * transaction is the caller's to account for. Another top-level instruction
 * that lists a key with more privilege raises it; the protocol-fee accounts
 * appended after the remaining accounts are writable; and the runtime demotes a
 * reserved account or an invoked program id to read-only whatever any list
 * says. A wrong guess fails closed: the program refuses the transaction (3005,
 * or 3015 for ExecuteDeferred) and nothing runs.
 */
function withRuntimeRoles(metas: AccountMeta[], feePayer?: Address): AccountMeta[] {
  // AccountRole is a bit set: bit 0 writable, bit 1 signer.
  const union = new Map<Address, number>();
  for (const m of metas) union.set(m.address, (union.get(m.address) ?? 0) | (m.role as number));
  if (feePayer) {
    union.set(feePayer, (union.get(feePayer) ?? 0) | (AccountRole.WRITABLE_SIGNER as number));
  }
  return metas.map((m) => ({ address: m.address, role: union.get(m.address)! as AccountRole }));
}

/**
 * Whether a deferred payload's inner instructions name tx2's payer (index 0)
 * or its refund destination (index 4) — the two fixed accounts whose hashed
 * flags depend on who sends tx2.
 */
function namesDeferredPayerSlot(
  compactInstructions: DeferredPayload['compactInstructions'],
): boolean {
  const payerSlot = (byte: number) => {
    const { index } = decodeAccountIndex(byte);
    return index === 0 || index === 4;
  };
  return compactInstructions.some(
    (ix) => payerSlot(ix.programIdIndex) || ix.accountIndexes.some(payerSlot),
  );
}

/**
 * Construct a LazorKit client.
 *
 * @param rpc       kit Rpc with at least GetAccountInfoApi + GetSlotApi capabilities
 * @param programId LazorKit program address (mainnet or devnet)
 *
 * Unlike sdk-legacy, this constructor does NOT auto-infer programId
 * from RPC URL — kit's Rpc<> type is opaque (the URL isn't reachable
 * post-construction). Pass it explicitly.
 */
export class LazorKit {
  /** Cached protocol config (fetched on first fee-eligible call). */
  private _protocolConfig:
    | { numShards: number; enabled: boolean }
    | null
    | undefined;
  private _registeredPayers = new Set<string>();

  readonly rpc: LazorKitRpc;
  readonly programId: Address;
  /** Whether fee-eligible instructions carry the protocol-fee suffix. */
  readonly protocolFees: boolean;

  constructor(rpc: LazorKitRpc, programId: Address, options: LazorKitOptions = {}) {
    this.rpc = rpc;
    this.programId = programId;
    this.protocolFees = options.protocolFees ?? true;
  }

  // ─── PDA helpers (sync wrappers around the module-level fns) ─────

  findWallet(userSeed: Uint8Array) {
    return findWalletPda(userSeed, this.programId);
  }
  findVault(walletPda: Address) {
    return findVaultPda(walletPda, this.programId);
  }
  findAuthority(walletPda: Address, credIdHash: Uint8Array) {
    return findAuthorityPda(walletPda, credIdHash, this.programId);
  }
  findSession(walletPda: Address, sessionKey: Uint8Array) {
    return findSessionPda(walletPda, sessionKey, this.programId);
  }
  findDeferredExec(walletPda: Address, authorityPda: Address, counter: number) {
    return findDeferredExecPda(walletPda, authorityPda, counter, this.programId);
  }
  findProtocolConfig() {
    return findProtocolConfigPda(this.programId);
  }
  findFeeRecord(payer: Address) {
    return findFeeRecordPda(payer, this.programId);
  }
  findTreasuryShard(shardId: number) {
    return findTreasuryShardPda(shardId, this.programId);
  }

  // ─── Protocol fee resolution ─────────────────────────────────────

  async getProtocolConfig(): Promise<{ numShards: number; enabled: boolean } | null> {
    if (this._protocolConfig !== undefined) return this._protocolConfig;
    const [configPda] = await this.findProtocolConfig();
    const info = await this.rpc.getAccountInfo(configPda, { encoding: 'base64' }).send();
    if (!info.value) {
      this._protocolConfig = null;
      return null;
    }
    const data = new Uint8Array(base64Encoder.encode(info.value.data[0]));
    if (data.length < 88 || data[0] !== ACCOUNT_DISCRIMINATOR.PROTOCOL_CONFIG) {
      this._protocolConfig = null;
      return null;
    }
    this._protocolConfig = { enabled: data[3] !== 0, numShards: data[4]! };
    return this._protocolConfig;
  }

  invalidateProtocolCache(): void {
    this._protocolConfig = undefined;
  }

  /**
   * Returns the four fee accounts every fee-eligible instruction (disc 0, 4, 7)
   * must carry. The program requires the suffix whether or not a fee is
   * charged: it rejects the instruction without it (4008 FeeAccountsRequired)
   * before reading the config, and strips it when the protocol is
   * uninitialised or disabled. Omitting it is what broke every CreateWallet /
   * Execute between an upgrade and `InitializeProtocol`, or while fees were
   * paused. The FeeRecord address is always canonical for the payer.
   *
   * Returns undefined only for a client built with `{ protocolFees: false }`,
   * for a binary without the fee layer.
   */
  async resolveProtocolFee(payer: Address): Promise<ProtocolFeeAccounts | undefined> {
    if (!this.protocolFees) return undefined;
    const config = await this.getProtocolConfig();
    const [protocolConfigPda] = await this.findProtocolConfig();
    const [feeRecordPda] = await this.findFeeRecord(payer);
    // A shard is only read when a fee is actually charged. Uninitialised or
    // disabled, the program strips the suffix without touching the shard or
    // the record (entrypoint `try_collect_fee`), so shard 0 serves.
    let shardId = 0;
    if (config && config.enabled && config.numShards > 0) {
      const randBuf = randomBytes(4);
      const randU32 =
        (randBuf[0]! | (randBuf[1]! << 8) | (randBuf[2]! << 16) | (randBuf[3]! << 24)) >>> 0;
      shardId = randU32 % config.numShards;
    }
    const [treasuryShardPda] = await this.findTreasuryShard(shardId);
    return { protocolConfigPda, feeRecordPda, treasuryShardPda };
  }

  async resolveProtocolFeeWithRegister(
    payer: Address,
  ): Promise<{ accounts: ProtocolFeeAccounts; registerIx?: Instruction } | undefined> {
    const accounts = await this.resolveProtocolFee(payer);
    if (!accounts) return undefined;

    // Only a live fee touches the FeeRecord. Uninitialised or disabled, the
    // program never reads it, and RegisterPayer needs a live config — so there
    // is nothing to register.
    const config = await this.getProtocolConfig();
    if (!config || !config.enabled) return { accounts };

    if (this._registeredPayers.has(payer)) return { accounts };

    const info = await this.rpc.getAccountInfo(accounts.feeRecordPda, { encoding: 'base64' }).send();
    let exists = false;
    if (info.value) {
      const data = new Uint8Array(base64Encoder.encode(info.value.data[0]));
      exists = data.length > 0 && data[0] === ACCOUNT_DISCRIMINATOR.FEE_RECORD;
    }
    if (exists) {
      this._registeredPayers.add(payer);
      return { accounts };
    }

    const registerIx = createRegisterPayerIx({
      payer,
      feeRecordPda: accounts.feeRecordPda,
      programId: this.programId,
    });
    this._registeredPayers.add(payer);
    return { accounts, registerIx };
  }

  // ─── Account readers ─────────────────────────────────────────────

  /**
   * The authority's odometer counter: the next passkey challenge signs one
   * more. Read at `opts.commitment` (default `'confirmed'`) and, with
   * `opts.minContextSlot`, from a node at or past that slot — see
   * `Secp256r1Params.minContextSlot`.
   */
  async readCounter(authorityPda: Address, opts?: ChallengeReadOptions): Promise<number> {
    return readAuthorityCounter(this.rpc, authorityPda, opts);
  }

  // ─── Secp256r1 prepare/finalize plumbing ─────────────────────────

  /**
   * `group`: when another read runs beside these, in it too (see
   * `prepareExecute`); by default the challenge reads get one of their own.
   */
  private async resolveSecp256r1(walletPda: Address, p: Secp256r1Params, group?: ChallengeReadGroup) {
    assertByteLength(p.credentialIdHash, 32, 'credentialIdHash');
    if (p.publicKeyBytes) assertByteLength(p.publicKeyBytes, 33, 'publicKeyBytes');
    const authorityPda =
      p.authorityPda ?? (await this.findAuthority(walletPda, p.credentialIdHash))[0];

    // Independent RPC reads, in parallel; what the caller passed is not read.
    // All three at one commitment and freshness floor: a node that has not yet
    // executed the authority's previous transaction hands back the counter it
    // consumed, and the signature fails with SignatureReused (3006). If one
    // read fails, the others stop waiting for the floor.
    const reads: ChallengeReadOptions = { commitment: p.commitment, minContextSlot: p.minContextSlot };
    const { publicKeyBytes, slot, counter } = await readChallengeInputs(
      this.rpc,
      authorityPda,
      reads,
      { publicKeyBytes: p.publicKeyBytes, slotOverride: p.slotOverride },
      group,
    );

    return { authorityPda, publicKeyBytes, slot, counter };
  }

  private extractSecp256r1Params(s: Secp256r1SignerConfig): Secp256r1Params {
    return {
      credentialIdHash: s.signer.credentialIdHash,
      publicKeyBytes: s.signer.publicKeyBytes,
      authorityPda: s.authorityPda,
      slotOverride: s.slotOverride,
      minContextSlot: s.minContextSlot,
      commitment: s.commitment,
    };
  }

  private async resolveEd25519AuthorityPda(
    s: { publicKey: Address; authorityPda?: Address },
    walletPda: Address,
  ): Promise<Address> {
    if (s.authorityPda) return s.authorityPda;
    const [pda] = await this.findAuthority(
      walletPda,
      addressEncoder.encode(s.publicKey) as Uint8Array,
    );
    return pda;
  }

  private buildPasskeySigning(args: {
    discriminator: number;
    sysvarIxIndex: number;
    signedPayload: Uint8Array;
    slot: bigint;
    counter: number;
    payer: Address;
    /** The wallet the signing authority belongs to; the challenge names it. */
    wallet: Address;
    publicKeyBytes: Uint8Array;
    /** The program that will verify the signature. Defaults to this client's. */
    programId?: Address;
  }): PreparedSecp256r1 {
    return prepareSecp256r1({
      discriminator: new Uint8Array([args.discriminator]),
      signedPayload: args.signedPayload,
      sysvarIxIndex: args.sysvarIxIndex,
      slot: args.slot,
      counter: args.counter,
      payer: args.payer,
      wallet: args.wallet,
      programId: args.programId ?? this.programId,
      publicKeyBytes: args.publicKeyBytes,
    });
  }

  private buildCompactLayoutAndHash(
    fixedAccounts: AccountMeta[],
    userInstructions: ReadonlyArray<Instruction>,
    // Threaded through rather than read off `fixedAccounts[0]`: the deferred
    // layout lists the payer twice, and the whole point of the payer exclusion
    // is that a duplicate entry must not launder it.
    payer: Address,
    feePayer?: Address,
  ): {
    compactInstructions: CompactInstruction[];
    remainingAccounts: AccountMeta[];
    allAccountMetas: AccountMeta[];
    accountsHash: Uint8Array;
  } {
    const fixedAddresses = fixedAccounts.map((a) => a.address);
    const { compactInstructions, remainingAccounts } = buildCompactLayout(
      fixedAddresses,
      userInstructions,
      payer,
    );
    // The program hashes the flags the runtime reports, so read the metas the
    // way the runtime does (see withRuntimeRoles).
    const allAccountMetas = withRuntimeRoles([...fixedAccounts, ...remainingAccounts], feePayer);
    const accountsHash = computeAccountsHash(allAccountMetas, compactInstructions);
    return { compactInstructions, remainingAccounts, allAccountMetas, accountsHash };
  }

  // ─── Wallet lookup ───────────────────────────────────────────────

  /**
   * Every wallet that lists this credential as an authority, at any rank.
   *
   * A raw lookup, not a way to find a returning user's wallet: a credential-id
   * hash is public (it sits in every authority account the passkey has) and
   * `CreateWallet`/`AddAuthority` take any owner without its consent, so
   * anyone can plant a wallet that lists it. For a returning passkey user use
   * {@link LazorKit.findOwnPasskeyWallet}, which proves the key and checks who
   * else can spend.
   *
   * @param credential - 32 bytes: Ed25519 pubkey or Secp256r1 credentialIdHash
   * @param authorityType - `'secp256r1'` (default) or `'ed25519'`
   */
  async findWalletsByAuthority(
    credential: Uint8Array,
    authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
  ): Promise<WalletAuthorityRecord[]> {
    assertByteLength(credential, 32, 'credential');
    const typeValue = authorityType === 'ed25519' ? AUTH_TYPE_ED25519 : AUTH_TYPE_SECP256R1;
    const discAndType = new Uint8Array([ACCOUNT_DISCRIMINATOR.AUTHORITY, typeValue]);

    const accounts = await this.rpc
      .getProgramAccounts(this.programId, {
        encoding: 'base64',
        filters: [
          {
            memcmp: {
              offset: 0n,
              // kit's getProgramAccounts requires Base58EncodedBytes for memcmp
              // when encoding is 'base58' (default). We use base58 here for
              // both filters to satisfy that brand.
              bytes: bs58Encode(discAndType) as Base58EncodedBytes,
              encoding: 'base58',
            },
          },
          {
            memcmp: {
              offset: 48n,
              bytes: bs58Encode(credential) as Base58EncodedBytes,
              encoding: 'base58',
            },
          },
        ],
      })
      .send();

    const out: WalletAuthorityRecord[] = [];
    // kit returns a Readonly array — iterate via index access.
    for (let idx = 0; idx < accounts.length; idx++) {
      const { pubkey, account } = accounts[idx]!;
      const data = new Uint8Array(base64Encoder.encode(account.data[0]));
      const walletBytes = data.slice(16, 48);
      const walletPda = addressFromBytes(walletBytes);
      const [vaultPda] = await this.findVault(walletPda);
      out.push({
        walletPda,
        authorityPda: pubkey,
        vaultPda,
        role: data[2]!,
        authorityType: data[1]!,
      });
    }
    return out;
  }

  // ─── Returning passkey user: which wallet is theirs ──────────────

  /**
   * Wallets this passkey is an Owner of, created under `rpId`: on this
   * client's program and, unless `includeV1: false`, on the v1 deployment
   * paired with it. v2 hits first, then v1.
   *
   * Candidates only. The credential-id hash these are found by is public, so
   * each one still has to be proven ({@link verifyOwnershipProof}) and
   * described ({@link LazorKit.describeWalletCandidates}) before it can be
   * called the user's — {@link LazorKit.findOwnPasskeyWallet} does all three.
   */
  async findPasskeyWalletCandidates(params: {
    credentialIdHash: Uint8Array;
    rpId: string;
    /** Also scan the v1 deployment paired with this client's program. Default `true`. */
    includeV1?: boolean;
  }): Promise<PasskeyWalletCandidate[]> {
    assertByteLength(params.credentialIdHash, 32, 'credentialIdHash');
    const rpIdHash = sha256(new TextEncoder().encode(params.rpId));

    const scan = async (version: 1 | 2, programId: Address): Promise<PasskeyWalletCandidate[]> => {
      const accounts = await this.rpc
        .getProgramAccounts(programId, {
          encoding: 'base64',
          filters: [
            memcmpFilter(0n, new Uint8Array([OWNERSHIP_DISCS[version].authority, AUTH_TYPE_SECP256R1])),
            memcmpFilter(48n, params.credentialIdHash),
            memcmpFilter(113n, rpIdHash),
          ],
        })
        .send();
      const out: PasskeyWalletCandidate[] = [];
      for (let i = 0; i < accounts.length; i++) {
        const { pubkey, account } = accounts[i]!;
        const data = new Uint8Array(base64Encoder.encode(account.data[0]));
        // Owner rank only: an Admin or Spender seat is someone else's wallet
        // that this passkey was given a place on — an Owner above it can take
        // that seat away.
        if (data.length < 145 || data[2] !== ROLE_OWNER) continue;
        const walletPda = addressFromBytes(data.slice(16, 48));
        const [vaultPda] =
          version === 2
            ? await findVaultPda(walletPda, programId)
            : await findV1VaultPda(walletPda, programId);
        out.push({
          version,
          programId,
          walletPda,
          vaultPda,
          authorityPda: pubkey,
          publicKey: data.slice(80, 113),
        });
      }
      return out;
    };

    // On an in-place layout (local, staging) both ids are the same program;
    // the two discriminators still keep the scans apart.
    const [v2, v1] = await Promise.all([
      scan(2, this.programId),
      params.includeV1 === false
        ? Promise.resolve([])
        : scan(1, legacyProgramIdFor(this.programId)),
    ]);
    return [...v2, ...v1];
  }

  /**
   * What each candidate holds and who else can spend from it: the vault's
   * balance, every other authority, live sessions, pending deferred
   * executions, rights over the vault's token accounts and whether the vault
   * is still a plain system account — each marked trusted or not.
   *
   * `trustedKeys` are Ed25519 keys the integrator vouches for (its own backend
   * signer, say); an authority, session or token grant with one of them does
   * not count against `controlledAlone`. A passkey authority is never trusted:
   * a passkey cannot be declared, only proven. Nor is a pending deferred
   * execution (see `pendingDeferred.trusted`). A malformed key throws rather
   * than silently trusting nothing.
   *
   * `watchMints` are SPL Token mints whose canonical vault token account is
   * checked for a changed owner, on top of wSOL, USDC, USDT and devnet USDC.
   * Pass the mints your app receives: one handed away for any other mint
   * cannot be found (see `WalletFacts.controlledAlone`).
   *
   * Reads the slot once, then every candidate's wallet account in pages of
   * 100; then per remaining candidate, four at a time, in the order power
   * flows between these accounts: its authorities; then its
   * sessions and deferred executions; then its wallet account, vault, the
   * vault's SPL Token account for each watched mint and the vault's token
   * accounts under both token programs. Each step asks the RPC for state at
   * least as new as the one before (`minContextSlot`), so a transaction that
   * lands mid-read cannot be half-seen — only an authority creates sessions
   * and deferred executions, and only those (or an authority) create what the
   * last step reads; see the comment in the body. Reads are at the RPC's
   * default commitment.
   *
   * A candidate whose wallet account is gone, or is not a wallet of its
   * program, is left out: MigrateWallet closes a v1 wallet and only the
   * authority that migrated it, and nothing can ever move funds sent to what
   * is left.
   *
   * Fails closed: an account too short to read is an untrusted authority, or
   * a live and untrusted session / deferred execution / token grant — never
   * skipped. A wallet on which this passkey's own authority is no longer the
   * Owner-rank key it was found with is not `controlledAlone` either (and its
   * `signatureCount` is 0).
   *
   * `signatureCount` is how many times this passkey has signed for the
   * wallet. 0 for a wallet someone handed to it, which `controlledAlone`
   * cannot fully vouch for: an SPL Token account moved off the vault is only
   * found for the watched mints. Not proof on its own: a count raised before
   * the passkey challenge named the wallet may hold a signature replayed from
   * another wallet (see {@link pickOwnWallet}).
   */
  async describeWalletCandidates(
    candidates: PasskeyWalletCandidate[],
    options: { trustedKeys?: (Address | string)[]; watchMints?: (Address | string)[] } = {},
  ): Promise<WalletFacts[]> {
    // Both throw on a malformed key rather than silently trusting or watching
    // less — with or without candidates, so a bad config fails the same way.
    const trusted = new Set<string>((options.trustedKeys ?? []).map((k) => address(k)));
    const mints = watchedMints(options.watchMints);
    if (candidates.length === 0) return [];
    // The slot first: one older than the scans can only count more things live.
    const slot = BigInt(await this.rpc.getSlot().send());
    // Drop candidates whose wallet is gone before scanning anything for them.
    // Each survivor's wallet is read again, in order with the rest.
    const { infos: wallets } = await this.readAccounts(candidates.map((c) => c.walletPda));
    const live = candidates.filter((c, i) => isLiveWallet(c, wallets[i] ?? null));
    const described = await mapBounded(live, 4, (c) => this.describeCandidate(c, slot, trusted, mints));
    return described.filter((f): f is WalletFacts => f !== null);
  }

  /**
   * The returning passkey user's wallet, if the chain can say so without
   * asking them.
   *
   * `proof` is a WebAuthn assertion over a challenge from
   * {@link createTaggedOwnershipChallenge}, made by the passkey that signed in.
   * Candidates whose stored key did not produce it are dropped (`unproven`
   * counts them): anyone can create a wallet listing this credential with
   * their own key.
   *
   * - `adopt`: the one proven wallet this passkey has signed for, when only
   *   it and trusted keys can spend from it. Use it.
   * - `needsConfirmation`: every proven wallet, when none can be adopted.
   *   Show them (by vault) and let the user choose one or none; never pick one
   *   for them.
   * - both empty: no live wallet — create one.
   *
   * A wallet this passkey has never signed for is never adopted, even the
   * only one and even with `trustedKeys`: anyone can hand a wallet to a
   * passkey, and what its earlier holder left on the vault is not all
   * readable. Nor is any wallet when two have been signed for: a count raised
   * before the passkey challenge named the wallet may hold a signature
   * replayed from another wallet (see {@link pickOwnWallet}).
   * So a user whose wallet was created but not used yet confirms it once;
   * after the first transaction it is adopted. An app that just created or
   * migrated into a wallet already knows it and need not look it up.
   */
  async findOwnPasskeyWallet(params: {
    credentialIdHash: Uint8Array;
    rpId: string;
    proof: OwnershipProof;
    trustedKeys?: (Address | string)[];
    /** SPL Token mints to check the vault's canonical account of; see describeWalletCandidates. */
    watchMints?: (Address | string)[];
    includeV1?: boolean;
  }): Promise<{
    adopt: WalletFacts | null;
    needsConfirmation: WalletFacts[];
    /** Found by hash but not proven. */
    unproven: number;
  }> {
    const candidates = await this.findPasskeyWalletCandidates({
      credentialIdHash: params.credentialIdHash,
      rpId: params.rpId,
      includeV1: params.includeV1,
    });
    const proven = verifyOwnershipProof(candidates, params.proof, params.rpId);
    const unproven = candidates.length - proven.length;
    if (proven.length === 0) return { adopt: null, needsConfirmation: [], unproven };
    const facts = await this.describeWalletCandidates(proven, {
      trustedKeys: params.trustedKeys,
      watchMints: params.watchMints,
    });
    return { ...pickOwnWallet(facts), unproven };
  }

  /**
   * `addresses` in pages of 100, in order; `null` for an account that does not
   * exist. `slot` is the newest context slot among the pages; each page is at
   * or after `minContextSlot`.
   */
  private async readAccounts(
    addresses: Address[],
    minContextSlot?: bigint,
  ): Promise<{ slot: bigint; infos: ({ owner: Address; lamports: bigint; data: Uint8Array } | null)[] }> {
    const infos: ({ owner: Address; lamports: bigint; data: Uint8Array } | null)[] = [];
    let slot = minContextSlot ?? 0n;
    for (let i = 0; i < addresses.length; i += 100) {
      const { context, value } = await atOrAfterSlot(() =>
        this.rpc
          .getMultipleAccounts(addresses.slice(i, i + 100), { encoding: 'base64', minContextSlot })
          .send(),
      );
      slot = maxSlot(slot, BigInt(context.slot));
      for (const info of value) {
        infos.push(
          info && {
            owner: info.owner,
            lamports: BigInt(info.lamports),
            data: new Uint8Array(base64Encoder.encode(info.data[0])),
          },
        );
      }
    }
    return { slot, infos };
  }

  /**
   * `programId`'s accounts with discriminator `disc` that name `wallet` at
   * `walletOffset`, as of `slot` — at or after `minContextSlot`.
   */
  private async scanWalletAccounts(
    programId: Address,
    wallet: Address,
    disc: number,
    walletOffset: bigint,
    minContextSlot?: bigint,
  ): Promise<{ slot: bigint; rows: TokenAccountRow[] }> {
    const { context, value } = await atOrAfterSlot(() =>
      this.rpc
        .getProgramAccounts(programId, {
          encoding: 'base64',
          withContext: true,
          minContextSlot,
          filters: [
            memcmpFilter(0n, new Uint8Array([disc])),
            {
              memcmp: {
                offset: walletOffset,
                bytes: wallet as string as Base58EncodedBytes,
                encoding: 'base58',
              },
            },
          ],
        })
        .send(),
    );
    return {
      slot: BigInt(context.slot),
      rows: value.map(({ pubkey, account }) => ({
        pubkey,
        data: new Uint8Array(base64Encoder.encode(account.data[0])),
      })),
    };
  }

  /**
   * The token accounts `vault` owns, under SPL Token and under Token-2022, at
   * or after `minContextSlot`. `slot` is the newer of the two reads.
   */
  private async readVaultTokenAccounts(
    vault: Address,
    minContextSlot?: bigint,
  ): Promise<{ slot: bigint; spl: TokenAccountRow[]; token2022: TokenAccountRow[] }> {
    const read = (programId: Address) =>
      atOrAfterSlot(() =>
        this.rpc
          .getTokenAccountsByOwner(vault, { programId }, { encoding: 'base64', minContextSlot })
          .send(),
      ).then(({ context, value }) => ({
        slot: BigInt(context.slot),
        rows: value.map(({ pubkey, account }) => ({
          pubkey,
          data: new Uint8Array(base64Encoder.encode(account.data[0])),
        })),
      }));
    const [spl, token2022] = await Promise.all([
      read(TOKEN_PROGRAM_ADDRESS),
      read(TOKEN_2022_PROGRAM_ADDRESS),
    ]);
    return { slot: maxSlot(spl.slot, token2022.slot), spl: spl.rows, token2022: token2022.rows };
  }

  /**
   * Everything that can move `wallet`'s funds, read so that no transaction can
   * be half-seen. Separate RPC reads are separate snapshots — a load-balanced
   * endpoint may even answer them from different nodes — so reading these
   * concurrently lets one attacker transaction that lands in between (open a
   * session or approve a delegate, and drop their own authority) show as
   * neither. They are read in the order power flows instead, each step at or
   * after the slot the previous one was answered at:
   *
   * 1. authorities — the only thing that creates authorities, sessions or
   *    deferred executions (the program refuses to call itself, and the
   *    runtime refuses reentry through another program);
   * 2. sessions and deferred executions — which, besides authorities, are all
   *    that can make the vault sign: `ExecuteDeferred` closes the account in
   *    the same instruction as its CPIs, and an expired session can be closed
   *    by anyone, so a grant they made is only ever seen after they are gone;
   * 3. `accounts` (the vault, its canonical token accounts, the wallet
   *    account) and the vault's token accounts — none of which can create
   *    anything the earlier steps read.
   *
   * Anything that can still spend at the last step either existed at the
   * step that reads its kind, or was made later by something an earlier step
   * saw. Expiries are compared against a slot read before any of this: no
   * newer than the slot the program will check them at, it only counts more
   * things live.
   */
  private async readSpendingState(
    programId: Address,
    wallet: Address,
    vault: Address,
    discs: { authority: number; session: number; deferred: number },
    accounts: Address[],
  ) {
    const scan = (disc: number, walletOffset: bigint, minContextSlot?: bigint) =>
      this.scanWalletAccounts(programId, wallet, disc, walletOffset, minContextSlot);
    const authorities = await scan(discs.authority, 16n);
    const [sessions, deferred] = await Promise.all([
      scan(discs.session, 8n, authorities.slot),
      scan(discs.deferred, 72n, authorities.slot),
    ]);
    const after = maxSlot(sessions.slot, deferred.slot);
    const [read, ownedTokens] = await Promise.all([
      this.readAccounts(accounts, after),
      this.readVaultTokenAccounts(vault, after),
    ]);
    return {
      authorities: authorities.rows,
      sessions: sessions.rows,
      deferred: deferred.rows,
      /** `accounts`, in order; `null` for one that does not exist. */
      infos: accounts.map((_, i) => read.infos[i] ?? null),
      ownedTokens,
      /** The newest state any of it was read at. */
      slot: maxSlot(read.slot, ownedTokens.slot),
    };
  }

  private async describeCandidate(
    c: PasskeyWalletCandidate,
    slot: bigint,
    trustedKeys: ReadonlySet<string>,
    mints: ReadonlyArray<Address>,
  ): Promise<WalletFacts | null> {
    const discs = OWNERSHIP_DISCS[c.version];
    const atas = await watchedAtasOf(c.vaultPda, mints);
    const {
      authorities,
      sessions,
      deferred,
      infos: [walletInfo, vaultInfo, ...ataInfos],
      ownedTokens,
    } = await this.readSpendingState(c.programId, c.walletPda, c.vaultPda, discs, [
      c.walletPda,
      c.vaultPda,
      ...atas,
    ]);

    if (!isLiveWallet(c, walletInfo ?? null)) return null;
    const lamports = vaultInfo?.lamports ?? 0n;
    const vaultIsSystemAccount = isSystemAccount(vaultInfo ?? null);

    // This passkey's own authority is not an "other". It must still be the
    // Owner-rank key the candidate was found with, and it carries the relying
    // party the other passkeys are compared against.
    const own = authorities.find((a) => a.pubkey === c.authorityPda)?.data;
    const ownIntact =
      !!own &&
      own.length >= 145 &&
      own[1] === AUTH_TYPE_SECP256R1 &&
      own[2] === ROLE_OWNER &&
      bytesEqual(own.subarray(80, 113), c.publicKey);
    const ownRpIdHash = own && own.length >= 145 ? own.subarray(113, 145) : null;

    const otherAuthorities: WalletFacts['otherAuthorities'] = [];
    for (const { pubkey, data } of authorities) {
      if (pubkey === c.authorityPda) continue;
      const role = roleName(data[2]);
      if (data[1] === AUTH_TYPE_ED25519) {
        const publicKey = data.length >= 80 ? addressFromBytes(data.slice(48, 80)) : undefined;
        otherAuthorities.push({
          authorityPda: pubkey,
          type: 'ed25519',
          role,
          publicKey,
          trusted: publicKey !== undefined && trustedKeys.has(publicKey),
        });
      } else {
        // Any type byte but Ed25519 is reported as a passkey: never trusted.
        otherAuthorities.push({
          authorityPda: pubkey,
          type: 'secp256r1',
          role,
          sameRelyingParty:
            ownRpIdHash !== null &&
            data.length >= 145 &&
            bytesEqual(data.subarray(113, 145), ownRpIdHash),
          trusted: false,
        });
      }
    }

    // The program refuses a session or deferred execution only once the slot is
    // past `expires_at`, so one expiring at `slot` still works.
    const liveSessions: WalletFacts['liveSessions'] = [];
    for (const { pubkey, data } of sessions) {
      const readable = data.length >= 80;
      const expiresAtSlot = readable ? readU64(data, 72) : U64_MAX;
      if (expiresAtSlot < slot) continue;
      const sessionKey = readable ? addressFromBytes(data.slice(40, 72)) : ZERO_ADDRESS;
      liveSessions.push({
        sessionPda: pubkey,
        sessionKey,
        expiresAtSlot,
        trusted: readable && trustedKeys.has(sessionKey),
      });
    }

    // No pending deferred execution is trusted, not even one recorded as this
    // passkey's. `ExecuteDeferred` never looks at the authority again, and the
    // PDA recorded is not the key: a passkey authority's address comes from
    // its credential-id hash, so an earlier holder of this PDA — or a passkey
    // registered under a trusted Ed25519 key's bytes — leaves one that reads
    // the same. It lapses within ~9000 slots.
    const pendingDeferred: WalletFacts['pendingDeferred'] = [];
    for (const { pubkey, data } of deferred) {
      const readable = data.length >= 176;
      const expiresAtSlot = readable ? readU64(data, 168) : U64_MAX;
      if (expiresAtSlot < slot) continue;
      const authorizedBy = readable ? addressFromBytes(data.slice(104, 136)) : ZERO_ADDRESS;
      pendingDeferred.push({ deferredPda: pubkey, authorizedBy, expiresAtSlot, trusted: false });
    }

    const tokenGrants = vaultTokenGrants(
      c.vaultPda,
      ownedTokens,
      atas.map((ata, i) => ({ address: ata, mint: mints[i]!, info: ataInfos[i] ?? null })),
      trustedKeys,
    );

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
      // The replay counter (u32 at 8). Only this passkey's key advances the
      // counter of an intact authority; a re-created one's count is another key's.
      signatureCount: ownIntact ? readU32(own, 8) : 0,
    };
  }

  /**
   * Throws unless `owner` is exactly the passkey on this v1 authority — its
   * public key and the relying party it was created under. `migrateV1Wallet`
   * uses `owner` to create or vet the v2 destination, where a wrong rpId would
   * mean a wallet no assertion can ever satisfy.
   */
  private async assertV1PasskeyOwner(authority: Address, owner: CreateWalletOwner): Promise<void> {
    const { secp256r1Pubkey, rpId } = resolveOwnerFields(owner);
    const { value } = await this.rpc.getAccountInfo(authority, { encoding: 'base64' }).send();
    if (!value) throw new Error(`v1 authority ${authority} not found`);
    const data = new Uint8Array(base64Encoder.encode(value.data[0]));
    if (data.length < 145) throw new Error('the v1 authority is not a passkey authority');
    if (!bytesEqual(data.subarray(80, 113), secp256r1Pubkey!)) {
      throw new Error("owner.compressedPubkey is not the v1 authority's public key");
    }
    if (!bytesEqual(data.subarray(113, 145), sha256(new TextEncoder().encode(rpId ?? '')))) {
      throw new Error('owner.rpId is not the relying party the v1 wallet was created under');
    }
  }

  /**
   * Whether `wallet` belongs to `credential` alone — safe to receive a v1
   * migration. `null` means yes; otherwise the reason it is not.
   *
   * Being *an* authority on a wallet proves nothing: anyone can add your key
   * to a wallet they control, then hand themselves the vault through another
   * authority, a session, or a pending deferred execution — none of which the
   * migration's signature covers. So the bar is: exactly one authority, which
   * is this key at Owner rank, no session or deferred execution the program
   * would still accept (expiry at or after the current slot).
   *
   * Nor can the vault carry what an earlier owner left in it. An Owner without
   * a policy can `Execute` System `Assign`/`Allocate` on the vault (the vault
   * signs), or `Approve`/`SetAuthority` on its token accounts, then hand the
   * wallet to the victim's passkey with `TransferOwnership`. So the vault must
   * be a plain system account (or not exist yet), and none of its token
   * accounts may carry a delegate or a close authority other than the vault,
   * nor its canonical account for a watched mint (wSOL, USDC, USDT, devnet
   * USDC, and any in `watchMints`) belong to anyone else — the same token
   * grants {@link LazorKit.describeWalletCandidates} reports, with no key
   * trusted.
   *
   * For a passkey, "this key" means all of it: the credential-id hash, the
   * public key and the relying party. The credential-id hash alone is public —
   * it sits in every authority account the passkey has — and `CreateWallet`
   * takes any owner without its consent, so a wallet with the victim's hash
   * and the attacker's public key would otherwise pass.
   *
   * Reads in the same order as describeWalletCandidates, each step at or
   * after the slot of the one before, so no transaction is half-seen.
   *
   * Fails closed: a session or deferred execution too short to read its expiry
   * counts as live, a token account too short to read as a grant.
   *
   * Passing is not proof the wallet is clean. An earlier holder could have
   * handed an SPL Token account of the vault's, for any mint not watched, to
   * someone else, and nothing on chain leads back to it; senders would still
   * pay into it. Which is why `migrateV1Wallet` reuses a wallet it finds by
   * itself only if it is the one wallet the passkey has signed on.
   *
   * An address that is not a wallet of this program — including one that only
   * holds lamports — fails; `migrateV1Wallet` creates a wallet there instead.
   */
  async vetMigrationDestination(
    wallet: Address,
    owner: CreateWalletOwner,
    options: { watchMints?: (Address | string)[] } = {},
  ): Promise<string | null> {
    return (await this.vetDestination(wallet, owner, watchedMints(options.watchMints))).problem;
  }

  /**
   * vetMigrationDestination, plus the slot the vet's newest read was answered
   * at — reads that must not see older state (the migration's destination
   * token accounts) are made at or after it — and how many times the passkey
   * has signed for the wallet (its authority's replay counter; 0 for an
   * Ed25519 owner, which has none, and whenever there is a problem).
   */
  private async vetDestination(
    wallet: Address,
    owner: CreateWalletOwner,
    mints: ReadonlyArray<Address>,
  ): Promise<{ problem: string | null; slot: bigint; signatureCount: number }> {
    const { authType, credentialOrPubkey: credential, secp256r1Pubkey, rpId } =
      resolveOwnerFields(owner);
    // The slot first: one older than the scans can only count more things live.
    const slot = BigInt(await this.rpc.getSlot().send());
    const [vault] = await this.findVault(wallet);
    const watchedAtas = await watchedAtasOf(vault, mints);
    const read = await this.readSpendingState(
      this.programId,
      wallet,
      vault,
      OWNERSHIP_DISCS[2],
      [wallet, vault, ...watchedAtas],
    );
    const { authorities, sessions, deferred, ownedTokens } = read;
    const [walletInfo, vaultInfo, ...watchedInfos] = read.infos;
    const refuse = (problem: string) => ({ problem, slot: read.slot, signatureCount: 0 });

    if (!isLiveWallet({ programId: this.programId, version: 2 }, walletInfo ?? null)) {
      return refuse(`${wallet} is not a wallet of program ${this.programId}`);
    }
    if (authorities.length !== 1) {
      return refuse(
        `wallet ${wallet} has ${authorities.length} authorities; a migration destination must have only its owner`,
      );
    }
    const a = authorities[0]!.data;
    if (a[1] !== authType || a[2] !== ROLE_OWNER || !bytesEqual(a.subarray(48, 80), credential)) {
      return refuse(`wallet ${wallet} is not owned by this key alone`);
    }
    if (
      authType === AUTH_TYPE_SECP256R1 &&
      (!bytesEqual(a.subarray(80, 113), secp256r1Pubkey!) ||
        !bytesEqual(a.subarray(113, 145), sha256(new TextEncoder().encode(rpId ?? ''))))
    ) {
      return refuse(
        `wallet ${wallet} lists this passkey's credential with another public key or relying party`,
      );
    }
    // The program refuses a session or deferred execution only once the slot
    // is past `expires_at`, so one expiring at `slot` still works.
    if (sessions.some((x) => expiryAt(x.data, 72) >= slot)) {
      return refuse(`wallet ${wallet} has a live session`);
    }
    if (deferred.some((x) => expiryAt(x.data, 168) >= slot)) {
      return refuse(`wallet ${wallet} has a pending deferred execution`);
    }
    if (!isSystemAccount(vaultInfo ?? null)) {
      return refuse(
        vaultInfo!.owner === SYSTEM_PROGRAM_ADDRESS
          ? `wallet ${wallet}'s vault ${vault} carries data, so it is no longer a plain system account`
          : `wallet ${wallet}'s vault ${vault} is owned by program ${vaultInfo!.owner}, not the System Program`,
      );
    }
    const [grant] = vaultTokenGrants(
      vault,
      ownedTokens,
      watchedAtas.map((ata, i) => ({
        address: ata,
        mint: mints[i]!,
        info: watchedInfos[i] ?? null,
      })),
      new Set(),
    );
    if (grant) {
      return refuse(`wallet ${wallet}'s vault token account ${grant.tokenAccount} ${grantPhrase(grant)}`);
    }
    // Only the key this authority stores advances its counter (Ed25519 never
    // does); the checks above made that key this passkey.
    return {
      problem: null,
      slot: read.slot,
      signatureCount: authType === AUTH_TYPE_SECP256R1 ? readU32(a, 8) : 0,
    };
  }

  /**
   * Every authority on this program that stores `owner`'s whole passkey — its
   * credential-id hash, public key and relying party — and that has taken a
   * signature (replay counter above 0), on any wallet, at any rank. Only this
   * passkey's signatures, first made or replayed, advance such a counter.
   */
  private async signedPasskeyAuthorities(
    owner: CreateWalletOwner,
  ): Promise<{ walletPda: Address; authorityPda: Address; role: number }[]> {
    const { credentialOrPubkey: credential, secp256r1Pubkey, rpId } = resolveOwnerFields(owner);
    const rpIdHash = sha256(new TextEncoder().encode(rpId ?? ''));
    const accounts = await this.rpc
      .getProgramAccounts(this.programId, {
        encoding: 'base64',
        filters: [
          memcmpFilter(0n, new Uint8Array([ACCOUNT_DISCRIMINATOR.AUTHORITY, AUTH_TYPE_SECP256R1])),
          memcmpFilter(48n, credential),
          memcmpFilter(113n, rpIdHash),
        ],
      })
      .send();
    const out: { walletPda: Address; authorityPda: Address; role: number }[] = [];
    for (let i = 0; i < accounts.length; i++) {
      const { pubkey, account } = accounts[i]!;
      const data = new Uint8Array(base64Encoder.encode(account.data[0]));
      if (
        data.length < 145 ||
        !bytesEqual(data.subarray(80, 113), secp256r1Pubkey!) ||
        !bytesEqual(data.subarray(113, 145), rpIdHash) ||
        readU32(data, 8) === 0
      ) {
        continue;
      }
      out.push({ walletPda: addressFromBytes(data.slice(16, 48)), authorityPda: pubkey, role: data[2]! });
    }
    return out;
  }

  // ─── CreateWallet ────────────────────────────────────────────────

  async createWallet(params: {
    payer: Address;
    userSeed: Uint8Array;
    owner: CreateWalletOwner;
  }): Promise<{
    instructions: Instruction[];
    walletPda: Address;
    vaultPda: Address;
    authorityPda: Address;
  }> {
    assertByteLength(params.userSeed, 32, 'userSeed');
    const [walletPda] = await this.findWallet(params.userSeed);
    const [vaultPda] = await this.findVault(walletPda);
    const { authType, credentialOrPubkey, secp256r1Pubkey, rpId } = resolveOwnerFields(params.owner);
    const [authorityPda, authBump] = await this.findAuthority(walletPda, credentialOrPubkey);
    const fee = await this.resolveProtocolFeeWithRegister(params.payer);

    const ix = createCreateWalletIx({
      payer: params.payer,
      walletPda,
      vaultPda,
      authorityPda,
      userSeed: params.userSeed,
      authType,
      authBump,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
      protocolFee: fee?.accounts,
      programId: this.programId,
    });
    const instructions = fee?.registerIx ? [fee.registerIx, ix] : [ix];
    return { instructions, walletPda, vaultPda, authorityPda };
  }

  // ─── AddAuthority (unified) ──────────────────────────────────────

  async addAuthority(params: {
    payer: Address;
    walletPda: Address;
    adminSigner: AdminSigner;
    newAuthority: CreateWalletOwner;
    role: number;
    /** Action buffer bounding what this authority may spend. Required for
     *  ROLE_DELEGATE, and rejected for any other rank — only a Delegate may
     *  carry one, so a policy always means a bounded spender. An asset the
     *  policy does not name cannot leave the vault: with no `Sol*` action no
     *  SOL can (rent the vault pays included), and each mint needs a `Token*`
     *  action. */
    policy?: Uint8Array;
    /** Opt in to creating another Owner. An Owner can manage and revoke every
     *  authority on the wallet, this one included, so it is never the default. */
    allowOwner?: boolean;
  }): Promise<{ instructions: Instruction[]; newAuthorityPda: Address }> {
    assertAddAuthorityRole(params.role, params.allowOwner, params.policy);
    const { authType: newType, credentialOrPubkey, secp256r1Pubkey, rpId } = resolveOwnerFields(
      params.newAuthority,
    );
    const [newAuthorityPda] = await this.findAuthority(params.walletPda, credentialOrPubkey);
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const adminAuthorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
      const ix = createAddAuthorityIx({
      policy: params.policy,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda,
        newAuthorityPda,
        newType,
        newRole: params.role,
        credentialOrPubkey,
        secp256r1Pubkey,
        rpId,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix], newAuthorityPda };
    }

    // `policy` and `allowOwner` must be forwarded: dropping `policy` writes an
    // authority with an empty action buffer, which for an Admin is an unbounded
    // authority the caller believed was capped, and dropping `allowOwner` makes
    // enrolling a second Owner — the only recovery path a passkey user has —
    // impossible.
    const prepared = await this.prepareAddAuthority({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      newAuthority: params.newAuthority,
      role: params.role,
      policy: params.policy,
      allowOwner: params.allowOwner,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeAddAuthority(prepared, response);
  }

  async prepareAddAuthority(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    newAuthority: CreateWalletOwner;
    role: number;
    /** Action buffer bounding what this authority may spend. Required for
     *  ROLE_DELEGATE, and rejected for any other rank — only a Delegate may
     *  carry one, so a policy always means a bounded spender. An asset the
     *  policy does not name cannot leave the vault: with no `Sol*` action no
     *  SOL can (rent the vault pays included), and each mint needs a `Token*`
     *  action. */
    policy?: Uint8Array;
    /** Opt in to creating another Owner. An Owner can manage and revoke every
     *  authority on the wallet, this one included, so it is never the default. */
    allowOwner?: boolean;
  }): Promise<PreparedAddAuthority> {
    assertAddAuthorityRole(params.role, params.allowOwner, params.policy);
    const { authType: newType, credentialOrPubkey, secp256r1Pubkey, rpId } = resolveOwnerFields(
      params.newAuthority,
    );
    const [newAuthorityPda] = await this.findAuthority(params.walletPda, credentialOrPubkey);
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const dataPayload = buildDataPayloadForAdd(
      newType,
      params.role,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
      params.policy,
    );
    const signedPayload = concatBytes([
      dataPayload,
      addressEncoder.encode(params.payer) as Uint8Array,
    ]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_ADD_AUTHORITY,
      sysvarIxIndex: SYSVAR_IX_INDEX_ADD_AUTHORITY,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      newAuthorityPda,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: authorityPda,
        newAuthorityPda,
        newType,
        newRole: params.role,
        policy: params.policy,
        credentialOrPubkey,
        secp256r1Pubkey,
        rpId,
        programId: this.programId,
      },
    };
  }

  finalizeAddAuthority(
    prepared: PreparedAddAuthority,
    response: WebAuthnResponse,
  ): { instructions: Instruction[]; newAuthorityPda: Address } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createAddAuthorityIx({
      policy: i.policy,
      payer: i.payer,
      walletPda: i.walletPda,
      adminAuthorityPda: i.adminAuthorityPda,
      newAuthorityPda: i.newAuthorityPda,
      newType: i.newType,
      newRole: i.newRole,
      credentialOrPubkey: i.credentialOrPubkey,
      secp256r1Pubkey: i.secp256r1Pubkey,
      rpId: i.rpId,
      authPayload,
      programId: i.programId,
    });
    return { instructions: [precompileIx, ix], newAuthorityPda: i.newAuthorityPda };
  }

  // ─── RemoveAuthority (unified) ───────────────────────────────────

  async removeAuthority(params: {
    payer: Address;
    walletPda: Address;
    adminSigner: AdminSigner;
    targetAuthorityPda: Address;
    refundDestination?: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const adminAuthorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
      const ix = createRemoveAuthorityIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda,
        targetAuthorityPda: params.targetAuthorityPda,
        refundDestination: refundDest,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix] };
    }

    const prepared = await this.prepareRemoveAuthority({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      targetAuthorityPda: params.targetAuthorityPda,
      refundDestination: params.refundDestination,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeRemoveAuthority(prepared, response);
  }

  async prepareRemoveAuthority(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    targetAuthorityPda: Address;
    refundDestination?: Address;
  }): Promise<PreparedRemoveAuthority> {
    const refundDest = params.refundDestination ?? params.payer;
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const signedPayload = concatBytes([
      addressEncoder.encode(params.targetAuthorityPda) as Uint8Array,
      addressEncoder.encode(refundDest) as Uint8Array,
    ]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_REMOVE_AUTHORITY,
      sysvarIxIndex: SYSVAR_IX_INDEX_REMOVE_AUTHORITY,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: authorityPda,
        targetAuthorityPda: params.targetAuthorityPda,
        refundDestination: refundDest,
        programId: this.programId,
      },
    };
  }

  finalizeRemoveAuthority(
    prepared: PreparedRemoveAuthority,
    response: WebAuthnResponse,
  ): { instructions: Instruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createRemoveAuthorityIx({
      payer: i.payer,
      walletPda: i.walletPda,
      adminAuthorityPda: i.adminAuthorityPda,
      targetAuthorityPda: i.targetAuthorityPda,
      refundDestination: i.refundDestination,
      authPayload,
      programId: i.programId,
    });
    return { instructions: [precompileIx, ix] };
  }

  // ─── TransferOwnership (unified) ─────────────────────────────────

  async transferOwnership(params: {
    payer: Address;
    walletPda: Address;
    ownerSigner: AdminSigner;
    newOwner: CreateWalletOwner;
    refundDestination?: Address;
  }): Promise<{ instructions: Instruction[]; newOwnerAuthorityPda: Address }> {
    const { authType: newType, credentialOrPubkey, secp256r1Pubkey, rpId } = resolveOwnerFields(
      params.newOwner,
    );
    const [newOwnerAuthorityPda] = await this.findAuthority(params.walletPda, credentialOrPubkey);
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.ownerSigner;

    if (s.type === 'ed25519') {
      const currentOwnerAuthorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
      const ix = createTransferOwnershipIx({
        payer: params.payer,
        walletPda: params.walletPda,
        currentOwnerAuthorityPda,
        newOwnerAuthorityPda,
        refundDestination: refundDest,
        newType,
        credentialOrPubkey,
        secp256r1Pubkey,
        rpId,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix], newOwnerAuthorityPda };
    }

    const prepared = await this.prepareTransferOwnership({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      newOwner: params.newOwner,
      refundDestination: params.refundDestination,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeTransferOwnership(prepared, response);
  }

  async prepareTransferOwnership(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    newOwner: CreateWalletOwner;
    refundDestination?: Address;
  }): Promise<PreparedTransferOwnership> {
    const { authType: newType, credentialOrPubkey, secp256r1Pubkey, rpId } = resolveOwnerFields(
      params.newOwner,
    );
    const [newOwnerAuthorityPda] = await this.findAuthority(params.walletPda, credentialOrPubkey);
    const refundDest = params.refundDestination ?? params.payer;
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const dataPayload = buildDataPayloadForTransfer(
      newType,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
    );
    const signedPayload = concatBytes([
      dataPayload,
      addressEncoder.encode(params.payer) as Uint8Array,
      addressEncoder.encode(refundDest) as Uint8Array,
    ]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_TRANSFER_OWNERSHIP,
      sysvarIxIndex: SYSVAR_IX_INDEX_TRANSFER_OWNERSHIP,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      newOwnerAuthorityPda,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        currentOwnerAuthorityPda: authorityPda,
        newOwnerAuthorityPda,
        refundDestination: refundDest,
        newType,
        credentialOrPubkey,
        secp256r1Pubkey,
        rpId,
        programId: this.programId,
      },
    };
  }

  finalizeTransferOwnership(
    prepared: PreparedTransferOwnership,
    response: WebAuthnResponse,
  ): { instructions: Instruction[]; newOwnerAuthorityPda: Address } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createTransferOwnershipIx({
      payer: i.payer,
      walletPda: i.walletPda,
      currentOwnerAuthorityPda: i.currentOwnerAuthorityPda,
      newOwnerAuthorityPda: i.newOwnerAuthorityPda,
      refundDestination: i.refundDestination,
      newType: i.newType,
      credentialOrPubkey: i.credentialOrPubkey,
      secp256r1Pubkey: i.secp256r1Pubkey,
      rpId: i.rpId,
      authPayload,
      programId: i.programId,
    });
    return {
      instructions: [precompileIx, ix],
      newOwnerAuthorityPda: i.newOwnerAuthorityPda,
    };
  }

  // ─── CreateSession (unified) ─────────────────────────────────────

  async createSession(params: {
    payer: Address;
    walletPda: Address;
    adminSigner: AdminSigner;
    sessionKey: Address;
    expiresAt: bigint;
    /** Actions bounding what this session may spend. An asset they do not
     *  name cannot leave the vault: with no `Sol*` action no SOL can (rent the
     *  vault pays included), and each mint needs a `Token*` action. Omitting
     *  them creates an UNRESTRICTED session and requires `unrestricted: true`. */
    actions?: SessionAction[];
    /** Opt in to a session with no actions — see `actions`. */
    unrestricted?: boolean;
  }): Promise<{ instructions: Instruction[]; sessionPda: Address }> {
    assertSessionActions(params.actions, params.unrestricted);
    const sessionKeyBytes = addressEncoder.encode(params.sessionKey) as Uint8Array;
    const [sessionPda] = await this.findSession(params.walletPda, sessionKeyBytes);
    const s = params.adminSigner;
    const actionsBuffer =
      params.actions && params.actions.length > 0 ? serializeActions(params.actions) : undefined;

    if (s.type === 'ed25519') {
      const adminAuthorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
      const ix = createCreateSessionIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda,
        sessionPda,
        sessionKey: sessionKeyBytes,
        expiresAt: params.expiresAt,
        actionsBuffer,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix], sessionPda };
    }

    const prepared = await this.prepareCreateSession({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      sessionKey: params.sessionKey,
      expiresAt: params.expiresAt,
      actions: params.actions,
      unrestricted: params.unrestricted,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeCreateSession(prepared, response);
  }

  async prepareCreateSession(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    sessionKey: Address;
    expiresAt: bigint;
    /** Actions bounding what this session may spend. An asset they do not
     *  name cannot leave the vault: with no `Sol*` action no SOL can (rent the
     *  vault pays included), and each mint needs a `Token*` action. Omitting
     *  them creates an UNRESTRICTED session and requires `unrestricted: true`. */
    actions?: SessionAction[];
    /** Opt in to a session with no actions — see `actions`. */
    unrestricted?: boolean;
  }): Promise<PreparedCreateSession> {
    assertSessionActions(params.actions, params.unrestricted);
    const sessionKeyBytes = addressEncoder.encode(params.sessionKey) as Uint8Array;
    const [sessionPda] = await this.findSession(params.walletPda, sessionKeyBytes);
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );
    const actionsBuffer =
      params.actions && params.actions.length > 0 ? serializeActions(params.actions) : undefined;

    const dataPayload = buildDataPayloadForSession(
      sessionKeyBytes,
      params.expiresAt,
      actionsBuffer,
    );
    const signedPayload = concatBytes([
      dataPayload,
      addressEncoder.encode(params.payer) as Uint8Array,
    ]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_CREATE_SESSION,
      sysvarIxIndex: SYSVAR_IX_INDEX_CREATE_SESSION,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      sessionPda,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: authorityPda,
        sessionPda,
        sessionKey: sessionKeyBytes,
        expiresAt: params.expiresAt,
        actionsBuffer,
        programId: this.programId,
      },
    };
  }

  finalizeCreateSession(
    prepared: PreparedCreateSession,
    response: WebAuthnResponse,
  ): { instructions: Instruction[]; sessionPda: Address } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createCreateSessionIx({
      payer: i.payer,
      walletPda: i.walletPda,
      adminAuthorityPda: i.adminAuthorityPda,
      sessionPda: i.sessionPda,
      sessionKey: i.sessionKey,
      expiresAt: i.expiresAt,
      actionsBuffer: i.actionsBuffer,
      authPayload,
      programId: i.programId,
    });
    return { instructions: [precompileIx, ix], sessionPda: i.sessionPda };
  }

  // ─── RevokeSession (unified) ─────────────────────────────────────

  async revokeSession(params: {
    payer: Address;
    walletPda: Address;
    adminSigner: AdminSigner;
    sessionPda: Address;
    refundDestination?: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const adminAuthorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
      const ix = createRevokeSessionIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda,
        sessionPda: params.sessionPda,
        refundDestination: refundDest,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix] };
    }

    const prepared = await this.prepareRevokeSession({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      sessionPda: params.sessionPda,
      refundDestination: params.refundDestination,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeRevokeSession(prepared, response);
  }

  async prepareRevokeSession(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    sessionPda: Address;
    refundDestination?: Address;
  }): Promise<PreparedRevokeSession> {
    const refundDest = params.refundDestination ?? params.payer;
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const signedPayload = concatBytes([
      addressEncoder.encode(params.sessionPda) as Uint8Array,
      addressEncoder.encode(refundDest) as Uint8Array,
    ]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_REVOKE_SESSION,
      sysvarIxIndex: SYSVAR_IX_INDEX_REVOKE_SESSION,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: authorityPda,
        sessionPda: params.sessionPda,
        refundDestination: refundDest,
        programId: this.programId,
      },
    };
  }

  finalizeRevokeSession(
    prepared: PreparedRevokeSession,
    response: WebAuthnResponse,
  ): { instructions: Instruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createRevokeSessionIx({
      payer: i.payer,
      walletPda: i.walletPda,
      adminAuthorityPda: i.adminAuthorityPda,
      sessionPda: i.sessionPda,
      refundDestination: i.refundDestination,
      authPayload,
      programId: i.programId,
    });
    return { instructions: [precompileIx, ix] };
  }

  // ─── Execute (unified) ───────────────────────────────────────────

  async execute(params: {
    payer: Address;
    walletPda: Address;
    signer: ExecuteSigner;
    instructions: Instruction[];
    /** Passkey signers: the fee payer, when it is not `payer` (see `prepareExecute`). */
    feePayer?: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const [vaultPda] = await this.findVault(params.walletPda);
    const s = params.signer;
    const fee = await this.resolveProtocolFeeWithRegister(params.payer);
    const protocolFee = fee?.accounts;
    const head: Instruction[] = fee?.registerIx ? [fee.registerIx] : [];

    switch (s.type) {
      case 'ed25519': {
        const authorityPda = await this.resolveEd25519AuthorityPda(s, params.walletPda);
        const fixedAccounts: Address[] = [
          params.payer,
          params.walletPda,
          authorityPda,
          vaultPda,
          s.publicKey,
        ];
        const { compactInstructions, remainingAccounts } = buildCompactLayout(
          fixedAccounts,
          params.instructions,
          params.payer,
        );
        const packed = packCompactInstructions(compactInstructions);
        const ix = createExecuteIx({
          payer: params.payer,
          walletPda: params.walletPda,
          authorityPda,
          vaultPda,
          packedInstructions: packed,
          authorizerSigner: s.publicKey,
          remainingAccounts,
          protocolFee,
          programId: this.programId,
        });
        return { instructions: [...head, ix] };
      }

      case 'secp256r1': {
        const prepared = await this.prepareExecute({
          payer: params.payer,
          walletPda: params.walletPda,
          secp256r1: this.extractSecp256r1Params(s),
          instructions: params.instructions,
          feePayer: params.feePayer,
        });
        const response = await s.signer.sign(prepared.challenge);
        return this.finalizeExecute(prepared, response);
      }

      case 'session': {
        const fixedAccounts: Address[] = [
          params.payer,
          params.walletPda,
          s.sessionPda,
          vaultPda,
          s.sessionKeyPubkey,
        ];
        const { compactInstructions, remainingAccounts } = buildCompactLayout(
          fixedAccounts,
          params.instructions,
          params.payer,
        );
        const packed = packCompactInstructions(compactInstructions);
        const sessionKeyMeta: AccountMeta = {
          address: s.sessionKeyPubkey,
          role: AccountRole.READONLY_SIGNER,
        };
        const allRemaining: AccountMeta[] = [sessionKeyMeta, ...remainingAccounts];
        const ix = createExecuteIx({
          payer: params.payer,
          walletPda: params.walletPda,
          authorityPda: s.sessionPda,
          vaultPda,
          packedInstructions: packed,
          remainingAccounts: allRemaining,
          protocolFee,
          programId: this.programId,
        });
        return { instructions: [...head, ix] };
      }
    }
  }

  async prepareExecute(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    instructions: Instruction[];
    /** The transaction's fee payer, when it is not `payer`. The runtime
     *  reports it a writable signer wherever it appears, so an inner
     *  instruction that names it (repaying a sponsor) is hashed that way. */
    feePayer?: Address;
  }): Promise<PreparedExecute> {
    const [vaultPda] = await this.findVault(params.walletPda);
    // The challenge reads and the protocol-fee read, in parallel and in one
    // read group: if the fee read fails, the call rejects with its error, and
    // the challenge reads must not go on polling -32016 for the floor after
    // that (nor start: the authority's address is derived first).
    const reads = new ChallengeReadGroup();
    const [resolved, fee] = await Promise.all([
      this.resolveSecp256r1(params.walletPda, params.secp256r1, reads),
      reads.run(this.resolveProtocolFeeWithRegister(params.payer)),
    ]);
    const { authorityPda, publicKeyBytes, slot, counter } = resolved;
    const protocolFee = fee?.accounts;
    const registerIx = fee?.registerIx;

    const SYSVAR_INSTRUCTIONS_ADDRESS = (await import('./instructions/system.js')).SYSVAR_INSTRUCTIONS_ADDRESS;
    // As createExecuteIx declares them. The payer is a writable signer there
    // because the runtime reports it as one anyway when it pays the fee, and
    // the accounts hash is over what the runtime reports: an inner
    // instruction that names the payer (repaying a paymaster) is hashed with
    // those flags on chain.
    const fixedAccounts: AccountMeta[] = [
      { address: params.payer, role: AccountRole.WRITABLE_SIGNER },
      { address: params.walletPda, role: AccountRole.READONLY },
      { address: authorityPda, role: AccountRole.WRITABLE },
      { address: vaultPda, role: AccountRole.WRITABLE },
      { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    ];
    const { compactInstructions, remainingAccounts, accountsHash } =
      this.buildCompactLayoutAndHash(
        fixedAccounts,
        params.instructions,
        params.payer,
        params.feePayer,
      );
    const packed = packCompactInstructions(compactInstructions);
    const signedPayload = concatBytes([packed, accountsHash]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_EXECUTE,
      sysvarIxIndex: SYSVAR_IX_INDEX_EXECUTE,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      _internal: {
        signing,
        payer: params.payer,
        walletPda: params.walletPda,
        authorityPda,
        vaultPda,
        packed,
        remainingAccounts,
        protocolFee,
        registerIx,
        programId: this.programId,
      },
    };
  }

  finalizeExecute(prepared: PreparedExecute, response: WebAuthnResponse): { instructions: Instruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const ix = createExecuteIx({
      payer: i.payer,
      walletPda: i.walletPda,
      authorityPda: i.authorityPda,
      vaultPda: i.vaultPda,
      packedInstructions: i.packed,
      authPayload,
      remainingAccounts: i.remainingAccounts,
      protocolFee: i.protocolFee,
      programId: i.programId,
    });
    const head = i.registerIx ? [i.registerIx, precompileIx] : [precompileIx];
    return { instructions: [...head, ix] };
  }

  // ─── Authorize / ExecuteDeferred / Reclaim ───────────────────────

  async authorize(params: {
    payer: Address;
    walletPda: Address;
    signer: Secp256r1SignerConfig;
    instructions: Instruction[];
    expiryOffset?: number;
    /** Who will send TX2, when not `payer` (see `prepareAuthorize`). */
    executor?: Address;
    /** TX2's fee payer, when not the executor (see `prepareAuthorize`). */
    feePayer?: Address;
  }): Promise<{
    instructions: Instruction[];
    deferredExecPda: Address;
    counter: number;
    deferredPayload: DeferredPayload;
  }> {
    const s = params.signer;
    const prepared = await this.prepareAuthorize({
      payer: params.payer,
      walletPda: params.walletPda,
      secp256r1: this.extractSecp256r1Params(s),
      instructions: params.instructions,
      expiryOffset: params.expiryOffset,
      executor: params.executor,
      feePayer: params.feePayer,
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeAuthorize(prepared, response);
  }

  /**
   * Tx1 of the deferred flow: the passkey approves `instructions` for a later
   * `ExecuteDeferred`, and `finalizeAuthorize` returns what tx2 needs.
   *
   * The accounts hash it signs is over tx2's accounts with the flags the
   * program will read there, and two of them depend on who sends tx2: its
   * payer (index 0) and its refund destination (index 4), which is always this
   * `payer` — the program returns the rent to no one else. Pass `executor` when
   * another key will send tx2 (a relayer); it defaults to `payer`. An inner
   * instruction that names either key is then hashed as the program will see
   * it: the executor as a writable signer, this payer as a signer as well only
   * when it is the executor. The payload records both, and
   * `executeDeferredFromPayload` refuses a different payer when an inner
   * instruction names either slot, rather than build a tx2 that fails with
   * `DeferredHashMismatch` (3015).
   */
  async prepareAuthorize(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    instructions: Instruction[];
    expiryOffset?: number;
    /** Who will send tx2 (ExecuteDeferred's payer). Defaults to `payer`. */
    executor?: Address;
    /** Tx2's fee payer, when it is not the executor (see `prepareExecute`). */
    feePayer?: Address;
  }): Promise<PreparedAuthorize> {
    const [vaultPda] = await this.findVault(params.walletPda);
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );
    const expiryOffset = params.expiryOffset ?? 300;
    const [deferredExecPda] = await this.findDeferredExec(
      params.walletPda,
      authorityPda,
      counter,
    );

    // TX2's (ExecuteDeferred's) layout, which is what the program hashes when
    // it replays, with the roles createExecuteDeferredIx gives them: the
    // executor as tx2's payer, this payer as the refund destination (see above).
    const executor = params.executor ?? params.payer;
    const fixedAccounts: AccountMeta[] = [
      { address: executor, role: AccountRole.WRITABLE_SIGNER },
      { address: params.walletPda, role: AccountRole.READONLY },
      { address: vaultPda, role: AccountRole.WRITABLE },
      { address: deferredExecPda, role: AccountRole.WRITABLE },
      { address: params.payer, role: AccountRole.WRITABLE },
    ];
    const { compactInstructions, remainingAccounts, accountsHash } =
      this.buildCompactLayoutAndHash(
        fixedAccounts,
        params.instructions,
        executor,
        params.feePayer,
      );
    const instructionsHash = computeInstructionsHash(compactInstructions);
    const expiryOffsetBuf = new Uint8Array(2);
    expiryOffsetBuf[0] = expiryOffset & 0xff;
    expiryOffsetBuf[1] = (expiryOffset >> 8) & 0xff;
    const signedPayload = concatBytes([instructionsHash, accountsHash, expiryOffsetBuf]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_AUTHORIZE,
      sysvarIxIndex: SYSVAR_IX_INDEX_AUTHORIZE,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      wallet: params.walletPda,
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      deferredExecPda,
      counter,
      _internal: {
        signing,
        payer: params.payer,
        executor,
        walletPda: params.walletPda,
        authorityPda,
        deferredExecPda,
        instructionsHash,
        accountsHash,
        expiryOffset,
        compactInstructions,
        remainingAccounts,
        programId: this.programId,
      },
    };
  }

  finalizeAuthorize(
    prepared: PreparedAuthorize,
    response: WebAuthnResponse,
  ): {
    instructions: Instruction[];
    deferredExecPda: Address;
    counter: number;
    deferredPayload: DeferredPayload;
  } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(i.signing, response);
    const authorizeIx = createAuthorizeIx({
      payer: i.payer,
      walletPda: i.walletPda,
      authorityPda: i.authorityPda,
      deferredExecPda: i.deferredExecPda,
      instructionsHash: i.instructionsHash,
      accountsHash: i.accountsHash,
      expiryOffset: i.expiryOffset,
      authPayload,
      programId: i.programId,
    });
    return {
      instructions: [precompileIx, authorizeIx],
      deferredExecPda: i.deferredExecPda,
      counter: prepared.counter,
      deferredPayload: {
        walletPda: i.walletPda,
        deferredExecPda: i.deferredExecPda,
        compactInstructions: i.compactInstructions,
        remainingAccounts: i.remainingAccounts,
        executor: i.executor,
        refundDestination: i.payer,
      },
    };
  }

  /**
   * Build TX2 from the payload returned by `authorize()`.
   *
   * The refund destination defaults to the Authorize payer the payload
   * records, the only one the program accepts (older payloads: `payer`). A
   * payload authorized for another executor is refused when an inner
   * instruction names tx2's payer or refund slot: the accounts hash fixed who
   * sends it, and the program would fail it with `DeferredHashMismatch` (3015).
   */
  async executeDeferredFromPayload(params: {
    payer: Address;
    deferredPayload: DeferredPayload;
    refundDestination?: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const { executor } = params.deferredPayload;
    if (
      executor &&
      executor !== params.payer &&
      namesDeferredPayerSlot(params.deferredPayload.compactInstructions)
    ) {
      throw new Error(
        `This authorization was signed for ${executor} to send ExecuteDeferred, and an ` +
          `inner instruction names tx2's payer or refund destination, whose flags depend ` +
          `on who sends it. Sent by ${params.payer} it would fail with ` +
          `DeferredHashMismatch (3015). Send it from ${executor}, or authorize again ` +
          `with executor: ${params.payer}.`,
      );
    }
    const [vaultPda] = await this.findVault(params.deferredPayload.walletPda);
    const refundDest =
      params.refundDestination ?? params.deferredPayload.refundDestination ?? params.payer;
    const packed = packCompactInstructions(params.deferredPayload.compactInstructions);
    const fee = await this.resolveProtocolFeeWithRegister(params.payer);
    const ix = createExecuteDeferredIx({
      payer: params.payer,
      walletPda: params.deferredPayload.walletPda,
      vaultPda,
      deferredExecPda: params.deferredPayload.deferredExecPda,
      refundDestination: refundDest,
      packedInstructions: packed,
      remainingAccounts: params.deferredPayload.remainingAccounts,
      protocolFee: fee?.accounts,
      programId: this.programId,
    });
    return { instructions: fee?.registerIx ? [fee.registerIx, ix] : [ix] };
  }

  reclaimDeferred(params: {
    payer: Address;
    deferredExecPda: Address;
    refundDestination?: Address;
  }): { instructions: Instruction[] } {
    const ix = createReclaimDeferredIx({
      payer: params.payer,
      deferredExecPda: params.deferredExecPda,
      refundDestination: params.refundDestination ?? params.payer,
      programId: this.programId,
    });
    return { instructions: [ix] };
  }

  // ─── Protocol fee management (admin-only on commercial binary) ───

  async initializeProtocol(params: {
    payer: Address;
    admin: Address;
    treasury: Address;
    creationFee: bigint;
    executionFee: bigint;
    numShards: number;
  }): Promise<{ instructions: Instruction[]; protocolConfigPda: Address }> {
    const [protocolConfigPda] = await this.findProtocolConfig();
    const ix = createInitializeProtocolIx({
      payer: params.payer,
      protocolConfigPda,
      admin: params.admin,
      treasury: params.treasury,
      creationFee: params.creationFee,
      executionFee: params.executionFee,
      numShards: params.numShards,
      programId: this.programId,
    });
    return { instructions: [ix], protocolConfigPda };
  }

  async updateProtocol(params: {
    admin: Address;
    creationFee: bigint;
    executionFee: bigint;
    enabled: boolean;
    newTreasury: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const [protocolConfigPda] = await this.findProtocolConfig();
    const ix = createUpdateProtocolIx({
      admin: params.admin,
      protocolConfigPda,
      creationFee: params.creationFee,
      executionFee: params.executionFee,
      enabled: params.enabled,
      newTreasury: params.newTreasury,
      programId: this.programId,
    });
    return { instructions: [ix] };
  }

  async initializeTreasuryShard(params: {
    payer: Address;
    admin: Address;
    shardId: number;
  }): Promise<{ instructions: Instruction[]; treasuryShardPda: Address }> {
    const [protocolConfigPda] = await this.findProtocolConfig();
    const [treasuryShardPda] = await this.findTreasuryShard(params.shardId);
    const ix = createInitializeTreasuryShardIx({
      payer: params.payer,
      protocolConfigPda,
      admin: params.admin,
      treasuryShardPda,
      shardId: params.shardId,
      programId: this.programId,
    });
    return { instructions: [ix], treasuryShardPda };
  }

  async registerPayer(params: {
    payer: Address;
  }): Promise<{ instructions: Instruction[]; feeRecordPda: Address }> {
    const [feeRecordPda] = await this.findFeeRecord(params.payer);
    const ix = createRegisterPayerIx({
      payer: params.payer,
      feeRecordPda,
      programId: this.programId,
    });
    return { instructions: [ix], feeRecordPda };
  }

  async withdrawTreasury(params: {
    admin: Address;
    shardId: number;
    treasury: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const [protocolConfigPda] = await this.findProtocolConfig();
    const [treasuryShardPda] = await this.findTreasuryShard(params.shardId);
    const ix = createWithdrawTreasuryIx({
      admin: params.admin,
      protocolConfigPda,
      treasuryShardPda,
      treasury: params.treasury,
      programId: this.programId,
    });
    return { instructions: [ix] };
  }

  // ─── v1 → v2 migration ───────────────────────────────────────────

  /**
   * Find this owner's v1 wallets from their key material alone.
   *
   * The v1 `userSeed` was random and lived in browser storage, so most
   * returning users cannot derive their own wallet any more; the chain can,
   * because the v1 authority account stores both the key and the wallet.
   *
   * The `ownerPubkey` on each record is what a returning passkey user needs
   * and cannot produce: signing in yields a WebAuthn assertion, and an
   * assertion carries no public key.
   *
   * A raw lookup: v1's `CreateWallet` took any owner without its consent, so a
   * record can list this credential next to someone else's key. To pick a
   * returning passkey user's v1 wallet use {@link LazorKit.findOwnPasskeyWallet}
   * (`version: 1`).
   */
  async findV1WalletsByOwner(
    credential: Uint8Array,
    authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
    /** Where the v1 wallets live. Defaults to the v1 deployment paired with this client's program. */
    v1ProgramId: Address = legacyProgramIdFor(this.programId),
  ): Promise<V1WalletRecord[]> {
    return findV1WalletsByOwner(this.rpc, credential, v1ProgramId, authorityType);
  }

  /**
   * Move a v1 wallet's SOL and tokens into a v2 wallet owned by the same key,
   * and close the v1 accounts.
   *
   * Pass `v1Wallet` (from {@link findV1WalletsByOwner}) for the common case of
   * a user whose seed is gone; `userSeed` only when the app still holds it.
   *
   * The returned `setupInstructions` create whatever the destination needs —
   * the v2 wallet, and an ATA per token — and must land before `migrate` in
   * the same transaction or an earlier one. `migrate` is a single instruction
   * for an Ed25519 owner, or a challenge to sign plus a `finalize` that turns
   * the WebAuthn response into `[precompile, migrate]`. Sent separately,
   * `migrate` goes only after the setup transaction *succeeded*: what the
   * owner signs names the destination vault, not who owns its wallet, so if
   * someone else's `CreateWallet` at that seed lands first, the setup fails
   * and a `migrate` sent anyway pays into their vault. One transaction makes
   * the two succeed or fail together.
   *
   * The v2 destination: with `userSeed` it is that seed's wallet; otherwise an
   * existing v2 wallet is reused only if this owner is a passkey that has
   * already signed for it — and on no other authority of this program, at any
   * rank — and if there is none a fresh one is created from
   * `destinationUserSeed` or a random seed. An Ed25519 owner's wallets are
   * never reused this way (its authority records no signatures); name one
   * with `destinationUserSeed`.
   *
   * Why not any wallet that lists this owner: `TransferOwnership` hands one
   * over without asking, and the vetting cannot see everything its earlier
   * holder left behind — an SPL Token account of the vault's, for a mint not
   * watched (see `watchMints`), handed to someone else, into which later
   * deposits of that mint would go. A wallet the passkey signed for is one its
   * user chose — unless the signature was replayed there from another wallet,
   * which the passkey challenge did not name until the program bound it (see
   * {@link pickOwnWallet}); so when the passkey has signed on two
   * authorities, neither wallet is reused. A `userSeed` wallet is vetted but
   * cannot be held to that bar
   * (the one this call creates has no signature on it either, until used);
   * because the seed is public, pass `v1Wallet` without `userSeed` (a fresh
   * destination) when a v2 wallet already exists at the userSeed and this app
   * did not create it.
   *
   * A reused wallet has passed {@link LazorKit.vetMigrationDestination}
   * already. For a `userSeed` or `destinationUserSeed` one, whether it exists
   * is decided from one read of its wallet account. Missing, or holding only
   * lamports (anyone can send them, and `CreateWallet` builds over them): it
   * is created here. Anything else is an existing wallet and must pass the
   * same vet, or the call throws with the reason.
   *
   * When this call has to mint a fresh v2 seed it comes back as
   * `destinationUserSeed` — persist it, or the new wallet is as underivable as
   * the old one.
   */
  async migrateV1Wallet(params: {
    payer: Address;
    owner: CreateWalletOwner;
    /** The seed the v1 wallet was created with, when the app still has it. */
    userSeed?: Uint8Array;
    /** The v1 wallet address, for a wallet whose seed is gone. */
    v1Wallet?: Address;
    /** Seed for the v2 wallet, when one has to be created. Defaults to random. */
    destinationUserSeed?: Uint8Array;
    /**
     * The program that owns the v1 wallet. The migration executes there — it
     * is the only program that can sign for the v1 vault — and delivers to a v2
     * wallet at this client's program id. Defaults to the paired v1 deployment.
     */
    v1ProgramId?: Address;
    /** Vault token accounts to leave behind, e.g. ones the user marked as spam. */
    excludeTokenAccounts?: Address[];
    /**
     * Where the rent of every closed v1 account goes: the wallet, the authority
     * and each emptied token account. Defaults to `payer`, which paid for the
     * setup; pass the new vault to hand it to the user instead. It is part of
     * what the owner signs, so a relayer cannot change it.
     */
    refundDestination?: Address;
    /**
     * Passkey owner only: read the v1 authority's counter and the challenge
     * slot from a node at or past this slot. See
     * `Secp256r1Params.minContextSlot`.
     */
    minContextSlot?: Slot;
    /**
     * Passkey owner only: commitment for those two reads (default
     * `'confirmed'`). The migration's other reads are unaffected.
     */
    commitment?: Commitment;
    /**
     * SPL Token mints whose canonical account in an existing destination vault
     * is checked for a changed owner, on top of wSOL, USDC, USDT and devnet
     * USDC; see vetMigrationDestination. The mints this migration moves are
     * checked regardless.
     */
    watchMints?: (Address | string)[];
  }): Promise<{
    v1: V1Accounts;
    destinationWallet: Address;
    /** Set only when this call had to mint a fresh seed — persist it. */
    destinationUserSeed?: Uint8Array;
    v2Vault: Address;
    /** The token accounts this migration moves. */
    tokens: V1VaultToken[];
    /**
     * Token accounts it cannot move, and why. They stay in the v1 vault and
     * become unreachable once the v1 id runs the sunset binary — show them to
     * the user before they sign.
     */
    skippedTokens: { token: V1VaultToken; reason: UnmovableReason }[];
    setupInstructions: Instruction[];
    migrate:
      | {
          type: 'ed25519';
          /** The MigrateWallet instruction alone. */
          instruction: Instruction;
          /** What to send, in one transaction: any fee harvests, then MigrateWallet. */
          instructions: Instruction[];
        }
      | {
          type: 'secp256r1';
          challenge: Uint8Array;
          finalize: (response: WebAuthnResponse) => Instruction[];
        };
  }> {
    const { authType, credentialOrPubkey } = resolveOwnerFields(params.owner);
    // v1 side — PDAs, instruction, passkey challenge — belongs to the v1
    // program; the v2 side to this client's. Equal ids = the in-place layout.
    const v1ProgramId = params.v1ProgramId ?? legacyProgramIdFor(this.programId);
    const retired = [PROGRAM_ID_MAINNET_V1, PROGRAM_ID_DEVNET_V1].filter(
      (id) => id !== PROGRAM_ID_MAINNET && id !== PROGRAM_ID_DEVNET,
    );
    if (retired.includes(this.programId)) {
      throw new Error(
        `this client is built at ${this.programId}, a retired v1 deployment. ` +
          'Build it at the v2 program id: the migration runs at the v1 id but must deliver to v2.',
      );
    }

    let v1: V1Accounts;
    if (params.v1Wallet) {
      const [vault] = await findV1VaultPda(params.v1Wallet, v1ProgramId);
      const [authority] = await findV1AuthorityPda(params.v1Wallet, credentialOrPubkey, v1ProgramId);
      v1 = { wallet: params.v1Wallet, vault, authority };
    } else if (params.userSeed) {
      v1 = await deriveV1Accounts(params.userSeed, credentialOrPubkey, v1ProgramId);
    } else {
      throw new Error(
        'migrateV1Wallet needs either userSeed or v1Wallet. A wallet created by ' +
          '@lazorkit/wallet used a random seed that lived in browser storage, so for ' +
          'most users the seed is gone: find the wallet with findV1WalletsByOwner and ' +
          'pass v1Wallet instead.',
      );
    }

    const state = await readV1WalletState(this.rpc, v1);
    if (!state) {
      throw new Error(
        params.v1Wallet
          ? `no v1 wallet at ${v1.wallet} for this owner`
          : 'no v1 wallet exists for this userSeed',
      );
    }
    if (state.ownerRole !== ROLE_OWNER) {
      throw new Error('MigrateWallet requires an Owner-rank v1 authority');
    }
    if (authType === AUTH_TYPE_SECP256R1) {
      // The migration itself checks the passkey against the v1 authority, but
      // `owner` also creates (or vets) the v2 wallet the funds land in. A wrong
      // rpId there would sweep everything into a wallet no assertion can ever
      // satisfy. So the owner given must be exactly the one on the v1 account.
      await this.assertV1PasskeyOwner(v1.authority, params.owner);
    }

    // Where the funds land. With `userSeed`, that seed's wallet. Without it,
    // the v2 wallet this passkey has signed for, if it passes the vet (see
    // vetMigrationDestination); failing that, the wallet of
    // `destinationUserSeed`, or of a seed minted here.
    //
    // Why "signed for": anyone can hand a wallet to this owner with
    // TransferOwnership (its key is public) after using the vault as they
    // liked, and vetting cannot see all of it — an SPL Token account moved off
    // the vault is only found for a watched mint. A passkey signs only for a
    // wallet its user chose, and its authority's counter records that. An
    // Ed25519 authority keeps no such record, so for one nothing is reused.
    //
    // Why "the": until the program named the wallet in the passkey challenge,
    // a signature for CreateSession, AddAuthority, TransferOwnership or
    // Authorize made on one authority of this key could be replayed on another
    // at the same counter, raising it too, and counts from then are still on
    // chain. With two signed-on authorities — at any rank, since an Admin
    // seat's signature replayed onto an Owner's — either could be the copy,
    // and a fresh wallet is the safe answer.
    const mints = watchedMints(params.watchMints);
    let v2Wallet: Address | undefined;
    /** The seed `v2Wallet` derives from, when this call knows it. */
    let seed = params.userSeed;
    /** Once `v2Wallet` has passed the vet: the slot its newest read was answered at. */
    let vettedAt: bigint | undefined;
    if (seed) {
      [v2Wallet] = await this.findWallet(seed);
    } else {
      if (authType === AUTH_TYPE_SECP256R1) {
        const signed = await this.signedPasskeyAuthorities(params.owner);
        if (signed.length === 1 && signed[0]!.role === ROLE_OWNER) {
          const vet = await this.vetDestination(signed[0]!.walletPda, params.owner, mints);
          if (vet.problem === null && vet.signatureCount > 0) {
            v2Wallet = signed[0]!.walletPda;
            vettedAt = vet.slot;
          }
        }
      }
      if (!v2Wallet) {
        seed = params.destinationUserSeed ?? randomBytes(32);
        [v2Wallet] = await this.findWallet(seed);
      }
    }
    /** Set when the destination wallet is created here, from this seed. */
    let createFrom: Uint8Array | undefined;
    // A reused wallet has just passed the vet, whose pinned read found it a
    // wallet of this program — and no v2 instruction closes a wallet. Any
    // other destination is decided by one read. A plain system account —
    // nothing there, or only lamports, which anyone can send — is no wallet
    // yet: CreateWallet builds over it, below. Anything else is a wallet
    // somebody created, and nothing is delivered into it before it passes the
    // vet, however it was named: a seed can be predicted, or read out of an
    // earlier setup transaction, and whoever creates the wallet there first
    // chooses its owner.
    if (vettedAt === undefined) {
      const { value: walletAccount } = await this.rpc
        .getAccountInfo(v2Wallet, { encoding: 'base64' })
        .send();
      if (
        isSystemAccount(
          walletAccount && {
            owner: walletAccount.owner,
            data: new Uint8Array(base64Encoder.encode(walletAccount.data[0])),
          },
        )
      ) {
        // Only a reused wallet comes without a seed, and it is vetted above.
        createFrom = seed;
      } else {
        const vet = await this.vetDestination(v2Wallet, params.owner, mints);
        if (vet.problem !== null) {
          const named = params.userSeed ? 'userSeed' : 'destinationUserSeed';
          throw new Error(`refusing to migrate into the ${named}'s v2 wallet: ${vet.problem}`);
        }
        vettedAt = vet.slot;
      }
    }
    // Returned only when the caller does not already hold it as `userSeed`.
    const destinationUserSeed = params.userSeed ? undefined : seed;
    const [v2Vault] = await this.findVault(v2Wallet);

    const classified = await classifyV1VaultTokens(
      this.rpc,
      await enumerateV1VaultTokens(this.rpc, v1.vault),
      params.excludeTokenAccounts,
    );
    // The destination side, now that the vault is known. An existing frozen
    // destination account makes the transfer fail; an existing thawed one
    // means a mint that freezes new accounts is no obstacle after all.
    // Lamports alone at the address (anyone can send them) are not an account
    // yet: the ATA program creates the token account over them. For a wallet
    // that passed the vet, read no older state than the vet did — a stale
    // node could still show a destination account before it was rigged.
    const toCheck = [
      ...classified.movable,
      ...classified.skipped.filter((s) => s.reason === 'frozen-on-arrival').map((s) => s.token),
    ];
    const destState = new Map<
      string,
      { dest: Address; frozen: boolean; problem: string | null }
    >();
    for (let i = 0; i < toCheck.length; i += 100) {
      const page = toCheck.slice(i, i + 100);
      const dests = await Promise.all(
        page.map((t) => getAssociatedTokenAddress(t.mint, v2Vault, t.tokenProgram)),
      );
      const { infos } = await this.readAccounts(dests, vettedAt);
      infos.forEach((info, j) => {
        if (isSystemAccount(info)) return;
        const t = page[j]!;
        destState.set(t.ata, {
          dest: dests[j]!,
          frozen: tokenAccountFrozen(info!.data),
          problem: destinationTokenAccountProblem(dests[j]!, info!, t.tokenProgram, v2Vault),
        });
      });
    }
    const tokens: V1VaultToken[] = [];
    const skippedTokens = classified.skipped.filter((s) => s.reason !== 'frozen-on-arrival');
    for (const t of classified.movable) {
      if (destState.get(t.ata)?.frozen) skippedTokens.push({ token: t, reason: 'destination-frozen' });
      else tokens.push(t);
    }
    for (const s of classified.skipped.filter((s) => s.reason === 'frozen-on-arrival')) {
      const dest = destState.get(s.token.ata);
      if (dest && !dest.frozen) tokens.push(s.token);
      else skippedTokens.push(s);
    }
    // Every existing account the migration delivers into must be the v2
    // vault's alone. A wallet can be handed to this owner (TransferOwnership
    // asks the new owner nothing) with its vault's token accounts rigged: one
    // given to another owner, or carrying a delegate or close authority that
    // would take what arrives. The program checks the owner, not the rest.
    const rigged = tokens.flatMap((t) => {
      const d = destState.get(t.ata);
      return d?.problem ? [`${d.dest} (mint ${t.mint}) ${d.problem}`] : [];
    });
    if (rigged.length > 0) {
      const named = rigged.slice(0, 3).join('; ');
      const more = rigged.length > 3 ? `; and ${rigged.length - 3} more` : '';
      throw new Error(
        `refusing to migrate into ${v2Wallet}: destination token account ${named}${more}`,
      );
    }
    if (tokens.length > 255) {
      throw new Error(`the v1 vault holds ${tokens.length} token accounts; one migration moves at most 255`);
    }

    const setupInstructions: Instruction[] = [];
    if (createFrom) {
      const created = await this.createWallet({
        payer: params.payer,
        userSeed: createFrom,
        owner: params.owner,
      });
      setupInstructions.push(...created.instructions);
    }
    const migrateTokens: MigrateTokenPair[] = [];
    for (const t of tokens) {
      const destAta = await getAssociatedTokenAddress(t.mint, v2Vault, t.tokenProgram);
      setupInstructions.push(
        createAssociatedTokenAccountIdempotentIx({
          payer: params.payer,
          ata: destAta,
          owner: v2Vault,
          mint: t.mint,
          tokenProgram: t.tokenProgram,
        }),
      );
      migrateTokens.push({ sourceAta: t.ata, destAta, mint: t.mint, tokenProgram: t.tokenProgram });
    }

    // signed_payload = destination || v1_wallet || num_tokens || refund_dest
    //                  || source_ata[0] || … || source_ata[n-1]
    // The trailing source ATAs bind WHICH token accounts move, not just how many
    // — without them a relayer could keep the count and swap in dust it created,
    // stranding the user's real tokens when the vault closes. Order must match
    // the program's read order (the migrateTokens order used to build the ix).
    // Withheld Token-2022 fees stop a source account from closing; harvesting
    // them to the mint needs no signer. Done in the migration's own
    // transaction, so none can be planted in between.
    const withheldByMint = new Map<Address, Address[]>();
    for (const t of tokens) {
      if (t.withheldFees) withheldByMint.set(t.mint, [...(withheldByMint.get(t.mint) ?? []), t.ata]);
    }
    const harvestInstructions = [...withheldByMint].map(([mint, sources]) => harvestWithheldIx(mint, sources));

    const refundDestination = params.refundDestination ?? params.payer;
    const signedPayload = concatBytes([
      addressEncoder.encode(v2Vault) as Uint8Array,
      addressEncoder.encode(v1.wallet) as Uint8Array,
      new Uint8Array([tokens.length]),
      addressEncoder.encode(refundDestination) as Uint8Array,
      ...migrateTokens.map((t) => addressEncoder.encode(t.sourceAta) as Uint8Array),
    ]);

    if (authType === AUTH_TYPE_ED25519) {
      const instruction = createMigrateWalletIx({
        payer: params.payer,
        v1Wallet: v1.wallet,
        v1Authority: v1.authority,
        v1Vault: v1.vault,
        destination: v2Vault,
        refundDestination,
        authSigner: (params.owner as { publicKey: Address }).publicKey,
        authSignerIsSigner: true,
        tokens: migrateTokens,
        programId: v1ProgramId,
      });
      return {
        v1,
        destinationWallet: v2Wallet,
        destinationUserSeed,
        v2Vault,
        tokens,
        skippedTokens,
        setupInstructions,
        migrate: { type: 'ed25519', instruction, instructions: [...harvestInstructions, instruction] },
      };
    }

    // Secp256r1 passkey. The key comes from the caller (it is on the v1
    // authority account, which `findV1WalletsByOwner` already read) rather than
    // from the WebAuthn response, which has none.
    const owner = params.owner as { compressedPubkey: Uint8Array };
    const reads: ChallengeReadOptions = {
      commitment: params.commitment,
      minContextSlot: params.minContextSlot,
    };
    // The key is the caller's, so only the counter and the slot are read.
    const { counter, slot } = await readChallengeInputs(this.rpc, v1.authority, reads, {
      publicKeyBytes: owner.compressedPubkey,
    });
    const prepared = this.buildPasskeySigning({
      discriminator: DISC_MIGRATE_WALLET,
      sysvarIxIndex: SYSVAR_IX_INDEX_MIGRATE_WALLET,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
      // The authority signing is the v1 one, and the challenge names the
      // wallet in its header: the v1 wallet, not the v2 destination.
      wallet: v1.wallet,
      publicKeyBytes: owner.compressedPubkey,
      // The challenge binds the program that verifies it: the v1 program.
      programId: v1ProgramId,
    });
    const finalize = (response: WebAuthnResponse): Instruction[] => {
      const { authPayload, precompileIx } = finalizeSecp256r1(prepared, response);
      const migrateIx = createMigrateWalletIx({
        payer: params.payer,
        v1Wallet: v1.wallet,
        v1Authority: v1.authority,
        v1Vault: v1.vault,
        destination: v2Vault,
        refundDestination,
        authSigner: params.payer,
        authSignerIsSigner: false,
        tokens: migrateTokens,
        authPayload,
        programId: v1ProgramId,
      });
      // Harvests first; the precompile must sit immediately before the migrate.
      return [...harvestInstructions, precompileIx, migrateIx];
    };
    return {
      v1,
      destinationWallet: v2Wallet,
      destinationUserSeed,
      v2Vault,
      tokens,
      skippedTokens,
      setupInstructions,
      migrate: { type: 'secp256r1', challenge: prepared.challenge, finalize },
    };
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function readU64(data: Uint8Array, offset: number): bigint {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true);
}

/** The u64 expiry slot at `offset`, or `U64_MAX` — never expiring — when the account is too short to hold it. */
function expiryAt(data: Uint8Array, offset: number): bigint {
  return data.length >= offset + 8 ? readU64(data, offset) : U64_MAX;
}

function readU32(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
}

// ─── Helper: decode Address from raw bytes (for findWalletsByAuthority) ──

import { getAddressDecoder } from '@solana/kit';
const addressDecoder = getAddressDecoder();
function addressFromBytes(bytes: Uint8Array): Address {
  return addressDecoder.decode(bytes);
}

// ─── Convenience exports ─────────────────────────────────────────────

/** Convenience: alias for sdk-legacy parity (LazorKitClient → LazorKit). */
export { LazorKit as LazorKitClient };

/** Default-export the well-known program IDs for explicit ergonomic init. */
export { PROGRAM_ID_DEVNET, PROGRAM_ID_MAINNET };

/** Options for {@link LazorKit}. */
export interface LazorKitOptions {
  /**
   * Append the `[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]` suffix
   * to fee-eligible instructions (CreateWallet, Execute, ExecuteDeferred).
   * Default `true` — this program requires the suffix on those instructions
   * even when no fee is charged. Set `false` only for a build without the fee
   * layer.
   */
  protocolFees?: boolean;
}
