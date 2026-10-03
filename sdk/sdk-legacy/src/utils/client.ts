import { Buffer } from 'buffer';
import {
  type Commitment,
  Connection,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from '@solana/web3.js';
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha2';
import {
  ACCOUNT_DISCRIMINATOR,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  PROGRAM_ID_MAINNET,
  PROGRAM_ID_MAINNET_V1,
  legacyProgramIdFor,
} from '../constants';
import {
  findWalletPda,
  findVaultPda,
  findAuthorityPda,
  findSessionPda,
  findDeferredExecPda,
  findProtocolConfigPda,
  findFeeRecordPda,
  findTreasuryShardPda,
} from './pdas';
import {
  classifyV1VaultTokens,
  harvestWithheldIx,
  tokenAccountFrozen,
  deriveV1Accounts,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletsByOwner,
  readV1WalletState,
  enumerateV1VaultTokens,
  type UnmovableReason,
  type V1Accounts,
  type V1VaultToken,
  type V1WalletRecord,
} from './v1';
import {
  getAssociatedTokenAddress,
  createAssociatedTokenAccountIdempotentIx,
} from './spl';
import { type ChallengeReadOptions, readAuthorityCounter } from './secp256r1';
import { ChallengeReadGroup, readChallengeInputs } from './challengeReads';
import {
  packCompactInstructions,
  computeAccountsHash,
  computeInstructionsHash,
  decodeAccountIndex,
  type CompactInstruction,
} from './packing';
import {
  createCreateWalletIx,
  createAddAuthorityIx,
  createRemoveAuthorityIx,
  createTransferOwnershipIx,
  createExecuteIx,
  createCreateSessionIx,
  createAuthorizeIx,
  createExecuteDeferredIx,
  createReclaimDeferredIx,
  createRevokeSessionIx,
  createInitializeProtocolIx,
  createUpdateProtocolIx,
  createRegisterPayerIx,
  createWithdrawTreasuryIx,
  createInitializeTreasuryShardIx,
  createMigrateWalletIx,
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  DISC_ADD_AUTHORITY,
  DISC_REMOVE_AUTHORITY,
  DISC_TRANSFER_OWNERSHIP,
  DISC_EXECUTE,
  DISC_CREATE_SESSION,
  DISC_AUTHORIZE,
  DISC_REVOKE_SESSION,
  DISC_MIGRATE_WALLET,
  ROLE_OWNER,
  ROLE_SPENDER,
} from './instructions';
import {
  prepareSecp256r1,
  finalizeSecp256r1,
  buildDataPayloadForAdd,
  buildDataPayloadForTransfer,
  buildDataPayloadForSession,
  type WebAuthnResponse,
  type PreparedSecp256r1,
} from './signing';
import { concatBytes } from './bytes';
import { buildCompactLayout } from './compact';
import { serializeActions, type SessionAction } from './actions';
import {
  deferredExpiry,
  describePasskeyWallets,
  grantPhrase,
  isPlainSystemAccount,
  pickOwnWallet,
  readAccounts,
  readSpendingState,
  scanPasskeyWalletCandidates,
  sessionExpiry,
  tokenAccountProblem,
  vaultTokenGrants,
  verifyOwnershipProof,
  watchedMints,
  watchedTokenAccounts,
  type OwnershipProof,
  type PasskeyWalletCandidate,
  type WalletFacts,
} from './ownership';
import type {
  CreateWalletOwner,
  AdminSigner,
  ExecuteSigner,
  Secp256r1SignerConfig,
  Secp256r1Params,
  DeferredPayload,
} from './types';
import type { AccountInfo, AccountMeta } from '@solana/web3.js';

// ─── Prepared operation types (for secp256r1 prepare/finalize flow) ──

interface PreparedBase {
  /** SHA-256 challenge to pass to navigator.credentials.get(): 32 bytes, approving this operation only. */
  challenge: Uint8Array;
}

export interface PreparedExecute extends PreparedBase {
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    authorityPda: PublicKey;
    vaultPda: PublicKey;
    packed: Uint8Array;
    remainingAccounts: AccountMeta[];
    protocolFee?: {
      protocolConfigPda: PublicKey;
      feeRecordPda: PublicKey;
      treasuryShardPda: PublicKey;
    };
    /** Auto-prepended payer-self-registration ix (first fee-paying tx only) */
    registerIx?: TransactionInstruction;
    programId: PublicKey;
  };
}

export interface PreparedAddAuthority extends PreparedBase {
  newAuthorityPda: PublicKey;
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    adminAuthorityPda: PublicKey;
    newAuthorityPda: PublicKey;
    newType: number;
    newRole: number;
    policy?: Uint8Array;
    credentialOrPubkey: Uint8Array;
    secp256r1Pubkey?: Uint8Array;
    rpId?: string;
    programId: PublicKey;
  };
}

export interface PreparedRemoveAuthority extends PreparedBase {
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    adminAuthorityPda: PublicKey;
    targetAuthorityPda: PublicKey;
    refundDestination: PublicKey;
    programId: PublicKey;
  };
}

export interface PreparedTransferOwnership extends PreparedBase {
  newOwnerAuthorityPda: PublicKey;
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    currentOwnerAuthorityPda: PublicKey;
    newOwnerAuthorityPda: PublicKey;
    refundDestination: PublicKey;
    newType: number;
    credentialOrPubkey: Uint8Array;
    secp256r1Pubkey?: Uint8Array;
    rpId?: string;
    programId: PublicKey;
  };
}

export interface PreparedCreateSession extends PreparedBase {
  sessionPda: PublicKey;
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    adminAuthorityPda: PublicKey;
    sessionPda: PublicKey;
    sessionKey: Uint8Array;
    expiresAt: bigint;
    actionsBuffer?: Uint8Array;
    programId: PublicKey;
  };
}

export interface PreparedRevokeSession extends PreparedBase {
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    walletPda: PublicKey;
    adminAuthorityPda: PublicKey;
    sessionPda: PublicKey;
    refundDestination: PublicKey;
    programId: PublicKey;
  };
}

/** One hit from `findWalletsByAuthority` — enough to bootstrap all downstream calls. */
export interface WalletAuthorityRecord {
  walletPda: PublicKey;
  authorityPda: PublicKey;
  vaultPda: PublicKey;
  /** Role enum: 0=Owner, 1=Admin, 2=Spender */
  role: number;
  /** Authority type enum: 0=Ed25519, 1=Secp256r1 */
  authorityType: number;
}

export interface PreparedAuthorize extends PreparedBase {
  deferredExecPda: PublicKey;
  counter: number;
  /** @internal — opaque signing state threaded to finalize(). Do not touch. */
  _internal: {
    signing: PreparedSecp256r1;
    payer: PublicKey;
    executor: PublicKey;
    walletPda: PublicKey;
    authorityPda: PublicKey;
    deferredExecPda: PublicKey;
    instructionsHash: Uint8Array;
    accountsHash: Uint8Array;
    expiryOffset: number;
    compactInstructions: CompactInstruction[];
    remainingAccounts: AccountMeta[];
    programId: PublicKey;
  };
}

// ─── Sysvar instruction indexes (auto-computed from account layouts) ──

const SYSVAR_IX_INDEX_ADD_AUTHORITY = 6;
const SYSVAR_IX_INDEX_REMOVE_AUTHORITY = 5;
const SYSVAR_IX_INDEX_TRANSFER_OWNERSHIP = 7; // account layout: payer,wallet,currentOwner,newOwner,refundDest,system,rent,sysvarIx
const SYSVAR_IX_INDEX_EXECUTE = 4;
const SYSVAR_IX_INDEX_CREATE_SESSION = 6;
const SYSVAR_IX_INDEX_AUTHORIZE = 6;
const SYSVAR_IX_INDEX_REVOKE_SESSION = 5;

// ─── Internal helpers ─────────────────────────────────────────────────

/** Throws if a Uint8Array isn't exactly the expected length. */
function assertByteLength(
  value: Uint8Array,
  expected: number,
  name: string,
): void {
  if (value.length !== expected) {
    throw new Error(
      `${name} must be exactly ${expected} bytes, got ${value.length}`,
    );
  }
}

function assertNonZeroBytes(value: Uint8Array, name: string): void {
  if (value.every((b) => b === 0)) {
    throw new Error(`${name} must not be all zero bytes`);
  }
}

/** Resolves a CreateWalletOwner to the low-level fields needed by IX builders */
function resolveOwnerFields(owner: CreateWalletOwner): {
  authType: number;
  credentialOrPubkey: Uint8Array;
  secp256r1Pubkey?: Uint8Array;
  rpId?: string;
} {
  if (owner.type === 'ed25519') {
    const publicKeyBytes = owner.publicKey.toBytes();
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

/// A session with no actions is not "a session with no limits" — it is a key
/// with *more* power over the vault than a bounded Delegate. The action buffer
/// is what switches on the vault invariants the program checks after the CPI
/// (owner and data length; every vault token account unchanged but for its
/// balance; no SOL and no mint the actions do not name leaving the vault), so
/// an empty buffer disables all of them: such a key can reassign the vault,
/// seize its token accounts, or move any asset it holds. That is a deliberate
/// capability, never a default, so it has to be asked for by name.
function assertSessionActions(
  actions: SessionAction[] | undefined,
  unrestricted = false,
): void {
  if ((!actions || actions.length === 0) && !unrestricted) {
    throw new Error(
      'createSession with no actions grants an UNRESTRICTED session key — it can ' +
        'move the whole vault and even reassign it, which is more power than a ' +
        'bounded Delegate has. Pass actions: [Actions.solLimit(...), ...] to bound ' +
        'it, or unrestricted: true to say you meant it.',
    );
  }
}

/**
 * Shared pipeline for prepareExecute + prepareAuthorize:
 *  1. runs buildCompactLayout over fixed keys + user instructions
 *  2. assembles the full AccountMeta[] with per-fixed-account flags
 *  3. computes the accounts hash that gets folded into the signed payload
 *
 * Call sites declare the fixed accounts exactly as the instruction builder
 * that will carry them does (`createExecuteIx`, `createExecuteDeferredIx`) and
 * pass the user instructions. The program hashes the flags the runtime
 * reports, so the metas are read the way the runtime reads them before hashing
 * (see {@link withRuntimeFlags}).
 */
function buildCompactLayoutAndHash(
  fixedAccounts: AccountMeta[],
  userInstructions: TransactionInstruction[],
  feePayer?: PublicKey,
): {
  compactInstructions: CompactInstruction[];
  remainingAccounts: AccountMeta[];
  allAccountMetas: AccountMeta[];
  accountsHash: Uint8Array;
} {
  const fixedKeys = fixedAccounts.map((a) => a.pubkey);
  const { compactInstructions, remainingAccounts } = buildCompactLayout(
    fixedKeys,
    userInstructions,
    fixedKeys[0],
  );
  const allAccountMetas = withRuntimeFlags(
    [...fixedAccounts, ...remainingAccounts],
    feePayer,
  );
  const accountsHash = computeAccountsHash(allAccountMetas, compactInstructions);
  return {
    compactInstructions,
    remainingAccounts,
    allAccountMetas,
    accountsHash,
  };
}

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
function withRuntimeFlags(metas: AccountMeta[], feePayer?: PublicKey): AccountMeta[] {
  const union = new Map<string, { isSigner: boolean; isWritable: boolean }>();
  const merge = (m: AccountMeta) => {
    const key = m.pubkey.toBase58();
    const u = union.get(key);
    union.set(key, {
      isSigner: m.isSigner || (u?.isSigner ?? false),
      isWritable: m.isWritable || (u?.isWritable ?? false),
    });
  };
  for (const m of metas) merge(m);
  if (feePayer) merge({ pubkey: feePayer, isSigner: true, isWritable: true });
  return metas.map((m) => ({ pubkey: m.pubkey, ...union.get(m.pubkey.toBase58())! }));
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
 * Infer the LazorKit program ID from a Connection's RPC endpoint:
 *
 *   - URLs containing "mainnet" → mainnet program ID
 *   - URLs containing "devnet"  → devnet program ID
 *   - localhost / 127.0.0.1     → devnet program ID (local-validator convention)
 *   - anything else              → throw, caller must pass `programId` explicitly
 *
 * The inference is intentionally narrow: covering Solana's canonical RPCs and
 * common third-party providers (Helius, Triton, QuickNode all encode cluster
 * in the hostname). For air-gapped clusters, forks, mainnet-forks served from
 * an unlabelled RPC, or any unusual setup, callers must pass `programId`
 * explicitly to avoid silently deriving wrong PDAs.
 */
function inferProgramIdFromRpc(connection: Connection): PublicKey {
  const rpc = connection.rpcEndpoint.toLowerCase();
  if (rpc.includes('mainnet')) return PROGRAM_ID_MAINNET;
  if (rpc.includes('devnet')) return PROGRAM_ID_DEVNET;
  if (
    rpc.includes('localhost') ||
    rpc.includes('127.0.0.1') ||
    rpc.includes('0.0.0.0')
  ) {
    return PROGRAM_ID_DEVNET;
  }
  throw new Error(
    `LazorKitClient: cannot infer program ID from RPC endpoint "${connection.rpcEndpoint}". ` +
      `Pass an explicit programId, e.g. ` +
      `\`new LazorKitClient(connection, PROGRAM_ID_MAINNET)\` or ` +
      `\`new LazorKitClient(connection, PROGRAM_ID_DEVNET)\`.`,
  );
}

export class LazorKitClient {
  /** Cached protocol config (fetched on first fee-eligible call) */
  private _protocolConfig:
    | { numShards: number; enabled: boolean }
    | null
    | undefined;

  readonly connection: Connection;
  readonly programId: PublicKey;
  /** Whether fee-eligible instructions carry the protocol-fee suffix. */
  readonly protocolFees: boolean;

  /**
   * Construct a client. The program ID is inferred from the connection's RPC
   * endpoint (mainnet / devnet / localhost), or you can pass it explicitly
   * for forks, custom RPC providers without recognisable hostnames, or
   * tests against arbitrary deploy keypairs:
   *
   * ```ts
   * // Auto-inferred from RPC URL — typical case
   * const client = new LazorKitClient(new Connection(MAINNET_RPC));
   *
   * // Explicit (custom RPC, forks, local-validator with non-default keypair)
   * const client = new LazorKitClient(connection, PROGRAM_ID_MAINNET);
   * ```
   */
  constructor(
    connection: Connection,
    programId?: PublicKey,
    options: LazorKitClientOptions = {},
  ) {
    this.connection = connection;
    this.programId = programId ?? inferProgramIdFromRpc(connection);
    this.protocolFees = options.protocolFees ?? true;
  }

  // ─── PDA helpers ─────────────────────────────────────────────────

  findWallet(userSeed: Uint8Array) {
    return findWalletPda(userSeed, this.programId);
  }
  findVault(walletPda: PublicKey) {
    return findVaultPda(walletPda, this.programId);
  }
  findAuthority(walletPda: PublicKey, credIdHash: Uint8Array) {
    return findAuthorityPda(walletPda, credIdHash, this.programId);
  }
  findSession(walletPda: PublicKey, sessionKey: Uint8Array) {
    return findSessionPda(walletPda, sessionKey, this.programId);
  }
  findDeferredExec(
    walletPda: PublicKey,
    authorityPda: PublicKey,
    counter: number,
  ) {
    return findDeferredExecPda(
      walletPda,
      authorityPda,
      counter,
      this.programId,
    );
  }
  findProtocolConfig() {
    return findProtocolConfigPda(this.programId);
  }
  findFeeRecord(payerPubkey: PublicKey) {
    return findFeeRecordPda(payerPubkey, this.programId);
  }
  findTreasuryShard(shardId: number) {
    return findTreasuryShardPda(shardId, this.programId);
  }

  /**
   * Fetch and cache the on-chain ProtocolConfig. Returns null if not initialized.
   * Cached after first fetch — call `invalidateProtocolCache()` to refresh.
   */
  async getProtocolConfig(): Promise<{
    numShards: number;
    enabled: boolean;
  } | null> {
    if (this._protocolConfig !== undefined) return this._protocolConfig;
    const [configPda] = this.findProtocolConfig();
    const info = await this.connection.getAccountInfo(configPda);
    if (!info || info.data.length < 88 || info.data[0] !== ACCOUNT_DISCRIMINATOR.PROTOCOL_CONFIG) {
      this._protocolConfig = null;
      return null;
    }
    this._protocolConfig = {
      enabled: info.data[3] !== 0,
      numShards: info.data[4],
    };
    return this._protocolConfig;
  }

  /** Clear cached protocol config (e.g. after UpdateProtocol) */
  invalidateProtocolCache(): void {
    this._protocolConfig = undefined;
  }

  /**
   * Auto-resolve protocol fee accounts for a payer.
   *
   * Returns the 4 accounts to append to every fee-eligible instruction (disc 0, 4, 7).
   * The `feeRecordPda` is always the canonical PDA derived from the payer. Under strict
   * fee enforcement, every successful fee-paying instruction must create or update this
   * record; there is no "pay fee but skip accounting" path.
   *
   * The program requires this suffix whether or not a fee is charged: it rejects a
   * fee-eligible instruction without it (4008 FeeAccountsRequired) before it reads the
   * config, and strips it again when the protocol is uninitialised or disabled. So the
   * accounts are returned even then — omitting them is what broke every CreateWallet /
   * Execute between an upgrade and `InitializeProtocol`, or while fees were paused.
   *
   * Returns undefined only for a client built with `{ protocolFees: false }`, for a
   * binary without the fee layer.
   */
  async resolveProtocolFee(payer: PublicKey): Promise<
    | {
        protocolConfigPda: PublicKey;
        feeRecordPda: PublicKey;
        treasuryShardPda: PublicKey;
      }
    | undefined
  > {
    if (!this.protocolFees) return undefined;
    const config = await this.getProtocolConfig();

    const [protocolConfigPda] = this.findProtocolConfig();
    const [feeRecordPda] = this.findFeeRecord(payer);
    // CSPRNG to avoid predictable shard selection. Not a direct exploit vector
    // (fees still land in a valid shard), but violates "no Math.random in
    // crypto-adjacent code" hygiene.
    //
    // A shard is only read when a fee is actually charged. Uninitialised or
    // disabled, the program strips the suffix without touching the shard or
    // the record (entrypoint `try_collect_fee`), so shard 0 serves.
    let shardId = 0;
    if (config && config.enabled && config.numShards > 0) {
      const randBuf = randomBytes(4);
      const randU32 = (randBuf[0] | (randBuf[1] << 8) | (randBuf[2] << 16) | (randBuf[3] << 24)) >>> 0;
      shardId = randU32 % config.numShards;
    }
    const [treasuryShardPda] = this.findTreasuryShard(shardId);
    return { protocolConfigPda, feeRecordPda, treasuryShardPda };
  }

  /**
   * Like {@link resolveProtocolFee} but additionally returns a `registerIx`
   * to prepend when the payer's FeeRecord PDA does not yet exist on-chain.
   * Fee-eligible tx builders use this so apps don't need to manually call
   * `registerPayer()` before their first fee-paying transaction.
   *
   * One extra `getAccountInfo` per first-time tx; subsequent txs short-circuit
   * via an in-memory cache of payers we've already seen registered.
   */
  private _registeredPayers = new Set<string>();

  async resolveProtocolFeeWithRegister(payer: PublicKey): Promise<
    | {
        accounts: {
          protocolConfigPda: PublicKey;
          feeRecordPda: PublicKey;
          treasuryShardPda: PublicKey;
        };
        registerIx?: TransactionInstruction;
      }
    | undefined
  > {
    const accounts = await this.resolveProtocolFee(payer);
    if (!accounts) return undefined;

    // Only a live fee touches the FeeRecord. Uninitialised or disabled, the
    // program never reads it, and RegisterPayer needs a live config — so there
    // is nothing to register.
    const config = await this.getProtocolConfig();
    if (!config || !config.enabled) return { accounts };

    const key = payer.toBase58();
    if (this._registeredPayers.has(key)) {
      return { accounts };
    }

    const info = await this.connection.getAccountInfo(accounts.feeRecordPda);
    const exists =
      !!info && info.data.length > 0 && info.data[0] === ACCOUNT_DISCRIMINATOR.FEE_RECORD;
    if (exists) {
      this._registeredPayers.add(key);
      return { accounts };
    }

    const registerIx = createRegisterPayerIx({
      payer,
      feeRecordPda: accounts.feeRecordPda,
      programId: this.programId,
    });
    // Mark optimistically — the same tx will create it. If it fails we'll
    // re-detect on the next call (set is in-memory only).
    this._registeredPayers.add(key);
    return { accounts, registerIx };
  }

  // ─── Account readers ─────────────────────────────────────────────

  /**
   * The authority's odometer counter: the next passkey challenge signs one
   * more. Read at `opts.commitment` (default `'confirmed'`, or `'processed'`
   * on a Connection at `'processed'`) and, with `opts.minContextSlot`, from a
   * node at or past that slot — see {@link Secp256r1Params.minContextSlot}.
   */
  async readCounter(authorityPda: PublicKey, opts?: ChallengeReadOptions): Promise<number> {
    return readAuthorityCounter(this.connection, authorityPda, opts);
  }

  // ─── Secp256r1 prepare/finalize helpers ─────────────────────────────

  /**
   * `group`: when another read runs beside these, in it too (see
   * `prepareExecute`); by default the challenge reads get one of their own.
   */
  private async resolveSecp256r1(walletPda: PublicKey, p: Secp256r1Params, group?: ChallengeReadGroup) {
    assertByteLength(p.credentialIdHash, 32, 'credentialIdHash');
    if (p.publicKeyBytes) {
      assertByteLength(p.publicKeyBytes, 33, 'publicKeyBytes');
    }
    const authorityPda =
      p.authorityPda ?? this.findAuthority(walletPda, p.credentialIdHash)[0];

    // Independent RPC reads, in parallel; what the caller passed is not read.
    // All three at one commitment and freshness floor: a node that has not yet
    // executed the authority's previous transaction hands back the counter it
    // consumed, and the signature fails with SignatureReused (3006). If one
    // read fails, the others stop waiting for the floor.
    const reads: ChallengeReadOptions = { commitment: p.commitment, minContextSlot: p.minContextSlot };
    const { publicKeyBytes, slot, counter } = await readChallengeInputs(
      this.connection,
      authorityPda,
      reads,
      { publicKeyBytes: p.publicKeyBytes, slotOverride: p.slotOverride },
      group,
    );

    return { authorityPda, publicKeyBytes, slot, counter };
  }

  /**
   * Flatten a Secp256r1SignerConfig into the raw Secp256r1Params that the
   * prepare* methods take. Strips the Signer callback — prepare* doesn't
   * sign, it only derives the challenge.
   */
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

  /**
   * Derive the Ed25519 admin's authority PDA, honoring the pre-computed
   * override if the caller supplied one (otherwise a fresh findAuthority).
   */
  private resolveEd25519AuthorityPda(
    s: { publicKey: PublicKey; authorityPda?: PublicKey },
    walletPda: PublicKey,
  ): PublicKey {
    return s.authorityPda ?? this.findAuthority(walletPda, s.publicKey.toBytes())[0];
  }

  /**
   * Thin wrapper around `prepareSecp256r1` that injects this client's
   * programId — every prepare method passes the same `payer` + `programId`
   * + (1-byte) discriminator, so threading those through a helper keeps
   * the per-op site focused on the signedPayload.
   */
  private buildPasskeySigning(args: {
    discriminator: number;
    sysvarIxIndex: number;
    signedPayload: Uint8Array;
    slot: bigint;
    counter: number;
    payer: PublicKey;
    /** The wallet the signing authority belongs to; the challenge names it. */
    wallet: PublicKey;
    publicKeyBytes: Uint8Array;
  }): PreparedSecp256r1 {
    return prepareSecp256r1({
      discriminator: new Uint8Array([args.discriminator]),
      signedPayload: args.signedPayload,
      sysvarIxIndex: args.sysvarIxIndex,
      slot: args.slot,
      counter: args.counter,
      payer: args.payer,
      wallet: args.wallet,
      programId: this.programId,
      publicKeyBytes: args.publicKeyBytes,
    });
  }

  // ── prepareExecute / finalizeExecute ──

  async prepareExecute(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    instructions: TransactionInstruction[];
    /** The transaction's fee payer, when it is not `payer`. The runtime
     *  reports it a writable signer wherever it appears, so an inner
     *  instruction that names it (repaying a sponsor) is hashed that way. */
    feePayer?: PublicKey;
  }): Promise<PreparedExecute> {
    const [vaultPda] = this.findVault(params.walletPda);
    // resolveSecp256r1 and protocol-fee resolution are fully independent — run
    // them in parallel, in one read group: if the fee read fails, the call
    // rejects with its error, and the challenge reads must not go on polling
    // -32016 for the floor after that.
    const reads = new ChallengeReadGroup();
    const [resolved, fee] = await Promise.all([
      this.resolveSecp256r1(params.walletPda, params.secp256r1, reads),
      reads.run(this.resolveProtocolFeeWithRegister(params.payer)),
    ]);
    const { authorityPda, publicKeyBytes, slot, counter } = resolved;
    const protocolFee = fee?.accounts;
    const registerIx = fee?.registerIx;

    // As createExecuteIx declares them. The payer is a writable signer there
    // because the runtime reports it as one anyway when it pays the fee, and
    // the accounts hash is over what the runtime reports: an inner
    // instruction that names the payer (repaying a paymaster) is hashed with
    // those flags on chain.
    const { compactInstructions, remainingAccounts, accountsHash } =
      buildCompactLayoutAndHash(
        [
          { pubkey: params.payer, isSigner: true, isWritable: true },
          { pubkey: params.walletPda, isSigner: false, isWritable: false },
          { pubkey: authorityPda, isSigner: false, isWritable: true },
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
        ],
        params.instructions,
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

  finalizeExecute(
    prepared: PreparedExecute,
    response: WebAuthnResponse,
  ): { instructions: TransactionInstruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ── prepareAddAuthority / finalizeAddAuthority ──

  /**
   * Phase 1 of adding a new authority under a passkey admin. Computes the
   * WebAuthn challenge that must be passed to `navigator.credentials.get()`.
   * After the authenticator signs, call `finalizeAddAuthority()` to build
   * the transaction instructions.
   *
   * Returns `{ challenge, _internal }`. Treat `_internal` as opaque state —
   * it carries the signing context through to the finalize step.
   */
  async prepareAddAuthority(params: {
    payer: PublicKey;
    walletPda: PublicKey;
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
    const {
      authType: newType,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
    } = resolveOwnerFields(params.newAuthority);
    const [newAuthorityPda] = this.findAuthority(
      params.walletPda,
      credentialOrPubkey,
    );
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
    const signedPayload = concatBytes([dataPayload, params.payer.toBytes()]);

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
  ): { instructions: TransactionInstruction[]; newAuthorityPda: PublicKey } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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
    return {
      instructions: [precompileIx, ix],
      newAuthorityPda: i.newAuthorityPda,
    };
  }

  // ── prepareRemoveAuthority / finalizeRemoveAuthority ──

  /**
   * Phase 1 of removing an authority under a passkey admin. Computes the
   * WebAuthn challenge; finalize with the authenticator response to produce
   * the transaction instructions. The target authority's PDA is closed and
   * its rent refunded to `refundDestination` on finalize+send.
   */
  async prepareRemoveAuthority(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    targetAuthorityPda: PublicKey;
    refundDestination?: PublicKey;
  }): Promise<PreparedRemoveAuthority> {
    const refundDest = params.refundDestination ?? params.payer;
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const signedPayload = concatBytes([
      params.targetAuthorityPda.toBytes(),
      refundDest.toBytes(),
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
  ): { instructions: TransactionInstruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ── prepareTransferOwnership / finalizeTransferOwnership ──

  async prepareTransferOwnership(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    newOwner: CreateWalletOwner;
    refundDestination?: PublicKey;
  }): Promise<PreparedTransferOwnership> {
    const {
      authType: newType,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
    } = resolveOwnerFields(params.newOwner);
    const [newOwnerAuthorityPda] = this.findAuthority(
      params.walletPda,
      credentialOrPubkey,
    );
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
      params.payer.toBytes(),
      refundDest.toBytes(),
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
  ): {
    instructions: TransactionInstruction[];
    newOwnerAuthorityPda: PublicKey;
  } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ── prepareCreateSession / finalizeCreateSession ──

  /**
   * Phase 1 of creating a session under a passkey admin. Computes the
   * WebAuthn challenge; after the authenticator signs, call
   * `finalizeCreateSession()` to build the transaction. The session PDA
   * is created and funded by `payer` on finalize+send.
   */
  async prepareCreateSession(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    sessionKey: PublicKey;
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
    const sessionKeyBytes = params.sessionKey.toBytes();
    const [sessionPda] = this.findSession(params.walletPda, sessionKeyBytes);
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );
    const actionsBuffer =
      params.actions && params.actions.length > 0
        ? serializeActions(params.actions)
        : undefined;

    const dataPayload = buildDataPayloadForSession(
      sessionKeyBytes,
      params.expiresAt,
      actionsBuffer,
    );
    const signedPayload = concatBytes([dataPayload, params.payer.toBytes()]);

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
  ): { instructions: TransactionInstruction[]; sessionPda: PublicKey } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ── prepareRevokeSession / finalizeRevokeSession ──

  /**
   * Phase 1 of revoking a session under a passkey admin. Computes the
   * WebAuthn challenge; finalize with the authenticator response. The
   * session PDA is closed and rent refunded to `refundDestination` on
   * finalize+send.
   */
  async prepareRevokeSession(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    sessionPda: PublicKey;
    refundDestination?: PublicKey;
  }): Promise<PreparedRevokeSession> {
    const refundDest = params.refundDestination ?? params.payer;
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );

    const signedPayload = concatBytes([
      params.sessionPda.toBytes(),
      refundDest.toBytes(),
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
  ): { instructions: TransactionInstruction[] } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ── prepareAuthorize / finalizeAuthorize ──

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
    payer: PublicKey;
    walletPda: PublicKey;
    secp256r1: Secp256r1Params;
    instructions: TransactionInstruction[];
    expiryOffset?: number;
    /** Who will send tx2 (ExecuteDeferred's payer). Defaults to `payer`. */
    executor?: PublicKey;
    /** Tx2's fee payer, when it is not the executor (see `prepareExecute`). */
    feePayer?: PublicKey;
  }): Promise<PreparedAuthorize> {
    const [vaultPda] = this.findVault(params.walletPda);
    const { authorityPda, publicKeyBytes, slot, counter } = await this.resolveSecp256r1(
      params.walletPda,
      params.secp256r1,
    );
    const expiryOffset = params.expiryOffset ?? 300;
    const [deferredExecPda] = this.findDeferredExec(
      params.walletPda,
      authorityPda,
      counter,
    );

    // The compact layout reflects TX2 (ExecuteDeferred) account order, because
    // that's the set of accounts the on-chain verifier will hash when replaying,
    // with the flags createExecuteDeferredIx gives them: the executor as tx2's
    // payer, this payer as the refund destination (see above).
    const executor = params.executor ?? params.payer;
    const { compactInstructions, remainingAccounts, accountsHash } =
      buildCompactLayoutAndHash(
        [
          { pubkey: executor, isSigner: true, isWritable: true },
          { pubkey: params.walletPda, isSigner: false, isWritable: false },
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: deferredExecPda, isSigner: false, isWritable: true },
          { pubkey: params.payer, isSigner: false, isWritable: true },
        ],
        params.instructions,
        params.feePayer,
      );
    const instructionsHash = computeInstructionsHash(compactInstructions);
    const expiryOffsetBuf = new Uint8Array(2);
    expiryOffsetBuf[0] = expiryOffset & 0xff;
    expiryOffsetBuf[1] = (expiryOffset >> 8) & 0xff;
    const signedPayload = concatBytes([
      instructionsHash,
      accountsHash,
      expiryOffsetBuf,
    ]);

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
    instructions: TransactionInstruction[];
    deferredExecPda: PublicKey;
    counter: number;
    deferredPayload: DeferredPayload;
  } {
    const i = prepared._internal;
    const { authPayload, precompileIx } = finalizeSecp256r1(
      i.signing,
      response,
    );
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

  // ─── Wallet lookup ─────────────────────────────────────────────────

  /**
   * Look up wallets by credential — a raw lookup: every wallet that lists it,
   * at any rank.
   *
   * Not the way to find a returning user's wallet. A credential-id hash is
   * public (it sits in every authority account the passkey has), and
   * `CreateWallet` / `AddAuthority` take any key without its consent, so
   * anyone can plant a wallet that lists it. Use {@link findOwnPasskeyWallet},
   * which proves the passkey and checks who else can spend.
   *
   * @param credential - 32 bytes: Ed25519 pubkey or Secp256r1 credentialIdHash
   * @param authorityType - `'secp256r1'` (default) or `'ed25519'`
   * @returns array of matching wallets (one credential can be authority on multiple wallets)
   *
   * @example Passkey user returns
   * ```typescript
   * const challenge = createTaggedOwnershipChallenge();
   * // navigator.credentials.get({ publicKey: { challenge, rpId } }) → proof
   * const { adopt, needsConfirmation } = await client.findOwnPasskeyWallet({
   *   credentialIdHash, rpId, proof,
   * });
   * ```
   *
   * @example Ed25519 lookup
   * ```typescript
   * // Every wallet listing this key — including any a stranger added it to.
   * const records = await client.findWalletsByAuthority(pubkeyBytes, 'ed25519');
   * ```
   */
  async findWalletsByAuthority(
    credential: Uint8Array,
    authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
  ): Promise<WalletAuthorityRecord[]> {
    assertByteLength(credential, 32, 'credential');

    const typeValue =
      authorityType === 'ed25519' ? AUTH_TYPE_ED25519 : AUTH_TYPE_SECP256R1;

    // Filters:
    //   offset 0: discriminator == ACCOUNT_DISCRIMINATOR.AUTHORITY
    //   offset 1: authority_type == typeValue
    //   offset 48: credential bytes match
    const discAndType = Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, typeValue]);

    const accounts = await this.connection.getProgramAccounts(this.programId, {
      encoding: 'base64',
      filters: [
        {
          memcmp: {
            offset: 0,
            bytes: discAndType.toString('base64'),
            encoding: 'base64',
          },
        },
        {
          memcmp: {
            offset: 48,
            bytes: Buffer.from(credential).toString('base64'),
            encoding: 'base64',
          },
        },
      ],
    });

    return accounts.map(({ pubkey: authorityPda, account }) => {
      const data = account.data;
      const walletPda = new PublicKey(data.slice(16, 48));
      const [vaultPda] = this.findVault(walletPda);
      return {
        walletPda,
        authorityPda,
        vaultPda,
        role: data[2],
        authorityType: data[1],
      };
    });
  }

  /**
   * Every wallet on which this passkey is an Owner, created under `rpId` — on
   * this client's program and, unless `includeV1` is `false`, on the v1
   * deployment paired with it (`version: 1`, a wallet not yet migrated). v2
   * hits come first.
   *
   * Nothing here is proven: the credential-id hash is public, and anyone can
   * create a wallet listing it next to their own public key. Keep only the
   * candidates a fresh assertion verifies against ({@link verifyOwnershipProof}),
   * or use {@link findOwnPasskeyWallet}, which does all of it.
   *
   * One `getProgramAccounts` per program, which some RPC providers
   * rate-limit or refuse; use an endpoint that allows it.
   */
  async findPasskeyWalletCandidates(params: {
    credentialIdHash: Uint8Array;
    rpId: string;
    /** Also scan the v1 deployment paired with this client's program. Default `true`. */
    includeV1?: boolean;
  }): Promise<PasskeyWalletCandidate[]> {
    return scanPasskeyWalletCandidates(this.connection, this.programId, params);
  }

  /**
   * Who, besides this passkey, can spend from each candidate: its other
   * authorities, live sessions, pending deferred executions, delegates or
   * foreign close authorities on the vault's token accounts, and whether the
   * vault is still a plain system account — plus the vault balance.
   * `controlledAlone` is true when the vault is a plain system account and
   * every one of the others is trusted.
   *
   * `trustedKeys` are the integrator's own Ed25519 keys (a backend admin, a
   * session key it issued): an authority, session or token grant held by one
   * of them does not count against the wallet. A passkey is never trusted by
   * declaration, and a pending deferred execution never is: the program does
   * not tie it to the key that signed it. Nor does any key make up for a vault
   * handed to another program (`vaultIsSystemAccount: false`).
   *
   * A candidate whose wallet account no longer exists — a migrated v1 wallet
   * leaves its other authorities behind — is left out of the result.
   *
   * `watchMints` are SPL Token mints whose canonical vault token account is
   * checked for a changed owner, on top of wSOL, USDC, USDT and devnet USDC.
   * Pass the mints your app receives: one handed away for any other mint
   * cannot be found.
   *
   * `signatureCount` is how many times this passkey has signed for the
   * wallet. 0 for a wallet someone handed to it, which `controlledAlone`
   * cannot fully vouch for: an SPL Token account moved off the vault is only
   * found for the watched mints. Not proof on its own: a count raised before
   * the passkey challenge named the wallet may hold a signature replayed from
   * another wallet (see {@link pickOwnWallet}).
   *
   * Reads the slot once, then every candidate's wallet account; then per
   * candidate, four at a time, in the order power flows: its authorities;
   * then its sessions and deferred executions; then its wallet account,
   * vault, watched token accounts and the vault's token accounts. Each step
   * asks the RPC for state at least as new as the one before
   * (`minContextSlot`), so a transaction that lands mid-read — a co-owner
   * that opens a session and removes itself, say — cannot be half-seen. A
   * node that has not caught up is asked again, up to five times, then the
   * call throws.
   */
  async describeWalletCandidates(
    candidates: PasskeyWalletCandidate[],
    options?: { trustedKeys?: (PublicKey | string)[]; watchMints?: (PublicKey | string)[] },
  ): Promise<WalletFacts[]> {
    return describePasskeyWallets(this.connection, candidates, options);
  }

  /**
   * Find a returning passkey user's own wallet.
   *
   * Candidates are found by credential-id hash, kept only if `proof` — an
   * assertion over a challenge from {@link createTaggedOwnershipChallenge} —
   * verifies against the key stored on them, and then described. `adopt` is
   * the one proven wallet this passkey has signed for, when nothing untrusted
   * can spend from it; use it. Otherwise `needsConfirmation` lists the proven
   * wallets for the user to choose from (show the vault address; never pick
   * for them). Both empty: this passkey owns no live wallet yet — create one.
   * `unproven` counts wallets that list the credential with some other public
   * key; someone planted them, and they are ignored.
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
   *
   * @example
   * ```typescript
   * const challenge = createTaggedOwnershipChallenge();
   * const credential = await navigator.credentials.get({ publicKey: { challenge, rpId } });
   * const response = credential.response as AuthenticatorAssertionResponse;
   * const { adopt, needsConfirmation } = await client.findOwnPasskeyWallet({
   *   credentialIdHash: sha256(new Uint8Array(credential.rawId)),
   *   rpId,
   *   proof: {
   *     challenge,
   *     signature: new Uint8Array(response.signature),
   *     authenticatorData: new Uint8Array(response.authenticatorData),
   *     clientDataJson: new Uint8Array(response.clientDataJSON),
   *   },
   * });
   * ```
   */
  async findOwnPasskeyWallet(params: {
    credentialIdHash: Uint8Array;
    rpId: string;
    proof: OwnershipProof;
    trustedKeys?: (PublicKey | string)[];
    /** SPL Token mints to check the vault's canonical account of; see describeWalletCandidates. */
    watchMints?: (PublicKey | string)[];
    includeV1?: boolean;
  }): Promise<{
    adopt: WalletFacts | null;
    needsConfirmation: WalletFacts[];
    /** found by hash but not proven */
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
   * Throws unless `owner` is exactly the passkey on this v1 authority — its
   * public key and the relying party it was created under. `migrateV1Wallet`
   * uses `owner` to create or vet the v2 destination, where a wrong rpId would
   * mean a wallet no assertion can ever satisfy.
   */
  private async assertV1PasskeyOwner(authority: PublicKey, owner: CreateWalletOwner): Promise<void> {
    const { secp256r1Pubkey, rpId } = resolveOwnerFields(owner);
    const info = await this.connection.getAccountInfo(authority);
    if (!info) throw new Error(`v1 authority ${authority.toBase58()} not found`);
    const data = info.data;
    if (data.length < 145) throw new Error('the v1 authority is not a passkey authority');
    if (!Buffer.from(data.subarray(80, 113)).equals(Buffer.from(secp256r1Pubkey!))) {
      throw new Error("owner.compressedPubkey is not the v1 authority's public key");
    }
    if (!Buffer.from(data.subarray(113, 145)).equals(Buffer.from(sha256(Buffer.from(rpId ?? '', 'utf8'))))) {
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
   * migration's signature covers. Nor does handing the wallet over with
   * `TransferOwnership` undo what its earlier Owner did to the vault itself:
   * `Assign` it to another program or `Allocate` it data (the vault signs for
   * an Owner's `Execute`), or leave a delegate or a close authority on its
   * token accounts. So the bar is: exactly one authority, which is this key
   * at Owner rank; no session or deferred execution the program would still
   * accept (expiry at or after the current slot); a vault that is a plain
   * system account, or not created yet; and no token account of the vault's
   * with a delegate, a close authority other than the vault, or a canonical
   * account moved to another owner for a watched mint (wSOL, USDC, USDT, devnet
   * USDC, and any in `watchMints`).
   *
   * For a passkey, "this key" means all of it: the credential-id hash, the
   * public key and the relying party. The credential-id hash alone is public —
   * it sits in every authority account the passkey has — and `CreateWallet`
   * takes any owner without its consent, so a wallet with the victim's hash
   * and the attacker's public key would otherwise pass.
   *
   * Passing is not proof the wallet is clean. An earlier holder could have
   * handed an SPL Token account of the vault's, for any mint not watched, to
   * someone else, and nothing on chain leads back to it; senders would still
   * pay into it. Which is why `migrateV1Wallet` reuses a wallet it finds by
   * itself only if it is the one wallet the passkey has signed on.
   *
   * An address that is not a wallet of this program — including one that only
   * holds lamports — fails; `migrateV1Wallet` creates a wallet there instead.
   *
   * Reads in the same order as {@link describeWalletCandidates} — the slot,
   * then the authorities, then sessions and deferred executions, then the
   * wallet account, vault and token accounts — each step at or after the slot
   * of the one before, so no transaction is half-seen.
   *
   * Fails closed: a session or deferred execution too short to read its expiry
   * counts as live, a token account too short to read as a grant.
   */
  async vetMigrationDestination(
    wallet: PublicKey,
    owner: CreateWalletOwner,
    options: { watchMints?: (PublicKey | string)[] } = {},
  ): Promise<string | null> {
    return (await this.inspectMigrationDestination(wallet, owner, watchedMints(options.watchMints))).problem;
  }

  /**
   * {@link vetMigrationDestination}, plus how many times the passkey has signed
   * for the wallet (its authority's replay counter; 0 for an Ed25519 owner,
   * which has none, and whenever there is a problem), and the slot the vet's
   * newest read was answered at: reads that must not see older state (the
   * migration's destination token accounts) are made at or after it.
   */
  private async inspectMigrationDestination(
    wallet: PublicKey,
    owner: CreateWalletOwner,
    mints: PublicKey[],
  ): Promise<{ problem: string | null; signatureCount: number; slot: number }> {
    const { authType, credentialOrPubkey: credential, secp256r1Pubkey, rpId } =
      resolveOwnerFields(owner);
    // The slot first: one older than the scans can only count more things live.
    const slot = BigInt(await this.connection.getSlot());
    const [vault] = this.findVault(wallet);
    const watched = watchedTokenAccounts(vault, mints);
    const read = await readSpendingState(
      this.connection,
      this.programId,
      wallet,
      vault,
      {
        authority: ACCOUNT_DISCRIMINATOR.AUTHORITY,
        session: ACCOUNT_DISCRIMINATOR.SESSION,
        deferred: ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC,
      },
      [wallet, vault, ...watched.map((w) => w.address)],
    );
    const { authorities, sessions, deferred, ownedTokens } = read;
    const [walletInfo, vaultInfo, ...watchedInfos] = read.infos;
    const fail = (problem: string) => ({ problem, signatureCount: 0, slot: read.slot });
    const where = wallet.toBase58();
    if (
      !walletInfo ||
      !walletInfo.owner.equals(this.programId) ||
      walletInfo.data[0] !== ACCOUNT_DISCRIMINATOR.WALLET
    ) {
      return fail(`${where} is not a wallet of program ${this.programId.toBase58()}`);
    }
    if (authorities.length !== 1) {
      return fail(
        `wallet ${where} has ${authorities.length} authorities; a migration destination must have only its owner`,
      );
    }
    const a = authorities[0].account.data;
    if (
      a[1] !== authType ||
      a[2] !== ROLE_OWNER ||
      !Buffer.from(a.subarray(48, 80)).equals(Buffer.from(credential))
    ) {
      return fail(`wallet ${where} is not owned by this key alone`);
    }
    if (
      authType === AUTH_TYPE_SECP256R1 &&
      (!Buffer.from(a.subarray(80, 113)).equals(Buffer.from(secp256r1Pubkey!)) ||
        !Buffer.from(a.subarray(113, 145)).equals(
          Buffer.from(sha256(Buffer.from(rpId ?? '', 'utf8'))),
        ))
    ) {
      return fail(`wallet ${where} lists this passkey's credential with another public key or relying party`);
    }
    // The program refuses a session or deferred execution only once the slot
    // is past its expiry; one too short to read counts as live.
    if (sessions.some((x) => sessionExpiry(x.account.data) >= slot)) {
      return fail(`wallet ${where} has a live session`);
    }
    if (deferred.some((x) => deferredExpiry(x.account.data) >= slot)) {
      return fail(`wallet ${where} has a pending deferred execution`);
    }
    if (!isPlainSystemAccount(vaultInfo)) {
      return fail(
        vaultInfo!.owner.equals(SystemProgram.programId)
          ? `wallet ${where}'s vault ${vault.toBase58()} carries data, so it is no longer a plain system account`
          : `wallet ${where}'s vault ${vault.toBase58()} is owned by program ${vaultInfo!.owner.toBase58()}, not the System Program`,
      );
    }
    const [grant] = vaultTokenGrants(
      vault,
      ownedTokens,
      watched.map((w, i) => ({ ...w, info: watchedInfos[i] })),
      new Set(),
    );
    if (grant) {
      return fail(`wallet ${where}'s vault token account ${grant.tokenAccount.toBase58()} ${grantPhrase(grant)}`);
    }
    // Only the key this authority stores advances its counter (Ed25519 never
    // does); the checks above made that key this passkey.
    return {
      problem: null,
      signatureCount: authType === AUTH_TYPE_SECP256R1 ? Buffer.from(a).readUInt32LE(8) : 0,
      slot: read.slot,
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
  ): Promise<{ walletPda: PublicKey; authorityPda: PublicKey; role: number }[]> {
    const { credentialOrPubkey: credential, secp256r1Pubkey, rpId } = resolveOwnerFields(owner);
    const rpIdHash = Buffer.from(sha256(Buffer.from(rpId ?? '', 'utf8')));
    const accounts = await this.connection.getProgramAccounts(this.programId, {
      encoding: 'base64',
      filters: [
        {
          memcmp: {
            offset: 0,
            bytes: Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, AUTH_TYPE_SECP256R1]).toString('base64'),
            encoding: 'base64',
          },
        },
        { memcmp: { offset: 48, bytes: Buffer.from(credential).toString('base64'), encoding: 'base64' } },
        { memcmp: { offset: 113, bytes: rpIdHash.toString('base64'), encoding: 'base64' } },
      ],
    });
    return accounts
      .filter(
        ({ account: { data } }) =>
          data.length >= 145 &&
          data.subarray(80, 113).equals(Buffer.from(secp256r1Pubkey!)) &&
          data.subarray(113, 145).equals(rpIdHash) &&
          data.readUInt32LE(8) > 0,
      )
      .map(({ pubkey, account: { data } }) => ({
        walletPda: new PublicKey(data.subarray(16, 48)),
        authorityPda: pubkey,
        role: data[2],
      }));
  }

  /**
   * Every authority on a wallet — the data a "your devices" screen is built
   * from. The inverse of {@link findWalletsByAuthority}: that one answers
   * "which wallets does this credential control", this one answers "which keys
   * control this wallet".
   *
   * `policyLen > 0` means the authority is bounded: rank says what it may
   * manage, the policy says what it may spend, and an asset the policy does
   * not name it cannot spend at all. Read the policy itself with
   * `parseActions` over the account bytes after the key material (80 bytes for
   * an Ed25519 authority, 145 for Secp256r1).
   *
   * Note the on-chain record stores the credential id's *hash*, so it cannot
   * rebuild a WebAuthn `allowCredentials` list — keep the raw credential ids
   * alongside, app-side.
   */
  async findAuthoritiesByWallet(walletPda: PublicKey): Promise<
    {
      authorityPda: PublicKey;
      /** 0 = Owner, 1 = Admin, 2 = Delegate. */
      role: number;
      /** 0 = Ed25519, 1 = Secp256r1 (passkey). */
      authorityType: number;
      /** Secp256r1 replay odometer. */
      counter: number;
      /** Bytes of spending policy. 0 = unbounded. */
      policyLen: number;
      /** Convenience: does this authority carry a spending policy? */
      isBounded: boolean;
      /** The raw policy bytes, if any — pass to `parseActions`. */
      policy?: Uint8Array;
    }[]
  > {
    // Filters: offset 0 = Authority discriminator, offset 16 = this wallet.
    const accounts = await this.connection.getProgramAccounts(this.programId, {
      encoding: 'base64',
      filters: [
        {
          memcmp: {
            offset: 0,
            bytes: Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY]).toString('base64'),
            encoding: 'base64',
          },
        },
        {
          memcmp: {
            offset: 16,
            bytes: walletPda.toBuffer().toString('base64'),
            encoding: 'base64',
          },
        },
      ],
    });

    return accounts.map(({ pubkey: authorityPda, account }) => {
      const data = account.data;
      const authorityType = data[1];
      const policyLen = data.readUInt16LE(12);
      // Key material length: Ed25519 pubkey (32) or credential hash + pubkey +
      // rpIdHash (97). The policy follows it.
      const fixedLen = authorityType === AUTH_TYPE_SECP256R1 ? 145 : 80;
      const policy =
        policyLen > 0 && data.length >= fixedLen + policyLen
          ? new Uint8Array(data.subarray(fixedLen, fixedLen + policyLen))
          : undefined;
      return {
        authorityPda,
        role: data[2],
        authorityType,
        counter: data.readUInt32LE(8),
        policyLen,
        isBounded: policyLen > 0,
        policy,
      };
    });
  }

  /**
   * Whether this wallet can survive losing a device.
   *
   * A wallet with a single Owner is **not recoverable**: only an Owner may add
   * or remove an Owner, so if that key is lost no instruction in the program
   * can ever enroll a replacement. An app should surface this *before* the
   * loss, at enrollment time — after it, nothing can be done.
   */
  async getRecoveryStatus(walletPda: PublicKey): Promise<{
    ownerCount: number;
    /** True once a second Owner exists — a surviving Owner can revoke a lost one. */
    isRecoverable: boolean;
  }> {
    const info = await this.connection.getAccountInfo(walletPda);
    if (!info || info.data.length < 8) {
      throw new Error(`Wallet account not found: ${walletPda.toBase58()}`);
    }
    // WalletAccount: disc(1) bump(1) version(1) _pad(1) owner_count(u32)
    const ownerCount = info.data.readUInt32LE(4);
    return { ownerCount, isRecoverable: ownerCount > 1 };
  }

  // ─── CreateWallet ────────────────────────────────────────────────

  /**
   * Create a new LazorKit wallet with the given owner.
   *
   * @example Ed25519 owner
   * ```typescript
   * const { instructions, walletPda, vaultPda } = client.createWallet({
   *   payer: payer.publicKey,
   *   userSeed: randomBytes(32),
   *   owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
   * });
   * ```
   *
   * @example Secp256r1 (passkey) owner
   * ```typescript
   * const { instructions, walletPda, vaultPda } = client.createWallet({
   *   payer: payer.publicKey,
   *   userSeed: randomBytes(32),
   *   owner: {
   *     type: 'secp256r1',
   *     credentialIdHash,
   *     compressedPubkey,
   *     rpId: 'example.com',
   *   },
   * });
   * ```
   */
  async createWallet(params: {
    payer: PublicKey;
    userSeed: Uint8Array;
    owner: CreateWalletOwner;
  }): Promise<{
    instructions: TransactionInstruction[];
    /** The wallet's identity PDA. It holds configuration, **never funds** —
     *  no instruction can sign for it to move value, so anything sent here is
     *  unrecoverable. Show `depositAddress` to users, not this. */
    walletPda: PublicKey;
    /** The vault PDA — the wallet's balance. This is the ONLY address that may
     *  receive SOL or tokens. Also returned as `depositAddress`. */
    vaultPda: PublicKey;
    /** Alias for `vaultPda`, named for the one thing it is safe to do with an
     *  address: give it out. */
    depositAddress: PublicKey;
    authorityPda: PublicKey;
  }> {
    assertByteLength(params.userSeed, 32, 'userSeed');
    const [walletPda] = this.findWallet(params.userSeed);
    const [vaultPda] = this.findVault(walletPda);
    const { authType, credentialOrPubkey, secp256r1Pubkey, rpId } =
      resolveOwnerFields(params.owner);
    const [authorityPda, authBump] = this.findAuthority(
      walletPda,
      credentialOrPubkey,
    );

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
    return {
      instructions,
      walletPda,
      vaultPda,
      depositAddress: vaultPda,
      authorityPda,
    };
  }

  // ─── AddAuthority (unified) ─────────────────────────────────────

  /**
   * Add a new authority to the wallet.
   *
   * @example Add Ed25519 admin via Ed25519 owner
   * ```typescript
   * const { instructions, newAuthorityPda } = await client.addAuthority({
   *   payer: payer.publicKey,
   *   walletPda,
   *   adminSigner: ed25519(ownerKp.publicKey),
   *   newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
   *   role: ROLE_ADMIN,
   * });
   * ```
   *
   * @example Add Secp256r1 spender via Secp256r1 owner
   * ```typescript
   * const { instructions, newAuthorityPda } = await client.addAuthority({
   *   payer: payer.publicKey,
   *   walletPda,
   *   adminSigner: secp256r1(ceoSigner),
   *   newAuthority: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
   *   role: ROLE_SPENDER,
   * });
   * ```
   */
  async addAuthority(params: {
    payer: PublicKey;
    walletPda: PublicKey;
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
  }): Promise<{
    instructions: TransactionInstruction[];
    newAuthorityPda: PublicKey;
  }> {
    assertAddAuthorityRole(params.role, params.allowOwner, params.policy);
    const {
      authType: newType,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
    } = resolveOwnerFields(params.newAuthority);
    const [newAuthorityPda] = this.findAuthority(
      params.walletPda,
      credentialOrPubkey,
    );
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const ix = createAddAuthorityIx({
      policy: params.policy,
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: this.resolveEd25519AuthorityPda(s, params.walletPda),
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

    // Secp256r1 — delegate to prepare/finalize. `policy` and `allowOwner` must
    // be forwarded: dropping `policy` writes an authority with an empty action
    // buffer, which for an Admin is an unbounded authority the caller believed
    // was capped, and dropping `allowOwner` makes enrolling a second Owner —
    // the only recovery path a passkey user has — impossible.
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

  // ─── RemoveAuthority (unified) ──────────────────────────────────

  async removeAuthority(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    adminSigner: AdminSigner;
    targetAuthorityPda: PublicKey;
    refundDestination?: PublicKey;
  }): Promise<{ instructions: TransactionInstruction[] }> {
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const ix = createRemoveAuthorityIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: this.resolveEd25519AuthorityPda(s, params.walletPda),
        targetAuthorityPda: params.targetAuthorityPda,
        refundDestination: refundDest,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix] };
    }

    // Secp256r1 — delegate to prepare/finalize
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

  // ─── TransferOwnership (unified) ────────────────────────────────

  /**
   * Transfer wallet ownership to a new authority.
   *
   * @example Transfer to new Secp256r1 owner
   * ```typescript
   * const { instructions } = await client.transferOwnership({
   *   payer: payer.publicKey,
   *   walletPda,
   *   ownerSigner: secp256r1(ceoSigner),
   *   newOwner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
   * });
   * ```
   */
  async transferOwnership(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    ownerSigner: AdminSigner;
    newOwner: CreateWalletOwner;
    /** Where the current owner account's rent goes. Defaults to payer if omitted. */
    refundDestination?: PublicKey;
  }): Promise<{
    instructions: TransactionInstruction[];
    newOwnerAuthorityPda: PublicKey;
  }> {
    const {
      authType: newType,
      credentialOrPubkey,
      secp256r1Pubkey,
      rpId,
    } = resolveOwnerFields(params.newOwner);
    const [newOwnerAuthorityPda] = this.findAuthority(
      params.walletPda,
      credentialOrPubkey,
    );
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.ownerSigner;

    if (s.type === 'ed25519') {
      const ix = createTransferOwnershipIx({
        payer: params.payer,
        walletPda: params.walletPda,
        currentOwnerAuthorityPda: this.resolveEd25519AuthorityPda(s, params.walletPda),
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

    // Secp256r1 — delegate to prepare/finalize
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

  // ─── CreateSession (unified) ────────────────────────────────────

  /**
   * Create a session key for the wallet.
   *
   * @example
   * ```typescript
   * const { instructions, sessionPda } = await client.createSession({
   *   payer: payer.publicKey,
   *   walletPda,
   *   adminSigner: ed25519(ownerKp.publicKey),
   *   sessionKey: sessionKp.publicKey,
   *   expiresAt: currentSlot + 9000n,
   * });
   * ```
   */
  async createSession(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    adminSigner: AdminSigner;
    sessionKey: PublicKey;
    expiresAt: bigint;
    /** Actions bounding what this session may spend. An asset they do not
     *  name cannot leave the vault: with no `Sol*` action no SOL can (rent the
     *  vault pays included), and each mint needs a `Token*` action. Omitting
     *  them creates an UNRESTRICTED session and requires `unrestricted: true`. */
    actions?: SessionAction[];
    /** Opt in to a session with no actions — see `actions`. */
    unrestricted?: boolean;
  }): Promise<{
    instructions: TransactionInstruction[];
    sessionPda: PublicKey;
  }> {
    assertSessionActions(params.actions, params.unrestricted);
    const sessionKeyBytes = params.sessionKey.toBytes();
    const [sessionPda] = this.findSession(params.walletPda, sessionKeyBytes);
    const s = params.adminSigner;
    const actionsBuffer =
      params.actions && params.actions.length > 0
        ? serializeActions(params.actions)
        : undefined;

    if (s.type === 'ed25519') {
      const ix = createCreateSessionIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: this.resolveEd25519AuthorityPda(s, params.walletPda),
        sessionPda,
        sessionKey: sessionKeyBytes,
        expiresAt: params.expiresAt,
        actionsBuffer,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix], sessionPda };
    }

    // Secp256r1 — delegate to prepare/finalize
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

  // ─── Execute (unified, accepts standard TransactionInstructions) ─

  /**
   * Execute arbitrary Solana instructions via the wallet.
   *
   * Works with any signer type: Ed25519, Secp256r1 (passkey), or Session key.
   * Pass standard `TransactionInstruction[]` — the SDK handles compact encoding,
   * account indexing, and signing automatically.
   *
   * @example
   * ```typescript
   * const [vault] = client.findVault(walletPda);
   * const { instructions } = await client.execute({
   *   payer: payer.publicKey,
   *   walletPda,
   *   signer: secp256r1(mySigner),
   *   instructions: [
   *     SystemProgram.transfer({ fromPubkey: vault, toPubkey: recipient, lamports: 1_000_000 }),
   *   ],
   * });
   * await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer]);
   * ```
   */
  async execute(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    signer: ExecuteSigner;
    instructions: TransactionInstruction[];
    /** Passkey signers: the fee payer, when it is not `payer` (see `prepareExecute`). */
    feePayer?: PublicKey;
  }): Promise<{ instructions: TransactionInstruction[] }> {
    const [vaultPda] = this.findVault(params.walletPda);
    const s = params.signer;
    const fee = await this.resolveProtocolFeeWithRegister(params.payer);
    const protocolFee = fee?.accounts;
    const head: TransactionInstruction[] = fee?.registerIx ? [fee.registerIx] : [];

    switch (s.type) {
      case 'ed25519': {
        const authorityPda = this.resolveEd25519AuthorityPda(s, params.walletPda);
        // Ed25519: signer at index 4 (program expects it there)
        const fixedAccounts = [
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
        // Delegate to prepare/finalize (which handles its own auto-register)
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
        // Session: sessionKey as signer is included in fixed accounts for index mapping
        const fixedAccounts = [
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

        // Session key must be prepended to remaining accounts as a signer
        const sessionKeyMeta = {
          pubkey: s.sessionKeyPubkey,
          isSigner: true,
          isWritable: false,
        };
        const allRemaining = [sessionKeyMeta, ...remainingAccounts];

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

  // ─── TransferSol (convenience) ──────────────────────────────────

  /**
   * Transfer SOL from the wallet vault to a recipient.
   * Works with any signer type.
   *
   * @example
   * ```typescript
   * const { instructions } = await client.transferSol({
   *   payer: payer.publicKey,
   *   walletPda,
   *   signer: secp256r1(mySigner),
   *   recipient: destination,
   *   lamports: 1_000_000n,
   * });
   * ```
   */
  async transferSol(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    signer: ExecuteSigner;
    recipient: PublicKey;
    lamports: bigint | number;
  }): Promise<{ instructions: TransactionInstruction[] }> {
    const [vaultPda] = this.findVault(params.walletPda);
    const amount =
      typeof params.lamports === 'bigint'
        ? Number(params.lamports)
        : params.lamports;

    return this.execute({
      payer: params.payer,
      walletPda: params.walletPda,
      signer: params.signer,
      instructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: params.recipient,
          lamports: amount,
        }),
      ],
    });
  }

  // ─── Authorize (deferred execution TX1) ─────────────────────────

  /**
   * Authorize deferred execution. Pass standard TransactionInstructions
   * — the SDK handles compact encoding and hash computation.
   *
   * Returns pre-computed `deferredPayload` for TX2.
   */
  async authorize(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    signer: Secp256r1SignerConfig;
    /** Standard instructions to defer */
    instructions: TransactionInstruction[];
    /** Expiry offset in slots (default 300 = ~2 minutes) */
    expiryOffset?: number;
    /** Who will send TX2, when not `payer` (see `prepareAuthorize`). */
    executor?: PublicKey;
    /** TX2's fee payer, when not the executor (see `prepareAuthorize`). */
    feePayer?: PublicKey;
  }): Promise<{
    instructions: TransactionInstruction[];
    deferredExecPda: PublicKey;
    counter: number;
    deferredPayload: DeferredPayload;
  }> {
    // Delegate to prepare/finalize
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
    return this.finalizeAuthorize(prepared, {
      signature: response.signature,
      authenticatorData: response.authenticatorData,
      clientDataJsonHash: response.clientDataJsonHash,
      clientDataJson: response.clientDataJson,
    });
  }

  // ─── ExecuteDeferred (from payload) ─────────────────────────────

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
    payer: PublicKey;
    deferredPayload: DeferredPayload;
    refundDestination?: PublicKey;
  }): Promise<{ instructions: TransactionInstruction[] }> {
    const { executor } = params.deferredPayload;
    if (
      executor &&
      !executor.equals(params.payer) &&
      namesDeferredPayerSlot(params.deferredPayload.compactInstructions)
    ) {
      throw new Error(
        `This authorization was signed for ${executor.toBase58()} to send ExecuteDeferred, ` +
          `and an inner instruction names tx2's payer or refund destination, whose flags ` +
          `depend on who sends it. Sent by ${params.payer.toBase58()} it would fail with ` +
          `DeferredHashMismatch (3015). Send it from ${executor.toBase58()}, or authorize ` +
          `again with executor: ${params.payer.toBase58()}.`,
      );
    }
    const [vaultPda] = this.findVault(params.deferredPayload.walletPda);
    const refundDest =
      params.refundDestination ?? params.deferredPayload.refundDestination ?? params.payer;
    const packed = packCompactInstructions(
      params.deferredPayload.compactInstructions,
    );
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

  // ─── ReclaimDeferred ────────────────────────────────────────────

  reclaimDeferred(params: {
    payer: PublicKey;
    deferredExecPda: PublicKey;
    refundDestination?: PublicKey;
  }): { instructions: TransactionInstruction[] } {
    const ix = createReclaimDeferredIx({
      payer: params.payer,
      deferredExecPda: params.deferredExecPda,
      refundDestination: params.refundDestination ?? params.payer,
      programId: this.programId,
    });
    return { instructions: [ix] };
  }

  // ─── RevokeSession ─────────────────────────────────────────────

  /**
   * Revoke a session key early (before expiry).
   * Only Owner or Admin can revoke. Refunds session rent.
   *
   * @example Revoke with Ed25519 admin
   * ```typescript
   * const { instructions } = await client.revokeSession({
   *   payer: payer.publicKey,
   *   walletPda,
   *   adminSigner: ed25519(adminKp.publicKey, adminAuthorityPda),
   *   sessionPda,
   * });
   * ```
   */
  async revokeSession(params: {
    payer: PublicKey;
    walletPda: PublicKey;
    adminSigner: AdminSigner;
    sessionPda: PublicKey;
    refundDestination?: PublicKey;
  }): Promise<{ instructions: TransactionInstruction[] }> {
    const refundDest = params.refundDestination ?? params.payer;
    const s = params.adminSigner;

    if (s.type === 'ed25519') {
      const ix = createRevokeSessionIx({
        payer: params.payer,
        walletPda: params.walletPda,
        adminAuthorityPda: this.resolveEd25519AuthorityPda(s, params.walletPda),
        sessionPda: params.sessionPda,
        refundDestination: refundDest,
        authorizerSigner: s.publicKey,
        programId: this.programId,
      });
      return { instructions: [ix] };
    }

    // Secp256r1 — delegate to prepare/finalize
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

  // ─── Protocol Fee Management ──────────────────────────────────────

  /** Initialize protocol fee configuration (one-time) */
  initializeProtocol(params: {
    payer: PublicKey;
    admin: PublicKey;
    treasury: PublicKey;
    creationFee: bigint;
    executionFee: bigint;
    numShards: number;
  }): { instructions: TransactionInstruction[]; protocolConfigPda: PublicKey } {
    const [protocolConfigPda] = this.findProtocolConfig();
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

  /** Update protocol fee configuration */
  updateProtocol(params: {
    admin: PublicKey;
    creationFee: bigint;
    executionFee: bigint;
    enabled: boolean;
    newTreasury: PublicKey;
  }): { instructions: TransactionInstruction[] } {
    const [protocolConfigPda] = this.findProtocolConfig();
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

  /** Initialize a treasury shard (call once per shard 0..numShards-1) */
  initializeTreasuryShard(params: {
    payer: PublicKey;
    admin: PublicKey;
    shardId: number;
  }): { instructions: TransactionInstruction[]; treasuryShardPda: PublicKey } {
    const [protocolConfigPda] = this.findProtocolConfig();
    const [treasuryShardPda] = this.findTreasuryShard(params.shardId);
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

  /**
   * Register a payer for fee-stats tracking. Permissionless: the payer
   * registers themselves (no admin signature required). Idempotent at the
   * SDK level — the fee-eligible builders auto-prepend this only when the
   * FeeRecord doesn't yet exist, so most apps never need to call it directly.
   */
  registerPayer(params: {
    payer: PublicKey;
  }): { instructions: TransactionInstruction[]; feeRecordPda: PublicKey } {
    const [feeRecordPda] = this.findFeeRecord(params.payer);
    const ix = createRegisterPayerIx({
      payer: params.payer,
      feeRecordPda,
      programId: this.programId,
    });
    return { instructions: [ix], feeRecordPda };
  }

  /** Withdraw accumulated fees from a treasury shard */
  withdrawTreasury(params: {
    admin: PublicKey;
    shardId: number;
    treasury: PublicKey;
  }): { instructions: TransactionInstruction[] } {
    const [protocolConfigPda] = this.findProtocolConfig();
    const [treasuryShardPda] = this.findTreasuryShard(params.shardId);
    const ix = createWithdrawTreasuryIx({
      admin: params.admin,
      protocolConfigPda,
      treasuryShardPda,
      treasury: params.treasury,
      programId: this.programId,
    });
    return { instructions: [ix] };
  }

  /**
   * Find this owner's v1 wallets on-chain, with no user seed — the path for a
   * user whose browser storage is gone. See {@link findV1WalletsByOwner}.
   */
  async findV1WalletsByOwner(
    ownerIdSeed: Uint8Array,
    authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
    /** Where the v1 wallets live. Defaults to the v1 deployment paired with this client's program. */
    v1ProgramId: PublicKey = legacyProgramIdFor(this.programId),
  ): Promise<V1WalletRecord[]> {
    return findV1WalletsByOwner(this.connection, ownerIdSeed, v1ProgramId, authorityType);
  }

  /**
   * Orchestrate a full v1 -> v2 migration for one wallet, authorized by the v1
   * owner. Returns the setup instructions (create the v2 wallet if it does not
   * exist yet, and a destination token account for every token being moved) and
   * the MigrateWallet step.
   *
   * `setupInstructions` must land before the migrate, in the same transaction
   * or an earlier one:
   *  - Ed25519: send `migrate.instructions` (any fee harvests, then the
   *    migrate), signed by the payer and the owner key.
   *  - Secp256r1: have the passkey sign `migrate.challenge`, pass the WebAuthn
   *    response to `migrate.finalize`, and send what it returns
   *    (`[...harvests, precompile, migrate]`).
   * One transaction makes the two succeed or fail together; prefer it when
   * everything fits. Sent separately, the migrate goes only after the setup
   * transaction is confirmed *successful*: what the owner signs names the
   * destination vault, not who owns its wallet, so if someone else's
   * `CreateWallet` at that seed lands first, the setup fails and a migrate
   * sent anyway pays into their vault.
   *
   * Identify the v1 wallet in one of two ways:
   *  - `userSeed`, when the app still has the seed the wallet was created with.
   *  - `v1Wallet`, the wallet address itself, for a user whose seed is gone.
   *    Find it with {@link findV1WalletsByOwner}. The program never needs the
   *    seed: it takes the v1 wallet as an account and derives the vault from
   *    that key.
   *
   * The v2 destination follows: with `userSeed` it is that seed's wallet;
   * otherwise an existing v2 wallet is reused only if this owner is a passkey
   * that has already signed for it — and on no other authority of this
   * program, at any rank — and if there is none a fresh one is created from
   * `destinationUserSeed` or a random seed. An Ed25519 owner's
   * wallets are never reused this way (its authority records no signatures);
   * name one with `destinationUserSeed`. A wallet is only ever used if this
   * owner holds it alone (see {@link vetMigrationDestination}); a `userSeed` or
   * `destinationUserSeed` wallet that fails that throws. An address holding
   * nothing but lamports is not a wallet yet, and one is created there.
   * The seed used is returned as `destinationUserSeed` when one was generated,
   * so the caller can persist it.
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
   * Only an Owner-rank v1 authority may migrate; throws otherwise, or if no v1
   * wallet is found. Every vault-owned token account (SPL Token and Token-2022)
   * that can move is migrated in one call; frozen accounts, transfer-hook mints
   * and `excludeTokenAccounts` come back in `skippedTokens` instead. A
   * destination token account that already exists must be the v2 vault's
   * alone — owned by it, with no delegate and no close authority but the
   * vault — or this throws, naming it: whoever holds such a right would get
   * what is delivered there.
   */
  async migrateV1Wallet(params: {
    payer: PublicKey;
    owner: CreateWalletOwner;
    /** The seed the v1 wallet was created with, when the app still has it. */
    userSeed?: Uint8Array;
    /** The v1 wallet address, for a wallet whose seed is gone. */
    v1Wallet?: PublicKey;
    /** Seed for the v2 wallet, when one has to be created. Defaults to random. */
    destinationUserSeed?: Uint8Array;
    /**
     * The program that owns the v1 wallet. The migration executes there — it is
     * the only program that can sign for the v1 vault — and delivers to a v2
     * wallet at this client's own program id. Defaults to the v1 deployment
     * paired with this client's program; set it for a non-standard pairing.
     */
    v1ProgramId?: PublicKey;
    /** Vault token accounts to leave behind, e.g. ones the user marked as spam. */
    excludeTokenAccounts?: PublicKey[];
    /**
     * SPL Token mints whose canonical account in an existing destination vault
     * is checked for a changed owner, on top of wSOL, USDC, USDT and devnet
     * USDC; see vetMigrationDestination. The mints this migration moves are
     * checked regardless.
     */
    watchMints?: (PublicKey | string)[];
    /**
     * Where the rent of every closed v1 account goes: the wallet, the authority
     * and each emptied token account. Defaults to `payer`, which paid for the
     * setup; pass the new vault to hand it to the user instead. It is part of
     * what the owner signs, so a relayer cannot change it.
     */
    refundDestination?: PublicKey;
    /**
     * Passkey owner only: read the v1 authority's counter and the challenge
     * slot from a node at or past this slot. See
     * {@link Secp256r1Params.minContextSlot}.
     */
    minContextSlot?: number;
    /**
     * Passkey owner only: commitment for those two reads (default
     * `'confirmed'`, or `'processed'` on a Connection at `'processed'`). The
     * migration's other reads are unaffected.
     */
    commitment?: Commitment;
  }): Promise<{
    v1: V1Accounts;
    destinationWallet: PublicKey;
    /** Set only when this call had to mint a fresh seed — persist it. */
    destinationUserSeed?: Uint8Array;
    v2Vault: PublicKey;
    /** The token accounts this migration moves. */
    tokens: V1VaultToken[];
    /**
     * Token accounts it cannot move, and why. They stay in the v1 vault and
     * become unreachable once the v1 id runs the sunset binary — show them to
     * the user before they sign.
     */
    skippedTokens: { token: V1VaultToken; reason: UnmovableReason }[];
    setupInstructions: TransactionInstruction[];
    migrate:
      | {
          type: 'ed25519';
          /** The MigrateWallet instruction alone. */
          instruction: TransactionInstruction;
          /** What to send, in one transaction: any fee harvests, then MigrateWallet. */
          instructions: TransactionInstruction[];
        }
      | {
          type: 'secp256r1';
          challenge: Uint8Array;
          finalize: (response: WebAuthnResponse) => TransactionInstruction[];
        };
  }> {
    const { authType, credentialOrPubkey } = resolveOwnerFields(params.owner);
    // Everything on the v1 side — its PDAs, the instruction, the passkey
    // challenge — belongs to the v1 program. Everything on the v2 side belongs
    // to this client's program. When the two ids coincide (staging, a local
    // rehearsal) this is the in-place layout and nothing changes.
    const v1ProgramId = params.v1ProgramId ?? legacyProgramIdFor(this.programId);
    const retired = [PROGRAM_ID_MAINNET_V1, PROGRAM_ID_DEVNET_V1].filter(
      (id) => !id.equals(PROGRAM_ID_MAINNET) && !id.equals(PROGRAM_ID_DEVNET),
    );
    if (retired.some((id) => id.equals(this.programId))) {
      throw new Error(
        `this client is built at ${this.programId.toBase58()}, a retired v1 deployment. ` +
          'Build it at the v2 program id: the migration runs at the v1 id but must deliver to v2.',
      );
    }

    let v1: V1Accounts;
    if (params.v1Wallet) {
      const [vault] = findV1VaultPda(params.v1Wallet, v1ProgramId);
      const [authority] = findV1AuthorityPda(params.v1Wallet, credentialOrPubkey, v1ProgramId);
      v1 = { wallet: params.v1Wallet, vault, authority };
    } else if (params.userSeed) {
      v1 = deriveV1Accounts(params.userSeed, credentialOrPubkey, v1ProgramId);
    } else {
      throw new Error(
        'migrateV1Wallet needs either userSeed or v1Wallet. A wallet created by ' +
          '@lazorkit/wallet used a random seed that lived in browser storage, so for ' +
          'most users the seed is gone: find the wallet with findV1WalletsByOwner and ' +
          'pass v1Wallet instead.',
      );
    }

    const state = await readV1WalletState(this.connection, v1);
    if (!state) {
      throw new Error(
        params.v1Wallet
          ? `no v1 wallet at ${v1.wallet.toBase58()} for this owner`
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

    // Where the funds land. With a seed, the destination is that seed's wallet.
    // Without one, reuse the v2 wallet this passkey has signed for, and only
    // mint a seed when there is none.
    //
    // Why "signed for": anyone can hand a wallet to this owner with
    // TransferOwnership (its key is public) after using the vault as they
    // liked, and vetting cannot see all of it — an SPL Token account moved off
    // the vault is only found for a watched mint. A passkey signs only
    // for a wallet its user chose, and its authority's counter records that.
    // An Ed25519 authority keeps no such record, so for one nothing is reused.
    //
    // Why "the": until the program named the wallet in the passkey challenge,
    // a signature for CreateSession, AddAuthority, TransferOwnership or
    // Authorize made on one authority of this key could be replayed on another
    // at the same counter, raising it too, and counts from then are still on
    // chain. With two signed-on authorities — at any rank, since an Admin
    // seat's signature replayed onto an Owner's — either could be the copy,
    // and a fresh wallet is the safe answer.
    const mints = watchedMints(params.watchMints);
    let v2Wallet: PublicKey | undefined;
    let destinationUserSeed: Uint8Array | undefined;
    /** Once `v2Wallet` has passed the vet: the slot its newest read was answered at. */
    let vettedAt: number | undefined;
    if (params.userSeed) {
      [v2Wallet] = this.findWallet(params.userSeed);
    } else {
      if (authType === AUTH_TYPE_SECP256R1) {
        const signed = await this.signedPasskeyAuthorities(params.owner);
        if (signed.length === 1 && signed[0].role === ROLE_OWNER) {
          const vet = await this.inspectMigrationDestination(signed[0].walletPda, params.owner, mints);
          if (!vet.problem && vet.signatureCount > 0) {
            v2Wallet = signed[0].walletPda;
            vettedAt = vet.slot;
          }
        }
      }
      if (!v2Wallet) {
        destinationUserSeed = params.destinationUserSeed ?? randomBytes(32);
        [v2Wallet] = this.findWallet(destinationUserSeed);
      }
    }
    // A seed's address holds nothing, bare lamports (anyone can send them to
    // a PDA; CreateWallet tops the balance up and takes the account), or a
    // wallet. The v1 CreateWallet instruction made the userSeed public, so a
    // wallet there may be anyone's: vet it. Otherwise create one — never
    // deliver into the vault of a wallet that does not exist yet, which
    // whoever creates it at that public seed would own.
    let createV2Wallet = false;
    if (vettedAt === undefined) {
      if (isPlainSystemAccount(await this.connection.getAccountInfo(v2Wallet))) {
        createV2Wallet = true;
      } else {
        const vet = await this.inspectMigrationDestination(v2Wallet, params.owner, mints);
        if (vet.problem) {
          const which = params.userSeed ? 'userSeed' : 'destinationUserSeed';
          throw new Error(`refusing to migrate into the ${which}'s v2 wallet: ${vet.problem}`);
        }
        vettedAt = vet.slot;
      }
    }
    const [v2Vault] = this.findVault(v2Wallet);

    const classified = await classifyV1VaultTokens(
      this.connection,
      await enumerateV1VaultTokens(this.connection, v1.vault),
      params.excludeTokenAccounts,
    );
    // The destination side, now that the vault is known. An existing frozen
    // destination account makes the transfer fail; an existing thawed one
    // means a mint that freezes new accounts is no obstacle after all. For a
    // wallet that passed the vet, read no older state than the vet did — a
    // stale node could still show a destination account before it was rigged.
    const destOf = (t: V1VaultToken) => getAssociatedTokenAddress(t.mint, v2Vault, t.tokenProgram);
    const toCheck = [...classified.movable, ...classified.skipped.filter((s) => s.reason === 'frozen-on-arrival').map((s) => s.token)];
    const destState = new Map<string, 'frozen' | 'open'>();
    const destInfo = new Map<string, AccountInfo<Buffer>>();
    for (let i = 0; i < toCheck.length; i += 100) {
      const page = toCheck.slice(i, i + 100);
      const { infos } = await readAccounts(this.connection, page.map(destOf), vettedAt);
      infos.forEach((info, j) => {
        // Nothing there, or bare lamports: the idempotent create below makes a
        // fresh account, the vault's alone (and frozen, for a mint that
        // freezes new accounts).
        if (isPlainSystemAccount(info)) return;
        destState.set(page[j].ata.toBase58(), tokenAccountFrozen(info!.data) ? 'frozen' : 'open');
        destInfo.set(page[j].ata.toBase58(), info!);
      });
    }
    const tokens: V1VaultToken[] = [];
    const skippedTokens = classified.skipped.filter((s) => s.reason !== 'frozen-on-arrival');
    for (const t of classified.movable) {
      if (destState.get(t.ata.toBase58()) === 'frozen') skippedTokens.push({ token: t, reason: 'destination-frozen' });
      else tokens.push(t);
    }
    for (const s of classified.skipped.filter((s) => s.reason === 'frozen-on-arrival')) {
      if (destState.get(s.token.ata.toBase58()) === 'open') tokens.push(s.token);
      else skippedTokens.push(s);
    }
    // Every existing account the migration delivers into must be the v2
    // vault's alone. A wallet can be handed to this owner (TransferOwnership
    // asks the new owner nothing) with its vault's token accounts rigged: one
    // given to another owner, or carrying a delegate or close authority that
    // would take what arrives. The program checks the owner, not the rest.
    // Refuse rather than skip: a skipped token is stranded once the v1 vault
    // closes.
    const rigged = tokens.flatMap((t) => {
      const dest = destInfo.get(t.ata.toBase58());
      const problem = dest && tokenAccountProblem(destOf(t), dest, v2Vault, t.tokenProgram);
      return problem ? [`${destOf(t).toBase58()} (mint ${t.mint.toBase58()}) ${problem}`] : [];
    });
    if (rigged.length > 0) {
      const named = rigged.slice(0, 3).join('; ');
      const more = rigged.length > 3 ? `; and ${rigged.length - 3} more` : '';
      throw new Error(
        `refusing to migrate into ${v2Wallet.toBase58()}: destination token account ${named}${more}`,
      );
    }
    if (tokens.length > 255) {
      throw new Error(`the v1 vault holds ${tokens.length} token accounts; one migration moves at most 255`);
    }

    const setupInstructions: TransactionInstruction[] = [];
    if (createV2Wallet) {
      // Only a seed's address is ever created: the userSeed's, or the one
      // minted (or given) above.
      const created = await this.createWallet({
        payer: params.payer,
        userSeed: params.userSeed ?? destinationUserSeed!,
        owner: params.owner,
      });
      setupInstructions.push(...created.instructions);
    }
    const migrateTokens = tokens.map((t) => {
      const destAta = getAssociatedTokenAddress(t.mint, v2Vault, t.tokenProgram);
      setupInstructions.push(
        createAssociatedTokenAccountIdempotentIx({
          payer: params.payer,
          ata: destAta,
          owner: v2Vault,
          mint: t.mint,
          tokenProgram: t.tokenProgram,
        }),
      );
      return { sourceAta: t.ata, destAta, mint: t.mint, tokenProgram: t.tokenProgram };
    });

    // signed_payload = destination || v1_wallet || num_tokens || refund_dest
    //                  || source_ata[0] || … || source_ata[n-1]
    // The trailing source ATAs bind WHICH token accounts move, not just how many
    // — without them a relayer could keep the count and swap in dust it created,
    // stranding the user's real tokens when the vault closes. Order must match
    // the program's read order (the migrateTokens order used to build the ix).
    // Withheld Token-2022 fees stop a source account from closing; harvesting
    // them to the mint needs no signer. Done in the migration's own
    // transaction, so none can be planted in between.
    const withheldByMint = new Map<string, PublicKey[]>();
    for (const t of tokens) {
      if (!t.withheldFees) continue;
      const key = t.mint.toBase58();
      withheldByMint.set(key, [...(withheldByMint.get(key) ?? []), t.ata]);
    }
    const harvestInstructions = [...withheldByMint].map(([mint, sources]) =>
      harvestWithheldIx(new PublicKey(mint), sources),
    );

    const refundDestination = params.refundDestination ?? params.payer;
    const signedPayload = concatBytes([
      v2Vault.toBytes(),
      v1.wallet.toBytes(),
      Uint8Array.from([tokens.length]),
      refundDestination.toBytes(),
      ...migrateTokens.map((t) => t.sourceAta.toBytes()),
    ]);

    if (authType === AUTH_TYPE_ED25519) {
      const instruction = createMigrateWalletIx({
        payer: params.payer,
        v1Wallet: v1.wallet,
        v1Authority: v1.authority,
        v1Vault: v1.vault,
        destination: v2Vault,
        refundDestination,
        authSigner: (params.owner as { publicKey: PublicKey }).publicKey,
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

    // Secp256r1 passkey.
    const owner = params.owner as { compressedPubkey: Uint8Array };
    const reads: ChallengeReadOptions = {
      commitment: params.commitment,
      minContextSlot: params.minContextSlot,
    };
    // The key is the caller's, so only the counter and the slot are read.
    const { counter, slot } = await readChallengeInputs(this.connection, v1.authority, reads, {
      publicKeyBytes: owner.compressedPubkey,
    });
    const prepared = prepareSecp256r1({
      discriminator: Uint8Array.from([DISC_MIGRATE_WALLET]),
      signedPayload,
      sysvarIxIndex: 7,
      slot,
      counter,
      payer: params.payer,
      // The authority signing is the v1 one, and the challenge names the
      // wallet in its header: the v1 wallet, not the v2 destination.
      wallet: v1.wallet,
      // The challenge binds the program that verifies it, which is the one the
      // migration executes in — the v1 program, not this client's.
      programId: v1ProgramId,
      publicKeyBytes: owner.compressedPubkey,
    });
    const finalize = (response: WebAuthnResponse): TransactionInstruction[] => {
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

/** Options for {@link LazorKitClient}. */
export interface LazorKitClientOptions {
  /**
   * Append the `[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]` suffix
   * to fee-eligible instructions (CreateWallet, Execute, ExecuteDeferred).
   * Default `true` — this program requires the suffix on those instructions
   * even when no fee is charged. Set `false` only for a build without the fee
   * layer.
   */
  protocolFees?: boolean;
}
