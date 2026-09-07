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
import { randomFillSync } from 'node:crypto';
import {
  AccountRole,
  getAddressEncoder,
  type AccountMeta,
  type Address,
  type Base58EncodedBytes,
  type GetAccountInfoApi,
  type GetProgramAccountsApi,
  type GetSlotApi,
  type Instruction,
  type Rpc,
} from '@solana/kit';
import { ACCOUNT_DISCRIMINATOR } from './constants.js';
import bs58 from 'bs58';

const bs58Encode = (b: Uint8Array): string => bs58.encode(b);
import { PROGRAM_ID_DEVNET, PROGRAM_ID_MAINNET } from './constants.js';
import { serializeActions, type SessionAction } from './codecs/actions.js';
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  DISC_ADD_AUTHORITY,
  DISC_AUTHORIZE,
  DISC_CREATE_SESSION,
  DISC_EXECUTE,
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
  createReclaimDeferredIx,
  createRegisterPayerIx,
  createRemoveAuthorityIx,
  createRevokeSessionIx,
  createTransferOwnershipIx,
  createUpdateProtocolIx,
  createWithdrawTreasuryIx,
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
  finalizeSecp256r1,
  prepareSecp256r1,
  buildDataPayloadForAdd,
  buildDataPayloadForSession,
  buildDataPayloadForTransfer,
  type PreparedSecp256r1,
} from './secp256r1/signing.js';
import {
  readAuthorityCounter,
  readAuthorityPubkey,
} from './secp256r1/secp256r1.js';
import {
  buildCompactLayout,
  computeAccountsHash,
  computeInstructionsHash,
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

// ─── Sysvar instruction indexes (auto-computed from account layouts) ──

const SYSVAR_IX_INDEX_ADD_AUTHORITY = 6;
const SYSVAR_IX_INDEX_REMOVE_AUTHORITY = 5;
const SYSVAR_IX_INDEX_TRANSFER_OWNERSHIP = 7;
const SYSVAR_IX_INDEX_EXECUTE = 4;
const SYSVAR_IX_INDEX_CREATE_SESSION = 6;
const SYSVAR_IX_INDEX_AUTHORIZE = 6;
const SYSVAR_IX_INDEX_REVOKE_SESSION = 5;

// ─── Prepared types (Secp256r1 prepare/finalize flow) ────────────────

interface PreparedBase {
  /** SHA-256 challenge to pass to navigator.credentials.get(). */
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

/// A session with no actions is not "a session with no limits" — it is a key
/// with *more* power over the vault than a bounded Delegate. The action buffer
/// is what switches on the vault invariants the program checks after the CPI
/// (lamport delta, owner, data length, and the token-authority snapshot), so an
/// empty buffer disables all of them: such a key can reassign the vault or seize
/// its token accounts. That is a deliberate capability, never a default, so it
/// has to be asked for by name.
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

/** RPC capability bag the client needs. Use kit's `createSolanaRpc(url)`. */
export type LazorKitRpc = Rpc<GetAccountInfoApi & GetSlotApi & GetProgramAccountsApi>;

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

  constructor(rpc: LazorKitRpc, programId: Address) {
    this.rpc = rpc;
    this.programId = programId;
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
    const data = new Uint8Array(Buffer.from(info.value.data[0], 'base64'));
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
   * Returns the four fee accounts required by fee-eligible instructions when
   * protocol fees are initialized and enabled. The FeeRecord address is always
   * canonical for the payer, and the program requires every successful fee
   * payment to update that record.
   */
  async resolveProtocolFee(payer: Address): Promise<ProtocolFeeAccounts | undefined> {
    const config = await this.getProtocolConfig();
    if (!config || !config.enabled) return undefined;
    const [protocolConfigPda] = await this.findProtocolConfig();
    const [feeRecordPda] = await this.findFeeRecord(payer);
    const randBuf = new Uint8Array(4);
    randomFillSync(randBuf);
    const randU32 =
      (randBuf[0]! | (randBuf[1]! << 8) | (randBuf[2]! << 16) | (randBuf[3]! << 24)) >>> 0;
    const shardId = randU32 % config.numShards;
    const [treasuryShardPda] = await this.findTreasuryShard(shardId);
    return { protocolConfigPda, feeRecordPda, treasuryShardPda };
  }

  async resolveProtocolFeeWithRegister(
    payer: Address,
  ): Promise<{ accounts: ProtocolFeeAccounts; registerIx?: Instruction } | undefined> {
    const accounts = await this.resolveProtocolFee(payer);
    if (!accounts) return undefined;

    if (this._registeredPayers.has(payer)) return { accounts };

    const info = await this.rpc.getAccountInfo(accounts.feeRecordPda, { encoding: 'base64' }).send();
    let exists = false;
    if (info.value) {
      const data = new Uint8Array(Buffer.from(info.value.data[0], 'base64'));
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

  async readCounter(authorityPda: Address): Promise<number> {
    return readAuthorityCounter(this.rpc, authorityPda);
  }

  // ─── Secp256r1 prepare/finalize plumbing ─────────────────────────

  private async resolveSecp256r1(walletPda: Address, p: Secp256r1Params) {
    assertByteLength(p.credentialIdHash, 32, 'credentialIdHash');
    if (p.publicKeyBytes) assertByteLength(p.publicKeyBytes, 33, 'publicKeyBytes');
    const authorityPda =
      p.authorityPda ?? (await this.findAuthority(walletPda, p.credentialIdHash))[0];

    const [publicKeyBytes, slot, counter] = await Promise.all([
      p.publicKeyBytes
        ? Promise.resolve(p.publicKeyBytes)
        : readAuthorityPubkey(this.rpc, authorityPda),
      p.slotOverride != null
        ? Promise.resolve(p.slotOverride)
        : this.rpc
            .getSlot()
            .send()
            .then((s) => BigInt(s)),
      this.readCounter(authorityPda).then((c) => c + 1),
    ]);

    return { authorityPda, publicKeyBytes, slot, counter };
  }

  private extractSecp256r1Params(s: Secp256r1SignerConfig): Secp256r1Params {
    return {
      credentialIdHash: s.signer.credentialIdHash,
      publicKeyBytes: s.signer.publicKeyBytes,
      authorityPda: s.authorityPda,
      slotOverride: s.slotOverride,
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
    publicKeyBytes: Uint8Array;
  }): PreparedSecp256r1 {
    return prepareSecp256r1({
      discriminator: new Uint8Array([args.discriminator]),
      signedPayload: args.signedPayload,
      sysvarIxIndex: args.sysvarIxIndex,
      slot: args.slot,
      counter: args.counter,
      payer: args.payer,
      programId: this.programId,
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
    const allAccountMetas = [...fixedAccounts, ...remainingAccounts];
    const accountsHash = computeAccountsHash(allAccountMetas, compactInstructions);
    return { compactInstructions, remainingAccounts, allAccountMetas, accountsHash };
  }

  // ─── Wallet lookup ───────────────────────────────────────────────

  async findWalletsByAuthority(
    credential: Uint8Array,
    authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
  ): Promise<WalletAuthorityRecord[]> {
    assertByteLength(credential, 32, 'credential');
    const typeValue = authorityType === 'ed25519' ? AUTH_TYPE_ED25519 : AUTH_TYPE_SECP256R1;
    const discAndType = Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, typeValue]);

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
              bytes: bs58Encode(Buffer.from(credential)) as Base58EncodedBytes,
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
      const data = new Uint8Array(Buffer.from(account.data[0], 'base64'));
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
     *  carry one, so a policy always means a bounded spender. */
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
     *  carry one, so a policy always means a bounded spender. */
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
    /** Actions bounding what this session may spend. Omitting them creates an
     *  UNRESTRICTED session and requires `unrestricted: true`. */
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
    /** Actions bounding what this session may spend. Omitting them creates an
     *  UNRESTRICTED session and requires `unrestricted: true`. */
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
  }): Promise<PreparedExecute> {
    const [vaultPda] = await this.findVault(params.walletPda);
    const [resolved, fee] = await Promise.all([
      this.resolveSecp256r1(params.walletPda, params.secp256r1),
      this.resolveProtocolFeeWithRegister(params.payer),
    ]);
    const { authorityPda, publicKeyBytes, slot, counter } = resolved;
    const protocolFee = fee?.accounts;
    const registerIx = fee?.registerIx;

    const SYSVAR_INSTRUCTIONS_ADDRESS = (await import('./instructions/system.js')).SYSVAR_INSTRUCTIONS_ADDRESS;
    const fixedAccounts: AccountMeta[] = [
      { address: params.payer, role: AccountRole.READONLY_SIGNER },
      { address: params.walletPda, role: AccountRole.READONLY },
      { address: authorityPda, role: AccountRole.WRITABLE },
      { address: vaultPda, role: AccountRole.WRITABLE },
      { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
    ];
    const { compactInstructions, remainingAccounts, accountsHash } =
      this.buildCompactLayoutAndHash(fixedAccounts, params.instructions, params.payer);
    const packed = packCompactInstructions(compactInstructions);
    const signedPayload = concatBytes([packed, accountsHash]);

    const signing = this.buildPasskeySigning({
      discriminator: DISC_EXECUTE,
      sysvarIxIndex: SYSVAR_IX_INDEX_EXECUTE,
      signedPayload,
      slot,
      counter,
      payer: params.payer,
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
    });
    const response = await s.signer.sign(prepared.challenge);
    return this.finalizeAuthorize(prepared, response);
  }

  async prepareAuthorize(params: {
    payer: Address;
    walletPda: Address;
    secp256r1: Secp256r1Params;
    instructions: Instruction[];
    expiryOffset?: number;
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

    const fixedAccounts: AccountMeta[] = [
      { address: params.payer, role: AccountRole.WRITABLE_SIGNER },
      { address: params.walletPda, role: AccountRole.WRITABLE },
      { address: vaultPda, role: AccountRole.WRITABLE },
      { address: deferredExecPda, role: AccountRole.WRITABLE },
      { address: params.payer, role: AccountRole.WRITABLE },
    ];
    const { compactInstructions, remainingAccounts, accountsHash } =
      this.buildCompactLayoutAndHash(fixedAccounts, params.instructions, params.payer);
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
      publicKeyBytes,
    });

    return {
      challenge: signing.challenge,
      deferredExecPda,
      counter,
      _internal: {
        signing,
        payer: params.payer,
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
      },
    };
  }

  async executeDeferredFromPayload(params: {
    payer: Address;
    deferredPayload: DeferredPayload;
    refundDestination?: Address;
  }): Promise<{ instructions: Instruction[] }> {
    const [vaultPda] = await this.findVault(params.deferredPayload.walletPda);
    const refundDest = params.refundDestination ?? params.payer;
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
