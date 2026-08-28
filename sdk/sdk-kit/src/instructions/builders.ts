/**
 * Hand-written LazorKit instruction builders for the kit (web3.js v2) flavor.
 *
 * Each builder produces the exact raw binary format the on-chain program
 * expects. Layouts mirror sdk-legacy/src/utils/instructions.ts byte-for-byte;
 * tests/instructions.test.ts proves cross-SDK parity on canonical fixtures.
 *
 * Why hand-written (not generated): the program uses a custom binary format
 * for several fields (e.g. raw-bytes auth payload, no length prefix on
 * compact_instructions) that codegen frameworks cannot express without
 * custom plugins.
 */
import {
  AccountRole,
  getAddressEncoder,
  type Address,
  type AccountMeta,
  type Instruction,
} from '@solana/kit';
import {
  SECP256R1_PROGRAM_ADDRESS,
  SYSTEM_PROGRAM_ADDRESS,
  SYSVAR_INSTRUCTIONS_ADDRESS,
  SYSVAR_RENT_ADDRESS,
} from './system.js';

// ─── Discriminators ──────────────────────────────────────────────────
export const DISC_CREATE_WALLET = 0;
export const DISC_ADD_AUTHORITY = 1;
export const DISC_REMOVE_AUTHORITY = 2;
export const DISC_TRANSFER_OWNERSHIP = 3;
export const DISC_EXECUTE = 4;
export const DISC_CREATE_SESSION = 5;
export const DISC_AUTHORIZE = 6;
export const DISC_EXECUTE_DEFERRED = 7;
export const DISC_RECLAIM_DEFERRED = 8;
export const DISC_REVOKE_SESSION = 9;
export const DISC_INITIALIZE_PROTOCOL = 10;
export const DISC_UPDATE_PROTOCOL = 11;
export const DISC_REGISTER_PAYER = 12;
export const DISC_WITHDRAW_TREASURY = 13;
export const DISC_INITIALIZE_TREASURY_SHARD = 14;
export const DISC_PROPOSE_PROTOCOL_ADMIN = 15;
export const DISC_ACCEPT_PROTOCOL_ADMIN = 16;

// ─── Authority types ─────────────────────────────────────────────────
export const AUTH_TYPE_ED25519 = 0;
export const AUTH_TYPE_SECP256R1 = 1;

// ─── Roles ───────────────────────────────────────────────────────────
export const ROLE_OWNER = 0;
export const ROLE_ADMIN = 1;
export const ROLE_SPENDER = 2;

// Re-export for convenience.
export { SECP256R1_PROGRAM_ADDRESS };

// ─── Internal byte helpers ───────────────────────────────────────────

const addressEncoder = getAddressEncoder();

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

function u16LE(value: number): Uint8Array {
  const buf = new Uint8Array(2);
  buf[0] = value & 0xff;
  buf[1] = (value >> 8) & 0xff;
  return buf;
}

function u64LE(value: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, value, /* le */ true);
  return buf;
}

function i64LE(value: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigInt64(0, value, /* le */ true);
  return buf;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function meta(
  address: Address,
  role: AccountRole,
): AccountMeta {
  return { address, role };
}

const RW = AccountRole.WRITABLE;
const RO = AccountRole.READONLY;
const SIGNER_RO = AccountRole.READONLY_SIGNER;
const SIGNER_RW = AccountRole.WRITABLE_SIGNER;

/** Append the four trailing protocol-fee accounts required by the strict commercial binary. */
export function appendProtocolFeeAccounts(
  accounts: AccountMeta[],
  protocolConfigPda: Address,
  feeRecordPda: Address,
  treasuryShardPda: Address,
): void {
  accounts.push(
    meta(protocolConfigPda, RO),
    meta(feeRecordPda, RW),
    meta(treasuryShardPda, RW),
    meta(SYSTEM_PROGRAM_ADDRESS, RO),
  );
}

export interface ProtocolFeeAccounts {
  protocolConfigPda: Address;
  feeRecordPda: Address;
  treasuryShardPda: Address;
}

// ─── CreateWallet ────────────────────────────────────────────────────

export function createCreateWalletIx(params: {
  payer: Address;
  walletPda: Address;
  vaultPda: Address;
  authorityPda: Address;
  userSeed: Uint8Array;
  authType: number;
  authBump: number;
  /** Ed25519: 32-byte pubkey. Secp256r1: 32-byte credential_id_hash */
  credentialOrPubkey: Uint8Array;
  /** Secp256r1 only: 33-byte compressed pubkey. */
  secp256r1Pubkey?: Uint8Array;
  /** Secp256r1 only: RP ID string (stored on-chain). */
  rpId?: string;
  protocolFee?: ProtocolFeeAccounts;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_CREATE_WALLET]),
    params.userSeed,
    new Uint8Array([params.authType, params.authBump]),
    new Uint8Array(6), // padding
    params.credentialOrPubkey,
  ];
  if (params.authType === AUTH_TYPE_SECP256R1 && params.secp256r1Pubkey) {
    parts.push(params.secp256r1Pubkey);
    if (params.rpId) {
      const rp = utf8(params.rpId);
      parts.push(new Uint8Array([rp.length]), rp);
    }
  }

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RW),
    meta(params.walletPda, RW),
    meta(params.vaultPda, RW),
    meta(params.authorityPda, RW),
    meta(SYSTEM_PROGRAM_ADDRESS, RO),
    meta(SYSVAR_RENT_ADDRESS, RO),
  ];
  if (params.protocolFee) {
    appendProtocolFeeAccounts(
      accounts,
      params.protocolFee.protocolConfigPda,
      params.protocolFee.feeRecordPda,
      params.protocolFee.treasuryShardPda,
    );
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── AddAuthority ────────────────────────────────────────────────────

export function createAddAuthorityIx(params: {
  payer: Address;
  walletPda: Address;
  adminAuthorityPda: Address;
  newAuthorityPda: Address;
  newType: number;
  newRole: number;
  credentialOrPubkey: Uint8Array;
  secp256r1Pubkey?: Uint8Array;
  rpId?: string;
  /** Action buffer bounding what this authority may spend. Required for
   *  ROLE_DELEGATE; optional for Owner and Admin. */
  policy?: Uint8Array;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_ADD_AUTHORITY]),
    new Uint8Array([params.newType, params.newRole]),
    new Uint8Array(6),
    params.credentialOrPubkey,
  ];
  if (params.newType === AUTH_TYPE_SECP256R1 && params.secp256r1Pubkey) {
    parts.push(params.secp256r1Pubkey);
    if (params.rpId) {
      const rp = utf8(params.rpId);
      parts.push(new Uint8Array([rp.length]), rp);
    }
  }
  // `[policy_len u16 LE][policy]` between the key material and the auth
  // payload. Always emitted, even when empty, because the program treats these
  // two bytes as part of the signed region — omitting them for a policy-less
  // authority would make the client's challenge and the program's disagree.
  const policy = params.policy ?? new Uint8Array(0);
  const policyLen = new Uint8Array(2);
  new DataView(policyLen.buffer).setUint16(0, policy.length, true);
  parts.push(policyLen, policy);

  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.adminAuthorityPda, RW),
    meta(params.newAuthorityPda, RW),
    meta(SYSTEM_PROGRAM_ADDRESS, RO),
    meta(SYSVAR_RENT_ADDRESS, RO),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── RemoveAuthority ─────────────────────────────────────────────────

export function createRemoveAuthorityIx(params: {
  payer: Address;
  walletPda: Address;
  adminAuthorityPda: Address;
  targetAuthorityPda: Address;
  refundDestination: Address;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [new Uint8Array([DISC_REMOVE_AUTHORITY])];
  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.adminAuthorityPda, RW),
    meta(params.targetAuthorityPda, RW),
    meta(params.refundDestination, RW),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── TransferOwnership ──────────────────────────────────────────────

export function createTransferOwnershipIx(params: {
  payer: Address;
  walletPda: Address;
  currentOwnerAuthorityPda: Address;
  newOwnerAuthorityPda: Address;
  refundDestination: Address;
  newType: number;
  credentialOrPubkey: Uint8Array;
  secp256r1Pubkey?: Uint8Array;
  rpId?: string;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_TRANSFER_OWNERSHIP]),
    new Uint8Array([params.newType]),
    params.credentialOrPubkey,
  ];
  if (params.newType === AUTH_TYPE_SECP256R1 && params.secp256r1Pubkey) {
    parts.push(params.secp256r1Pubkey);
    if (params.rpId) {
      const rp = utf8(params.rpId);
      parts.push(new Uint8Array([rp.length]), rp);
    }
  }
  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.currentOwnerAuthorityPda, RW),
    meta(params.newOwnerAuthorityPda, RW),
    meta(params.refundDestination, RW),
    meta(SYSTEM_PROGRAM_ADDRESS, RO),
    meta(SYSVAR_RENT_ADDRESS, RO),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── Execute ─────────────────────────────────────────────────────────

export function createExecuteIx(params: {
  payer: Address;
  walletPda: Address;
  authorityPda: Address;
  vaultPda: Address;
  packedInstructions: Uint8Array;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  remainingAccounts?: AccountMeta[];
  protocolFee?: ProtocolFeeAccounts;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_EXECUTE]),
    params.packedInstructions,
  ];
  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.authorityPda, RW),
    meta(params.vaultPda, RW),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }
  if (params.remainingAccounts) accounts.push(...params.remainingAccounts);
  if (params.protocolFee) {
    appendProtocolFeeAccounts(
      accounts,
      params.protocolFee.protocolConfigPda,
      params.protocolFee.feeRecordPda,
      params.protocolFee.treasuryShardPda,
    );
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── CreateSession ───────────────────────────────────────────────────

export function createCreateSessionIx(params: {
  payer: Address;
  walletPda: Address;
  adminAuthorityPda: Address;
  sessionPda: Address;
  sessionKey: Uint8Array;
  expiresAt: bigint;
  actionsBuffer?: Uint8Array;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_CREATE_SESSION]),
    params.sessionKey,
    i64LE(params.expiresAt),
  ];

  const actionsBuffer = params.actionsBuffer ?? new Uint8Array(0);
  parts.push(u16LE(actionsBuffer.length));
  if (actionsBuffer.length > 0) parts.push(actionsBuffer);

  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.adminAuthorityPda, RW),
    meta(params.sessionPda, RW),
    meta(SYSTEM_PROGRAM_ADDRESS, RO),
    meta(SYSVAR_RENT_ADDRESS, RO),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── Authorize (deferred-execution tx 1 of 2) ───────────────────────

export function createAuthorizeIx(params: {
  payer: Address;
  walletPda: Address;
  authorityPda: Address;
  deferredExecPda: Address;
  instructionsHash: Uint8Array;
  accountsHash: Uint8Array;
  expiryOffset: number;
  authPayload: Uint8Array;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_AUTHORIZE]),
    params.instructionsHash,
    params.accountsHash,
    u16LE(params.expiryOffset),
    params.authPayload,
  ];

  return {
    programAddress: params.programId,
    accounts: [
      meta(params.payer, SIGNER_RW),
      meta(params.walletPda, RO),
      meta(params.authorityPda, RW),
      meta(params.deferredExecPda, RW),
      meta(SYSTEM_PROGRAM_ADDRESS, RO),
      meta(SYSVAR_RENT_ADDRESS, RO),
      meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO),
    ],
    data: concatBytes(parts),
  };
}

// ─── ExecuteDeferred (deferred-execution tx 2 of 2) ─────────────────

export function createExecuteDeferredIx(params: {
  payer: Address;
  walletPda: Address;
  vaultPda: Address;
  deferredExecPda: Address;
  refundDestination: Address;
  packedInstructions: Uint8Array;
  remainingAccounts?: AccountMeta[];
  protocolFee?: ProtocolFeeAccounts;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_EXECUTE_DEFERRED]),
    params.packedInstructions,
  ];

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RW),
    meta(params.walletPda, RO),
    meta(params.vaultPda, RW),
    meta(params.deferredExecPda, RW),
    meta(params.refundDestination, RW),
  ];
  if (params.remainingAccounts) accounts.push(...params.remainingAccounts);
  if (params.protocolFee) {
    appendProtocolFeeAccounts(
      accounts,
      params.protocolFee.protocolConfigPda,
      params.protocolFee.feeRecordPda,
      params.protocolFee.treasuryShardPda,
    );
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── ReclaimDeferred ────────────────────────────────────────────────

export function createReclaimDeferredIx(params: {
  payer: Address;
  deferredExecPda: Address;
  refundDestination: Address;
  programId: Address;
}): Instruction {
  return {
    programAddress: params.programId,
    accounts: [
      meta(params.payer, SIGNER_RO),
      meta(params.deferredExecPda, RW),
      meta(params.refundDestination, RW),
    ],
    data: new Uint8Array([DISC_RECLAIM_DEFERRED]),
  };
}

// ─── RevokeSession ──────────────────────────────────────────────────

export function createRevokeSessionIx(params: {
  payer: Address;
  walletPda: Address;
  adminAuthorityPda: Address;
  sessionPda: Address;
  refundDestination: Address;
  authPayload?: Uint8Array;
  authorizerSigner?: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [new Uint8Array([DISC_REVOKE_SESSION])];
  if (params.authPayload) parts.push(params.authPayload);

  const accounts: AccountMeta[] = [
    meta(params.payer, SIGNER_RO),
    meta(params.walletPda, RO),
    meta(params.adminAuthorityPda, RW),
    meta(params.sessionPda, RW),
    meta(params.refundDestination, RW),
  ];
  if (params.authorizerSigner) {
    accounts.push(meta(params.authorizerSigner, SIGNER_RO));
  } else if (params.authPayload) {
    accounts.push(meta(SYSVAR_INSTRUCTIONS_ADDRESS, RO));
  }

  return {
    programAddress: params.programId,
    accounts,
    data: concatBytes(parts),
  };
}

// ─── InitializeProtocol ─────────────────────────────────────────────

export function createInitializeProtocolIx(params: {
  payer: Address;
  protocolConfigPda: Address;
  admin: Address;
  treasury: Address;
  creationFee: bigint;
  executionFee: bigint;
  numShards: number;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_INITIALIZE_PROTOCOL]),
    addressEncoder.encode(params.admin) as Uint8Array,
    addressEncoder.encode(params.treasury) as Uint8Array,
    u64LE(params.creationFee),
    u64LE(params.executionFee),
    new Uint8Array([params.numShards]),
  ];

  return {
    programAddress: params.programId,
    accounts: [
      meta(params.payer, SIGNER_RW),
      meta(params.protocolConfigPda, RW),
      meta(SYSTEM_PROGRAM_ADDRESS, RO),
      meta(SYSVAR_RENT_ADDRESS, RO),
    ],
    data: concatBytes(parts),
  };
}

// ─── UpdateProtocol ─────────────────────────────────────────────────

export function createUpdateProtocolIx(params: {
  admin: Address;
  protocolConfigPda: Address;
  creationFee: bigint;
  executionFee: bigint;
  enabled: boolean;
  newTreasury: Address;
  programId: Address;
}): Instruction {
  const parts: Uint8Array[] = [
    new Uint8Array([DISC_UPDATE_PROTOCOL]),
    u64LE(params.creationFee),
    u64LE(params.executionFee),
    new Uint8Array([params.enabled ? 1 : 0]),
    new Uint8Array(7),
    addressEncoder.encode(params.newTreasury) as Uint8Array,
  ];

  return {
    programAddress: params.programId,
    accounts: [
      meta(params.admin, SIGNER_RO),
      meta(params.protocolConfigPda, RW),
    ],
    data: concatBytes(parts),
  };
}

// ─── RegisterPayer ──────────────────────────────────────────────────

export function createRegisterPayerIx(params: {
  payer: Address;
  feeRecordPda: Address;
  programId: Address;
}): Instruction {
  return {
    programAddress: params.programId,
    accounts: [
      meta(params.payer, SIGNER_RW),
      meta(params.feeRecordPda, RW),
      meta(SYSTEM_PROGRAM_ADDRESS, RO),
      meta(SYSVAR_RENT_ADDRESS, RO),
    ],
    data: new Uint8Array([DISC_REGISTER_PAYER]),
  };
}

// ─── WithdrawTreasury ───────────────────────────────────────────────

export function createWithdrawTreasuryIx(params: {
  admin: Address;
  protocolConfigPda: Address;
  treasuryShardPda: Address;
  treasury: Address;
  programId: Address;
}): Instruction {
  return {
    programAddress: params.programId,
    accounts: [
      meta(params.admin, SIGNER_RO),
      meta(params.protocolConfigPda, RO),
      meta(params.treasuryShardPda, RW),
      meta(params.treasury, RW),
      meta(SYSVAR_RENT_ADDRESS, RO),
    ],
    data: new Uint8Array([DISC_WITHDRAW_TREASURY]),
  };
}

// ─── InitializeTreasuryShard ────────────────────────────────────────

export function createInitializeTreasuryShardIx(params: {
  payer: Address;
  protocolConfigPda: Address;
  admin: Address;
  treasuryShardPda: Address;
  shardId: number;
  programId: Address;
}): Instruction {
  return {
    programAddress: params.programId,
    accounts: [
      meta(params.payer, SIGNER_RW),
      meta(params.protocolConfigPda, RO),
      meta(params.admin, SIGNER_RO),
      meta(params.treasuryShardPda, RW),
      meta(SYSTEM_PROGRAM_ADDRESS, RO),
      meta(SYSVAR_RENT_ADDRESS, RO),
    ],
    data: new Uint8Array([DISC_INITIALIZE_TREASURY_SHARD, params.shardId]),
  };
}
