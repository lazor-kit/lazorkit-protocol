// Instruction-builder parity test against sdk-legacy.
//
// For each on-chain instruction the SDK supports, both flavors must
// produce:
//   1. Byte-identical instruction data (the program reads this raw).
//   2. Equivalent account ordering (same addresses in the same positions).
//   3. Equivalent account roles (READONLY vs WRITABLE vs *_SIGNER) — kit
//      uses an AccountRole enum, sdk-legacy uses {isSigner, isWritable}
//      booleans. We map between them and check both shapes encode the
//      same on-chain meta.
//
// If parity holds across this suite, the on-chain program cannot tell
// the difference between transactions assembled with kit vs. legacy.

import { describe, it, expect } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import {
  AccountRole,
  address,
  type Address,
  type AccountMeta,
} from '@solana/kit';

// kit (this package)
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
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
} from '../src/instructions/builders.js';

// sdk-legacy (sibling package)
import {
  createAddAuthorityIx as legacyAddAuthorityIx,
  createAuthorizeIx as legacyAuthorizeIx,
  createCreateSessionIx as legacyCreateSessionIx,
  createCreateWalletIx as legacyCreateWalletIx,
  createExecuteDeferredIx as legacyExecuteDeferredIx,
  createExecuteIx as legacyExecuteIx,
  createInitializeProtocolIx as legacyInitProtocolIx,
  createInitializeTreasuryShardIx as legacyInitTreasuryShardIx,
  createReclaimDeferredIx as legacyReclaimDeferredIx,
  createRegisterPayerIx as legacyRegisterPayerIx,
  createRemoveAuthorityIx as legacyRemoveAuthorityIx,
  createRevokeSessionIx as legacyRevokeSessionIx,
  createTransferOwnershipIx as legacyTransferOwnershipIx,
  createUpdateProtocolIx as legacyUpdateProtocolIx,
  createWithdrawTreasuryIx as legacyWithdrawTreasuryIx,
} from '../../sdk-legacy/src/utils/instructions.js';

// ─── Fixtures ────────────────────────────────────────────────────────

const PROGRAM = '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS';
const PAYER = '11111111111111111111111111111112';
const WALLET = 'So11111111111111111111111111111111111111112';
const VAULT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const AUTHORITY = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';
const NEW_AUTHORITY = 'orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE';
const SESSION = 'SysvarRent111111111111111111111111111111111';
const REFUND = 'StakeConfig11111111111111111111111111111111';
const ADMIN = 'Stake11111111111111111111111111111111111111';
const TREASURY = 'Vote111111111111111111111111111111111111111';
const PROTOCOL_CONFIG = 'BPFLoaderUpgradeab1e11111111111111111111111';
const FEE_RECORD = 'BPFLoader2111111111111111111111111111111111';
const TREASURY_SHARD = 'BPFLoader1111111111111111111111111111111111';

const KIT = (s: string): Address => address(s);
const PK = (s: string): PublicKey => new PublicKey(s);

const userSeed = new Uint8Array(32).fill(0xa5);
const ed25519Pubkey = new Uint8Array(32).fill(0x11);
const credIdHash = new Uint8Array(32).fill(0xab);
const secp256r1Pubkey = new Uint8Array(33).fill(0xcc);
const sessionKey = new Uint8Array(32).fill(0xdd);
const authPayload = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x42, 0x42]);
const packedInstructions = new Uint8Array(64).fill(0x77);
const instructionsHash = new Uint8Array(32).fill(0x01);
const accountsHash = new Uint8Array(32).fill(0x02);

// ─── Helpers ─────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

interface LegacyAccountMeta {
  pubkey: PublicKey;
  isSigner: boolean;
  isWritable: boolean;
}

interface LegacyTxIx {
  programId: PublicKey;
  keys: LegacyAccountMeta[];
  data: Buffer;
}

function expectAccountsParity(
  kitAccounts: readonly AccountMeta[],
  legacyKeys: readonly LegacyAccountMeta[],
): void {
  expect(kitAccounts.length).toBe(legacyKeys.length);
  for (let i = 0; i < kitAccounts.length; i++) {
    const k = kitAccounts[i]!;
    const l = legacyKeys[i]!;
    expect(k.address).toBe(l.pubkey.toBase58());
    const isSigner =
      k.role === AccountRole.READONLY_SIGNER ||
      k.role === AccountRole.WRITABLE_SIGNER;
    const isWritable =
      k.role === AccountRole.WRITABLE ||
      k.role === AccountRole.WRITABLE_SIGNER;
    expect(isSigner).toBe(l.isSigner);
    expect(isWritable).toBe(l.isWritable);
  }
}

function expectIxParity(
  kit: { programAddress: Address; accounts: readonly AccountMeta[]; data?: Uint8Array | undefined },
  legacy: LegacyTxIx,
): void {
  expect(kit.programAddress).toBe(legacy.programId.toBase58());
  expectAccountsParity(kit.accounts, legacy.keys);
  expect(kit.data).toBeDefined();
  expect(bytesEqual(kit.data!, new Uint8Array(legacy.data))).toBe(true);
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('createCreateWallet — Ed25519, no fee', () => {
  it('byte-parity', () => {
    const kit = createCreateWalletIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      vaultPda: KIT(VAULT),
      authorityPda: KIT(AUTHORITY),
      userSeed,
      authType: AUTH_TYPE_ED25519,
      authBump: 254,
      credentialOrPubkey: ed25519Pubkey,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyCreateWalletIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      vaultPda: PK(VAULT),
      authorityPda: PK(AUTHORITY),
      userSeed,
      authType: AUTH_TYPE_ED25519,
      authBump: 254,
      credentialOrPubkey: ed25519Pubkey,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createCreateWallet — Secp256r1 with rpId + fee accts', () => {
  it('byte-parity', () => {
    const fee = {
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      feeRecordPda: KIT(FEE_RECORD),
      treasuryShardPda: KIT(TREASURY_SHARD),
    };
    const kit = createCreateWalletIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      vaultPda: KIT(VAULT),
      authorityPda: KIT(AUTHORITY),
      userSeed,
      authType: AUTH_TYPE_SECP256R1,
      authBump: 251,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      protocolFee: fee,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyCreateWalletIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      vaultPda: PK(VAULT),
      authorityPda: PK(AUTHORITY),
      userSeed,
      authType: AUTH_TYPE_SECP256R1,
      authBump: 251,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      protocolFee: {
        protocolConfigPda: PK(PROTOCOL_CONFIG),
        feeRecordPda: PK(FEE_RECORD),
        treasuryShardPda: PK(TREASURY_SHARD),
      },
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createAddAuthority — Ed25519 admin adding new Ed25519 spender', () => {
  it('byte-parity', () => {
    const kit = createAddAuthorityIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      adminAuthorityPda: KIT(AUTHORITY),
      newAuthorityPda: KIT(NEW_AUTHORITY),
      newType: AUTH_TYPE_ED25519,
      newRole: ROLE_SPENDER,
      credentialOrPubkey: ed25519Pubkey,
      authorizerSigner: KIT(ADMIN),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyAddAuthorityIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      adminAuthorityPda: PK(AUTHORITY),
      newAuthorityPda: PK(NEW_AUTHORITY),
      newType: AUTH_TYPE_ED25519,
      newRole: ROLE_SPENDER,
      credentialOrPubkey: ed25519Pubkey,
      authorizerSigner: PK(ADMIN),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createAddAuthority — Secp256r1 admin adding Secp256r1 spender', () => {
  it('byte-parity', () => {
    const kit = createAddAuthorityIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      adminAuthorityPda: KIT(AUTHORITY),
      newAuthorityPda: KIT(NEW_AUTHORITY),
      newType: AUTH_TYPE_SECP256R1,
      newRole: ROLE_SPENDER,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      authPayload,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyAddAuthorityIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      adminAuthorityPda: PK(AUTHORITY),
      newAuthorityPda: PK(NEW_AUTHORITY),
      newType: AUTH_TYPE_SECP256R1,
      newRole: ROLE_SPENDER,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      authPayload,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createRemoveAuthority — Secp256r1 path', () => {
  it('byte-parity', () => {
    const kit = createRemoveAuthorityIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      adminAuthorityPda: KIT(AUTHORITY),
      targetAuthorityPda: KIT(NEW_AUTHORITY),
      refundDestination: KIT(REFUND),
      authPayload,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyRemoveAuthorityIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      adminAuthorityPda: PK(AUTHORITY),
      targetAuthorityPda: PK(NEW_AUTHORITY),
      refundDestination: PK(REFUND),
      authPayload,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createTransferOwnership — Ed25519 → Secp256r1 with rpId', () => {
  it('byte-parity', () => {
    const kit = createTransferOwnershipIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      currentOwnerAuthorityPda: KIT(AUTHORITY),
      newOwnerAuthorityPda: KIT(NEW_AUTHORITY),
      refundDestination: KIT(REFUND),
      newType: AUTH_TYPE_SECP256R1,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      authorizerSigner: KIT(ADMIN),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyTransferOwnershipIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      currentOwnerAuthorityPda: PK(AUTHORITY),
      newOwnerAuthorityPda: PK(NEW_AUTHORITY),
      refundDestination: PK(REFUND),
      newType: AUTH_TYPE_SECP256R1,
      credentialOrPubkey: credIdHash,
      secp256r1Pubkey,
      rpId: 'lazor.dev',
      authorizerSigner: PK(ADMIN),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createExecute — Secp256r1 with remaining accts + fee', () => {
  it('byte-parity', () => {
    const remainingKit: AccountMeta[] = [
      { address: KIT(REFUND), role: AccountRole.WRITABLE },
    ];
    const remainingLegacy = [
      { pubkey: PK(REFUND), isSigner: false, isWritable: true },
    ];
    const fee = {
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      feeRecordPda: KIT(FEE_RECORD),
      treasuryShardPda: KIT(TREASURY_SHARD),
    };
    const kit = createExecuteIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      authorityPda: KIT(AUTHORITY),
      vaultPda: KIT(VAULT),
      packedInstructions,
      authPayload,
      remainingAccounts: remainingKit,
      protocolFee: fee,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyExecuteIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      authorityPda: PK(AUTHORITY),
      vaultPda: PK(VAULT),
      packedInstructions,
      authPayload,
      remainingAccounts: remainingLegacy,
      protocolFee: {
        protocolConfigPda: PK(PROTOCOL_CONFIG),
        feeRecordPda: PK(FEE_RECORD),
        treasuryShardPda: PK(TREASURY_SHARD),
      },
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createCreateSession — with action buffer', () => {
  it('byte-parity', () => {
    const actionsBuffer = new Uint8Array(43).fill(0x55);
    const kit = createCreateSessionIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      adminAuthorityPda: KIT(AUTHORITY),
      sessionPda: KIT(SESSION),
      sessionKey,
      expiresAt: 1_700_000_000n,
      actionsBuffer,
      authorizerSigner: KIT(ADMIN),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyCreateSessionIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      adminAuthorityPda: PK(AUTHORITY),
      sessionPda: PK(SESSION),
      sessionKey,
      expiresAt: 1_700_000_000n,
      actionsBuffer,
      authorizerSigner: PK(ADMIN),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createAuthorize — deferred-exec tx 1', () => {
  it('byte-parity', () => {
    const kit = createAuthorizeIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      authorityPda: KIT(AUTHORITY),
      deferredExecPda: KIT(SESSION),
      instructionsHash,
      accountsHash,
      expiryOffset: 9000,
      authPayload,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyAuthorizeIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      authorityPda: PK(AUTHORITY),
      deferredExecPda: PK(SESSION),
      instructionsHash,
      accountsHash,
      expiryOffset: 9000,
      authPayload,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createExecuteDeferred — with remaining accts + fee', () => {
  it('byte-parity', () => {
    const remainingKit: AccountMeta[] = [
      { address: KIT(REFUND), role: AccountRole.WRITABLE },
    ];
    const remainingLegacy = [
      { pubkey: PK(REFUND), isSigner: false, isWritable: true },
    ];
    const fee = {
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      feeRecordPda: KIT(FEE_RECORD),
      treasuryShardPda: KIT(TREASURY_SHARD),
    };
    const kit = createExecuteDeferredIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      vaultPda: KIT(VAULT),
      deferredExecPda: KIT(SESSION),
      refundDestination: KIT(REFUND),
      packedInstructions,
      remainingAccounts: remainingKit,
      protocolFee: fee,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyExecuteDeferredIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      vaultPda: PK(VAULT),
      deferredExecPda: PK(SESSION),
      refundDestination: PK(REFUND),
      packedInstructions,
      remainingAccounts: remainingLegacy,
      protocolFee: {
        protocolConfigPda: PK(PROTOCOL_CONFIG),
        feeRecordPda: PK(FEE_RECORD),
        treasuryShardPda: PK(TREASURY_SHARD),
      },
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createReclaimDeferred — discriminator-only', () => {
  it('byte-parity', () => {
    const kit = createReclaimDeferredIx({
      payer: KIT(PAYER),
      deferredExecPda: KIT(SESSION),
      refundDestination: KIT(REFUND),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyReclaimDeferredIx({
      payer: PK(PAYER),
      deferredExecPda: PK(SESSION),
      refundDestination: PK(REFUND),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createRevokeSession — Ed25519 admin', () => {
  it('byte-parity', () => {
    const kit = createRevokeSessionIx({
      payer: KIT(PAYER),
      walletPda: KIT(WALLET),
      adminAuthorityPda: KIT(AUTHORITY),
      sessionPda: KIT(SESSION),
      refundDestination: KIT(REFUND),
      authorizerSigner: KIT(ADMIN),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyRevokeSessionIx({
      payer: PK(PAYER),
      walletPda: PK(WALLET),
      adminAuthorityPda: PK(AUTHORITY),
      sessionPda: PK(SESSION),
      refundDestination: PK(REFUND),
      authorizerSigner: PK(ADMIN),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createInitializeProtocol', () => {
  it('byte-parity', () => {
    const kit = createInitializeProtocolIx({
      payer: KIT(PAYER),
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      admin: KIT(ADMIN),
      treasury: KIT(TREASURY),
      creationFee: 100_000n,
      executionFee: 50_000n,
      numShards: 16,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyInitProtocolIx({
      payer: PK(PAYER),
      protocolConfigPda: PK(PROTOCOL_CONFIG),
      admin: PK(ADMIN),
      treasury: PK(TREASURY),
      creationFee: 100_000n,
      executionFee: 50_000n,
      numShards: 16,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createUpdateProtocol', () => {
  it('byte-parity', () => {
    const kit = createUpdateProtocolIx({
      admin: KIT(ADMIN),
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      creationFee: 200_000n,
      executionFee: 75_000n,
      enabled: true,
      newTreasury: KIT(TREASURY),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyUpdateProtocolIx({
      admin: PK(ADMIN),
      protocolConfigPda: PK(PROTOCOL_CONFIG),
      creationFee: 200_000n,
      executionFee: 75_000n,
      enabled: true,
      newTreasury: PK(TREASURY),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createRegisterPayer', () => {
  it('byte-parity', () => {
    const kit = createRegisterPayerIx({
      payer: KIT(PAYER),
      feeRecordPda: KIT(FEE_RECORD),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyRegisterPayerIx({
      payer: PK(PAYER),
      feeRecordPda: PK(FEE_RECORD),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createWithdrawTreasury', () => {
  it('byte-parity', () => {
    const kit = createWithdrawTreasuryIx({
      admin: KIT(ADMIN),
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      treasuryShardPda: KIT(TREASURY_SHARD),
      treasury: KIT(TREASURY),
      programId: KIT(PROGRAM),
    });
    const legacy = legacyWithdrawTreasuryIx({
      admin: PK(ADMIN),
      protocolConfigPda: PK(PROTOCOL_CONFIG),
      treasuryShardPda: PK(TREASURY_SHARD),
      treasury: PK(TREASURY),
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});

describe('createInitializeTreasuryShard', () => {
  it('byte-parity', () => {
    const kit = createInitializeTreasuryShardIx({
      payer: KIT(PAYER),
      protocolConfigPda: KIT(PROTOCOL_CONFIG),
      admin: KIT(ADMIN),
      treasuryShardPda: KIT(TREASURY_SHARD),
      shardId: 7,
      programId: KIT(PROGRAM),
    });
    const legacy = legacyInitTreasuryShardIx({
      payer: PK(PAYER),
      protocolConfigPda: PK(PROTOCOL_CONFIG),
      admin: PK(ADMIN),
      treasuryShardPda: PK(TREASURY_SHARD),
      shardId: 7,
      programId: PK(PROGRAM),
    });
    expectIxParity(kit, legacy);
  });
});
