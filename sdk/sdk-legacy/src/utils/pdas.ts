import { PublicKey } from '@solana/web3.js';

// ─── PDA seeds ────────────────────────────────────────────────────────────
//
// Namespaced by protocol major version, byte-identical with
// program/src/seeds.rs. The program keeps its address across major versions, so
// PDA addresses are a pure function of the seeds; without the namespace a v2
// binary would inherit v1's accounts at the addresses it wants for its own, and
// for the singletons — protocol_config, treasury_shard — that collision is
// certain rather than theoretical. Bump the prefix whenever
// PROTOCOL_VERSION does.
export const SEED_PREFIX = 'lk2:';
export const SEED_WALLET = `${SEED_PREFIX}wallet`;
export const SEED_VAULT = `${SEED_PREFIX}vault`;
export const SEED_AUTHORITY = `${SEED_PREFIX}authority`;
export const SEED_SESSION = `${SEED_PREFIX}session`;
export const SEED_DEFERRED = `${SEED_PREFIX}deferred`;
export const SEED_PROTOCOL_CONFIG = `${SEED_PREFIX}protocol_config`;
export const SEED_TREASURY_SHARD = `${SEED_PREFIX}treasury_shard`;
export const SEED_FEE_RECORD = `${SEED_PREFIX}fee_record`;


// PDA derivation helpers. Every function takes the program ID explicitly —
// there is no ambient default. Use the cluster-specific constants from
// `../constants` (`PROGRAM_ID_MAINNET` / `PROGRAM_ID_DEVNET`), or pass
// `LazorKitClient.programId` from a client instance.

export function findWalletPda(
  userSeed: Uint8Array,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_WALLET), userSeed],
    programId,
  );
}

export function findVaultPda(
  walletPda: PublicKey,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_VAULT), walletPda.toBuffer()],
    programId,
  );
}

export function findAuthorityPda(
  walletPda: PublicKey,
  credentialIdHash: Uint8Array,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_AUTHORITY), walletPda.toBuffer(), credentialIdHash],
    programId,
  );
}

export function findSessionPda(
  walletPda: PublicKey,
  sessionKey: Uint8Array,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_SESSION), walletPda.toBuffer(), sessionKey],
    programId,
  );
}

export function findProtocolConfigPda(
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_PROTOCOL_CONFIG)],
    programId,
  );
}

export function findFeeRecordPda(
  payerPubkey: PublicKey,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_FEE_RECORD), payerPubkey.toBuffer()],
    programId,
  );
}

export function findTreasuryShardPda(
  shardId: number,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEED_TREASURY_SHARD), Buffer.from([shardId])],
    programId,
  );
}

export function findDeferredExecPda(
  walletPda: PublicKey,
  authorityPda: PublicKey,
  counter: number,
  programId: PublicKey,
): [PublicKey, number] {
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32LE(counter);
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from(SEED_DEFERRED),
      walletPda.toBuffer(),
      authorityPda.toBuffer(),
      counterBuf,
    ],
    programId,
  );
}
