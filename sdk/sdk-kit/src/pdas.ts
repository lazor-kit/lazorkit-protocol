import {
  getAddressEncoder,
  getProgramDerivedAddress,
  getUtf8Encoder,
  type Address,
  type ProgramDerivedAddress,
} from '@solana/kit';

// PDA derivation helpers. Every function takes the program ID explicitly —
// there is no ambient default. Use the cluster-specific constants from
// `./constants` (`PROGRAM_ID_MAINNET` / `PROGRAM_ID_DEVNET`).
//
// Seeds are byte-identical with the on-chain program (see
// program/src/state/*.rs and the legacy v1 SDK at sdk/sdk-legacy/src/utils/pdas.ts).
//
// All functions return ProgramDerivedAddress (a tuple-like { '0': Address,
// '1': bump }). Kit returns this asynchronously because the PDA-finding loop
// is potentially expensive; treat the await as cheap (it's CPU, not IO).

const utf8 = getUtf8Encoder();
const addressEncoder = getAddressEncoder();

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


export async function findWalletPda(
  userSeed: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(SEED_WALLET), userSeed],
  });
}

export async function findVaultPda(
  walletPda: Address,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(SEED_VAULT), addressEncoder.encode(walletPda)],
  });
}

export async function findAuthorityPda(
  walletPda: Address,
  credentialIdHash: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [
      utf8.encode(SEED_AUTHORITY),
      addressEncoder.encode(walletPda),
      credentialIdHash,
    ],
  });
}

export async function findSessionPda(
  walletPda: Address,
  sessionKey: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [
      utf8.encode(SEED_SESSION),
      addressEncoder.encode(walletPda),
      sessionKey,
    ],
  });
}

export async function findProtocolConfigPda(
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(SEED_PROTOCOL_CONFIG)],
  });
}

export async function findFeeRecordPda(
  payerPubkey: Address,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(SEED_FEE_RECORD), addressEncoder.encode(payerPubkey)],
  });
}

export async function findTreasuryShardPda(
  shardId: number,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(SEED_TREASURY_SHARD), new Uint8Array([shardId])],
  });
}

export async function findDeferredExecPda(
  walletPda: Address,
  authorityPda: Address,
  counter: number,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  const counterBuf = new Uint8Array(4);
  new DataView(counterBuf.buffer).setUint32(0, counter, /* littleEndian */ true);
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [
      utf8.encode(SEED_DEFERRED),
      addressEncoder.encode(walletPda),
      addressEncoder.encode(authorityPda),
      counterBuf,
    ],
  });
}
