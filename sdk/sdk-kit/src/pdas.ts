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

export async function findWalletPda(
  userSeed: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode('wallet'), userSeed],
  });
}

export async function findVaultPda(
  walletPda: Address,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode('vault'), addressEncoder.encode(walletPda)],
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
      utf8.encode('authority'),
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
      utf8.encode('session'),
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
    seeds: [utf8.encode('protocol_config')],
  });
}

export async function findFeeRecordPda(
  payerPubkey: Address,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode('fee_record'), addressEncoder.encode(payerPubkey)],
  });
}

export async function findTreasuryShardPda(
  shardId: number,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode('treasury_shard'), new Uint8Array([shardId])],
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
      utf8.encode('deferred'),
      addressEncoder.encode(walletPda),
      addressEncoder.encode(authorityPda),
      counterBuf,
    ],
  });
}
