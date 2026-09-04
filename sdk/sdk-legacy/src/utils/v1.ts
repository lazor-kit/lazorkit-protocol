// v1 account derivation, for the one flow that must reach the retired v1 world:
// migration. v2 renamed every seed (`lk2:` prefix) so its address space is
// disjoint from v1's; these bare-seed derivations reach the *old* addresses, and
// live apart from `pdas.ts` deliberately so the two are never confused.
//
// Pair with `createMigrateWalletIx`. The migration tool derives a user's v1
// wallet/vault/authority here, their v2 destination with `pdas.ts`, and hands
// both to the builder.

import { PublicKey } from '@solana/web3.js';

/** v1 PDA seeds — bare, un-prefixed. The v2 forms carry `lk2:`. */
export const V1_SEED_WALLET = 'wallet';
export const V1_SEED_VAULT = 'vault';
export const V1_SEED_AUTHORITY = 'authority';

/** v1 account discriminators. v2 uses `0x2N`. */
export const V1_DISC_WALLET = 1;
export const V1_DISC_AUTHORITY = 2;

export function findV1WalletPda(
  userSeed: Uint8Array,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(V1_SEED_WALLET), Buffer.from(userSeed)],
    programId,
  );
}

export function findV1VaultPda(
  walletPda: PublicKey,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(V1_SEED_VAULT), walletPda.toBuffer()],
    programId,
  );
}

/**
 * A v1 authority PDA. `idSeed` is the credential-id hash for a passkey, or the
 * Ed25519 public key bytes for an Ed25519 authority — the same seed v1 used.
 */
export function findV1AuthorityPda(
  walletPda: PublicKey,
  idSeed: Uint8Array,
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(V1_SEED_AUTHORITY), walletPda.toBuffer(), Buffer.from(idSeed)],
    programId,
  );
}
