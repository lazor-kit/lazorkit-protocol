// v1 account derivation, for the one flow that must reach the retired v1 world:
// migration. v2 renamed every seed (`lk2:` prefix) so its address space is
// disjoint from v1's; these bare-seed derivations reach the *old* addresses, and
// live apart from `pdas.ts` deliberately so the two are never confused.
//
// Pair with `createMigrateWalletIx`. The migration tool derives a user's v1
// wallet/vault/authority here, their v2 destination with `pdas.ts`, and hands
// both to the builder.

import { Connection, PublicKey } from '@solana/web3.js';
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from './spl';

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


export interface V1Accounts {
  wallet: PublicKey;
  vault: PublicKey;
  authority: PublicKey;
}

/**
 * All three v1 PDAs for one wallet, from the user seed and the owner's id seed
 * (the credential-id hash for a passkey, the Ed25519 public-key bytes for an
 * Ed25519 owner) — the same inputs that derive the v2 wallet, so a migration
 * tool can line up the two.
 */
export function deriveV1Accounts(
  userSeed: Uint8Array,
  ownerIdSeed: Uint8Array,
  programId: PublicKey,
): V1Accounts {
  const [wallet] = findV1WalletPda(userSeed, programId);
  const [vault] = findV1VaultPda(wallet, programId);
  const [authority] = findV1AuthorityPda(wallet, ownerIdSeed, programId);
  return { wallet, vault, authority };
}

export interface V1VaultToken {
  /** The vault-owned token account (migration source). */
  ata: PublicKey;
  mint: PublicKey;
  amount: bigint;
  /** Which token program owns the account — the migration must pass this one. */
  tokenProgram: PublicKey;
}

/**
 * Every token account the v1 vault owns, across SPL Token and Token-2022, with a
 * non-zero balance filtered out is NOT done here — an empty account still costs
 * rent and should be migrated+closed, so all are returned. The migration MUST
 * enumerate all of these; any it omits is stranded when the wallet closes.
 */
export async function enumerateV1VaultTokens(
  connection: Connection,
  vault: PublicKey,
): Promise<V1VaultToken[]> {
  const out: V1VaultToken[] = [];
  for (const tokenProgram of [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]) {
    const res = await connection.getTokenAccountsByOwner(vault, {
      programId: tokenProgram,
    });
    for (const { pubkey, account } of res.value) {
      const data = account.data as Buffer;
      out.push({
        ata: pubkey,
        mint: new PublicKey(data.subarray(0, 32)),
        amount: data.readBigUInt64LE(64),
        tokenProgram,
      });
    }
  }
  return out;
}

/**
 * Read a v1 wallet's on-chain state. Returns `null` if the wallet PDA does not
 * exist (nothing to migrate). Otherwise reports the owner authority's rank and
 * auth type and the vault's SOL — enough for a UI to decide what to show.
 */
export async function readV1WalletState(
  connection: Connection,
  accounts: V1Accounts,
): Promise<null | {
  ownerAuthType: number; // 0 = Ed25519, 1 = Secp256r1
  ownerRole: number; // 0 = Owner
  vaultLamports: number;
}> {
  const [walletInfo, authInfo, vaultInfo] = await connection.getMultipleAccountsInfo([
    accounts.wallet,
    accounts.authority,
    accounts.vault,
  ]);
  if (!walletInfo || walletInfo.data.length === 0) return null;
  if (walletInfo.data[0] !== V1_DISC_WALLET) return null;
  if (!authInfo || authInfo.data[0] !== V1_DISC_AUTHORITY) return null;
  return {
    ownerAuthType: authInfo.data[1],
    ownerRole: authInfo.data[2],
    vaultLamports: vaultInfo?.lamports ?? 0,
  };
}
