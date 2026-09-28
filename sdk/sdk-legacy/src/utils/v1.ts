import { Buffer } from 'buffer';
// v1 account derivation, for the one flow that must reach the retired v1 world:
// migration. v2 renamed every seed (`lk2:` prefix) so its address space is
// disjoint from v1's; these bare-seed derivations reach the *old* addresses, and
// live apart from `pdas.ts` deliberately so the two are never confused.
//
// Pair with `createMigrateWalletIx`. The migration tool derives a user's v1
// wallet/vault/authority here, their v2 destination with `pdas.ts`, and hands
// both to the builder.

import { Connection, PublicKey, TransactionInstruction } from '@solana/web3.js';
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from './spl';

/** v1 PDA seeds — bare, un-prefixed. The v2 forms carry `lk2:`. */
export const V1_SEED_WALLET = 'wallet';
export const V1_SEED_VAULT = 'vault';
export const V1_SEED_AUTHORITY = 'authority';

/** v1 account discriminators. v2 uses `0x2N`. */
export const V1_DISC_WALLET = 1;
export const V1_DISC_AUTHORITY = 2;
export const V1_DISC_SESSION = 3;
export const V1_DISC_DEFERRED_EXEC = 4;

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

/** One v1 wallet found by scanning, plus the rank of the authority that found it. */
export interface V1WalletRecord extends V1Accounts {
  /** Role enum: 0=Owner, 1=Admin, 2=Spender. Only an Owner may migrate. */
  role: number;
  /** Authority type enum: 0=Ed25519, 1=Secp256r1 */
  authorityType: number;
  /**
   * The owner's key as stored on-chain: 33 compressed bytes for a passkey, the
   * 32 public-key bytes for Ed25519.
   *
   * Read it from here rather than from a WebAuthn response. Signing in with an
   * existing passkey returns an assertion, and an assertion carries no public
   * key — only registration does. The chain is the only place a returning user's
   * key can be found.
   */
  ownerPubkey: Uint8Array;
}

/**
 * Find a user's v1 wallets from their key material alone, with no user seed.
 *
 * The seed matters: wallets created through `@lazorkit/wallet` used a random
 * 32-byte `userSeed` that lived in the browser's storage, so a user who
 * cleared it, or moved to another device, cannot derive their own v1 wallet
 * any more. The chain can still answer the question, because the authority
 * account stores both the owner's key material and the wallet it belongs to.
 *
 * `MigrateWallet` never needs the seed either — it takes the v1 wallet as an
 * account and derives the vault from that key. So this scan plus
 * `migrateV1Wallet({ v1Wallet })` is the path for a user whose storage is gone.
 *
 * The scan is a `getProgramAccounts` call with two memcmp filters, which some
 * RPC providers rate-limit or refuse; use an endpoint that allows it.
 */
export async function findV1WalletsByOwner(
  connection: Connection,
  /** Credential-id hash for a passkey, or the 32 public-key bytes for Ed25519. */
  ownerIdSeed: Uint8Array,
  programId: PublicKey,
  authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
): Promise<V1WalletRecord[]> {
  if (ownerIdSeed.length !== 32) {
    throw new Error(`ownerIdSeed must be 32 bytes, got ${ownerIdSeed.length}`);
  }
  // v1 authority layout, byte-compatible with v2 apart from the discriminator:
  //   0 discriminator (2) | 1 authority_type | 2 role | 16..48 wallet | 48.. key material
  const discAndType = Buffer.from([
    V1_DISC_AUTHORITY,
    authorityType === 'ed25519' ? 0 : 1,
  ]);
  const accounts = await connection.getProgramAccounts(programId, {
    encoding: 'base64',
    filters: [
      { memcmp: { offset: 0, bytes: discAndType.toString('base64'), encoding: 'base64' } },
      {
        memcmp: {
          offset: 48,
          bytes: Buffer.from(ownerIdSeed).toString('base64'),
          encoding: 'base64',
        },
      },
    ],
  });

  return accounts.map(({ pubkey: authority, account }) => {
    const wallet = new PublicKey(account.data.slice(16, 48));
    const [vault] = findV1VaultPda(wallet, programId);
    // Key material starts after the 48-byte header: an Ed25519 authority keeps
    // its 32-byte public key there, a Secp256r1 one keeps the credential-id
    // hash and then 33 compressed bytes.
    const ownerPubkey =
      account.data[1] === 1
        ? new Uint8Array(account.data.slice(80, 113))
        : new Uint8Array(account.data.slice(48, 80));
    return {
      wallet,
      vault,
      authority,
      role: account.data[2],
      authorityType: account.data[1],
      ownerPubkey,
    };
  });
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
  /** A frozen account cannot be transferred from or closed. */
  frozen: boolean;
  /** Why this account itself cannot move (frozen, non-transferable, …), or null. */
  blocker: UnmovableReason | null;
  /** Token-2022 fees withheld here, to harvest before the account can close. */
  withheldFees: boolean;
}

/**
 * Why a vault token account cannot be migrated. Every one of these, left in
 * the migration, makes the whole transaction revert — and a stranger can plant
 * most of them in anyone's vault for the price of a token account's rent.
 *
 *  - `frozen`            the account is frozen; it cannot be moved or closed
 *  - `transfer-hook`     the mint's transfer hook needs extra accounts
 *  - `non-transferable`  the mint (or account) forbids transfers outright
 *  - `paused`            the mint is paused
 *  - `frozen-on-arrival` the mint freezes new accounts, so the destination
 *                        account would be frozen before the tokens arrive
 *  - `cpi-guard`         the account refuses transfers made through a program
 *  - `mint-missing`      the mint is gone (closed) or not owned by the account's
 *                        token program, so no transfer can name it
 *  - `destination-frozen` the destination token account exists and is frozen
 *  - `excluded`          the caller chose to leave it (`excludeTokenAccounts`)
 *
 * Withheld transfer fees are not on the list: they only stop the source from
 * closing, and anyone may harvest them to the mint — `migrateV1Wallet` does,
 * in the same transaction (see `harvestWithheldIx`).
 */
export type UnmovableReason =
  | 'frozen'
  | 'transfer-hook'
  | 'non-transferable'
  | 'paused'
  | 'frozen-on-arrival'
  | 'cpi-guard'
  | 'mint-missing'
  | 'destination-frozen'
  | 'excluded';

/** Token-account state byte: 0 uninitialized, 1 initialized, 2 frozen. */
const TOKEN_STATE_OFFSET = 108;
const TOKEN_STATE_FROZEN = 2;
/** Token-2022 TLV: account-type byte at 165, then [type u16][len u16][value]. */
const TLV_START = 166;
// spl-token-2022 ExtensionType discriminants.
const EXT_TRANSFER_FEE_AMOUNT = 2;
const EXT_DEFAULT_ACCOUNT_STATE = 6;
const EXT_NON_TRANSFERABLE = 9;
const EXT_CPI_GUARD = 11;
const EXT_NON_TRANSFERABLE_ACCOUNT = 13;
const EXT_TRANSFER_HOOK = 14;
const EXT_PAUSABLE = 26;

/** The TLV extensions of a Token-2022 mint or account, by type. */
function tlvExtensions(data: Uint8Array): Map<number, Uint8Array> {
  const out = new Map<number, Uint8Array>();
  let off = TLV_START;
  while (off + 4 <= data.length) {
    const type = data[off]! | (data[off + 1]! << 8);
    const len = data[off + 2]! | (data[off + 3]! << 8);
    if (type === 0 && len === 0) break; // uninitialized tail
    out.set(type, data.subarray(off + 4, off + 4 + len));
    off += 4 + len;
  }
  return out;
}

/**
 * The transfer-hook program a Token-2022 mint names, or `null` if it has none.
 * MigrateWallet cannot move such a token: `TransferChecked` needs the hook's
 * extra accounts, and the migration has no way to supply them.
 */
export function mintTransferHook(mintData: Uint8Array): PublicKey | null {
  const value = tlvExtensions(mintData).get(EXT_TRANSFER_HOOK);
  if (!value || value.length < 64) return null;
  const program = value.subarray(32, 64);
  return program.some((b) => b !== 0) ? new PublicKey(program) : null;
}

/** Why no account of this Token-2022 mint can be migrated, or `null`. */
export function mintBlocker(mintData: Uint8Array): UnmovableReason | null {
  const ext = tlvExtensions(mintData);
  if (ext.has(EXT_NON_TRANSFERABLE)) return 'non-transferable';
  if (mintTransferHook(mintData)) return 'transfer-hook';
  const pausable = ext.get(EXT_PAUSABLE);
  if (pausable && pausable.length >= 33 && pausable[32] !== 0) return 'paused';
  const defaultState = ext.get(EXT_DEFAULT_ACCOUNT_STATE);
  if (defaultState && defaultState[0] === TOKEN_STATE_FROZEN) return 'frozen-on-arrival';
  return null;
}

/**
 * Whether a Token-2022 account holds withheld transfer fees. Such an account
 * cannot be closed until they are harvested to the mint — which needs no
 * signer, so the migration does it first rather than leaving the account.
 */
export function tokenAccountWithheldFees(accountData: Uint8Array): boolean {
  const fees = tlvExtensions(accountData).get(EXT_TRANSFER_FEE_AMOUNT);
  return !!fees && fees.length >= 8 && fees.subarray(0, 8).some((b) => b !== 0);
}

/** Whether a token account is frozen (state byte 2). */
export function tokenAccountFrozen(accountData: Uint8Array): boolean {
  return accountData.length > TOKEN_STATE_OFFSET && accountData[TOKEN_STATE_OFFSET] === TOKEN_STATE_FROZEN;
}

/** Why this token account itself cannot be migrated, or `null`. */
export function tokenAccountBlocker(accountData: Uint8Array): UnmovableReason | null {
  if (accountData[TOKEN_STATE_OFFSET] === TOKEN_STATE_FROZEN) return 'frozen';
  const ext = tlvExtensions(accountData);
  if (ext.has(EXT_NON_TRANSFERABLE_ACCOUNT)) return 'non-transferable';
  const guard = ext.get(EXT_CPI_GUARD);
  if (guard && guard[0] !== 0) return 'cpi-guard';
  return null;
}

/**
 * Every token account the v1 vault owns, across SPL Token and Token-2022. Empty
 * ones are included — an empty account still costs rent and should be migrated
 * and closed. Pass the result through {@link classifyV1VaultTokens}: some can
 * never move, and any the migration omits is stranded when the wallet closes.
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
        frozen: data[TOKEN_STATE_OFFSET] === TOKEN_STATE_FROZEN,
        blocker: tokenAccountBlocker(data),
        withheldFees: tokenAccountWithheldFees(data),
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

/**
 * Split a vault's token accounts into those MigrateWallet can move and those it
 * cannot, with the reason. Anything left out stays in the v1 vault when the
 * wallet closes — permanently, once the v1 id runs the sunset binary — so the
 * caller must show the user what is being left behind rather than hide it.
 *
 * Unmovable: see {@link UnmovableReason}. Left in, any of them would make the
 * whole migration revert, and a stranger can plant most of them in anyone's
 * vault for the price of a token account's rent.
 */
export async function classifyV1VaultTokens(
  connection: Connection,
  tokens: V1VaultToken[],
  exclude: ReadonlyArray<PublicKey> = [],
): Promise<{ movable: V1VaultToken[]; skipped: { token: V1VaultToken; reason: UnmovableReason }[] }> {
  const movable: V1VaultToken[] = [];
  const skipped: { token: V1VaultToken; reason: UnmovableReason }[] = [];
  const candidates: V1VaultToken[] = [];
  for (const t of tokens) {
    if (exclude.some((e) => e.equals(t.ata))) skipped.push({ token: t, reason: 'excluded' });
    else candidates.push(t);
  }
  // Every mint, in pages of 100 (the RPC's limit): a mint that is gone, or is
  // owned by another token program, can never be named in a transfer.
  const mints = [...new Set(candidates.map((t) => t.mint.toBase58()))];
  const mintInfo = new Map<string, { owner: PublicKey; data: Uint8Array } | null>();
  for (let i = 0; i < mints.length; i += 100) {
    const page = mints.slice(i, i + 100);
    const infos = await connection.getMultipleAccountsInfo(page.map((m) => new PublicKey(m)));
    infos.forEach((info, j) => mintInfo.set(page[j], info ? { owner: info.owner, data: info.data } : null));
  }
  for (const t of candidates) {
    const mint = mintInfo.get(t.mint.toBase58());
    const reason: UnmovableReason | null =
      t.blocker ??
      (t.frozen ? 'frozen' : null) ??
      (!mint || !mint.owner.equals(t.tokenProgram) ? 'mint-missing' : null) ??
      (mint && t.tokenProgram.equals(TOKEN_2022_PROGRAM_ID) ? mintBlocker(mint.data) : null);
    if (reason) skipped.push({ token: t, reason });
    else movable.push(t);
  }
  return { movable, skipped };
}

/**
 * Token-2022 `HarvestWithheldTokensToMint` for these accounts of one mint.
 * Needs no signer: it only moves withheld fees from the accounts to the mint,
 * after which the accounts can close.
 */
export function harvestWithheldIx(mint: PublicKey, sources: PublicKey[]): TransactionInstruction {
  return new TransactionInstruction({
    programId: TOKEN_2022_PROGRAM_ID,
    keys: [
      { pubkey: mint, isSigner: false, isWritable: true },
      ...sources.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
    ],
    data: Buffer.from([26, 4]), // TransferFeeExtension, HarvestWithheldTokensToMint
  });
}
