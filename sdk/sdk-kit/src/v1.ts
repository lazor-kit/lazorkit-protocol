// v1 account derivation and lookup, for the one flow that must reach the
// retired v1 world: migration.
//
// v2 renamed every seed (`lk2:` prefix) so its address space is disjoint from
// v1's. These bare-seed derivations reach the *old* addresses and live apart
// from `pdas.ts` deliberately, so the two are never confused.
import {
  AccountRole,
  getAddressDecoder,
  getAddressEncoder,
  getBase64Encoder,
  getProgramDerivedAddress,
  getUtf8Encoder,
  type Address,
  type Base58EncodedBytes,
  type GetAccountInfoApi,
  type GetMultipleAccountsApi,
  type GetProgramAccountsApi,
  type GetTokenAccountsByOwnerApi,
  type Instruction,
  type ProgramDerivedAddress,
  type Rpc,
} from '@solana/kit';
import bs58 from 'bs58';

import {
  TOKEN_2022_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
} from './instructions/system.js';
import { tokenAccountAmount, tokenAccountMint } from './spl.js';

const utf8 = getUtf8Encoder();
const base64Encoder = getBase64Encoder();
const addressEncoder = getAddressEncoder();
const addressDecoder = getAddressDecoder();

/** v1 PDA seeds — bare, un-prefixed. The v2 forms carry `lk2:`. */
export const V1_SEED_WALLET = 'wallet';
export const V1_SEED_VAULT = 'vault';
export const V1_SEED_AUTHORITY = 'authority';

/** v1 account discriminators, before v2 moved them into the `0x2N` range. */
export const V1_DISC_WALLET = 1;
export const V1_DISC_AUTHORITY = 2;
export const V1_DISC_SESSION = 3;
export const V1_DISC_DEFERRED_EXEC = 4;

export type V1Rpc = Rpc<
  GetAccountInfoApi & GetMultipleAccountsApi & GetProgramAccountsApi & GetTokenAccountsByOwnerApi
>;

export async function findV1WalletPda(
  userSeed: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(V1_SEED_WALLET), userSeed],
  });
}

export async function findV1VaultPda(
  walletPda: Address,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(V1_SEED_VAULT), addressEncoder.encode(walletPda)],
  });
}

export async function findV1AuthorityPda(
  walletPda: Address,
  ownerIdSeed: Uint8Array,
  programId: Address,
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({
    programAddress: programId,
    seeds: [utf8.encode(V1_SEED_AUTHORITY), addressEncoder.encode(walletPda), ownerIdSeed],
  });
}

export interface V1Accounts {
  wallet: Address;
  vault: Address;
  authority: Address;
}

/**
 * All three v1 PDAs from the user seed and the owner's id seed — the
 * credential-id hash for a passkey, the public-key bytes for Ed25519.
 *
 * Only useful when the app still holds the seed. Most do not: see
 * {@link findV1WalletsByOwner}.
 */
export async function deriveV1Accounts(
  userSeed: Uint8Array,
  ownerIdSeed: Uint8Array,
  programId: Address,
): Promise<V1Accounts> {
  const [wallet] = await findV1WalletPda(userSeed, programId);
  const [vault] = await findV1VaultPda(wallet, programId);
  const [authority] = await findV1AuthorityPda(wallet, ownerIdSeed, programId);
  return { wallet, vault, authority };
}

/** One v1 wallet found by scanning, and the authority that found it. */
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
   * key — only registration does. The chain is the only place a returning
   * user's key can be found.
   */
  ownerPubkey: Uint8Array;
}

/**
 * Find a user's v1 wallets from their key material alone, with no user seed.
 *
 * The seed matters: wallets created through `@lazorkit/wallet` used a random
 * 32-byte `userSeed` that lived in the browser's storage, so a user who cleared
 * it, or who moved to another device, cannot derive their own wallet any more.
 * The chain can still answer, because the authority account stores both the
 * owner's key material and the wallet it belongs to.
 *
 * `MigrateWallet` never needs the seed either — it takes the v1 wallet as an
 * account and derives the vault from that key.
 *
 * The scan is a `getProgramAccounts` call with two memcmp filters, which some
 * RPC providers rate-limit or refuse; use an endpoint that allows it.
 */
export async function findV1WalletsByOwner(
  rpc: V1Rpc,
  /** Credential-id hash for a passkey, or the 32 public-key bytes for Ed25519. */
  ownerIdSeed: Uint8Array,
  programId: Address,
  authorityType: 'ed25519' | 'secp256r1' = 'secp256r1',
): Promise<V1WalletRecord[]> {
  if (ownerIdSeed.length !== 32) {
    throw new Error(`ownerIdSeed must be 32 bytes, got ${ownerIdSeed.length}`);
  }
  // v1 authority layout, byte-compatible with v2 apart from the discriminator:
  //   0 discriminator (2) | 1 authority_type | 2 role | 16..48 wallet | 48.. key material
  const discAndType = new Uint8Array([V1_DISC_AUTHORITY, authorityType === 'ed25519' ? 0 : 1]);

  const accounts = await rpc
    .getProgramAccounts(programId, {
      encoding: 'base64',
      filters: [
        {
          memcmp: {
            offset: 0n,
            bytes: bs58.encode(discAndType) as Base58EncodedBytes,
            encoding: 'base58',
          },
        },
        {
          memcmp: {
            offset: 48n,
            bytes: bs58.encode(ownerIdSeed) as Base58EncodedBytes,
            encoding: 'base58',
          },
        },
      ],
    })
    .send();

  const out: V1WalletRecord[] = [];
  for (let i = 0; i < accounts.length; i++) {
    const { pubkey: authority, account } = accounts[i]!;
    const data = decodeBase64(account.data[0]);
    const wallet = addressDecoder.decode(data.slice(16, 48));
    const [vault] = await findV1VaultPda(wallet, programId);
    // Key material starts after the 48-byte header: an Ed25519 authority keeps
    // its 32-byte public key there, a Secp256r1 one keeps the credential-id
    // hash and then 33 compressed bytes.
    const ownerPubkey =
      data[1] === 1 ? data.slice(80, 113) : data.slice(48, 80);
    out.push({ wallet, vault, authority, role: data[2]!, authorityType: data[1]!, ownerPubkey });
  }
  return out;
}

/**
 * A v1 wallet's on-chain state, or `null` when the wallet does not exist —
 * nothing to migrate. Otherwise the owner authority's rank and auth type and
 * the vault's SOL, which is what a UI needs to decide what to show.
 */
export async function readV1WalletState(
  rpc: V1Rpc,
  accounts: V1Accounts,
): Promise<null | { ownerAuthType: number; ownerRole: number; vaultLamports: bigint }> {
  const { value } = await rpc
    .getMultipleAccounts([accounts.wallet, accounts.authority, accounts.vault], {
      encoding: 'base64',
    })
    .send();
  const [walletInfo, authInfo, vaultInfo] = value;
  if (!walletInfo) return null;
  const walletData = decodeBase64(walletInfo.data[0]);
  if (walletData.length === 0 || walletData[0] !== V1_DISC_WALLET) return null;
  if (!authInfo) return null;
  const authData = decodeBase64(authInfo.data[0]);
  if (authData[0] !== V1_DISC_AUTHORITY) return null;
  return {
    ownerAuthType: authData[1]!,
    ownerRole: authData[2]!,
    vaultLamports: vaultInfo ? BigInt(vaultInfo.lamports) : 0n,
  };
}

export interface V1VaultToken {
  /** The vault-owned token account: the migration's source. */
  ata: Address;
  mint: Address;
  amount: bigint;
  /** Which token program owns the account — the migration must pass this one. */
  tokenProgram: Address;
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
export function mintTransferHook(mintData: Uint8Array): string | null {
  const value = tlvExtensions(mintData).get(EXT_TRANSFER_HOOK);
  if (!value || value.length < 64) return null;
  const program = value.subarray(32, 64);
  return program.some((b) => b !== 0) ? addressDecoder.decode(program) : null;
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
 * Every token account the v1 vault owns, across SPL Token and Token-2022.
 *
 * Empty ones are returned too: an empty account still holds rent and should be
 * migrated and closed. Any account the migration omits is stranded when the
 * wallet closes, so pass all of them.
 */
export async function enumerateV1VaultTokens(
  rpc: V1Rpc,
  vault: Address,
): Promise<V1VaultToken[]> {
  const out: V1VaultToken[] = [];
  for (const tokenProgram of [TOKEN_PROGRAM_ADDRESS, TOKEN_2022_PROGRAM_ADDRESS]) {
    const { value } = await rpc
      .getTokenAccountsByOwner(vault, { programId: tokenProgram }, { encoding: 'base64' })
      .send();
    for (let i = 0; i < value.length; i++) {
      const entry = value[i]!;
      const data = decodeBase64(entry.account.data[0]);
      out.push({
        ata: entry.pubkey,
        mint: tokenAccountMint(data),
        amount: tokenAccountAmount(data),
        tokenProgram,
        frozen: data[TOKEN_STATE_OFFSET] === TOKEN_STATE_FROZEN,
        blocker: tokenAccountBlocker(data),
        withheldFees: tokenAccountWithheldFees(data),
      });
    }
  }
  return out;
}

function decodeBase64(encoded: string): Uint8Array {
  return new Uint8Array(base64Encoder.encode(encoded));
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
  rpc: V1Rpc,
  tokens: V1VaultToken[],
  exclude: ReadonlyArray<Address> = [],
): Promise<{ movable: V1VaultToken[]; skipped: { token: V1VaultToken; reason: UnmovableReason }[] }> {
  const movable: V1VaultToken[] = [];
  const skipped: { token: V1VaultToken; reason: UnmovableReason }[] = [];
  const candidates: V1VaultToken[] = [];
  for (const t of tokens) {
    if (exclude.includes(t.ata)) skipped.push({ token: t, reason: 'excluded' });
    else candidates.push(t);
  }
  // Every mint, in pages of 100 (the RPC's limit): a mint that is gone, or is
  // owned by another token program, can never be named in a transfer.
  const mints = [...new Set(candidates.map((t) => t.mint))];
  const mintInfo = new Map<string, { owner: Address; data: Uint8Array } | null>();
  for (let i = 0; i < mints.length; i += 100) {
    const page = mints.slice(i, i + 100);
    const { value } = await rpc.getMultipleAccounts(page, { encoding: 'base64' }).send();
    value.forEach((info, j) =>
      mintInfo.set(page[j]!, info ? { owner: info.owner, data: decodeBase64(info.data[0]) } : null),
    );
  }
  for (const t of candidates) {
    const mint = mintInfo.get(t.mint);
    const reason: UnmovableReason | null =
      t.blocker ??
      (t.frozen ? 'frozen' : null) ??
      (!mint || mint.owner !== t.tokenProgram ? 'mint-missing' : null) ??
      (mint && t.tokenProgram === TOKEN_2022_PROGRAM_ADDRESS ? mintBlocker(mint.data) : null);
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
export function harvestWithheldIx(mint: Address, sources: Address[]): Instruction {
  return {
    programAddress: TOKEN_2022_PROGRAM_ADDRESS,
    accounts: [
      { address: mint, role: AccountRole.WRITABLE },
      ...sources.map((address) => ({ address, role: AccountRole.WRITABLE })),
    ],
    data: new Uint8Array([26, 4]), // TransferFeeExtension, HarvestWithheldTokensToMint
  };
}
