/**
 * The v1 → v2 migration path, against a stubbed RPC.
 *
 * Wallets created through `@lazorkit/wallet` used a random 32-byte `userSeed`
 * kept in browser storage. Most users no longer have it, so migration cannot
 * depend on it — and it does not have to: `MigrateWallet` takes the v1 wallet
 * as an account and derives the vault from that key. These tests pin the two
 * halves of that path: finding the wallet from the owner's key, and migrating
 * by address.
 *
 * Mirrors tests-sdk/tests/16-v1-migration-unit.test.ts, the sdk-legacy twin.
 */
import { describe, it, expect } from 'vitest';
import { address, getAddressDecoder, getAddressEncoder, type Address } from '@solana/kit';
import bs58lib from 'bs58';
import { sha256 } from '@noble/hashes/sha2';

import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  findVaultPda,
  V1_DISC_AUTHORITY,
  V1_DISC_WALLET,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletPda,
  findV1WalletsByOwner,
  getAssociatedTokenAddress,
  mintBlocker,
  tokenAccountBlocker,
  tokenAccountWithheldFees,
} from '../src/index.js';
import { ACCOUNT_DISCRIMINATOR } from '../src/constants.js';
import {
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_2022_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
} from '../src/instructions/system.js';

// v2 and v1 live at different program ids, as they do on the real clusters:
// the migration executes against the v1 program (the only one that can sign
// for a v1 vault) and delivers to a v2 vault at the v2 program.
const PROGRAM_ID = PROGRAM_ID_DEVNET;
const V1_PROGRAM_ID = PROGRAM_ID_DEVNET_V1;
const addressEncoder = getAddressEncoder();

// An Ed25519 owner: the id seed *is* the public key.
const OWNER = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
const CREDENTIAL = new Uint8Array(addressEncoder.encode(OWNER));
const PAYER = address('11111111111111111111111111111112');
const MINT = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const HOOKED_MINT = address('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo');
const STRANGER = address('Vote111111111111111111111111111111111111111');

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
/** Same encoder the SDK uses for memcmp filter bytes. */
const bs58 = (bytes: Uint8Array): string => bs58lib.encode(bytes);
const bytesOf = (a: Address): Uint8Array => new Uint8Array(addressEncoder.encode(a));

/** A v1 authority account: disc | type | role | .. | wallet at 16 | key at 48. */
function v1AuthorityData(wallet: Address, role = 0, authType = 0): Uint8Array {
  const data = new Uint8Array(145);
  data[0] = V1_DISC_AUTHORITY;
  data[1] = authType;
  data[2] = role;
  data.set(bytesOf(wallet), 16);
  data.set(CREDENTIAL, 48);
  if (authType === 1) {
    data.set(new Uint8Array(33).fill(0x7c), 80); // compressed pubkey
    data.set(sha256(new TextEncoder().encode('portal.lazor.sh')), 113); // rpIdHash
  }
  return data;
}

function v1WalletData(): Uint8Array {
  const data = new Uint8Array(8);
  data[0] = V1_DISC_WALLET;
  return data;
}

/** A v2 wallet account, as the v2 program keeps it. */
function v2WalletData(): Uint8Array {
  return new Uint8Array([ACCOUNT_DISCRIMINATOR.WALLET, 0, 0, 0, 1, 0, 0, 0]);
}

/** The v1 wallet's owner as a passkey: the same id seed, key 0x7c.., created under portal.lazor.sh. */
const PASSKEY_OWNER = {
  type: 'secp256r1' as const,
  credentialIdHash: CREDENTIAL,
  compressedPubkey: new Uint8Array(33).fill(0x7c),
  rpId: 'portal.lazor.sh',
};
const ED25519_OWNER = { type: 'ed25519' as const, publicKey: OWNER };

function account(data: Uint8Array, lamports = 1n, owner?: Address) {
  return { data: [b64(data), 'base64'] as const, lamports, executable: false, ...(owner ? { owner } : {}) };
}

/** The slot every stubbed read is answered at (and getSlot returns). */
const STUB_SLOT = 1_000n;

/** A getProgramAccounts answer: wrapped with its context slot when the call asked `withContext`. */
async function programAccounts(config: { withContext?: boolean }, rows: () => Promise<unknown[]>) {
  const value = await rows();
  return config.withContext ? { context: { slot: STUB_SLOT }, value } : value;
}

describe('findV1WalletsByOwner', () => {
  it('filters on the v1 discriminator and the owner key, and reads the wallet out of the record', async () => {
    const [wallet] = await findV1WalletPda(new Uint8Array(32).fill(7), PROGRAM_ID);
    const [authorityPda] = await findV1AuthorityPda(wallet, CREDENTIAL, PROGRAM_ID);
    let seenFilters: unknown;
    const rpc = {
      getProgramAccounts: (_programId: Address, config: { filters: unknown }) => ({
        send: async () => {
          seenFilters = config.filters;
          return [{ pubkey: authorityPda, account: account(v1AuthorityData(wallet)) }];
        },
      }),
    } as never;

    const found = await findV1WalletsByOwner(rpc, CREDENTIAL, PROGRAM_ID, 'ed25519');

    expect(found).toHaveLength(1);
    expect(found[0]!.wallet).toBe(wallet);
    expect(found[0]!.vault).toBe((await findV1VaultPda(wallet, PROGRAM_ID))[0]);
    expect(found[0]!.authority).toBe(authorityPda);
    expect(found[0]!.role).toBe(0);
    // The owner key comes out of the record, because a returning user's browser
    // cannot produce it: signing in with a passkey yields an assertion, and an
    // assertion carries no public key.
    expect(found[0]!.ownerPubkey).toEqual(CREDENTIAL);

    // The filters are the contract with the RPC: a v1 authority (disc 2) whose
    // key material at offset 48 is this owner's.
    const filters = seenFilters as Array<{ memcmp: { offset: bigint; bytes: string } }>;
    expect(filters.map((f) => f.memcmp.offset)).toEqual([0n, 48n]);
    expect(filters[0]!.memcmp.bytes).toBe(bs58(new Uint8Array([V1_DISC_AUTHORITY, 0])));
    expect(filters[1]!.memcmp.bytes).toBe(bs58(CREDENTIAL));
  });

  it('reads a passkey owner key from offset 80, where the compressed key lives', async () => {
    const [wallet] = await findV1WalletPda(new Uint8Array(32).fill(9), PROGRAM_ID);
    const rpc = {
      getProgramAccounts: () => ({
        send: async () => [
          { pubkey: wallet, account: account(v1AuthorityData(wallet, 0, /* secp */ 1)) },
        ],
      }),
    } as never;

    const found = await findV1WalletsByOwner(rpc, CREDENTIAL, PROGRAM_ID, 'secp256r1');

    expect(found[0]!.authorityType).toBe(1);
    expect(found[0]!.ownerPubkey).toEqual(new Uint8Array(33).fill(0x7c));
  });

  it('rejects an id seed that is not 32 bytes', async () => {
    await expect(
      findV1WalletsByOwner({} as never, new Uint8Array(16), PROGRAM_ID, 'ed25519'),
    ).rejects.toThrow('32 bytes');
  });
});

/**
 * How an attacker can keep a hand on a v2 wallet that still lists the owner —
 * each with what vetMigrationDestination says about it. The vault ones are
 * left by an Owner without a policy (System Assign/Allocate on the vault, SPL
 * Approve/SetAuthority on its token accounts) before it hands the wallet to
 * the victim with TransferOwnership.
 */
const HOSTILE = {
  'second-authority': '2 authorities',
  'spender-rank': 'not owned by this key alone',
  session: 'live session',
  deferred: 'pending deferred execution',
  // The program refuses a session or deferred only once the slot is past its
  // expiry, so one expiring at the current slot still works.
  'session-expiring-now': 'live session',
  'deferred-expiring-now': 'pending deferred execution',
  'unreadable-session': 'live session',
  'vault-assigned': 'is owned by program Vote111111111111111111111111111111111111111, not the System Program',
  'vault-allocated': 'carries data',
  'token-delegate': 'has a delegate, Vote111111111111111111111111111111111111111',
  'token-close-authority': 'has a close authority other than the vault, Vote111111111111111111111111111111111111111',
  'token2022-delegate': 'has a delegate',
  'wsol-account-handed-over': 'belongs to Vote111111111111111111111111111111111111111',
  'unreadable-token-account': 'cannot be read',
} as const;
type Hostile = keyof typeof HOSTILE;

/** Vault states that look odd but leave nobody else a way in. */
type Harmless = 'expired-session' | 'vault-missing' | 'close-authority-is-vault';

const WSOL = address('So11111111111111111111111111111111111111112');

/** Sets an SPL token account's COption<Pubkey> at `offset` (72 delegate, 129 close authority). */
function withAuthority(data: Uint8Array, offset: 72 | 129, key: Address): Uint8Array {
  const out = data.slice();
  new DataView(out.buffer).setUint32(offset, 1, true);
  out.set(bytesOf(key), offset + 4);
  return out;
}

/** A token account: mint | owner | amount | .. | state at 108. */
function tokenAccountData(mint: Address, owner: Address, amount: bigint, frozen = false) {
  const data = new Uint8Array(165);
  data.set(bytesOf(mint), 0);
  data.set(bytesOf(owner), 32);
  new DataView(data.buffer).setBigUint64(64, amount, true);
  data[108] = frozen ? 2 : 1;
  return data;
}

/** A Token-2022 mint with a TransferHook extension (TLV type 14) naming a program. */
function hookedMintData(): Uint8Array {
  const data = new Uint8Array(166 + 4 + 64);
  data[165] = 1; // AccountType::Mint
  new DataView(data.buffer).setUint16(166, 14, true);
  new DataView(data.buffer).setUint16(168, 64, true);
  data.set(bytesOf(STRANGER), 170 + 32); // program_id
  return data;
}

describe('migrateV1Wallet by address', () => {
  /**
   * Stub RPC holding one v1 wallet, its authority and a funded vault — and,
   * with `v2Wallet`, a v2 wallet whose one authority is this owner: an Ed25519
   * key unless `ownerType` says passkey, which has signed for the wallet
   * `counter` times (default 1).
   */
  async function fixture(
    options: {
      v2Wallet?: Address;
      hostile?: Hostile;
      harmless?: Harmless;
      token?: boolean;
      frozenToken?: boolean;
      hookedToken?: boolean;
      ownerType?: 'ed25519' | 'secp256r1';
      counter?: number;
      /** More authority accounts the lookup by this owner's credential finds (on other wallets). */
      alsoListed?: Uint8Array[];
    } = {},
  ) {
    const authType = options.ownerType === 'secp256r1' ? 1 : 0;
    const v2Vault = options.v2Wallet ? (await findVaultPda(options.v2Wallet, PROGRAM_ID))[0] : null;
    const v2Wsol = v2Vault ? await getAssociatedTokenAddress(WSOL, v2Vault, TOKEN_PROGRAM_ADDRESS) : null;
    const [v1Wallet] = await findV1WalletPda(new Uint8Array(32).fill(0x5a), V1_PROGRAM_ID);
    const [v1Authority] = await findV1AuthorityPda(v1Wallet, CREDENTIAL, V1_PROGRAM_ID);
    const [v1Vault] = await findV1VaultPda(v1Wallet, V1_PROGRAM_ID);
    const sourceAta = await getAssociatedTokenAddress(MINT, v1Vault, TOKEN_PROGRAM_ADDRESS);

    const tokenAccount = tokenAccountData(MINT, v1Vault, 1_234_000n);
    const frozenAta = address('SysvarRent111111111111111111111111111111111');
    const hookedAta = await getAssociatedTokenAddress(
      HOOKED_MINT,
      v1Vault,
      TOKEN_2022_PROGRAM_ADDRESS,
    );

    const rpc = {
      getMultipleAccounts: (keys: Address[]) => ({
        send: async () => ({
          context: { slot: STUB_SLOT },
          value: keys.map((key) => {
            if (key === v1Wallet) return account(v1WalletData(), 890_880n);
            if (key === v1Authority) return account(v1AuthorityData(v1Wallet));
            if (key === HOOKED_MINT) return account(hookedMintData(), 1n, TOKEN_2022_PROGRAM_ADDRESS);
            if (key === MINT) return account(new Uint8Array(82), 1n, TOKEN_PROGRAM_ADDRESS);
            if (options.v2Wallet && key === options.v2Wallet) return account(v2WalletData(), 1_000_000n, PROGRAM_ID);
            if (key === v2Vault) {
              if (options.harmless === 'vault-missing') return null;
              if (options.hostile === 'vault-assigned') return account(new Uint8Array(0), 5_000_000n, STRANGER);
              if (options.hostile === 'vault-allocated') {
                return account(new Uint8Array(8), 5_000_000n, SYSTEM_PROGRAM_ADDRESS);
              }
            }
            if (key === v2Wsol && options.hostile === 'wsol-account-handed-over') {
              return account(tokenAccountData(WSOL, STRANGER, 0n), 2_039_280n, TOKEN_PROGRAM_ADDRESS);
            }
            // Anything else — the v1 vault, a v2 vault, an address that only
            // holds lamports — is a plain system account.
            return account(new Uint8Array(0), 50_000_000n, SYSTEM_PROGRAM_ADDRESS);
          }),
        }),
      }),
      // The v1 authority is readable (the passkey path reads its counter); the
      // v2 wallet exists only when the test says so.
      getAccountInfo: (key: Address) => ({
        send: async () => {
          if (key === v1Authority) return { value: account(v1AuthorityData(v1Wallet, 0, 1)) };
          if (options.v2Wallet && key === options.v2Wallet) {
            return { value: account(v2WalletData(), 1_000_000n, PROGRAM_ID) };
          }
          return { value: null };
        },
      }),
      // The v2 scans: which wallets list this owner, then — for the one the
      // SDK wants to reuse — its authorities, sessions and deferred executions.
      getProgramAccounts: (_programId: Address, config: { filters: unknown; withContext?: boolean }) => ({
        send: () => programAccounts(config, async () => {
          const [head] = (config.filters as Array<{ memcmp: { bytes: string } }>).map(
            (f) => f.memcmp.bytes,
          );
          const tag = (...b: number[]) => bs58(new Uint8Array(b));
          const v2 = options.v2Wallet;
          if (!v2) return [];
          /** This owner's authority on the v2 wallet, with its replay counter at 8. */
          const authorityData = (role: number) => {
            const d = v1AuthorityData(v2, role, authType);
            d[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
            new DataView(d.buffer).setUint32(8, options.counter ?? 1, true);
            return d;
          };
          const owner = { pubkey: v1Authority, account: account(authorityData(0)) };
          const expiring = (at: bigint) => {
            const d = new Uint8Array(176);
            new DataView(d.buffer).setBigUint64(72, at, true);
            new DataView(d.buffer).setBigUint64(168, at, true);
            return [{ pubkey: STRANGER, account: account(d) }];
          };
          switch (head) {
            // The lookup by this owner's key (findWalletsByAuthority).
            case tag(ACCOUNT_DISCRIMINATOR.AUTHORITY, authType):
              return [owner, ...(options.alsoListed ?? []).map((d) => ({ pubkey: STRANGER, account: account(d) }))];
            case tag(ACCOUNT_DISCRIMINATOR.AUTHORITY):
              if (options.hostile === 'spender-rank') {
                return [{ pubkey: v1Authority, account: account(authorityData(2)) }];
              }
              return options.hostile === 'second-authority'
                ? [owner, { pubkey: STRANGER, account: account(v1AuthorityData(v2)) }]
                : [owner];
            // The slot is 1_000.
            case tag(ACCOUNT_DISCRIMINATOR.SESSION):
              if (options.hostile === 'session') return expiring(5_000n);
              if (options.hostile === 'session-expiring-now') return expiring(1_000n);
              if (options.harmless === 'expired-session') return expiring(999n);
              if (options.hostile === 'unreadable-session') {
                return [{ pubkey: STRANGER, account: account(new Uint8Array(40)) }];
              }
              return [];
            case tag(ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC):
              if (options.hostile === 'deferred') return expiring(5_000n);
              if (options.hostile === 'deferred-expiring-now') return expiring(1_000n);
              return [];
            default:
              return [];
          }
        }),
      }),
      getTokenAccountsByOwner: (owner: Address, filter: { programId: Address }) => ({
        send: async () => {
          const context = { slot: STUB_SLOT };
          if (owner === v2Vault) {
            // What an earlier owner of the v2 wallet left on its vault's tokens.
            const own = tokenAccountData(MINT, v2Vault, 0n);
            const rows: Record<string, [Address, Uint8Array] | undefined> = {
              'token-delegate': [TOKEN_PROGRAM_ADDRESS, withAuthority(own, 72, STRANGER)],
              'token-close-authority': [TOKEN_PROGRAM_ADDRESS, withAuthority(own, 129, STRANGER)],
              'token2022-delegate': [TOKEN_2022_PROGRAM_ADDRESS, withAuthority(own, 72, STRANGER)],
              'unreadable-token-account': [TOKEN_PROGRAM_ADDRESS, new Uint8Array(100)],
              'close-authority-is-vault': [TOKEN_PROGRAM_ADDRESS, withAuthority(own, 129, v2Vault)],
            };
            const row = rows[options.hostile ?? options.harmless ?? ''];
            return {
              context,
              value:
                row && row[0] === filter.programId
                  ? [{ pubkey: frozenAta, account: account(row[1], 2_039_280n, row[0]) }]
                  : [],
            };
          }
          const value = [];
          if (filter.programId === TOKEN_PROGRAM_ADDRESS) {
            if (options.token) value.push({ pubkey: sourceAta, account: account(tokenAccount, 2_039_280n) });
            if (options.frozenToken) {
              value.push({
                pubkey: frozenAta,
                account: account(tokenAccountData(MINT, v1Vault, 5n, true), 2_039_280n),
              });
            }
          }
          if (filter.programId === TOKEN_2022_PROGRAM_ADDRESS && options.hookedToken) {
            value.push({
              pubkey: hookedAta,
              account: account(tokenAccountData(HOOKED_MINT, v1Vault, 7n), 2_074_080n),
            });
          }
          return { context, value };
        },
      }),
      getSlot: () => ({ send: async () => STUB_SLOT }),
    } as never;

    return { rpc, v1Wallet, v1Authority, v1Vault, sourceAta, frozenAta, hookedAta };
  }

  it('migrates a wallet whose seed is gone, and hands back the seed it had to mint', async () => {
    const { rpc, v1Wallet, v1Authority, v1Vault } = await fixture();
    const lk = new LazorKit(rpc, PROGRAM_ID);

    const result = await lk.migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
    });

    // v1 side derived from the address alone.
    expect(result.v1.wallet).toBe(v1Wallet);
    expect(result.v1.authority).toBe(v1Authority);
    expect(result.v1.vault).toBe(v1Vault);

    // v2 side: nothing existed, so a wallet is created and its seed returned.
    expect(result.destinationUserSeed).toBeInstanceOf(Uint8Array);
    expect(result.destinationUserSeed).toHaveLength(32);
    expect(result.destinationWallet).toBe(
      (await lk.findWallet(result.destinationUserSeed!))[0],
    );
    expect(result.setupInstructions.length).toBeGreaterThan(0);

    expect(result.migrate.type).toBe('ed25519');
    const ix = result.migrate.type === 'ed25519' ? result.migrate.instruction : null;
    const accounts = ix!.accounts!.map((a) => a.address);
    expect(accounts).toContain(v1Wallet);
    expect(accounts).toContain(v1Authority);
    expect(accounts).toContain(v1Vault);
    expect(accounts).toContain(result.v2Vault);
    // MigrateWallet, zero tokens — sent to the v1 program, delivering to a v2
    // vault derived under the v2 program.
    expect(Array.from(ix!.data!)).toEqual([17, 0]);
    expect(ix!.programAddress).toBe(V1_PROGRAM_ID);
    expect(result.v2Vault).toBe((await lk.findVault(result.destinationWallet))[0]);
  });

  it('reuses a v2 wallet this passkey has already signed for instead of minting a seed', async () => {
    const existing = (await new LazorKit({} as never, PROGRAM_ID).findWallet(
      new Uint8Array(32).fill(0x11),
    ))[0];
    const { rpc, v1Wallet } = await fixture({ v2Wallet: existing, ownerType: 'secp256r1' });

    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: PASSKEY_OWNER,
      v1Wallet,
    });

    expect(result.destinationWallet).toBe(existing);
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  // Anyone can hand a wallet to this owner (TransferOwnership asks it
  // nothing), and vetting cannot see everything its earlier holder left on the
  // vault — an SPL Token account for an unwatched mint, moved to them. So a
  // wallet found by itself is reused only if the passkey signed for it.
  it('does not reuse a clean wallet this passkey has never signed for — it mints a fresh one', async () => {
    const lk0 = new LazorKit({} as never, PROGRAM_ID);
    const [handed] = await lk0.findWallet(new Uint8Array(32).fill(0x14));
    const { rpc, v1Wallet } = await fixture({ v2Wallet: handed, ownerType: 'secp256r1', counter: 0 });
    const lk = new LazorKit(rpc, PROGRAM_ID);
    // It would pass vetting.
    expect(await lk.vetMigrationDestination(handed, PASSKEY_OWNER)).toBeNull();

    const result = await lk.migrateV1Wallet({ payer: PAYER, owner: PASSKEY_OWNER, v1Wallet });
    expect(result.destinationWallet).not.toBe(handed);
    expect(result.destinationWallet).toBe((await lk0.findWallet(result.destinationUserSeed!))[0]);
    expect(result.setupInstructions.length).toBeGreaterThan(0);
  });

  /** This owner's passkey authority on some other wallet: `counter` signatures, at `role`; its key byte and rpId can differ. */
  function listedElsewhere(o: { role?: number; counter: number; keyByte?: number; rpId?: string }): Uint8Array {
    const data = v1AuthorityData(STRANGER, o.role ?? 0, 1);
    data[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
    new DataView(data.buffer).setUint32(8, o.counter, true);
    if (o.keyByte !== undefined) data.set(new Uint8Array(33).fill(o.keyByte), 80);
    if (o.rpId) data.set(sha256(new TextEncoder().encode(o.rpId)), 113);
    return data;
  }

  // The program's passkey challenge does not name the wallet for
  // CreateSession, AddAuthority, TransferOwnership or Authorize: a signature
  // this passkey made on one authority can be submitted again on another at
  // the same counter, through the same fee payer. With two signed on, either
  // wallet's count may be the copy — including one copied from an Admin seat.
  for (const [label, role] of [
    ['as an Owner of another wallet', 0],
    ['at Admin rank on another wallet', 1],
  ] as const) {
    it(`does not reuse the wallet it signed for when it has also signed ${label} — it mints a fresh one`, async () => {
      const lk0 = new LazorKit({} as never, PROGRAM_ID);
      const [mine] = await lk0.findWallet(new Uint8Array(32).fill(0x1b));
      const { rpc, v1Wallet } = await fixture({
        v2Wallet: mine,
        ownerType: 'secp256r1',
        alsoListed: [listedElsewhere({ role, counter: 2 })],
      });
      const lk = new LazorKit(rpc, PROGRAM_ID);
      expect(await lk.vetMigrationDestination(mine, PASSKEY_OWNER)).toBeNull();
      const result = await lk.migrateV1Wallet({ payer: PAYER, owner: PASSKEY_OWNER, v1Wallet });
      expect(result.destinationWallet).not.toBe(mine);
      expect(result.destinationWallet).toBe((await lk0.findWallet(result.destinationUserSeed!))[0]);
    });
  }

  it('still reuses it beside authorities this passkey never signed on, or that hold another key or relying party', async () => {
    const [mine] = await new LazorKit({} as never, PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x1c));
    const { rpc, v1Wallet } = await fixture({
      v2Wallet: mine,
      ownerType: 'secp256r1',
      alsoListed: [
        listedElsewhere({ role: 1, counter: 0 }),
        // Only this passkey's own key advances a counter it can be blamed for.
        listedElsewhere({ counter: 5, keyByte: 0x7d }),
        listedElsewhere({ counter: 5, rpId: 'evil.example' }),
      ],
    });
    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({ payer: PAYER, owner: PASSKEY_OWNER, v1Wallet });
    expect(result.destinationWallet).toBe(mine);
    expect(result.setupInstructions).toHaveLength(0);
  });

  it("never reuses an Ed25519 owner's wallet by itself (it records no signatures); destinationUserSeed can name it", async () => {
    const seed = new Uint8Array(32).fill(0x16);
    const [existing] = await new LazorKit({} as never, PROGRAM_ID).findWallet(seed);
    // Even with a counter on it: Ed25519 authentication never moves it, so
    // nothing but an earlier holder could have put it there.
    const { rpc, v1Wallet } = await fixture({ v2Wallet: existing, counter: 5 });
    const lk = new LazorKit(rpc, PROGRAM_ID);
    expect(await lk.vetMigrationDestination(existing, ED25519_OWNER)).toBeNull();

    const found = await lk.migrateV1Wallet({ payer: PAYER, owner: ED25519_OWNER, v1Wallet });
    expect(found.destinationWallet).not.toBe(existing);
    expect(found.destinationUserSeed).toHaveLength(32);

    const named = await lk.migrateV1Wallet({
      payer: PAYER,
      owner: ED25519_OWNER,
      v1Wallet,
      destinationUserSeed: seed,
    });
    expect(named.destinationWallet).toBe(existing);
    expect(named.setupInstructions).toHaveLength(0);
  });

  // Being listed on a wallet is not owning it. Each of these leaves someone
  // else able to spend what lands in the vault, so the SDK must not reuse it —
  // even one the passkey has signed for. TransferOwnership hands a wallet over
  // without undoing any of the vault or token ones, which its earlier Owner
  // set up through Execute.
  for (const hostile of Object.keys(HOSTILE) as Hostile[]) {
    it(`does not deliver into a wallet with a ${hostile} — it mints a fresh one`, async () => {
      const planted = (await new LazorKit({} as never, PROGRAM_ID).findWallet(
        new Uint8Array(32).fill(0x66),
      ))[0];
      const { rpc, v1Wallet } = await fixture({ v2Wallet: planted, hostile, ownerType: 'secp256r1' });

      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: PASSKEY_OWNER,
        v1Wallet,
      });

      expect(result.destinationWallet).not.toBe(planted);
      expect(result.destinationUserSeed).toHaveLength(32);
      expect(result.destinationWallet).toBe(
        (await new LazorKit({} as never, PROGRAM_ID).findWallet(result.destinationUserSeed!))[0],
      );
    });
  }

  for (const harmless of ['expired-session', 'vault-missing', 'close-authority-is-vault'] as const) {
    it(`still reuses a wallet with ${harmless}`, async () => {
      const existing = (await new LazorKit({} as never, PROGRAM_ID).findWallet(
        new Uint8Array(32).fill(0x12),
      ))[0];
      const { rpc, v1Wallet } = await fixture({ v2Wallet: existing, harmless, ownerType: 'secp256r1' });

      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: PASSKEY_OWNER,
        v1Wallet,
      });

      expect(result.destinationWallet).toBe(existing);
      expect(result.destinationUserSeed).toBeUndefined();
    });
  }

  it("delivers into the userSeed's own v2 wallet once vetted, signed for or not (a retry after its setup landed)", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [seedWallet] = await new LazorKit({} as never, PROGRAM_ID).findWallet(seed);
    const { rpc } = await fixture({ v2Wallet: seedWallet, ownerType: 'secp256r1', counter: 0 });
    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: PASSKEY_OWNER,
      userSeed: seed,
    });
    expect(result.destinationWallet).toBe(seedWallet);
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  // Only a v2 wallet account makes an address a wallet. A plain system account
  // (lamports alone) is created over; anything else cannot be, and is refused.
  it('refuses a userSeed address some other program owns: no wallet can be created there', async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [target] = await new LazorKit({} as never, PROGRAM_ID).findWallet(seed);
    const base = await fixture();
    const inner = base.rpc as unknown as {
      getAccountInfo: (k: Address) => { send: () => Promise<unknown> };
      getMultipleAccounts: (k: Address[], c?: unknown) => { send: () => Promise<{ context: unknown; value: unknown[] }> };
    };
    const foreign = () => account(new Uint8Array(8), 1_000_000n, STRANGER);
    const rpc = {
      ...(base.rpc as object),
      getAccountInfo: (key: Address) => ({
        send: async () => (key === target ? { value: foreign() } : inner.getAccountInfo(key).send()),
      }),
      getMultipleAccounts: (keys: Address[], config: unknown) => ({
        send: async () => {
          const answer = await inner.getMultipleAccounts(keys, config).send();
          return { ...answer, value: keys.map((k, i) => (k === target ? foreign() : answer.value[i])) };
        },
      }),
    } as never;
    const lk = new LazorKit(rpc, PROGRAM_ID);
    await expect(
      lk.migrateV1Wallet({ payer: PAYER, owner: ED25519_OWNER, userSeed: seed }),
    ).rejects.toThrow(`refusing to migrate into the userSeed's v2 wallet: ${target} is not a wallet of program ${PROGRAM_ID}`);
    expect(await lk.vetMigrationDestination(target, ED25519_OWNER)).toBe(
      `${target} is not a wallet of program ${PROGRAM_ID}`,
    );
    // An address holding only lamports is no wallet either: the vet says so,
    // and migrateV1Wallet creates one there (below).
    const [lamportsOnly] = await new LazorKit({} as never, PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x19));
    expect(await lk.vetMigrationDestination(lamportsOnly, ED25519_OWNER)).toBe(
      `${lamportsOnly} is not a wallet of program ${PROGRAM_ID}`,
    );
  });

  for (const [hostile, reason] of Object.entries(HOSTILE) as [Hostile, string][]) {
    it(`refuses the userSeed's own v2 wallet with a ${hostile}, and says why`, async () => {
      const seed = new Uint8Array(32).fill(0x5a);
      const seedWallet = (await new LazorKit({} as never, PROGRAM_ID).findWallet(seed))[0];
      const { rpc } = await fixture({ v2Wallet: seedWallet, hostile });

      await expect(
        new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
          payer: PAYER,
          owner: { type: 'ed25519', publicKey: OWNER },
          userSeed: seed,
        }),
      ).rejects.toThrow(reason);
    });
  }

  // A destinationUserSeed can be known to others: derived by the integrator,
  // or read out of an earlier setup transaction that landed and failed —
  // retried with the seed the caller was told to persist. Whoever creates the
  // wallet there first chooses its owner, so what sits there is vetted too.
  describe('the wallet at destinationUserSeed', () => {
    const seed = new Uint8Array(32).fill(0x78);
    const lk0 = new LazorKit({} as never, PROGRAM_ID);

    for (const [hostile, reason] of Object.entries(HOSTILE) as [Hostile, string][]) {
      it(`is refused when it exists with a ${hostile}, and the call says why`, async () => {
        const [planted] = await lk0.findWallet(seed);
        const { rpc, v1Wallet } = await fixture({ v2Wallet: planted, hostile });
        const failure = await new LazorKit(rpc, PROGRAM_ID)
          .migrateV1Wallet({
            payer: PAYER,
            owner: { type: 'ed25519', publicKey: OWNER },
            v1Wallet,
            destinationUserSeed: seed,
          })
          .catch((e: Error) => e);
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toContain("refusing to migrate into the destinationUserSeed's v2 wallet: ");
        expect((failure as Error).message).toContain(reason);
      });
    }

    it("is refused when an attacker created it under their own key — one that never lists this owner", async () => {
      const [planted] = await lk0.findWallet(seed);
      const base = await fixture({ v2Wallet: planted });
      const attackerAuthority = v1AuthorityData(planted);
      attackerAuthority.set(bytesOf(STRANGER), 48);
      const rpc = {
        ...(base.rpc as object),
        getProgramAccounts: (_id: Address, config: { filters: Array<{ memcmp: { bytes: string } }>; withContext?: boolean }) => ({
          send: () =>
            programAccounts(config, async () => {
              const head = config.filters[0]!.memcmp.bytes;
              const tag = (...b: number[]) => bs58(new Uint8Array(b));
              // The lookup by this owner's key finds nothing to reuse…
              if (head === tag(ACCOUNT_DISCRIMINATOR.AUTHORITY, 0)) return [];
              // …while the wallet at the seed is the attacker's.
              if (head === tag(ACCOUNT_DISCRIMINATOR.AUTHORITY)) {
                return [{ pubkey: STRANGER, account: account(attackerAuthority) }];
              }
              return [];
            }),
        }),
      } as never;
      await expect(
        new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
          payer: PAYER,
          owner: { type: 'ed25519', publicKey: OWNER },
          v1Wallet: base.v1Wallet,
          destinationUserSeed: seed,
        }),
      ).rejects.toThrow(`wallet ${planted} is not owned by this key alone`);
    });

    // CreateWallet builds over lamports someone sent to the wallet address
    // (it tops them up to rent). Skipping it would pay the migration into
    // the vault of a wallet that does not exist, for whoever creates it.
    it('holding only lamports, is created — never skipped', async () => {
      const [pda] = await lk0.findWallet(seed);
      const base = await fixture();
      const inner = base.rpc as unknown as { getAccountInfo: (k: Address) => { send: () => Promise<unknown> } };
      const rpc = {
        ...(base.rpc as object),
        getAccountInfo: (key: Address) => ({
          send: async () =>
            key === pda
              ? { value: account(new Uint8Array(0), 1n, SYSTEM_PROGRAM_ADDRESS) }
              : inner.getAccountInfo(key).send(),
        }),
      } as never;
      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        v1Wallet: base.v1Wallet,
        destinationUserSeed: seed,
      });
      expect(result.destinationWallet).toBe(pda);
      expect(result.destinationUserSeed).toEqual(seed);
      const created = await new LazorKit(rpc, PROGRAM_ID).createWallet({
        payer: PAYER,
        userSeed: seed,
        owner: { type: 'ed25519', publicKey: OWNER },
      });
      expect(result.setupInstructions).toEqual(created.instructions);
    });

    it("the userSeed's wallet holding only lamports is created too, not refused", async () => {
      const userSeed = new Uint8Array(32).fill(0x5a);
      const [pda] = await lk0.findWallet(userSeed);
      const base = await fixture();
      const inner = base.rpc as unknown as { getAccountInfo: (k: Address) => { send: () => Promise<unknown> } };
      const rpc = {
        ...(base.rpc as object),
        getAccountInfo: (key: Address) => ({
          send: async () =>
            key === pda
              ? { value: account(new Uint8Array(0), 5_000n, SYSTEM_PROGRAM_ADDRESS) }
              : inner.getAccountInfo(key).send(),
        }),
      } as never;
      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        userSeed,
      });
      expect(result.destinationWallet).toBe(pda);
      expect(result.destinationUserSeed).toBeUndefined(); // the caller has it
      expect(result.setupInstructions.length).toBeGreaterThan(0);
    });

    it('a reused wallet is not read again after its vet: a lagging node cannot fail the migration', async () => {
      // No v2 instruction closes a wallet; the vet's pinned read already found it.
      const existing = (await lk0.findWallet(new Uint8Array(32).fill(0x11)))[0];
      const base = await fixture({ v2Wallet: existing, ownerType: 'secp256r1' });
      const inner = base.rpc as unknown as { getAccountInfo: (k: Address) => { send: () => Promise<unknown> } };
      const asked: Address[] = [];
      const rpc = {
        ...(base.rpc as object),
        getAccountInfo: (key: Address) => ({
          send: async () => {
            asked.push(key);
            return key === existing ? { value: null } : inner.getAccountInfo(key).send();
          },
        }),
      } as never;
      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: PASSKEY_OWNER,
        v1Wallet: base.v1Wallet,
      });
      expect(result.destinationWallet).toBe(existing);
      expect(result.setupInstructions).toHaveLength(0);
      expect(asked).not.toContain(existing);
    });
  });

  // A vet reads the wallet at some slot; a node behind it could still show a
  // destination token account as it was before someone rigged it. So the
  // migration's own read of those accounts asks for state no older than the
  // vet's newest read — whichever way the vetted wallet was named.
  for (const label of ['a reused wallet', "the userSeed's wallet", "the destinationUserSeed's wallet"] as const) {
    it(`reads ${label}'s destination token accounts no older than its vet did`, async () => {
      const seed = new Uint8Array(32).fill(label === "the userSeed's wallet" ? 0x5a : 0x14);
      const existing = (await new LazorKit({} as never, PROGRAM_ID).findWallet(seed))[0];
      const [v2Vault] = await findVaultPda(existing, PROGRAM_ID);
      const destAta = await getAssociatedTokenAddress(MINT, v2Vault, TOKEN_PROGRAM_ADDRESS);
      const reused = label === 'a reused wallet';
      const base = await fixture({ v2Wallet: existing, token: true, ownerType: reused ? 'secp256r1' : 'ed25519' });
      const inner = base.rpc as unknown as {
        getMultipleAccounts: (k: Address[], c?: unknown) => { send: () => Promise<unknown> };
      };
      const asked: { keys: Address[]; minContextSlot?: bigint }[] = [];
      const rpc = {
        ...(base.rpc as object),
        getMultipleAccounts: (keys: Address[], config: { minContextSlot?: bigint }) => {
          asked.push({ keys, minContextSlot: config?.minContextSlot });
          return inner.getMultipleAccounts(keys, config);
        },
      } as never;
      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: reused ? PASSKEY_OWNER : ED25519_OWNER,
        ...(label === "the userSeed's wallet"
          ? { userSeed: seed }
          : { v1Wallet: base.v1Wallet, ...(reused ? {} : { destinationUserSeed: seed }) }),
      });
      expect(result.destinationWallet).toBe(existing);
      expect(result.tokens.map((t) => t.ata)).toEqual([base.sourceAta]);
      // MINT is USDC, a watched mint, so the vet reads this account too; the
      // migration's own read of it comes last.
      const destReads = asked.filter((a) => a.keys.includes(destAta));
      expect(destReads.length).toBeGreaterThan(1);
      expect(destReads.map((a) => a.minContextSlot)).toEqual(destReads.map(() => STUB_SLOT));
    });
  }

  it('reads a fresh destination without a floor: nothing was vetted there', async () => {
    const base = await fixture({ token: true });
    const inner = base.rpc as unknown as {
      getMultipleAccounts: (k: Address[], c?: unknown) => { send: () => Promise<unknown> };
    };
    const asked: { keys: Address[]; minContextSlot?: bigint }[] = [];
    const rpc = {
      ...(base.rpc as object),
      getMultipleAccounts: (keys: Address[], config: { minContextSlot?: bigint }) => {
        asked.push({ keys, minContextSlot: config?.minContextSlot });
        return inner.getMultipleAccounts(keys, config);
      },
    } as never;
    const plan = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: ED25519_OWNER,
      v1Wallet: base.v1Wallet,
    });
    expect(plan.setupInstructions.length).toBeGreaterThan(0);
    const destAta = await getAssociatedTokenAddress(MINT, plan.v2Vault, TOKEN_PROGRAM_ADDRESS);
    const destReads = asked.filter((a) => a.keys.includes(destAta));
    expect(destReads).toHaveLength(1);
    expect(destReads[0]!.minContextSlot).toBeUndefined();
  });

  it('vetMigrationDestination checks the canonical account of each mint in watchMints too', async () => {
    const wallet = (await new LazorKit({} as never, PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x15)))[0];
    const [vault] = await findVaultPda(wallet, PROGRAM_ID);
    // Not one of the always-watched mints (MINT here is USDC, which is).
    const BONK = address('DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263');
    const bonkAta = await getAssociatedTokenAddress(BONK, vault, TOKEN_PROGRAM_ADDRESS);
    const base = await fixture({ v2Wallet: wallet, ownerType: 'secp256r1' });
    const inner = base.rpc as unknown as {
      getMultipleAccounts: (k: Address[], c?: unknown) => { send: () => Promise<{ context: unknown; value: unknown[] }> };
    };
    const rpc = {
      ...(base.rpc as object),
      getMultipleAccounts: (keys: Address[], config: unknown) => ({
        send: async () => {
          const answer = await inner.getMultipleAccounts(keys, config).send();
          return {
            ...answer,
            value: keys.map((k, i) =>
              k === bonkAta ? account(tokenAccountData(BONK, STRANGER, 0n), 2_039_280n, TOKEN_PROGRAM_ADDRESS) : answer.value[i],
            ),
          };
        },
      }),
    } as never;
    const owner = PASSKEY_OWNER;
    const lk = new LazorKit(rpc, PROGRAM_ID);
    // Not a watched mint: the handed-over account cannot be seen.
    expect(await lk.vetMigrationDestination(wallet, owner)).toBeNull();
    expect(await lk.vetMigrationDestination(wallet, owner, { watchMints: [BONK] })).toBe(
      `wallet ${wallet}'s vault token account ${bonkAta} (the vault's own account for mint ${BONK}) belongs to ${STRANGER}`,
    );
    // …and migrateV1Wallet passes watchMints to the vet of a wallet it would reuse.
    const reused = await lk.migrateV1Wallet({ payer: PAYER, owner, v1Wallet: base.v1Wallet });
    expect(reused.destinationWallet).toBe(wallet);
    const fresh = await lk.migrateV1Wallet({ payer: PAYER, owner, v1Wallet: base.v1Wallet, watchMints: [BONK] });
    expect(fresh.destinationWallet).not.toBe(wallet);
  });

  it('vetMigrationDestination names the vault and the token account it refuses', async () => {
    const wallet = (await new LazorKit({} as never, PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x13)))[0];
    const [vault] = await findVaultPda(wallet, PROGRAM_ID);
    const owner = { type: 'ed25519', publicKey: OWNER } as const;

    const assigned = await fixture({ v2Wallet: wallet, hostile: 'vault-assigned' });
    expect(await new LazorKit(assigned.rpc, PROGRAM_ID).vetMigrationDestination(wallet, owner)).toBe(
      `wallet ${wallet}'s vault ${vault} is owned by program ${STRANGER}, not the System Program`,
    );

    const delegated = await fixture({ v2Wallet: wallet, hostile: 'token-delegate' });
    expect(await new LazorKit(delegated.rpc, PROGRAM_ID).vetMigrationDestination(wallet, owner)).toBe(
      `wallet ${wallet}'s vault token account ${delegated.frozenAta} has a delegate, ${STRANGER}`,
    );

    const handed = await fixture({ v2Wallet: wallet, hostile: 'wsol-account-handed-over' });
    const wsolAta = await getAssociatedTokenAddress(WSOL, vault, TOKEN_PROGRAM_ADDRESS);
    expect(await new LazorKit(handed.rpc, PROGRAM_ID).vetMigrationDestination(wallet, owner)).toBe(
      `wallet ${wallet}'s vault token account ${wsolAta} (the vault's own account for mint ${WSOL}) belongs to ${STRANGER}`,
    );

    const clean = await fixture({ v2Wallet: wallet });
    expect(await new LazorKit(clean.rpc, PROGRAM_ID).vetMigrationDestination(wallet, owner)).toBeNull();
  });

  it('refuses to run from a client built at the retired v1 id', async () => {
    const { rpc, v1Wallet } = await fixture();
    await expect(
      new LazorKit(rpc, V1_PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        v1Wallet,
      }),
    ).rejects.toThrow('retired v1 deployment');
  });

  it('leaves frozen, hooked and excluded token accounts behind, and says so', async () => {
    const { rpc, v1Wallet, sourceAta, frozenAta, hookedAta } = await fixture({
      token: true,
      frozenToken: true,
      hookedToken: true,
    });

    const all = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
    });
    expect(all.tokens.map((t) => t.ata)).toEqual([sourceAta]);
    expect(all.skippedTokens.map((s) => [s.token.ata, s.reason])).toEqual([
      [frozenAta, 'frozen'],
      [hookedAta, 'transfer-hook'],
    ]);
    const ix = all.migrate.type === 'ed25519' ? all.migrate.instruction : null;
    expect(Array.from(ix!.data!)).toEqual([17, 1]);

    const none = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
      excludeTokenAccounts: [sourceAta],
    });
    expect(none.tokens).toHaveLength(0);
    expect(none.skippedTokens.find((s) => s.token.ata === sourceAta)?.reason).toBe('excluded');
  });

  // The credential-id hash is public and CreateWallet takes any owner, so a
  // wallet can carry the victim's hash next to the attacker's public key. Only
  // the whole passkey — hash, key and relying party — makes a wallet the user's.
  describe('reusing a passkey destination', () => {
    const RP = 'portal.lazor.sh';
    const PASSKEY = new Uint8Array(33).fill(0x7c);
    const passkeyAuthority = (wallet: Address, keyByte: number, rp: string) => {
      const d = new Uint8Array(145);
      d[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
      d[1] = 1; // secp256r1
      d[2] = 0; // Owner
      new DataView(d.buffer).setUint32(8, 4, true); // signed for four times
      d.set(bytesOf(wallet), 16);
      d.set(CREDENTIAL, 48);
      d.set(new Uint8Array(33).fill(keyByte), 80);
      d.set(sha256(new TextEncoder().encode(rp)), 113);
      return d;
    };
    async function planAgainst(keyByte: number, rp = RP) {
      const planted = (await new LazorKit({} as never, PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x77)))[0];
      // The planted wallet's account exists; its authority is replaced below.
      const base = await fixture({ v2Wallet: planted });
      const rpc = {
        ...(base.rpc as object),
        getProgramAccounts: (
          _id: Address,
          config: { filters: Array<{ memcmp: { bytes: string } }>; withContext?: boolean },
        ) => ({
          send: () => programAccounts(config, async () => {
            const head = config.filters[0]!.memcmp.bytes;
            const tag = (...b: number[]) => bs58(new Uint8Array(b));
            if (head === tag(ACCOUNT_DISCRIMINATOR.AUTHORITY, 1) || head === tag(ACCOUNT_DISCRIMINATOR.AUTHORITY)) {
              return [{ pubkey: STRANGER, account: account(passkeyAuthority(planted, keyByte, rp)) }];
            }
            return [];
          }),
        }),
      } as never;
      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'secp256r1', credentialIdHash: CREDENTIAL, compressedPubkey: PASSKEY, rpId: RP },
        v1Wallet: base.v1Wallet,
      });
      return { planted, result };
    }

    it('reuses a v2 wallet that holds exactly this passkey', async () => {
      const { planted, result } = await planAgainst(0x7c);
      expect(result.destinationWallet).toBe(planted);
    });

    it("does not reuse one listing the credential with someone else's public key", async () => {
      const { planted, result } = await planAgainst(0x7d);
      expect(result.destinationWallet).not.toBe(planted);
      expect(result.destinationUserSeed).toHaveLength(32);
    });

    it('does not reuse one created under another relying party', async () => {
      const { planted, result } = await planAgainst(0x7c, 'evil.example');
      expect(result.destinationWallet).not.toBe(planted);
    });
  });

  it('sends the closed accounts\' rent where the caller says, and binds it', async () => {
    const { rpc, v1Wallet } = await fixture();
    const refund = STRANGER;
    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
      refundDestination: refund,
    });
    const ix = result.migrate.type === 'ed25519' ? result.migrate.instruction : null;
    expect(ix!.accounts![5]!.address).toBe(refund);
  });

  // The token side of a plan, against a vault holding exactly `accounts`.
  describe('which tokens a plan moves', () => {
    const T22 = TOKEN_2022_PROGRAM_ADDRESS;
    const tokenData = (mint: Address, owner: Address, amount: bigint, extras: Array<[number, Uint8Array]> = [], state = 1) => {
      const tlv = extras.flatMap(([type, value]) => {
        const head = new Uint8Array(4);
        new DataView(head.buffer).setUint16(0, type, true);
        new DataView(head.buffer).setUint16(2, value.length, true);
        return [...head, ...value];
      });
      const d = new Uint8Array(extras.length ? 166 + tlv.length : 165);
      d.set(bytesOf(mint), 0);
      d.set(bytesOf(owner), 32);
      new DataView(d.buffer).setBigUint64(64, amount, true);
      d[108] = state;
      if (extras.length) {
        d[165] = 2;
        d.set(tlv, 166);
      }
      return d;
    };
    type Held = { ata: Address; mint: Address; program: Address; data: Uint8Array };
    /** What sits at a destination address: SPL Token account data, or any owner's. */
    type Dest = Uint8Array | { owner: Address; data: Uint8Array };
    async function planWith(
      held: (vault: Address) => Promise<Held[]>,
      mints: Record<string, { owner: Address; data: Uint8Array } | null>,
      dests: (v2Vault: Address) => Promise<Record<string, Dest>> = async () => ({}),
      pages: number[] = [],
    ) {
      const base = await fixture();
      const inner = base.rpc as unknown as {
        getMultipleAccounts: (k: Address[]) => { send: () => Promise<{ value: unknown[] }> };
      };
      const lk = new LazorKit({} as never, PROGRAM_ID);
      let destData: Record<string, Dest> = {};
      const accounts = await held(base.v1Vault);
      const rpc = {
        ...(base.rpc as object),
        getTokenAccountsByOwner: (_o: Address, f: { programId: Address }) => ({
          send: async () => ({
            context: { slot: STUB_SLOT },
            value: accounts
              .filter((h) => h.program === f.programId)
              .map((h) => ({ pubkey: h.ata, account: account(h.data, 2_039_280n, h.program) })),
          }),
        }),
        getMultipleAccounts: (keys: Address[]) => ({
          send: async () => {
            pages.push(keys.length);
            if (keys.some((k) => k in mints || k in destData)) {
              return {
                context: { slot: STUB_SLOT },
                value: keys.map((k) =>
                  k in destData
                    ? destData[k] instanceof Uint8Array
                      ? account(destData[k], 2_039_280n, TOKEN_PROGRAM_ADDRESS)
                      : account(destData[k]!.data, 2_039_280n, destData[k]!.owner)
                    : mints[k]
                      ? account(mints[k]!.data, 1n, mints[k]!.owner)
                      : k in mints
                        ? null
                        : account(new Uint8Array(0), 1n, SYSTEM_PROGRAM_ADDRESS),
                ),
              };
            }
            return inner.getMultipleAccounts(keys).send();
          },
        }),
      } as never;
      // Destinations are keyed by ATA, which needs the plan's v2 vault: plan
      // once to learn it, then plan for real.
      const first = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        v1Wallet: base.v1Wallet,
        destinationUserSeed: new Uint8Array(32).fill(9),
      });
      destData = await dests(first.v2Vault);
      const plan = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        v1Wallet: base.v1Wallet,
        destinationUserSeed: new Uint8Array(32).fill(9),
      });
      void lk;
      return plan;
    }

    it('harvests withheld Token-2022 fees in the migration transaction and moves the account', async () => {
      const mint = address('Ek5JdE3pHMjWMQAhxtBXPH3Z1SutAkZjZ7ARjfFkXFui');
      const withheld = new Uint8Array(8);
      withheld[0] = 7;
      let ata: Address = PAYER;
      const plan = await planWith(
        async (vault) => {
          ata = await getAssociatedTokenAddress(mint, vault, T22);
          return [{ ata, mint, program: T22, data: tokenData(mint, vault, 990n, [[2, withheld]]) }];
        },
        { [mint]: { owner: T22, data: new Uint8Array(82) } },
      );
      expect(plan.tokens.map((t) => t.ata)).toEqual([ata]);
      expect(plan.skippedTokens).toHaveLength(0);
      if (plan.migrate.type !== 'ed25519') throw new Error('ed25519 expected');
      const [harvest, migrate] = plan.migrate.instructions;
      expect(harvest!.programAddress).toBe(T22);
      expect(Array.from(harvest!.data!)).toEqual([26, 4]);
      expect(harvest!.accounts!.map((a) => a.address)).toEqual([mint, ata]);
      expect(migrate).toBe(plan.migrate.instruction);
    });

    it('leaves a token whose mint is gone, or owned by another program', async () => {
      const gone = address('9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin');
      const foreign = address('So11111111111111111111111111111111111111112');
      const plan = await planWith(
        async (vault) => [
          { ata: await getAssociatedTokenAddress(gone, vault, T22), mint: gone, program: T22, data: tokenData(gone, vault, 0n) },
          { ata: await getAssociatedTokenAddress(foreign, vault, T22), mint: foreign, program: T22, data: tokenData(foreign, vault, 0n) },
        ],
        { [gone]: null, [foreign]: { owner: TOKEN_PROGRAM_ADDRESS, data: new Uint8Array(82) } },
      );
      expect(plan.tokens).toHaveLength(0);
      expect(plan.skippedTokens.map((s) => s.reason)).toEqual(['mint-missing', 'mint-missing']);
    });

    it('leaves a token whose destination account is already frozen', async () => {
      const plan = await planWith(
        async (vault) => [
          { ata: await getAssociatedTokenAddress(MINT, vault, TOKEN_PROGRAM_ADDRESS), mint: MINT, program: TOKEN_PROGRAM_ADDRESS, data: tokenData(MINT, vault, 5n) },
        ],
        { [MINT]: { owner: TOKEN_PROGRAM_ADDRESS, data: new Uint8Array(82) } },
        async (v2Vault) => ({
          [await getAssociatedTokenAddress(MINT, v2Vault, TOKEN_PROGRAM_ADDRESS)]: tokenData(MINT, v2Vault, 0n, [], 2),
        }),
      );
      expect(plan.tokens).toHaveLength(0);
      expect(plan.skippedTokens.map((s) => s.reason)).toEqual(['destination-frozen']);
    });

    it('moves a default-frozen mint when the destination is already thawed', async () => {
      const mint = address('Ek5JdE3pHMjWMQAhxtBXPH3Z1SutAkZjZ7ARjfFkXFui');
      const defaultFrozen = new Uint8Array(166 + 4 + 1);
      defaultFrozen[165] = 1;
      new DataView(defaultFrozen.buffer).setUint16(166, 6, true);
      new DataView(defaultFrozen.buffer).setUint16(168, 1, true);
      defaultFrozen[170] = 2;
      const plan = await planWith(
        async (vault) => [
          { ata: await getAssociatedTokenAddress(mint, vault, T22), mint, program: T22, data: tokenData(mint, vault, 5n) },
        ],
        { [mint]: { owner: T22, data: defaultFrozen } },
        async (v2Vault) => ({
          [await getAssociatedTokenAddress(mint, v2Vault, T22)]: { owner: T22, data: tokenData(mint, v2Vault, 0n) },
        }),
      );
      expect(plan.tokens).toHaveLength(1);
    });

    // A wallet can be handed to this owner (TransferOwnership asks the new
    // owner nothing) with its vault's token accounts rigged by the owner
    // before. The program checks a destination's owner and mint, not who else
    // may move or close it, so every existing account the plan delivers into
    // is checked here.
    describe('an existing destination token account', () => {
      /** Plan one SPL token whose destination address already holds `dest(v2Vault)`. */
      async function planInto(dest: (v2Vault: Address) => Dest) {
        let destAta: Address = PAYER;
        const plan = planWith(
          async (vault) => [
            {
              ata: await getAssociatedTokenAddress(MINT, vault, TOKEN_PROGRAM_ADDRESS),
              mint: MINT,
              program: TOKEN_PROGRAM_ADDRESS,
              data: tokenData(MINT, vault, 5n),
            },
          ],
          { [MINT]: { owner: TOKEN_PROGRAM_ADDRESS, data: new Uint8Array(82) } },
          async (v2Vault) => {
            destAta = await getAssociatedTokenAddress(MINT, v2Vault, TOKEN_PROGRAM_ADDRESS);
            return { [destAta]: dest(v2Vault) };
          },
        );
        return { plan: await plan.catch((e: Error) => e), destAta };
      }
      const rejected = async (dest: (v2Vault: Address) => Dest) => {
        const { plan, destAta } = await planInto(dest);
        expect(plan).toBeInstanceOf(Error);
        return { message: (plan as Error).message, destAta };
      };

      it('with a delegate: refused, naming the account', async () => {
        const { message, destAta } = await rejected((v) => withAuthority(tokenData(MINT, v, 0n), 72, STRANGER));
        expect(message).toContain(`destination token account ${destAta} (mint ${MINT}) has a delegate, ${STRANGER}`);
      });

      it('with a close authority other than the vault: refused', async () => {
        const { message, destAta } = await rejected((v) => withAuthority(tokenData(MINT, v, 0n), 129, STRANGER));
        expect(message).toContain(`${destAta} (mint ${MINT}) has a close authority other than the vault, ${STRANGER}`);
      });

      it('handed to another owner: refused', async () => {
        const { message, destAta } = await rejected(() => tokenData(MINT, STRANGER, 0n));
        expect(message).toContain(`${destAta} (mint ${MINT}) belongs to ${STRANGER}, not the v2 vault`);
      });

      it('too short to read, or owned by another program: refused', async () => {
        expect((await rejected(() => new Uint8Array(100))).message).toContain('cannot be read as a token account');
        const foreign = await rejected((v) => ({ owner: STRANGER, data: tokenData(MINT, v, 0n) }));
        expect(foreign.message).toContain(`is owned by program ${STRANGER}, not ${TOKEN_PROGRAM_ADDRESS}`);
      });

      it("the vault's own, with no delegate and the vault as close authority: delivered into", async () => {
        const { plan } = await planInto((v) => withAuthority(tokenData(MINT, v, 0n), 129, v));
        expect(plan).not.toBeInstanceOf(Error);
        expect((plan as Awaited<ReturnType<typeof planWith>>).tokens).toHaveLength(1);
      });

      it('frozen, even with a delegate: skipped rather than refused — nothing is delivered into it', async () => {
        const { plan } = await planInto((v) => withAuthority(tokenData(MINT, v, 0n, [], 2), 72, STRANGER));
        expect(plan).not.toBeInstanceOf(Error);
        const p = plan as Awaited<ReturnType<typeof planWith>>;
        expect(p.tokens).toHaveLength(0);
        expect(p.skippedTokens.map((s) => s.reason)).toEqual(['destination-frozen']);
      });

      it('lamports alone at the address are no account: a fresh destination', async () => {
        const lamportsOnly = () => ({ owner: SYSTEM_PROGRAM_ADDRESS, data: new Uint8Array(0) });
        const { plan } = await planInto(lamportsOnly);
        expect((plan as Awaited<ReturnType<typeof planWith>>).tokens).toHaveLength(1);

        // So a mint that freezes new accounts still freezes this one: anyone
        // can send lamports there, and they must not pass for a thawed account.
        const mint = address('Ek5JdE3pHMjWMQAhxtBXPH3Z1SutAkZjZ7ARjfFkXFui');
        const defaultFrozen = new Uint8Array(166 + 4 + 1);
        defaultFrozen[165] = 1;
        new DataView(defaultFrozen.buffer).setUint16(166, 6, true);
        new DataView(defaultFrozen.buffer).setUint16(168, 1, true);
        defaultFrozen[170] = 2;
        const frozenOnArrival = await planWith(
          async (vault) => [
            { ata: await getAssociatedTokenAddress(mint, vault, T22), mint, program: T22, data: tokenData(mint, vault, 5n) },
          ],
          { [mint]: { owner: T22, data: defaultFrozen } },
          async (v2Vault) => ({ [await getAssociatedTokenAddress(mint, v2Vault, T22)]: lamportsOnly() }),
        );
        expect(frozenOnArrival.tokens).toHaveLength(0);
        expect(frozenOnArrival.skippedTokens.map((s) => s.reason)).toEqual(['frozen-on-arrival']);
      });
    });

    it('reads mints in pages of at most 100', async () => {
      const pages: number[] = [];
      const many = Array.from({ length: 150 }, (_, i) => {
        const b = new Uint8Array(32);
        b[0] = 1 + (i >> 8);
        b[1] = i & 0xff;
        b[31] = 7;
        return getAddressDecoder().decode(b);
      });
      const mintMap = Object.fromEntries(many.map((m) => [m, { owner: TOKEN_PROGRAM_ADDRESS, data: new Uint8Array(82) }]));
      await expect(
        planWith(
          async (vault) =>
            Promise.all(
              many.map(async (m) => ({
                ata: await getAssociatedTokenAddress(m, vault, TOKEN_PROGRAM_ADDRESS),
                mint: m,
                program: TOKEN_PROGRAM_ADDRESS,
                data: tokenData(m, vault, 0n),
              })),
            ),
          mintMap,
          async () => ({}),
          pages,
        ),
      ).resolves.toBeDefined();
      expect(Math.max(...pages)).toBeLessThanOrEqual(100);
    });
  });

  it("refuses a passkey owner whose relying party is not the v1 wallet's", async () => {
    const { rpc, v1Wallet } = await fixture();
    await expect(
      new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: {
          type: 'secp256r1',
          credentialIdHash: CREDENTIAL,
          compressedPubkey: new Uint8Array(33).fill(0x7c),
          rpId: 'lazor.sh',
        },
        v1Wallet,
      }),
    ).rejects.toThrow('relying party');
  });

  it('creates a destination ATA per token and passes the quadruple to the program', async () => {
    const { rpc, v1Wallet, sourceAta } = await fixture({ token: true });
    const lk = new LazorKit(rpc, PROGRAM_ID);

    const result = await lk.migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
    });

    expect(result.tokens).toHaveLength(1);
    expect(result.tokens[0]!.mint).toBe(MINT);
    expect(result.tokens[0]!.amount).toBe(1_234_000n);

    const destAta = await getAssociatedTokenAddress(MINT, result.v2Vault, TOKEN_PROGRAM_ADDRESS);
    const ix = result.migrate.type === 'ed25519' ? result.migrate.instruction : null;
    const accounts = ix!.accounts!.map((a) => a.address);
    // Trailing quadruple: source, destination, mint, token program — in that order.
    expect(accounts.slice(-4)).toEqual([sourceAta, destAta, MINT, TOKEN_PROGRAM_ADDRESS]);
    expect(Array.from(ix!.data!)).toEqual([17, 1]);
    // And the destination ATA is created before the migration runs.
    expect(
      result.setupInstructions.some((s) => s.accounts?.some((a) => a.address === destAta)),
    ).toBe(true);
  });

  it('hands a passkey owner a challenge to sign rather than a finished instruction', async () => {
    const { rpc, v1Wallet } = await fixture();

    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: {
        type: 'secp256r1',
        credentialIdHash: CREDENTIAL,
        // Read off the v1 authority account by findV1WalletsByOwner — a
        // WebAuthn assertion does not carry it.
        compressedPubkey: new Uint8Array(33).fill(0x7c),
        rpId: 'portal.lazor.sh',
      },
      v1Wallet,
    });

    expect(result.migrate.type).toBe('secp256r1');
    if (result.migrate.type !== 'secp256r1') return;
    expect(result.migrate.challenge).toHaveLength(32);
    expect(result.migrate.finalize).toBeTypeOf('function');
  });

  it('says what to do when neither a seed nor an address is given', async () => {
    const { rpc } = await fixture();
    await expect(
      new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
      }),
    ).rejects.toThrow('findV1WalletsByOwner');
  });
});

// Token-2022 states that make a migration revert. Each is plantable in any
// vault, so each must be caught before the owner signs.
describe('unmovable Token-2022 states', () => {
  const tlv = (base: number, entries: Array<[number, Uint8Array]>) => {
    const parts = entries.map(([type, value]) => {
      const head = new Uint8Array(4);
      new DataView(head.buffer).setUint16(0, type, true);
      new DataView(head.buffer).setUint16(2, value.length, true);
      return [head, value];
    });
    const out = new Uint8Array(166 + parts.flat().reduce((n, p) => n + p.length, 0));
    out[165] = base; // AccountType: 1 mint, 2 account
    let off = 166;
    for (const p of parts.flat()) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  };
  const mint = (entries: Array<[number, Uint8Array]>) => tlv(1, entries);
  const tokenAccount = (entries: Array<[number, Uint8Array]>, state = 1) => {
    const d = tlv(2, entries);
    d[108] = state;
    return d;
  };

  it('a plain mint and account can move', () => {
    expect(mintBlocker(mint([]))).toBeNull();
    expect(tokenAccountBlocker(tokenAccount([]))).toBeNull();
  });
  it('non-transferable mints', () => expect(mintBlocker(mint([[9, new Uint8Array(0)]]))).toBe('non-transferable'));
  it('paused mints, but not unpaused ones', () => {
    const paused = new Uint8Array(33);
    paused[32] = 1;
    expect(mintBlocker(mint([[26, paused]]))).toBe('paused');
    expect(mintBlocker(mint([[26, new Uint8Array(33)]]))).toBeNull();
  });
  it('mints that freeze new accounts', () =>
    expect(mintBlocker(mint([[6, new Uint8Array([2])]]))).toBe('frozen-on-arrival'));
  it('frozen accounts', () => expect(tokenAccountBlocker(tokenAccount([], 2))).toBe('frozen'));
  // Withheld fees only stop the account from closing, and anyone may harvest
  // them — so they are not a reason to leave the balance behind.
  it('withheld transfer fees are noted, not a blocker', () => {
    const withheld = new Uint8Array(8);
    withheld[0] = 5;
    expect(tokenAccountBlocker(tokenAccount([[2, withheld]]))).toBeNull();
    expect(tokenAccountWithheldFees(tokenAccount([[2, withheld]]))).toBe(true);
    expect(tokenAccountWithheldFees(tokenAccount([[2, new Uint8Array(8)]]))).toBe(false);
  });
  it('accounts with the CPI guard on', () =>
    expect(tokenAccountBlocker(tokenAccount([[11, new Uint8Array([1])]]))).toBe('cpi-guard'));
});
