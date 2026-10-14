/**
 * The seedless migration path, with a stubbed Connection.
 *
 * Wallets created through `@lazorkit/wallet` used a random 32-byte `userSeed`
 * kept in browser storage. Most users no longer have it, so migration cannot
 * depend on it — and it does not have to: `MigrateWallet` takes the v1 wallet
 * as an account and derives the vault from that key. These tests pin the two
 * halves of that path: finding the wallet from the passkey, and migrating by
 * address.
 */
import { describe, it, expect } from 'vitest';
import { Connection, Keypair, PublicKey, SystemProgram } from '@solana/web3.js';
import { createHash } from 'crypto';

import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_DEVNET_V1,
  findV1WalletsByOwner,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletPda,
  V1_DISC_WALLET,
  V1_DISC_AUTHORITY,
  ACCOUNT_DISCRIMINATOR,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddress,
  mintBlocker,
  buildSecp256r1Challenge,
} from '../../sdk/sdk-legacy/src';
import { contextual, STUB_CONTEXT_SLOT, STUB_UNIX_TIME, type AccountsRead } from './contextReads';

// v2 and v1 at different program ids, as on the real clusters: the migration
// executes against the v1 program and delivers to a v2 vault at the v2 program.
const PROGRAM_ID = PROGRAM_ID_DEVNET;
const V1_PROGRAM_ID = PROGRAM_ID_DEVNET_V1;
const OWNER_PUBKEY = Keypair.generate().publicKey;
const CREDENTIAL = OWNER_PUBKEY.toBytes(); // Ed25519 owner: id seed is the pubkey

/** A v1 authority account: disc | type | role | .. | wallet at 16 | key at 48. */
function v1AuthorityData(wallet: PublicKey, role = 0, authType = 0): Buffer {
  const data = Buffer.alloc(145);
  data[0] = V1_DISC_AUTHORITY;
  data[1] = authType;
  data[2] = role;
  Buffer.from(wallet.toBytes()).copy(data, 16);
  Buffer.from(CREDENTIAL).copy(data, 48);
  if (authType === 1) {
    Buffer.alloc(33, 0x7c).copy(data, 80); // compressed pubkey
    createHash('sha256').update('portal.lazor.sh').digest().copy(data, 113); // rpIdHash
  }
  return data;
}

/** A 165-byte SPL token account, as SPL Token and Token-2022 both lay it out. */
function tokenAccountData(
  mint: PublicKey,
  owner: PublicKey,
  opts: { delegate?: PublicKey; closeAuthority?: PublicKey; frozen?: boolean } = {},
): Buffer {
  const data = Buffer.alloc(165);
  mint.toBuffer().copy(data, 0);
  owner.toBuffer().copy(data, 32);
  if (opts.delegate) {
    data.writeUInt32LE(1, 72);
    opts.delegate.toBuffer().copy(data, 76);
    data.writeBigUInt64LE(1_000n, 121);
  }
  data[108] = opts.frozen ? 2 : 1;
  if (opts.closeAuthority) {
    data.writeUInt32LE(1, 129);
    opts.closeAuthority.toBuffer().copy(data, 133);
  }
  return data;
}

/** Ways a v2 wallet listing this owner can still be someone else's to spend from, and two that are not. */
type Hostile =
  | 'second-authority'
  | 'spender-rank'
  | 'session'
  | 'session-last-slot'
  | 'session-unreadable'
  | 'deferred'
  | 'deferred-last-slot'
  | 'vault-assigned'
  | 'vault-allocated'
  | 'token-delegate'
  | 'token-close-authority'
  | 'token-unreadable'
  | 'watched-ata-moved'
  | 'app-ata-moved'
  | 'expired'
  | 'token-rights-held-by-vault';

function v1WalletData(): Buffer {
  const data = Buffer.alloc(8);
  data[0] = V1_DISC_WALLET;
  return data;
}

describe('findV1WalletsByOwner', () => {
  it('filters on the v1 discriminator and the owner key, and reads the wallet out of the record', async () => {
    const [wallet] = findV1WalletPda(new Uint8Array(32).fill(7), PROGRAM_ID);
    let seenFilters: unknown;
    const connection = {
      getProgramAccounts: async (_programId: PublicKey, config: { filters: unknown }) => {
        seenFilters = config.filters;
        return [
          {
            pubkey: findV1AuthorityPda(wallet, CREDENTIAL, PROGRAM_ID)[0],
            account: { data: v1AuthorityData(wallet) },
          },
        ];
      },
    } as unknown as Connection;

    const found = await findV1WalletsByOwner(connection, CREDENTIAL, PROGRAM_ID, 'ed25519');

    expect(found).toHaveLength(1);
    expect(found[0].wallet.toBase58()).toBe(wallet.toBase58());
    expect(found[0].vault.toBase58()).toBe(findV1VaultPda(wallet, PROGRAM_ID)[0].toBase58());
    expect(found[0].role).toBe(0);
    // The owner key comes out of the record, because a returning user's browser
    // cannot produce it: signing in with a passkey yields an assertion, and an
    // assertion carries no public key.
    expect(Buffer.from(found[0].ownerPubkey)).toEqual(Buffer.from(CREDENTIAL));

    // The filters are the contract with the RPC: a v1 authority (disc 2) whose
    // key material at offset 48 is this owner's.
    const filters = seenFilters as Array<{ memcmp: { offset: number; bytes: string } }>;
    expect(filters.map((f) => f.memcmp.offset)).toEqual([0, 48]);
    expect(Buffer.from(filters[0].memcmp.bytes, 'base64')).toEqual(
      Buffer.from([V1_DISC_AUTHORITY, 0]),
    );
    expect(Buffer.from(filters[1].memcmp.bytes, 'base64')).toEqual(Buffer.from(CREDENTIAL));
  });

  it('rejects an id seed that is not 32 bytes', async () => {
    await expect(
      findV1WalletsByOwner({} as Connection, new Uint8Array(16), PROGRAM_ID, 'ed25519'),
    ).rejects.toThrow('32 bytes');
  });
});

describe('migrateV1Wallet by address', () => {
  const [v1Wallet] = findV1WalletPda(new Uint8Array(32).fill(0x5a), V1_PROGRAM_ID);
  const [v1Authority] = findV1AuthorityPda(v1Wallet, CREDENTIAL, V1_PROGRAM_ID);
  const [v1Vault] = findV1VaultPda(v1Wallet, V1_PROGRAM_ID);

  /**
   * The v1 wallet and its authority exist, as does each of `mints` (an SPL
   * Token mint) and anything in `accounts`; nothing else does — no v2 vault,
   * no destination token account.
   */
  function stubConnection(
    mints: PublicKey[] = [],
    accounts: Map<string, { data: Buffer; lamports: number; owner: PublicKey }> = new Map(),
  ): Connection {
    return contextual({
      getMultipleAccountsInfo: async (keys: PublicKey[]) =>
        keys.map((key) => {
          if (key.equals(v1Wallet)) return { data: v1WalletData(), lamports: 890880 };
          if (key.equals(v1Authority)) return { data: v1AuthorityData(v1Wallet), lamports: 1 };
          if (mints.some((m) => m.equals(key))) {
            return { data: Buffer.alloc(82), lamports: 1_461_600, owner: TOKEN_PROGRAM_ID };
          }
          return accounts.get(key.toBase58()) ?? null;
        }),
      // No v2 wallet yet, and no protocol config.
      getAccountInfo: async () => null,
      getProgramAccounts: async () => [],
      getTokenAccountsByOwner: async () => ({ value: [] }),
      getSlot: async () => 1_000,
    });
  }

  it('migrates a wallet whose seed is gone, and hands back the seed it had to mint', async () => {
    const client = new LazorKitClient(stubConnection(), PROGRAM_ID);
    const result = await client.migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
    });

    // v1 side derived from the address alone.
    expect(result.v1.wallet.toBase58()).toBe(v1Wallet.toBase58());
    expect(result.v1.authority.toBase58()).toBe(v1Authority.toBase58());
    expect(result.v1.vault.toBase58()).toBe(v1Vault.toBase58());

    // v2 side: nothing existed, so a wallet is created and its seed returned.
    expect(result.destinationUserSeed).toBeInstanceOf(Uint8Array);
    expect(result.destinationUserSeed).toHaveLength(32);
    expect(result.destinationWallet.toBase58()).toBe(
      client.findWallet(result.destinationUserSeed!)[0].toBase58(),
    );
    expect(result.setupInstructions.length).toBeGreaterThan(0);

    expect(result.migrate.type).toBe('ed25519');
    const keys =
      result.migrate.type === 'ed25519'
        ? result.migrate.instruction.keys.map((k) => k.pubkey.toBase58())
        : [];
    expect(keys).toContain(v1Wallet.toBase58());
    expect(keys).toContain(v1Authority.toBase58());
    expect(keys).toContain(v1Vault.toBase58());
    expect(keys).toContain(result.v2Vault.toBase58());
    // Sent to the v1 program — the only one that can sign for a v1 vault.
    expect(
      result.migrate.type === 'ed25519' ? result.migrate.instruction.programId.toBase58() : '',
    ).toBe(V1_PROGRAM_ID.toBase58());
  });

  /** The v1 wallet's owner as a passkey: the same id seed, key 0x7c.., created under portal.lazor.sh. */
  const PASSKEY_OWNER = {
    type: 'secp256r1' as const,
    credentialIdHash: CREDENTIAL,
    compressedPubkey: new Uint8Array(33).fill(0x7c),
    rpId: 'portal.lazor.sh',
  };
  const ED25519_OWNER = { type: 'ed25519' as const, publicKey: OWNER_PUBKEY };
  /** An SPL Token mint outside the four always watched: an app's own token. */
  const APP_MINT = Keypair.generate().publicKey;

  /** A live v2 wallet account, as getAccountInfo / getMultipleAccountsInfo return it. */
  const v2WalletAccount = () => ({
    data: Buffer.from([ACCOUNT_DISCRIMINATOR.WALLET, 0, 0, 0, 1, 0, 0, 0]),
    lamports: 1_000_000,
    owner: PROGRAM_ID,
  });

  /**
   * A connection where `existing` is a v2 wallet whose one authority is this
   * owner — cleanly, or with one of the ways an attacker keeps a hand on it.
   * The owner is the passkey unless `ownerType` says otherwise; `counter` is
   * how many times it has signed for the wallet (default 1: it has used it).
   */
  function withV2Wallet(
    existing: PublicKey,
    hostile?: Hostile,
    opts: {
      counter?: number;
      ownerType?: 'ed25519' | 'secp256r1';
      /** More authority accounts the lookup by this owner's credential finds (on other wallets). */
      alsoListed?: Buffer[];
    } = {},
  ): Connection {
    const authType = opts.ownerType === 'ed25519' ? 0 : 1;
    // A session expires by Unix time (STUB_UNIX_TIME), a deferred execution
    // by slot (1_000). The program refuses either only once the clock is past
    // its expiry: `lastSlot` still works for one more second, or slot.
    const live = Buffer.alloc(176);
    live.writeBigUInt64LE(STUB_UNIX_TIME + 4_000n, 72);
    live.writeBigUInt64LE(5_000n, 168);
    const lastSlot = Buffer.alloc(176);
    lastSlot.writeBigUInt64LE(STUB_UNIX_TIME, 72);
    lastSlot.writeBigUInt64LE(1_000n, 168);
    const expired = Buffer.alloc(176);
    expired.writeBigUInt64LE(STUB_UNIX_TIME - 1n, 72);
    expired.writeBigUInt64LE(999n, 168);
    const authorityData = (role: number) => {
      const data = v1AuthorityData(existing, role, authType);
      data[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
      data.writeUInt32LE(opts.counter ?? 1, 8);
      return data;
    };
    const owner = { pubkey: Keypair.generate().publicKey, account: { data: authorityData(0) } };
    const vault = new LazorKitClient({} as Connection, PROGRAM_ID).findVault(existing)[0];
    const stranger = Keypair.generate().publicKey;
    const mint = Keypair.generate().publicKey;
    const sessionData =
      hostile === 'session' ? live
      : hostile === 'session-last-slot' ? lastSlot
      : hostile === 'session-unreadable' ? live.subarray(0, 79)
      : hostile === 'expired' ? expired
      : null;
    const deferredData =
      hostile === 'deferred' ? live
      : hostile === 'deferred-last-slot' ? lastSlot
      : hostile === 'expired' ? expired
      : null;
    // The wallet, and the vault as the v2 program last left it.
    const vaultAccounts = new Map<string, { data: Buffer; lamports: number; owner: PublicKey }>();
    vaultAccounts.set(existing.toBase58(), v2WalletAccount());
    if (hostile === 'vault-assigned') {
      vaultAccounts.set(vault.toBase58(), { data: Buffer.alloc(0), lamports: 5_000_000, owner: stranger });
    } else if (hostile === 'vault-allocated') {
      vaultAccounts.set(vault.toBase58(), { data: Buffer.alloc(80), lamports: 5_000_000, owner: SystemProgram.programId });
    } else {
      vaultAccounts.set(vault.toBase58(), { data: Buffer.alloc(0), lamports: 5_000_000, owner: SystemProgram.programId });
    }
    if (hostile === 'watched-ata-moved' || hostile === 'app-ata-moved') {
      const moved = hostile === 'app-ata-moved' ? APP_MINT : new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      vaultAccounts.set(getAssociatedTokenAddress(moved, vault, TOKEN_PROGRAM_ID).toBase58(), {
        data: tokenAccountData(moved, stranger),
        lamports: 2_039_280,
        owner: TOKEN_PROGRAM_ID,
      });
    }
    const vaultTokens =
      hostile === 'token-delegate' ? [tokenAccountData(mint, vault, { delegate: stranger })]
      : hostile === 'token-close-authority' ? [tokenAccountData(mint, vault, { closeAuthority: stranger })]
      : hostile === 'token-unreadable' ? [tokenAccountData(mint, vault).subarray(0, 100)]
      // Rights held by the vault itself grant nothing.
      : hostile === 'token-rights-held-by-vault' ? [tokenAccountData(mint, vault, { delegate: vault, closeAuthority: vault })]
      : [];
    return contextual({
      ...stubConnection([], vaultAccounts),
      getTokenAccountsByOwner: async (who: PublicKey, filter: { programId: PublicKey }) => ({
        value:
          who.equals(vault) && filter.programId.equals(TOKEN_2022_PROGRAM_ID)
            ? vaultTokens.map((data) => ({
                pubkey: Keypair.generate().publicKey,
                account: { data, owner: TOKEN_2022_PROGRAM_ID },
              }))
            : [],
      }),
      getProgramAccounts: async (_id: PublicKey, config: { filters: Array<{ memcmp: { bytes: string } }> }) => {
        const head = Buffer.from(config.filters[0].memcmp.bytes, 'base64');
        // The lookup by credential (findWalletsByAuthority).
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, authType]))) {
          return [owner, ...(opts.alsoListed ?? []).map((data) => ({ pubkey: Keypair.generate().publicKey, account: { data } }))];
        }
        // The wallet's own authorities (vetting).
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY]))) {
          if (hostile === 'spender-rank') return [{ ...owner, account: { data: authorityData(2) } }];
          return hostile === 'second-authority' ? [owner, owner] : [owner];
        }
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.SESSION]))) {
          return sessionData ? [{ pubkey: owner.pubkey, account: { data: sessionData } }] : [];
        }
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC]))) {
          return deferredData ? [{ pubkey: owner.pubkey, account: { data: deferredData } }] : [];
        }
        return [];
      },
      // The v2 wallet exists; the v1 authority is readable as this owner's
      // (the passkey path checks its key and reads its counter).
      getAccountInfo: async (key: PublicKey) =>
        key.equals(existing)
          ? v2WalletAccount()
          : key.equals(v1Authority)
            ? { data: v1AuthorityData(v1Wallet, 0, authType), lamports: 1, owner: V1_PROGRAM_ID }
            : null,
    });
  }

  it('reuses a v2 wallet this passkey has already signed for instead of minting a seed', async () => {
    const [existingWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(
      new Uint8Array(32).fill(0x11),
    );

    const result = await new LazorKitClient(withV2Wallet(existingWallet), PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: PASSKEY_OWNER,
      v1Wallet,
    });

    expect(result.destinationWallet.toBase58()).toBe(existingWallet.toBase58());
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  // Anyone can hand a wallet to this owner (TransferOwnership asks it
  // nothing), and vetting cannot see everything its earlier holder left on the
  // vault — an SPL Token account for an unwatched mint, moved to them. So a
  // wallet found by itself is reused only if the passkey signed for it.
  it('does not reuse a clean wallet this passkey has never signed for — it mints a fresh one', async () => {
    const [handed] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x14));
    const client = new LazorKitClient(withV2Wallet(handed, undefined, { counter: 0 }), PROGRAM_ID);
    // It would pass vetting.
    expect(await client.vetMigrationDestination(handed, PASSKEY_OWNER)).toBeNull();

    const result = await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: PASSKEY_OWNER, v1Wallet });
    expect(result.destinationWallet.equals(handed)).toBe(false);
    expect(result.destinationWallet.toBase58()).toBe(client.findWallet(result.destinationUserSeed!)[0].toBase58());
    expect(result.setupInstructions.length).toBeGreaterThan(0);
  });

  /** This owner's passkey authority on some other wallet: `counter` signatures, at `role`; its key byte and rpId can differ. */
  function listedElsewhere(o: { role?: number; counter: number; keyByte?: number; rpId?: string }): Buffer {
    const data = v1AuthorityData(Keypair.generate().publicKey, o.role ?? 0, 1);
    data[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
    data.writeUInt32LE(o.counter, 8);
    if (o.keyByte !== undefined) Buffer.alloc(33, o.keyByte).copy(data, 80);
    if (o.rpId) createHash('sha256').update(o.rpId).digest().copy(data, 113);
    return data;
  }

  // Until the program named the wallet in the passkey challenge, a signature
  // this passkey made on one authority for CreateSession, AddAuthority,
  // TransferOwnership or Authorize could be submitted again on another at the
  // same counter, through the same fee payer, and counts from then are still
  // on chain. With two signed on, either wallet's count may be the copy —
  // including one copied from an Admin seat.
  for (const [label, role] of [
    ['as an Owner of another wallet', 0],
    ['at Admin rank on another wallet', 1],
  ] as const) {
    it(`does not reuse the wallet it signed for when it has also signed ${label} — it mints a fresh one`, async () => {
      const [mine] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x1b));
      const client = new LazorKitClient(
        withV2Wallet(mine, undefined, { alsoListed: [listedElsewhere({ role, counter: 2 })] }),
        PROGRAM_ID,
      );
      expect(await client.vetMigrationDestination(mine, PASSKEY_OWNER)).toBeNull();
      const result = await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: PASSKEY_OWNER, v1Wallet });
      expect(result.destinationWallet.equals(mine)).toBe(false);
      expect(result.destinationWallet.toBase58()).toBe(client.findWallet(result.destinationUserSeed!)[0].toBase58());
    });
  }

  it('still reuses it beside authorities this passkey never signed on, or that hold another key or relying party', async () => {
    const [mine] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x1c));
    const client = new LazorKitClient(
      withV2Wallet(mine, undefined, {
        alsoListed: [
          listedElsewhere({ role: 1, counter: 0 }),
          // Only this passkey's own key advances a counter it can be blamed for.
          listedElsewhere({ counter: 5, keyByte: 0x7d }),
          listedElsewhere({ counter: 5, rpId: 'evil.example' }),
        ],
      }),
      PROGRAM_ID,
    );
    const result = await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: PASSKEY_OWNER, v1Wallet });
    expect(result.destinationWallet.equals(mine)).toBe(true);
    expect(result.setupInstructions).toHaveLength(0);
  });

  it('does not read a reused wallet again after its vet: a lagging node cannot fail the migration', async () => {
    // No v2 instruction closes a wallet; the vet's pinned read already found it.
    const [mine] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x1d));
    const base = withV2Wallet(mine) as unknown as { getAccountInfo: (k: PublicKey) => Promise<unknown> };
    const asked: PublicKey[] = [];
    const connection = contextual({
      ...base,
      getAccountInfo: async (key: PublicKey) => {
        asked.push(key);
        return key.equals(mine) ? null : base.getAccountInfo(key);
      },
    });
    const result = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: PASSKEY_OWNER,
      v1Wallet,
    });
    expect(result.destinationWallet.equals(mine)).toBe(true);
    expect(result.setupInstructions).toHaveLength(0);
    expect(asked.some((k) => k.equals(mine))).toBe(false);
  });

  it("never reuses an Ed25519 owner's wallet by itself (it records no signatures); destinationUserSeed can name it", async () => {
    const seed = new Uint8Array(32).fill(0x15);
    const [existing] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);
    const client = new LazorKitClient(withV2Wallet(existing, undefined, { ownerType: 'ed25519' }), PROGRAM_ID);
    expect(await client.vetMigrationDestination(existing, ED25519_OWNER)).toBeNull();

    const found = await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: ED25519_OWNER, v1Wallet });
    expect(found.destinationWallet.equals(existing)).toBe(false);

    const named = await client.migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: ED25519_OWNER,
      v1Wallet,
      destinationUserSeed: seed,
    });
    expect(named.destinationWallet.equals(existing)).toBe(true);
    expect(named.setupInstructions).toHaveLength(0);
  });

  // Being listed on a wallet is not owning it. Each of these leaves someone
  // else able to spend what lands in the vault, so the SDK must not reuse it —
  // even one the passkey has signed for. TransferOwnership hands a wallet over
  // without undoing any of the vault or token ones, which its earlier Owner
  // set up through Execute.
  for (const hostile of [
    'second-authority',
    'spender-rank',
    'session',
    'session-last-slot',
    'session-unreadable',
    'deferred',
    'deferred-last-slot',
    'vault-assigned',
    'vault-allocated',
    'token-delegate',
    'token-close-authority',
    'token-unreadable',
    'watched-ata-moved',
  ] as const) {
    it(`does not deliver into a wallet with a ${hostile} — it mints a fresh one`, async () => {
      const [planted] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(
        new Uint8Array(32).fill(0x66),
      );
      const client = new LazorKitClient(withV2Wallet(planted, hostile), PROGRAM_ID);

      const result = await client.migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: PASSKEY_OWNER,
        v1Wallet,
      });

      expect(result.destinationWallet.toBase58()).not.toBe(planted.toBase58());
      expect(result.destinationWallet.toBase58()).toBe(
        client.findWallet(result.destinationUserSeed!)[0].toBase58(),
      );
    });
  }

  for (const benign of ['expired', 'token-rights-held-by-vault'] as const) {
    it(`still reuses a wallet with ${benign === 'expired' ? 'a session and a deferred execution past their expiry' : 'token rights held by the vault itself'}`, async () => {
      const [existing] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x12));
      const result = await new LazorKitClient(withV2Wallet(existing, benign), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: PASSKEY_OWNER,
        v1Wallet,
      });
      expect(result.destinationWallet.toBase58()).toBe(existing.toBase58());
    });
  }

  for (const [hostile, reason] of [
    ['vault-assigned', 'not the System Program'],
    ['vault-allocated', 'carries data, so it is no longer a plain system account'],
    ['token-delegate', 'has a delegate'],
    ['token-close-authority', 'has a close authority other than the vault'],
    ['watched-ata-moved', "(the vault's own account for mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v) belongs to"],
    ['session-last-slot', 'live session'],
    ['deferred-last-slot', 'pending deferred execution'],
  ] as const) {
    it(`vetMigrationDestination names the problem: ${hostile}`, async () => {
      const [existing] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x13));
      const problem = await new LazorKitClient(withV2Wallet(existing, hostile), PROGRAM_ID).vetMigrationDestination(
        existing,
        PASSKEY_OWNER,
      );
      expect(problem).toContain(existing.toBase58());
      expect(problem).toContain(reason);
    });
  }

  // The canonical vault account for an unwatched mint, handed away, is out of
  // sight — unless the caller names the mint.
  it('sees a moved canonical account only for a mint in watchMints, then neither vets nor reuses the wallet', async () => {
    const [existing] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x18));
    const client = new LazorKitClient(withV2Wallet(existing, 'app-ata-moved'), PROGRAM_ID);
    expect(await client.vetMigrationDestination(existing, PASSKEY_OWNER)).toBeNull();
    expect(await client.vetMigrationDestination(existing, PASSKEY_OWNER, { watchMints: [APP_MINT] })).toContain(
      `(the vault's own account for mint ${APP_MINT.toBase58()}) belongs to`,
    );

    const blind = await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: PASSKEY_OWNER, v1Wallet });
    expect(blind.destinationWallet.equals(existing)).toBe(true);
    const watching = await client.migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: PASSKEY_OWNER,
      v1Wallet,
      watchMints: [APP_MINT.toBase58()],
    });
    expect(watching.destinationWallet.equals(existing)).toBe(false);
  });

  // A vet reads the wallet at some slot; a node behind it could still show a
  // destination token account as it was before someone rigged it. So the
  // migration's own read of those accounts asks for state no older than the
  // vet's newest read — for a wallet it reused and for one it was named.
  for (const [label, owner, seed, by] of [
    ['a reused wallet', PASSKEY_OWNER, undefined, undefined],
    ["the userSeed's wallet", ED25519_OWNER, new Uint8Array(32).fill(0x5a), 'userSeed'],
    ['a wallet named by destinationUserSeed', ED25519_OWNER, new Uint8Array(32).fill(0x19), 'destinationUserSeed'],
  ] as const) {
    it(`reads ${label}'s destination token accounts no older than its vet did`, async () => {
      const mint = Keypair.generate().publicKey;
      const source = Keypair.generate().publicKey;
      const [existing] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed ?? new Uint8Array(32).fill(0x1a));
      const [v2Vault] = new LazorKitClient(stubConnection(), PROGRAM_ID).findVault(existing);
      const destAta = getAssociatedTokenAddress(mint, v2Vault, TOKEN_PROGRAM_ID);
      const base = withV2Wallet(existing, undefined, { ownerType: owner.type }) as unknown as {
        getMultipleAccountsInfo: (k: PublicKey[]) => Promise<unknown[]>;
      };
      const reads: AccountsRead[] = [];
      const connection = contextual(
        {
          ...base,
          // The v1 vault holds one SPL token; the v2 vault none yet.
          getTokenAccountsByOwner: async (who: PublicKey, filter: { programId: PublicKey }) => ({
            value:
              who.equals(v1Vault) && filter.programId.equals(TOKEN_PROGRAM_ID)
                ? [{ pubkey: source, account: { data: tokenAccountData(mint, v1Vault), owner: TOKEN_PROGRAM_ID } }]
                : [],
          }),
          getMultipleAccountsInfo: async (keys: PublicKey[]) =>
            keys.some((k) => k.equals(mint))
              ? keys.map((k) => (k.equals(mint) ? { data: Buffer.alloc(82), owner: TOKEN_PROGRAM_ID, lamports: 1 } : null))
              : base.getMultipleAccountsInfo(keys),
        },
        reads,
      );

      const plan = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner,
        ...(by === 'userSeed' ? { userSeed: seed } : { v1Wallet, ...(by ? { destinationUserSeed: seed } : {}) }),
      });
      expect(plan.destinationWallet.equals(existing)).toBe(true);
      expect(plan.tokens.map((t) => t.ata.toBase58())).toEqual([source.toBase58()]);
      const destRead = reads.find((r) => r.keys.some((k) => k.equals(destAta)));
      expect(destRead?.minContextSlot).toBe(STUB_CONTEXT_SLOT);
    });
  }

  it('reads a fresh destination without a floor: nothing was vetted there', async () => {
    const mint = Keypair.generate().publicKey;
    const reads: AccountsRead[] = [];
    const base = stubConnection([mint]) as unknown as Record<string, unknown>;
    const connection = contextual(
      {
        ...base,
        getTokenAccountsByOwner: async (who: PublicKey, filter: { programId: PublicKey }) => ({
          value:
            who.equals(v1Vault) && filter.programId.equals(TOKEN_PROGRAM_ID)
              ? [{ pubkey: Keypair.generate().publicKey, account: { data: tokenAccountData(mint, v1Vault), owner: TOKEN_PROGRAM_ID } }]
              : [],
        }),
      },
      reads,
    );
    const plan = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: ED25519_OWNER,
      v1Wallet,
    });
    const destAta = getAssociatedTokenAddress(mint, plan.v2Vault, TOKEN_PROGRAM_ID);
    const destRead = reads.find((r) => r.keys.some((k) => k.equals(destAta)));
    expect(destRead).toBeDefined();
    expect(destRead!.minContextSlot).toBeUndefined();
  });

  it("refuses the userSeed's own v2 wallet when its vault was handed to another program", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [seedWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);

    await expect(
      new LazorKitClient(withV2Wallet(seedWallet, 'vault-assigned', { ownerType: 'ed25519' }), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: ED25519_OWNER,
        userSeed: seed,
      }),
    ).rejects.toThrow('not the System Program');
  });

  it("refuses the userSeed's own v2 wallet when someone else can spend from it", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [seedWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);

    await expect(
      new LazorKitClient(withV2Wallet(seedWallet, 'deferred', { ownerType: 'ed25519' }), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: ED25519_OWNER,
        userSeed: seed,
      }),
    ).rejects.toThrow('pending deferred execution');
  });

  it("delivers into the userSeed's own v2 wallet once vetted, signed for or not (a retry after its setup landed)", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [seedWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);
    const result = await new LazorKitClient(withV2Wallet(seedWallet, undefined, { counter: 0 }), PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: PASSKEY_OWNER,
      userSeed: seed,
    });
    expect(result.destinationWallet.equals(seedWallet)).toBe(true);
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  it("vets a wallet named by destinationUserSeed, and refuses it when someone else can spend from it", async () => {
    const seed = new Uint8Array(32).fill(0x16);
    const [named] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);
    await expect(
      new LazorKitClient(withV2Wallet(named, 'session', { ownerType: 'ed25519' }), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: ED25519_OWNER,
        v1Wallet,
        destinationUserSeed: seed,
      }),
    ).rejects.toThrow("refusing to migrate into the destinationUserSeed's v2 wallet");
  });

  // Anyone can send lamports to a wallet address — a userSeed's is public, in
  // the v1 CreateWallet instruction. That is not a wallet yet: create one there
  // (the program tops the balance up and takes the account). Refusing would let
  // a stranger block the migration for a few thousand lamports; skipping the
  // creation would deliver into the vault of a wallet that does not exist yet,
  // which whoever then creates it at that public seed would own.
  for (const [label, seedOpts] of [
    ['userSeed', { userSeed: new Uint8Array(32).fill(0x5a) }],
    ['destinationUserSeed', { v1Wallet, destinationUserSeed: new Uint8Array(32).fill(0x17) }],
  ] as const) {
    it(`creates the ${label}'s wallet over an address holding only lamports`, async () => {
      const seed = 'userSeed' in seedOpts ? seedOpts.userSeed : seedOpts.destinationUserSeed;
      const [target] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);
      const funded = { data: Buffer.alloc(0), lamports: 1_000_000, owner: SystemProgram.programId };
      const client = new LazorKitClient(
        contextual({
          ...stubConnection(),
          getAccountInfo: async (key: PublicKey) => (key.equals(target) ? funded : null),
        }),
        PROGRAM_ID,
      );
      const result = await client.migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: ED25519_OWNER,
        ...seedOpts,
      });
      expect(result.destinationWallet.equals(target)).toBe(true);
      const creates = result.setupInstructions.filter(
        (ix) => ix.programId.equals(PROGRAM_ID) && ix.keys.some((k) => k.pubkey.equals(target)),
      );
      expect(creates).toHaveLength(1);
      expect(creates[0].data[0]).toBe(0); // CreateWallet
      expect(result.destinationUserSeed === undefined).toBe(label === 'userSeed');
    });
  }

  it('refuses a userSeed address some other program owns: no wallet can be created there', async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [target] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);
    const client = new LazorKitClient(
      contextual({
        ...stubConnection(),
        getAccountInfo: async (key: PublicKey) =>
          key.equals(target) ? { data: Buffer.alloc(8), lamports: 1_000_000, owner: Keypair.generate().publicKey } : null,
      }),
      PROGRAM_ID,
    );
    await expect(
      client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner: ED25519_OWNER, userSeed: seed }),
    ).rejects.toThrow(`${target.toBase58()} is not a wallet of program ${PROGRAM_ID.toBase58()}`);
  });

  // A wallet can carry a victim's (public) credential hash next to an
  // attacker's public key; only the whole passkey makes it the user's.
  for (const [label, keyByte, rp, reused] of [
    ['reuses a v2 wallet that holds exactly this passkey', 0x7c, 'portal.lazor.sh', true],
    ["does not reuse one listing the credential with someone else's key", 0x7d, 'portal.lazor.sh', false],
    ['does not reuse one created under another relying party', 0x7c, 'evil.example', false],
  ] as const) {
    it(label, async () => {
      const [planted] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(new Uint8Array(32).fill(0x77));
      const authority = Buffer.alloc(145);
      authority[0] = ACCOUNT_DISCRIMINATOR.AUTHORITY;
      authority[1] = 1;
      authority[2] = 0;
      authority.writeUInt32LE(4, 8); // signed for four times
      planted.toBuffer().copy(authority, 16);
      Buffer.from(CREDENTIAL).copy(authority, 48);
      Buffer.alloc(33, keyByte).copy(authority, 80);
      createHash('sha256').update(rp).digest().copy(authority, 113);
      const connection = contextual({
        ...stubConnection(new Array<PublicKey>(), new Map([[planted.toBase58(), v2WalletAccount()]])),
        getProgramAccounts: async (_id: PublicKey, config: { filters: Array<{ memcmp: { bytes: string } }> }) => {
          const head = Buffer.from(config.filters[0].memcmp.bytes, 'base64');
          const isAuthorityScan =
            head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, 1])) ||
            head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY]));
          return isAuthorityScan ? [{ pubkey: Keypair.generate().publicKey, account: { data: authority } }] : [];
        },
        // The planted wallet exists; the v1 authority is readable (the passkey
        // path reads its counter).
        getAccountInfo: async (key: PublicKey) =>
          key.equals(planted)
            ? v2WalletAccount()
            : key.equals(v1Authority)
              ? { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 }
              : null,
      });

      const result = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: PASSKEY_OWNER,
        v1Wallet,
      });
      expect(result.destinationWallet.equals(planted)).toBe(reused);
    });
  }

  it("sends the closed accounts' rent where the caller says", async () => {
    const refund = Keypair.generate().publicKey;
    const result = await new LazorKitClient(stubConnection(), PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
      refundDestination: refund,
    });
    const ix = result.migrate.type === 'ed25519' ? result.migrate.instruction : null;
    expect(ix!.keys[5].pubkey.toBase58()).toBe(refund.toBase58());
  });

  it('knows a paused Token-2022 mint cannot move', () => {
    const data = Buffer.alloc(166 + 4 + 33);
    data[165] = 1;
    data.writeUInt16LE(26, 166);
    data.writeUInt16LE(33, 168);
    data[170 + 32] = 1;
    expect(mintBlocker(data)).toBe('paused');
  });

  it('harvests withheld Token-2022 fees in the migration transaction and moves the account', async () => {
    const mint = Keypair.generate().publicKey;
    const ata = Keypair.generate().publicKey;
    const T22 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
    const data = Buffer.alloc(166 + 4 + 8);
    mint.toBuffer().copy(data, 0);
    v1Vault.toBuffer().copy(data, 32);
    data.writeBigUInt64LE(990n, 64);
    data[108] = 1;
    data[165] = 2; // AccountType::Account
    data.writeUInt16LE(2, 166); // TransferFeeAmount
    data.writeUInt16LE(8, 168);
    data.writeBigUInt64LE(7n, 170); // withheld
    const base = stubConnection() as unknown as { getMultipleAccountsInfo: (k: PublicKey[]) => Promise<unknown[]> };
    const connection = contextual({
      ...stubConnection(),
      getTokenAccountsByOwner: async (_o: PublicKey, f: { programId: PublicKey }) => ({
        value: f.programId.equals(T22) ? [{ pubkey: ata, account: { data, owner: T22 } }] : [],
      }),
      getMultipleAccountsInfo: async (keys: PublicKey[]) =>
        keys.some((k) => k.equals(mint))
          ? keys.map((k) => (k.equals(mint) ? { data: Buffer.alloc(82), owner: T22, lamports: 1 } : null))
          : base.getMultipleAccountsInfo(keys),
    });

    const plan = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
    });
    expect(plan.tokens.map((x) => x.ata.toBase58())).toEqual([ata.toBase58()]);
    if (plan.migrate.type !== 'ed25519') throw new Error('ed25519 expected');
    const [harvest, migrate] = plan.migrate.instructions;
    expect(harvest.programId.toBase58()).toBe(T22.toBase58());
    expect(Array.from(harvest.data)).toEqual([26, 4]);
    expect(harvest.keys.map((k) => k.pubkey.toBase58())).toEqual([mint.toBase58(), ata.toBase58()]);
    expect(migrate).toBe(plan.migrate.instruction);
  });

  it("refuses a passkey owner whose relying party is not the v1 wallet's", async () => {
    const connection = contextual({
      ...stubConnection(),
      getAccountInfo: async (key: PublicKey) =>
        key.equals(v1Authority) ? { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 } : null,
    });
    await expect(
      new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
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

  // The v1 authority signs, so the wallet the challenge names is the one in
  // its header — the v1 wallet — and the program verifying it is the v1 id.
  // Naming the v2 destination instead would fail on chain with 3005.
  it("binds a passkey migration's challenge to the v1 wallet, not the v2 destination", async () => {
    const connection = contextual({
      ...stubConnection(),
      getAccountInfo: async (key: PublicKey) =>
        key.equals(v1Authority) ? { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 } : null,
    });
    const payer = Keypair.generate().publicKey;
    const plan = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer,
      owner: {
        type: 'secp256r1',
        credentialIdHash: CREDENTIAL,
        compressedPubkey: new Uint8Array(33).fill(0x7c),
        rpId: 'portal.lazor.sh',
      },
      v1Wallet,
    });
    if (plan.migrate.type !== 'secp256r1') throw new Error('secp256r1 expected');
    expect(plan.tokens).toEqual([]);

    // The 14-byte prefix the program hashes rides in the migrate instruction,
    // after [discriminator, token count].
    const instructions = plan.migrate.finalize({
      signature: new Uint8Array(64),
      authenticatorData: new Uint8Array(37),
      clientDataJsonHash: new Uint8Array(32),
      clientDataJson: new TextEncoder().encode('{}'),
    });
    const prefix = new Uint8Array(instructions[instructions.length - 1].data.subarray(2, 16));
    const challengeFor = (wallet: PublicKey) =>
      buildSecp256r1Challenge({
        discriminator: new Uint8Array([17]),
        authPayload: prefix,
        // destination || v1_wallet || num_tokens || refund_dest (no tokens here).
        signedPayload: new Uint8Array(
          Buffer.concat([plan.v2Vault.toBuffer(), v1Wallet.toBuffer(), Buffer.from([0]), payer.toBuffer()]),
        ),
        slot: 0n, // unused: the slot is inside the prefix
        payer,
        wallet,
        counter: Buffer.from(prefix).readUInt32LE(8),
        programId: V1_PROGRAM_ID,
      });

    expect(Buffer.from(plan.migrate.challenge).toString('hex')).toBe(
      Buffer.from(challengeFor(v1Wallet)).toString('hex'),
    );
    expect(Buffer.from(plan.migrate.challenge).equals(Buffer.from(challengeFor(plan.destinationWallet)))).toBe(false);
  });

  it("reads a passkey migration's counter and slot at the commitment and floor it is given", async () => {
    // The counter the challenge signs, and the slot it carries, come from a
    // node at or past `minContextSlot` (3006 otherwise, if the v1 authority
    // signed something just before). The owner check reads the authority too,
    // with no config: only the counter read is held to the floor.
    const counterReads: unknown[] = [];
    const slotReads: unknown[] = [];
    const connection = contextual({
      ...stubConnection(),
      getAccountInfo: async (key: PublicKey, config?: unknown) => {
        if (!key.equals(v1Authority)) return null;
        if (config !== undefined) counterReads.push(config);
        return { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 };
      },
      getSlot: async (config?: unknown) => {
        slotReads.push(config);
        return 1_000;
      },
    });
    const owner = {
      type: 'secp256r1' as const,
      credentialIdHash: CREDENTIAL,
      compressedPubkey: new Uint8Array(33).fill(0x7c),
      rpId: 'portal.lazor.sh',
    };
    const client = new LazorKitClient(connection, PROGRAM_ID);

    await client.migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner,
      v1Wallet,
      minContextSlot: 4_242,
      commitment: 'processed',
    });
    expect(counterReads).toEqual([{ commitment: 'processed', minContextSlot: 4_242 }]);
    expect(slotReads).toContainEqual({ commitment: 'processed', minContextSlot: 4_242 });

    // Without options: 'confirmed', whatever the Connection's default, and no floor.
    counterReads.length = 0;
    slotReads.length = 0;
    await client.migrateV1Wallet({ payer: Keypair.generate().publicKey, owner, v1Wallet });
    expect(counterReads).toEqual([{ commitment: 'confirmed' }]);
    expect(slotReads).toContainEqual({ commitment: 'confirmed' });
  });

  it('refuses to run from a client built at the retired v1 id', async () => {
    await expect(
      new LazorKitClient(stubConnection(), V1_PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
        v1Wallet,
      }),
    ).rejects.toThrow('retired v1 deployment');
  });

  it('passes source, destination, mint, token program per token and skips a frozen one', async () => {
    const mint = Keypair.generate().publicKey;
    const good = Keypair.generate().publicKey;
    const frozen = Keypair.generate().publicKey;
    const tokenData = (isFrozen: boolean) => {
      const data = Buffer.alloc(165);
      mint.toBuffer().copy(data, 0);
      v1Vault.toBuffer().copy(data, 32);
      data.writeBigUInt64LE(42n, 64);
      data[108] = isFrozen ? 2 : 1;
      return data;
    };
    const connection = contextual({
      ...stubConnection([mint]),
      getTokenAccountsByOwner: async (_owner: PublicKey, filter: { programId: PublicKey }) => ({
        value: filter.programId.equals(TOKEN_PROGRAM_ID)
          ? [
              { pubkey: good, account: { data: tokenData(false) } },
              { pubkey: frozen, account: { data: tokenData(true) } },
            ]
          : [],
      }),
    });

    const result = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
    });

    expect(result.tokens.map((t) => t.ata.toBase58())).toEqual([good.toBase58()]);
    expect(result.skippedTokens.map((s) => [s.token.ata.toBase58(), s.reason])).toEqual([
      [frozen.toBase58(), 'frozen'],
    ]);
    const ix = result.migrate.type === 'ed25519' ? result.migrate.instruction : null;
    const destAta = getAssociatedTokenAddress(mint, result.v2Vault, TOKEN_PROGRAM_ID);
    expect(ix!.keys.slice(-4).map((k) => k.pubkey.toBase58())).toEqual(
      [good, destAta, mint, TOKEN_PROGRAM_ID].map((k) => k.toBase58()),
    );
    expect(Array.from(ix!.data)).toEqual([17, 1]);
  });

  describe('an existing destination token account', () => {
    const mint = Keypair.generate().publicKey;
    const source = Keypair.generate().publicKey;
    const destinationUserSeed = new Uint8Array(32).fill(0x3c);
    const planner = new LazorKitClient({} as Connection, PROGRAM_ID);
    const [v2Vault] = planner.findVault(planner.findWallet(destinationUserSeed)[0]);
    const destAta = getAssociatedTokenAddress(mint, v2Vault, TOKEN_PROGRAM_ID);
    const stranger = Keypair.generate().publicKey;

    /** Migrate one SPL token into a fresh v2 wallet whose destination account is `dest`. */
    function migrateInto(dest: { data: Buffer; lamports: number; owner: PublicKey } | null) {
      const accounts = new Map<string, { data: Buffer; lamports: number; owner: PublicKey }>();
      if (dest) accounts.set(destAta.toBase58(), dest);
      const connection = contextual({
        ...stubConnection([mint], accounts),
        getTokenAccountsByOwner: async (who: PublicKey, filter: { programId: PublicKey }) => ({
          value:
            who.equals(v1Vault) && filter.programId.equals(TOKEN_PROGRAM_ID)
              ? [{ pubkey: source, account: { data: tokenAccountData(mint, v1Vault), owner: TOKEN_PROGRAM_ID } }]
              : [],
        }),
      });
      return new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
        v1Wallet,
        destinationUserSeed,
      });
    }
    const tokenAccount = (data: Buffer, owner = TOKEN_PROGRAM_ID) => ({ data, lamports: 2_039_280, owner });

    for (const [label, dest, reason] of [
      ['with a delegate', tokenAccount(tokenAccountData(mint, v2Vault, { delegate: stranger })), `has a delegate, ${stranger.toBase58()}`],
      ['with a foreign close authority', tokenAccount(tokenAccountData(mint, v2Vault, { closeAuthority: stranger })), `has a close authority other than the vault, ${stranger.toBase58()}`],
      ['owned by someone else', tokenAccount(tokenAccountData(mint, stranger)), `belongs to ${stranger.toBase58()}, not the v2 vault ${v2Vault.toBase58()}`],
      ['too short to read', tokenAccount(tokenAccountData(mint, v2Vault).subarray(0, 100)), 'cannot be read as a token account'],
      ['owned by another program', tokenAccount(tokenAccountData(mint, v2Vault), stranger), `is owned by program ${stranger.toBase58()}, not ${TOKEN_PROGRAM_ID.toBase58()}`],
    ] as const) {
      it(`${label}: refuses to deliver into it, naming it`, async () => {
        const failure = migrateInto(dest);
        await expect(failure).rejects.toThrow(destAta.toBase58());
        await expect(failure).rejects.toThrow(reason);
      });
    }

    for (const [label, dest] of [
      ['that does not exist', null],
      ['that holds only lamports', { data: Buffer.alloc(0), lamports: 1_000_000, owner: SystemProgram.programId }],
      ['that is the vault\'s alone', tokenAccount(tokenAccountData(mint, v2Vault))],
      ['whose close authority is the vault', tokenAccount(tokenAccountData(mint, v2Vault, { closeAuthority: v2Vault }))],
    ] as const) {
      it(`${label}: delivers into it`, async () => {
        const plan = await migrateInto(dest);
        expect(plan.tokens.map((t) => t.ata.toBase58())).toEqual([source.toBase58()]);
        const ix = plan.migrate.type === 'ed25519' ? plan.migrate.instruction : null;
        expect(ix!.keys.slice(-4)[1].pubkey.toBase58()).toBe(destAta.toBase58());
      });
    }

    // A Token-2022 mint whose new accounts start frozen moves only into an
    // existing thawed account — which must then be the vault's alone too.
    describe('for a mint that freezes new accounts', () => {
      const frozenMint = Keypair.generate().publicKey;
      const t22Source = Keypair.generate().publicKey;
      const t22Dest = getAssociatedTokenAddress(frozenMint, v2Vault, TOKEN_2022_PROGRAM_ID);
      const mintData = Buffer.alloc(166 + 4 + 1);
      mintData[165] = 1; // AccountType::Mint
      mintData.writeUInt16LE(6, 166); // DefaultAccountState
      mintData.writeUInt16LE(1, 168);
      mintData[170] = 2; // Frozen

      function migrateFrozenMintInto(dest: { data: Buffer; lamports: number; owner: PublicKey } | null) {
        const accounts = new Map<string, { data: Buffer; lamports: number; owner: PublicKey }>([
          [frozenMint.toBase58(), { data: mintData, lamports: 1, owner: TOKEN_2022_PROGRAM_ID }],
        ]);
        if (dest) accounts.set(t22Dest.toBase58(), dest);
        const connection = contextual({
          ...stubConnection([], accounts),
          getTokenAccountsByOwner: async (who: PublicKey, filter: { programId: PublicKey }) => ({
            value:
              who.equals(v1Vault) && filter.programId.equals(TOKEN_2022_PROGRAM_ID)
                ? [{ pubkey: t22Source, account: { data: tokenAccountData(frozenMint, v1Vault), owner: TOKEN_2022_PROGRAM_ID } }]
                : [],
          }),
        });
        return new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
          payer: Keypair.generate().publicKey,
          owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
          v1Wallet,
          destinationUserSeed,
        });
      }
      const t22Account = (data: Buffer) => ({ data, lamports: 2_074_080, owner: TOKEN_2022_PROGRAM_ID });

      it('with no destination, or only lamports there, it stays behind: the account created would be frozen', async () => {
        for (const dest of [null, { data: Buffer.alloc(0), lamports: 1_000_000, owner: SystemProgram.programId }]) {
          const plan = await migrateFrozenMintInto(dest);
          expect(plan.tokens).toEqual([]);
          expect(plan.skippedTokens.map((t) => t.reason)).toEqual(['frozen-on-arrival']);
        }
      });

      it("moves into an existing thawed account that is the vault's alone", async () => {
        const plan = await migrateFrozenMintInto(t22Account(tokenAccountData(frozenMint, v2Vault)));
        expect(plan.tokens.map((t) => t.ata.toBase58())).toEqual([t22Source.toBase58()]);
      });

      it('refuses one with a delegate', async () => {
        await expect(
          migrateFrozenMintInto(t22Account(tokenAccountData(frozenMint, v2Vault, { delegate: stranger }))),
        ).rejects.toThrow(`${t22Dest.toBase58()} (mint ${frozenMint.toBase58()}) has a delegate`);
      });
    });

    it('a frozen one is skipped, not checked: nothing is delivered into it', async () => {
      const plan = await migrateInto(tokenAccount(tokenAccountData(mint, v2Vault, { delegate: stranger, frozen: true })));
      expect(plan.tokens).toEqual([]);
      expect(plan.skippedTokens.map((t) => t.reason)).toEqual(['destination-frozen']);
    });
  });

  it('says what to do when neither a seed nor an address is given', async () => {
    await expect(
      new LazorKitClient(stubConnection(), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      }),
    ).rejects.toThrow('findV1WalletsByOwner');
  });
});
