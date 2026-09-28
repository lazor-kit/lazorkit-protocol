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
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
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
  getAssociatedTokenAddress,
  mintBlocker,
} from '../../sdk/sdk-legacy/src';

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

  function stubConnection(): Connection {
    return {
      getMultipleAccountsInfo: async (keys: PublicKey[]) =>
        keys.map((key) => {
          if (key.equals(v1Wallet)) return { data: v1WalletData(), lamports: 890880 };
          if (key.equals(v1Authority)) return { data: v1AuthorityData(v1Wallet), lamports: 1 };
          // Anything else here is a mint (owned by SPL Token) or a destination.
          return { data: Buffer.alloc(82), lamports: 50_000_000, owner: TOKEN_PROGRAM_ID };
        }),
      // No v2 wallet yet, and no protocol config.
      getAccountInfo: async () => null,
      getProgramAccounts: async () => [],
      getTokenAccountsByOwner: async () => ({ value: [] }),
      getSlot: async () => 1_000,
    } as unknown as Connection;
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

  /**
   * A connection where `existing` is a v2 wallet listing this owner — cleanly,
   * or with one of the ways an attacker keeps a hand on it.
   */
  function withV2Wallet(
    existing: PublicKey,
    hostile?: 'second-authority' | 'spender-rank' | 'session' | 'deferred',
  ): Connection {
    const live = Buffer.alloc(176);
    live.writeBigUInt64LE(5_000n, 72);
    live.writeBigUInt64LE(5_000n, 168);
    const owner = { pubkey: Keypair.generate().publicKey, account: { data: v1AuthorityData(existing) } };
    return {
      ...stubConnection(),
      getProgramAccounts: async (_id: PublicKey, config: { filters: Array<{ memcmp: { bytes: string } }> }) => {
        const head = Buffer.from(config.filters[0].memcmp.bytes, 'base64');
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY, 0]))) return [owner];
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.AUTHORITY]))) {
          if (hostile === 'spender-rank') {
            return [{ ...owner, account: { data: v1AuthorityData(existing, 2) } }];
          }
          return hostile === 'second-authority' ? [owner, owner] : [owner];
        }
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.SESSION]))) {
          return hostile === 'session' ? [{ pubkey: owner.pubkey, account: { data: live } }] : [];
        }
        if (head.equals(Buffer.from([ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC]))) {
          return hostile === 'deferred' ? [{ pubkey: owner.pubkey, account: { data: live } }] : [];
        }
        return [];
      },
      // The v2 wallet exists, so no creation instructions.
      getAccountInfo: async (key: PublicKey) =>
        key.equals(existing) ? { data: Buffer.alloc(8), lamports: 1 } : null,
    } as unknown as Connection;
  }

  it('reuses the v2 wallet this owner already has instead of minting a seed', async () => {
    const [existingWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(
      new Uint8Array(32).fill(0x11),
    );

    const result = await new LazorKitClient(withV2Wallet(existingWallet), PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
    });

    expect(result.destinationWallet.toBase58()).toBe(existingWallet.toBase58());
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  // Being listed on a wallet is not owning it. Each of these leaves someone
  // else able to spend what lands in the vault, so the SDK must not reuse it.
  for (const hostile of ['second-authority', 'spender-rank', 'session', 'deferred'] as const) {
    it(`does not deliver into a wallet with a ${hostile} — it mints a fresh one`, async () => {
      const [planted] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(
        new Uint8Array(32).fill(0x66),
      );
      const client = new LazorKitClient(withV2Wallet(planted, hostile), PROGRAM_ID);

      const result = await client.migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
        v1Wallet,
      });

      expect(result.destinationWallet.toBase58()).not.toBe(planted.toBase58());
      expect(result.destinationWallet.toBase58()).toBe(
        client.findWallet(result.destinationUserSeed!)[0].toBase58(),
      );
    });
  }

  it("refuses the userSeed's own v2 wallet when someone else can spend from it", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const [seedWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(seed);

    await expect(
      new LazorKitClient(withV2Wallet(seedWallet, 'deferred'), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
        userSeed: seed,
      }),
    ).rejects.toThrow('pending deferred execution');
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
      planted.toBuffer().copy(authority, 16);
      Buffer.from(CREDENTIAL).copy(authority, 48);
      Buffer.alloc(33, keyByte).copy(authority, 80);
      createHash('sha256').update(rp).digest().copy(authority, 113);
      const connection = {
        ...stubConnection(),
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
            ? { data: Buffer.alloc(8), lamports: 1 }
            : key.equals(v1Authority)
              ? { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 }
              : null,
      } as unknown as Connection;

      const result = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: {
          type: 'secp256r1',
          credentialIdHash: CREDENTIAL,
          compressedPubkey: new Uint8Array(33).fill(0x7c),
          rpId: 'portal.lazor.sh',
        },
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
    const connection = {
      ...stubConnection(),
      getTokenAccountsByOwner: async (_o: PublicKey, f: { programId: PublicKey }) => ({
        value: f.programId.equals(T22) ? [{ pubkey: ata, account: { data, owner: T22 } }] : [],
      }),
      getMultipleAccountsInfo: async (keys: PublicKey[]) =>
        keys.some((k) => k.equals(mint))
          ? keys.map((k) => (k.equals(mint) ? { data: Buffer.alloc(82), owner: T22, lamports: 1 } : null))
          : base.getMultipleAccountsInfo(keys),
    } as unknown as Connection;

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
    const connection = {
      ...stubConnection(),
      getAccountInfo: async (key: PublicKey) =>
        key.equals(v1Authority) ? { data: v1AuthorityData(v1Wallet, 0, 1), lamports: 1 } : null,
    } as unknown as Connection;
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
    const connection = {
      ...stubConnection(),
      getTokenAccountsByOwner: async (_owner: PublicKey, filter: { programId: PublicKey }) => ({
        value: filter.programId.equals(TOKEN_PROGRAM_ID)
          ? [
              { pubkey: good, account: { data: tokenData(false) } },
              { pubkey: frozen, account: { data: tokenData(true) } },
            ]
          : [],
      }),
    } as unknown as Connection;

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

  it('says what to do when neither a seed nor an address is given', async () => {
    await expect(
      new LazorKitClient(stubConnection(), PROGRAM_ID).migrateV1Wallet({
        payer: Keypair.generate().publicKey,
        owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      }),
    ).rejects.toThrow('findV1WalletsByOwner');
  });
});
