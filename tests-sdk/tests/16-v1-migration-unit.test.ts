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

import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  findV1WalletsByOwner,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletPda,
  V1_DISC_WALLET,
  V1_DISC_AUTHORITY,
} from '../../sdk/sdk-legacy/src';

const PROGRAM_ID = PROGRAM_ID_DEVNET;
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
  const [v1Wallet] = findV1WalletPda(new Uint8Array(32).fill(0x5a), PROGRAM_ID);
  const [v1Authority] = findV1AuthorityPda(v1Wallet, CREDENTIAL, PROGRAM_ID);
  const [v1Vault] = findV1VaultPda(v1Wallet, PROGRAM_ID);

  function stubConnection(): Connection {
    return {
      getMultipleAccountsInfo: async (keys: PublicKey[]) =>
        keys.map((key) => {
          if (key.equals(v1Wallet)) return { data: v1WalletData(), lamports: 890880 };
          if (key.equals(v1Authority)) return { data: v1AuthorityData(v1Wallet), lamports: 1 };
          return { data: Buffer.alloc(0), lamports: 50_000_000 };
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
  });

  it('reuses the v2 wallet this owner already has instead of minting a seed', async () => {
    const [existingWallet] = new LazorKitClient(stubConnection(), PROGRAM_ID).findWallet(
      new Uint8Array(32).fill(0x11),
    );
    const connection = {
      ...stubConnection(),
      getProgramAccounts: async () => [
        {
          pubkey: Keypair.generate().publicKey,
          account: { data: v1AuthorityData(existingWallet) },
        },
      ],
      // The v2 wallet exists, so no creation instructions.
      getAccountInfo: async (key: PublicKey) =>
        key.equals(existingWallet) ? { data: Buffer.alloc(8), lamports: 1 } : null,
    } as unknown as Connection;

    const result = await new LazorKitClient(connection, PROGRAM_ID).migrateV1Wallet({
      payer: Keypair.generate().publicKey,
      owner: { type: 'ed25519', publicKey: OWNER_PUBKEY },
      v1Wallet,
    });

    expect(result.destinationWallet.toBase58()).toBe(existingWallet.toBase58());
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
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
