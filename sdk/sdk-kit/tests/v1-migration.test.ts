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
import { address, getAddressEncoder, type Address } from '@solana/kit';
import bs58lib from 'bs58';

import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  V1_DISC_AUTHORITY,
  V1_DISC_WALLET,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletPda,
  findV1WalletsByOwner,
  getAssociatedTokenAddress,
} from '../src/index.js';
import { ACCOUNT_DISCRIMINATOR } from '../src/constants.js';
import { TOKEN_PROGRAM_ADDRESS } from '../src/instructions/system.js';

const PROGRAM_ID = PROGRAM_ID_DEVNET;
const addressEncoder = getAddressEncoder();

// An Ed25519 owner: the id seed *is* the public key.
const OWNER = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
const CREDENTIAL = new Uint8Array(addressEncoder.encode(OWNER));
const PAYER = address('11111111111111111111111111111112');
const MINT = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

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
  if (authType === 1) data.set(new Uint8Array(33).fill(0x7c), 80); // compressed pubkey
  return data;
}

function v1WalletData(): Uint8Array {
  const data = new Uint8Array(8);
  data[0] = V1_DISC_WALLET;
  return data;
}

function account(data: Uint8Array, lamports = 1n) {
  return { data: [b64(data), 'base64'] as const, lamports, executable: false };
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

describe('migrateV1Wallet by address', () => {
  /** Stub RPC holding one v1 wallet, its authority and a funded vault. */
  async function fixture(options: { v2Wallet?: Address; token?: boolean } = {}) {
    const [v1Wallet] = await findV1WalletPda(new Uint8Array(32).fill(0x5a), PROGRAM_ID);
    const [v1Authority] = await findV1AuthorityPda(v1Wallet, CREDENTIAL, PROGRAM_ID);
    const [v1Vault] = await findV1VaultPda(v1Wallet, PROGRAM_ID);
    const sourceAta = await getAssociatedTokenAddress(MINT, v1Vault, TOKEN_PROGRAM_ADDRESS);

    const tokenAccount = new Uint8Array(165);
    tokenAccount.set(bytesOf(MINT), 0);
    tokenAccount.set(bytesOf(v1Vault), 32);
    new DataView(tokenAccount.buffer).setBigUint64(64, 1_234_000n, true);

    const rpc = {
      getMultipleAccounts: (keys: Address[]) => ({
        send: async () => ({
          value: keys.map((key) => {
            if (key === v1Wallet) return account(v1WalletData(), 890_880n);
            if (key === v1Authority) return account(v1AuthorityData(v1Wallet));
            return account(new Uint8Array(0), 50_000_000n);
          }),
        }),
      }),
      // The v1 authority is readable (the passkey path reads its counter); the
      // v2 wallet exists only when the test says so.
      getAccountInfo: (key: Address) => ({
        send: async () => {
          if (key === v1Authority) return { value: account(v1AuthorityData(v1Wallet, 0, 1)) };
          if (options.v2Wallet && key === options.v2Wallet) {
            return { value: account(new Uint8Array(8)) };
          }
          return { value: null };
        },
      }),
      // v2 authority scan: whatever v2 wallet this owner already has.
      getProgramAccounts: (_programId: Address, config: { filters: unknown }) => ({
        send: async () => {
          const filters = config.filters as Array<{ memcmp: { bytes: string } }>;
          const isV2Scan =
            filters[0]!.memcmp.bytes === bs58(new Uint8Array([ACCOUNT_DISCRIMINATOR.AUTHORITY, 0]));
          if (!isV2Scan || !options.v2Wallet) return [];
          return [{ pubkey: v1Authority, account: account(v1AuthorityData(options.v2Wallet)) }];
        },
      }),
      getTokenAccountsByOwner: (_owner: Address, filter: { programId: Address }) => ({
        send: async () => ({
          value:
            options.token && filter.programId === TOKEN_PROGRAM_ADDRESS
              ? [{ pubkey: sourceAta, account: account(tokenAccount, 2_039_280n) }]
              : [],
        }),
      }),
      getSlot: () => ({ send: async () => 1_000n }),
    } as never;

    return { rpc, v1Wallet, v1Authority, v1Vault, sourceAta };
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
    // MigrateWallet, zero tokens.
    expect(Array.from(ix!.data!)).toEqual([17, 0]);
  });

  it('reuses the v2 wallet this owner already has instead of minting a seed', async () => {
    const existing = (await new LazorKit({} as never, PROGRAM_ID).findWallet(
      new Uint8Array(32).fill(0x11),
    ))[0];
    const { rpc, v1Wallet } = await fixture({ v2Wallet: existing });

    const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
      payer: PAYER,
      owner: { type: 'ed25519', publicKey: OWNER },
      v1Wallet,
    });

    expect(result.destinationWallet).toBe(existing);
    expect(result.destinationUserSeed).toBeUndefined();
    expect(result.setupInstructions).toHaveLength(0);
  });

  it('creates a destination ATA per token and passes the triple to the program', async () => {
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
    // Trailing triple: source, destination, token program — in that order.
    expect(accounts.slice(-3)).toEqual([sourceAta, destAta, TOKEN_PROGRAM_ADDRESS]);
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
