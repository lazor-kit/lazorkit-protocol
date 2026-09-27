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
  PROGRAM_ID_DEVNET_V1,
  V1_DISC_AUTHORITY,
  V1_DISC_WALLET,
  findV1AuthorityPda,
  findV1VaultPda,
  findV1WalletPda,
  findV1WalletsByOwner,
  getAssociatedTokenAddress,
} from '../src/index.js';
import { ACCOUNT_DISCRIMINATOR } from '../src/constants.js';
import {
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

/** How an attacker can keep a hand on a v2 wallet that still lists the owner. */
type Hostile = 'second-authority' | 'spender-rank' | 'session' | 'deferred';

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
  /** Stub RPC holding one v1 wallet, its authority and a funded vault. */
  async function fixture(
    options: {
      v2Wallet?: Address;
      hostile?: Hostile;
      token?: boolean;
      frozenToken?: boolean;
      hookedToken?: boolean;
    } = {},
  ) {
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
          value: keys.map((key) => {
            if (key === v1Wallet) return account(v1WalletData(), 890_880n);
            if (key === v1Authority) return account(v1AuthorityData(v1Wallet));
            if (key === HOOKED_MINT) return account(hookedMintData());
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
      // The v2 scans: which wallets list this owner, then — for the one the
      // SDK wants to reuse — its authorities, sessions and deferred executions.
      getProgramAccounts: (_programId: Address, config: { filters: unknown }) => ({
        send: async () => {
          const [head] = (config.filters as Array<{ memcmp: { bytes: string } }>).map(
            (f) => f.memcmp.bytes,
          );
          const tag = (...b: number[]) => bs58(new Uint8Array(b));
          const v2 = options.v2Wallet;
          if (!v2) return [];
          const owner = { pubkey: v1Authority, account: account(v1AuthorityData(v2)) };
          const live = new Uint8Array(176);
          new DataView(live.buffer).setBigUint64(72, 5_000n, true);
          new DataView(live.buffer).setBigUint64(168, 5_000n, true);
          switch (head) {
            case tag(ACCOUNT_DISCRIMINATOR.AUTHORITY, 0):
              return [owner];
            case tag(ACCOUNT_DISCRIMINATOR.AUTHORITY):
              if (options.hostile === 'spender-rank') {
                return [{ pubkey: v1Authority, account: account(v1AuthorityData(v2, 2)) }];
              }
              return options.hostile === 'second-authority'
                ? [owner, { pubkey: STRANGER, account: account(v1AuthorityData(v2)) }]
                : [owner];
            case tag(ACCOUNT_DISCRIMINATOR.SESSION):
              return options.hostile === 'session' ? [{ pubkey: STRANGER, account: account(live) }] : [];
            case tag(ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC):
              return options.hostile === 'deferred' ? [{ pubkey: STRANGER, account: account(live) }] : [];
            default:
              return [];
          }
        },
      }),
      getTokenAccountsByOwner: (_owner: Address, filter: { programId: Address }) => ({
        send: async () => {
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
          return { value };
        },
      }),
      getSlot: () => ({ send: async () => 1_000n }),
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

  // Being listed on a wallet is not owning it. Each of these leaves someone
  // else able to spend what lands in the vault, so the SDK must not reuse it.
  for (const hostile of ['second-authority', 'spender-rank', 'session', 'deferred'] as const) {
    it(`does not deliver into a wallet with a ${hostile} — it mints a fresh one`, async () => {
      const planted = (await new LazorKit({} as never, PROGRAM_ID).findWallet(
        new Uint8Array(32).fill(0x66),
      ))[0];
      const { rpc, v1Wallet } = await fixture({ v2Wallet: planted, hostile });

      const result = await new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        v1Wallet,
      });

      expect(result.destinationWallet).not.toBe(planted);
      expect(result.destinationUserSeed).toHaveLength(32);
      expect(result.destinationWallet).toBe(
        (await new LazorKit({} as never, PROGRAM_ID).findWallet(result.destinationUserSeed!))[0],
      );
    });
  }

  it("refuses the userSeed's own v2 wallet when someone else can spend from it", async () => {
    const seed = new Uint8Array(32).fill(0x5a);
    const seedWallet = (await new LazorKit({} as never, PROGRAM_ID).findWallet(seed))[0];
    const { rpc } = await fixture({ v2Wallet: seedWallet, hostile: 'session' });

    await expect(
      new LazorKit(rpc, PROGRAM_ID).migrateV1Wallet({
        payer: PAYER,
        owner: { type: 'ed25519', publicKey: OWNER },
        userSeed: seed,
      }),
    ).rejects.toThrow('live session');
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
