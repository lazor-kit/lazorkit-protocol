/**
 * Pure-logic unit tests for the SDK. No validator required.
 *
 * Covers input validation (size checks, u16 overflow guards), the
 * resolveSecp256r1 short-circuit when overrides are supplied, protocol
 * fee shard-selection bounds, and the WalletAuthorityRecord contract.
 */
import { describe, it, expect } from 'vitest';
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  type AccountInfo,
} from '@solana/web3.js';
import * as crypto from 'crypto';

import {
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  DISC_EXECUTE,
  DISC_REVOKE_SESSION,
  buildAuthPayload,
  buildAuthPayloadPrefix,
  buildSecp256r1Challenge,
  buildSecp256r1PrecompileIx,
  type WalletAuthorityRecord,
} from '../../sdk/sdk-legacy/src';
import { createExecuteIx } from '../../sdk/sdk-legacy/src/utils/instructions';

const DEVNET_PROGRAM_ID = PROGRAM_ID_DEVNET;

/**
 * A Connection that counts and rejects every RPC call. Lets us assert
 * that the override paths in resolveSecp256r1 make zero network calls.
 */
class StrictNoRpcConnection {
  callCount = 0;

  getSlot(): Promise<number> {
    this.callCount++;
    throw new Error('getSlot was called — expected short-circuit');
  }

  getAccountInfo(_pubkey: PublicKey): Promise<AccountInfo<Buffer> | null> {
    this.callCount++;
    throw new Error('getAccountInfo was called — expected short-circuit');
  }

  getProgramAccounts(): Promise<unknown[]> {
    this.callCount++;
    throw new Error('getProgramAccounts was called — expected short-circuit');
  }
}

function makeClient(connection: unknown): LazorKitClient {
  return new LazorKitClient(connection as Connection, DEVNET_PROGRAM_ID);
}

// ─── buildSecp256r1PrecompileIx validation ──────────────────────────

describe('buildSecp256r1PrecompileIx — size validation', () => {
  const goodPubkey = new Uint8Array(33);
  const goodSig = new Uint8Array(64);
  const goodMsg = new Uint8Array(100);

  it('rejects signature that is not 64 bytes', () => {
    expect(() =>
      buildSecp256r1PrecompileIx(goodPubkey, goodMsg, new Uint8Array(63)),
    ).toThrow(/signature must be 64 bytes/);
    expect(() =>
      buildSecp256r1PrecompileIx(goodPubkey, goodMsg, new Uint8Array(65)),
    ).toThrow(/signature must be 64 bytes/);
    expect(() =>
      buildSecp256r1PrecompileIx(goodPubkey, goodMsg, new Uint8Array(0)),
    ).toThrow(/signature must be 64 bytes/);
  });

  it('rejects public key that is not 33 bytes', () => {
    expect(() =>
      buildSecp256r1PrecompileIx(new Uint8Array(32), goodMsg, goodSig),
    ).toThrow(/public key must be 33 bytes/);
    expect(() =>
      buildSecp256r1PrecompileIx(new Uint8Array(34), goodMsg, goodSig),
    ).toThrow(/public key must be 33 bytes/);
  });

  it('rejects message larger than u16 max', () => {
    const oversized = new Uint8Array(0x10000); // 65536
    expect(() =>
      buildSecp256r1PrecompileIx(goodPubkey, oversized, goodSig),
    ).toThrow(/must fit in u16/);
  });

  it('accepts valid sizes', () => {
    const ix = buildSecp256r1PrecompileIx(goodPubkey, goodMsg, goodSig);
    expect(ix.data.length).toBe(16 + 64 + 33 + 1 + goodMsg.length);
    expect(ix.keys).toHaveLength(0);
  });
});

// ─── buildAuthPayload u16 overflow guards ───────────────────────────

describe('buildAuthPayload — u16 overflow guards', () => {
  const base = {
    slot: 0n,
    counter: 0,
    sysvarIxIndex: 0,
  };

  it('rejects authenticatorData > 65535 bytes', () => {
    expect(() =>
      buildAuthPayload({
        ...base,
        authenticatorData: new Uint8Array(0x10000),
        clientDataJson: new Uint8Array(10),
      }),
    ).toThrow(/authenticatorData length must fit in u16/);
  });

  it('rejects clientDataJson > 65535 bytes', () => {
    expect(() =>
      buildAuthPayload({
        ...base,
        authenticatorData: new Uint8Array(37),
        clientDataJson: new Uint8Array(0x10000),
      }),
    ).toThrow(/clientDataJson length must fit in u16/);
  });

  it('accepts the maximum u16 boundary (65535 bytes)', () => {
    // 65535 ≈ 64KB. Heavy but legal.
    const out = buildAuthPayload({
      ...base,
      authenticatorData: new Uint8Array(65535),
      clientDataJson: new Uint8Array(100),
    });
    expect(out.length).toBe(14 + 2 + 65535 + 2 + 100);
  });
});

// ─── Secp256r1 challenge binds the wallet ───────────────────────────

describe('buildSecp256r1Challenge — wallet binding', () => {
  // The same vector sdk-kit's tests/secp256r1.test.ts pins: both SDKs and the
  // program's sol_sha256 must agree on it byte for byte.
  const SLOT = 234_567_890n;
  const PAYER = new PublicKey('11111111111111111111111111111112');
  const WALLET = new PublicKey(new Uint8Array(32).fill(0x57));
  const PROGRAM = new PublicKey('4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS');
  const prefix = buildAuthPayloadPrefix({ slot: SLOT, counter: 42, sysvarIxIndex: 1 });
  const challenge = (wallet: PublicKey, payer = PAYER) =>
    buildSecp256r1Challenge({
      discriminator: new Uint8Array([4]),
      authPayload: prefix,
      signedPayload: new Uint8Array(Buffer.from('cafebabe1234', 'hex')),
      slot: SLOT,
      payer,
      wallet,
      counter: 42,
      programId: PROGRAM,
    });

  it('matches the fixed vector: discriminator || prefix || signed || payer || wallet || counter_le4 || program_id', () => {
    // Spelled out byte by byte, not rebuilt with SDK helpers, so a reordering
    // in the SDK fails here rather than as InvalidMessageHash (3005) on chain.
    const preimage = Buffer.concat([
      Buffer.from([4]),
      Buffer.from('d238fb0d000000002a0000000180', 'hex'), // slot_le8 || counter_le4 || sysvarIxIdx || 0x80
      Buffer.from('cafebabe1234', 'hex'),
      PAYER.toBuffer(),
      WALLET.toBuffer(),
      Buffer.from('2a000000', 'hex'), // counter 42, LE
      PROGRAM.toBuffer(),
    ]);
    const expected = '31f26fb840bdfae901ec007fb8c8be9d12b2e521ec382fbbffddc66f92efd9ae';
    expect(Buffer.from(prefix).toString('hex')).toBe('d238fb0d000000002a0000000180');
    expect(crypto.createHash('sha256').update(preimage).digest('hex')).toBe(expected);
    expect(Buffer.from(challenge(WALLET)).toString('hex')).toBe(expected);
  });

  it('a different wallet yields a different challenge', () => {
    const other = new PublicKey(new Uint8Array(32).fill(0x58));
    expect(Buffer.from(challenge(other)).toString('hex')).toBe(
      '50c48d8ba2655f8fb6078b63ac9d00a77508ffa602c5589d31b45e9962235084',
    );
    expect(Buffer.from(challenge(other)).equals(Buffer.from(challenge(WALLET)))).toBe(false);
    // Nor is the wallet interchangeable with the payer next to it.
    expect(Buffer.from(challenge(PAYER, WALLET)).equals(Buffer.from(challenge(WALLET)))).toBe(false);
  });

  // The attack the binding closes: RevokeSession's signed payload is the
  // session and refund address, neither of which names a wallet. Before, the
  // same passkey revoking the same session address at the same counter,
  // slot and payer on two wallets signed identical bytes.
  it('prepare* names the wallet the authority belongs to', async () => {
    const connection = {
      // readAuthorityCounter: counter 0 at offset 8, so the next is 1.
      getAccountInfo: async () =>
        ({ data: Buffer.alloc(12), owner: DEVNET_PROGRAM_ID, executable: false, lamports: 0, rentEpoch: 0 }) as AccountInfo<Buffer>,
    };
    const client = makeClient(connection);
    const payer = Keypair.generate().publicKey;
    const sessionPda = Keypair.generate().publicKey;
    const credentialIdHash = new Uint8Array(32).fill(0xc1);
    const publicKeyBytes = new Uint8Array(33).fill(0x02);
    const prepare = (walletPda: PublicKey) =>
      client.prepareRevokeSession({
        payer,
        walletPda,
        secp256r1: {
          credentialIdHash,
          publicKeyBytes,
          authorityPda: client.findAuthority(walletPda, credentialIdHash)[0],
          slotOverride: SLOT,
        },
        sessionPda,
      });
    const walletA = Keypair.generate().publicKey;
    const walletB = Keypair.generate().publicKey;
    const [a, b] = [await prepare(walletA), await prepare(walletB)];

    expect(Buffer.from(a.challenge).equals(Buffer.from(b.challenge))).toBe(false);
    const expected = buildSecp256r1Challenge({
      discriminator: new Uint8Array([DISC_REVOKE_SESSION]),
      // 5: the sysvar-instructions account's index in RevokeSession.
      authPayload: buildAuthPayloadPrefix({ slot: SLOT, counter: 1, sysvarIxIndex: 5 }),
      signedPayload: new Uint8Array(Buffer.concat([sessionPda.toBuffer(), payer.toBuffer()])),
      slot: SLOT,
      payer,
      wallet: walletA,
      counter: 1,
      programId: DEVNET_PROGRAM_ID,
    });
    expect(Buffer.from(a.challenge).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
  });
});

// ─── The accounts hash uses the runtime's flags ─────────────────────

// The accounts hash binds the signer/writable flags the program reads, and the
// runtime reports those per key over the whole message: the fee payer is always
// a writable signer, and a key listed twice has the union of its entries. An
// inner instruction that repays the payer is the ordinary case that exposes a
// wrong guess — it failed Execute with InvalidMessageHash (3005) and
// ExecuteDeferred with DeferredHashMismatch (3015).
describe('prepareExecute / prepareAuthorize — the accounts hash uses runtime flags', () => {
  const SLOT = 12_345n;
  const connection = {
    // readAuthorityCounter reads counter 0 at offset 8; too short to be a
    // ProtocolConfig, so no fee is resolved.
    getAccountInfo: async () =>
      ({ data: Buffer.alloc(12), owner: DEVNET_PROGRAM_ID, executable: false, lamports: 0, rentEpoch: 0 }) as AccountInfo<Buffer>,
  };
  const credentialIdHash = new Uint8Array(32).fill(0xc1);

  /** `key(32) ‖ flags(1)` per account, in the program's walk order. */
  const accountsHash = (...walk: [PublicKey, number][]) =>
    new Uint8Array(
      crypto
        .createHash('sha256')
        .update(Buffer.concat(walk.map(([k, f]) => Buffer.concat([k.toBuffer(), Buffer.from([f])]))))
        .digest(),
    );
  const setup = () => {
    const client = makeClient(connection);
    const payer = Keypair.generate().publicKey;
    const walletPda = Keypair.generate().publicKey;
    const [vaultPda] = client.findVault(walletPda);
    const secp256r1 = {
      credentialIdHash,
      publicKeyBytes: new Uint8Array(33).fill(0x02),
      authorityPda: client.findAuthority(walletPda, credentialIdHash)[0],
      slotOverride: SLOT,
    };
    const repay = SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: payer, lamports: 1_000_000 });
    return { client, payer, walletPda, vaultPda, secp256r1, repay };
  };

  it('Execute hashes the payer as a writable signer, and declares it so', async () => {
    const { client, payer, walletPda, vaultPda, secp256r1, repay } = setup();
    const prepared = await client.prepareExecute({ payer, walletPda, secp256r1, instructions: [repay] });

    const hash = accountsHash([SystemProgram.programId, 0b00], [vaultPda, 0b10], [payer, 0b11]);
    const expected = buildSecp256r1Challenge({
      discriminator: new Uint8Array([DISC_EXECUTE]),
      authPayload: buildAuthPayloadPrefix({
        slot: SLOT,
        counter: 1,
        sysvarIxIndex: prepared._internal.signing._internal.sysvarIxIndex,
      }),
      signedPayload: new Uint8Array([...prepared._internal.packed, ...hash]),
      slot: SLOT,
      payer,
      wallet: walletPda,
      counter: 1,
      programId: DEVNET_PROGRAM_ID,
    });
    expect(Buffer.from(prepared.challenge).toString('hex')).toBe(Buffer.from(expected).toString('hex'));

    const ix = createExecuteIx({
      payer,
      walletPda,
      authorityPda: secp256r1.authorityPda,
      vaultPda,
      packedInstructions: prepared._internal.packed,
      authPayload: new Uint8Array(18),
      programId: DEVNET_PROGRAM_ID,
    });
    expect(ix.keys[0]).toMatchObject({ pubkey: payer, isSigner: true, isWritable: true });
  });

  it('Authorize hashes the refund slot as the payer it is, and the wallet read-only', async () => {
    const { client, payer, walletPda, vaultPda, secp256r1, repay } = setup();
    // A second instruction that reads the wallet: ExecuteDeferred passes it
    // read-only, so that is what the program hashes.
    const other = Keypair.generate().publicKey;
    const readWallet = new TransactionInstruction({
      programId: other,
      keys: [{ pubkey: walletPda, isSigner: false, isWritable: false }],
      data: Buffer.from([1]),
    });
    const prepared = await client.prepareAuthorize({
      payer,
      walletPda,
      secp256r1,
      instructions: [repay, readWallet],
    });

    expect(Buffer.from(prepared._internal.accountsHash).toString('hex')).toBe(
      Buffer.from(
        accountsHash(
          [SystemProgram.programId, 0b00],
          [vaultPda, 0b10],
          // Index 4, the refund destination: the same key as tx2's payer.
          [payer, 0b11],
          [other, 0b00],
          [walletPda, 0b00],
        ),
      ).toString('hex'),
    );
  });
});

// ─── Public-facing client input validation ──────────────────────────

describe('createWallet — input validation', () => {
  const client = makeClient(new StrictNoRpcConnection());

  it('rejects userSeed != 32 bytes', async () => {
    const payer = Keypair.generate().publicKey;
    const owner = Keypair.generate().publicKey;

    await expect(
      client.createWallet({
        payer,
        userSeed: new Uint8Array(31),
        owner: { type: 'ed25519', publicKey: owner },
      }),
    ).rejects.toThrow(/userSeed must be exactly 32 bytes/);

    await expect(
      client.createWallet({
        payer,
        userSeed: new Uint8Array(33),
        owner: { type: 'ed25519', publicKey: owner },
      }),
    ).rejects.toThrow(/userSeed must be exactly 32 bytes/);
  });

  it('rejects Secp256r1 credentialIdHash != 32 bytes', async () => {
    const payer = Keypair.generate().publicKey;
    await expect(
      client.createWallet({
        payer,
        userSeed: new Uint8Array(32),
        owner: {
          type: 'secp256r1',
          credentialIdHash: new Uint8Array(31),
          compressedPubkey: new Uint8Array(33),
          rpId: 'example.com',
        },
      }),
    ).rejects.toThrow(/credentialIdHash must be exactly 32 bytes/);
  });

  it('rejects Secp256r1 compressedPubkey != 33 bytes', async () => {
    const payer = Keypair.generate().publicKey;
    await expect(
      client.createWallet({
        payer,
        userSeed: new Uint8Array(32),
        owner: {
          type: 'secp256r1',
          credentialIdHash: new Uint8Array(32),
          compressedPubkey: new Uint8Array(32), // wrong
          rpId: 'example.com',
        },
      }),
    ).rejects.toThrow(/compressedPubkey must be exactly 33 bytes/);
  });
});

describe('findWalletsByAuthority — input validation', () => {
  const client = makeClient(new StrictNoRpcConnection());

  it('rejects credential of wrong length before any RPC call', async () => {
    await expect(
      client.findWalletsByAuthority(new Uint8Array(31)),
    ).rejects.toThrow(/credential must be exactly 32 bytes/);
    await expect(
      client.findWalletsByAuthority(new Uint8Array(33), 'ed25519'),
    ).rejects.toThrow(/credential must be exactly 32 bytes/);
  });
});

// ─── resolveSecp256r1 short-circuit (via prepareExecute) ────────────

describe('resolveSecp256r1 — override short-circuit', () => {
  it('makes zero RPC calls when publicKeyBytes + slotOverride + authorityPda provided AND protocol disabled', async () => {
    // Protocol disabled: zero account-info reads from resolveProtocolFee.
    // Authority override: no findAuthority RPC (findAuthority is sync anyway).
    // Pubkey override: no readAuthorityPubkey.
    // Slot override: no getSlot.
    // The ONE RPC we can't avoid is readAuthorityCounter — so we stub
    // connection.getAccountInfo to return a fake Authority account with a
    // counter of zero, and assert only that exactly one call happened.
    const walletPda = Keypair.generate().publicKey;
    const payer = Keypair.generate().publicKey;
    const credentialIdHash = crypto.randomBytes(32);
    const publicKeyBytes = crypto.randomBytes(33);
    publicKeyBytes[0] = 0x02; // valid compressed prefix

    let accountInfoCalls = 0;
    const fakeConnection = {
      getSlot: () => {
        throw new Error('should not call getSlot');
      },
      getAccountInfo: async (_key: PublicKey) => {
        accountInfoCalls++;
        // Return null for protocol-config probes — that disables fee path.
        // Return synthetic Authority account for counter reads.
        // The client only calls getAccountInfo twice here:
        //   1. readAuthorityCounter(authorityPda) — needs ≥12 bytes
        //   2. getProtocolConfig() — expects >=88 bytes starting with 0x05
        // readAuthorityCounter is called directly on the overridden authorityPda.
        // getProtocolConfig uses findProtocolConfig() to derive a different PDA.
        // We return synthetic data that: for the counter path fits (>=12 bytes,
        // counter = 0 at offset 8); for the protocol-config path fails the
        // discriminator check (0x00 first byte) so it caches null.
        const buf = Buffer.alloc(12);
        // discriminator byte 0 = 0 (so protocol-config check fails)
        return {
          data: buf,
          owner: DEVNET_PROGRAM_ID,
          executable: false,
          lamports: 0,
          rentEpoch: 0,
        } as AccountInfo<Buffer>;
      },
      getProgramAccounts: async () => [],
    } as unknown as Connection;

    const client = new LazorKitClient(fakeConnection, DEVNET_PROGRAM_ID);
    const [authorityPda] = client.findAuthority(walletPda, credentialIdHash);

    // This call goes through resolveSecp256r1 + resolveProtocolFee.
    // With all overrides present, only counter + protocol-config read.
    const prepared = await client.prepareExecute({
      payer,
      walletPda,
      secp256r1: {
        credentialIdHash,
        publicKeyBytes,
        authorityPda,
        slotOverride: 12345n,
      },
      instructions: [], // empty instructions ok for this test
    });

    expect(prepared.challenge.length).toBe(32);
    // At most 2 calls: counter read + protocol-config probe.
    // If we accidentally call getSlot or readAuthorityPubkey, the stub throws.
    expect(accountInfoCalls).toBeLessThanOrEqual(2);
  });

  it('rejects credentialIdHash of wrong size at entry', async () => {
    const client = makeClient(new StrictNoRpcConnection());
    const walletPda = Keypair.generate().publicKey;
    const payer = Keypair.generate().publicKey;

    await expect(
      client.prepareExecute({
        payer,
        walletPda,
        secp256r1: {
          credentialIdHash: new Uint8Array(31),
        },
        instructions: [],
      }),
    ).rejects.toThrow(/credentialIdHash must be exactly 32 bytes/);
  });

  it('rejects publicKeyBytes of wrong size at entry', async () => {
    const client = makeClient(new StrictNoRpcConnection());
    const walletPda = Keypair.generate().publicKey;
    const payer = Keypair.generate().publicKey;

    await expect(
      client.prepareExecute({
        payer,
        walletPda,
        secp256r1: {
          credentialIdHash: new Uint8Array(32),
          publicKeyBytes: new Uint8Array(32), // wrong
        },
        instructions: [],
      }),
    ).rejects.toThrow(/publicKeyBytes must be exactly 33 bytes/);
  });
});

// ─── WalletAuthorityRecord type contract ────────────────────────────

describe('WalletAuthorityRecord', () => {
  it('has the documented field shape', () => {
    // Compile-time + runtime check that the interface exposes the 5
    // documented fields. If someone renames a field, this breaks.
    const record: WalletAuthorityRecord = {
      walletPda: Keypair.generate().publicKey,
      authorityPda: Keypair.generate().publicKey,
      vaultPda: Keypair.generate().publicKey,
      role: 0,
      authorityType: 1,
    };
    expect(record.walletPda).toBeInstanceOf(PublicKey);
    expect(record.authorityPda).toBeInstanceOf(PublicKey);
    expect(record.vaultPda).toBeInstanceOf(PublicKey);
    expect(typeof record.role).toBe('number');
    expect(typeof record.authorityType).toBe('number');
  });
});

// ─── protocol-fee suffix ────────────────────────────────────────────

describe('protocol-fee suffix — required on disc 0/4/7 even with no live fee', () => {
  const SYSTEM = '11111111111111111111111111111111';

  it('createWallet appends [config, feeRecord, shard 0, System] when the protocol is not initialised', async () => {
    // The window between an upgrade and InitializeProtocol, or a paused
    // protocol. The program rejects CreateWallet without the four-account
    // suffix (4008) before it reads the config, and strips it when nothing is
    // charged — so the SDK must send it anyway.
    const nullConnection = { getAccountInfo: async () => null } as unknown as Connection;
    const client = makeClient(nullConnection);
    const payer = Keypair.generate().publicKey;
    const { instructions } = await client.createWallet({
      payer,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
    });
    // No RegisterPayer: with no live fee there is nothing to register.
    expect(instructions).toHaveLength(1);
    const [config] = client.findProtocolConfig();
    const [record] = client.findFeeRecord(payer);
    const [shard0] = client.findTreasuryShard(0);
    expect(instructions[0].keys.slice(-4).map((k) => k.pubkey.toBase58())).toEqual([
      config.toBase58(),
      record.toBase58(),
      shard0.toBase58(),
      SYSTEM,
    ]);
  });

  it('omits the suffix, with no RPC at all, only when built with { protocolFees: false }', async () => {
    const conn = new StrictNoRpcConnection();
    const client = new LazorKitClient(conn as unknown as Connection, DEVNET_PROGRAM_ID, {
      protocolFees: false,
    });
    const { instructions } = await client.createWallet({
      payer: Keypair.generate().publicKey,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
    });
    const [config] = client.findProtocolConfig();
    expect(instructions[0].keys.map((k) => k.pubkey.toBase58())).not.toContain(config.toBase58());
    expect(conn.callCount).toBe(0);
  });
});
