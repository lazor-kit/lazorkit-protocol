/**
 * Port of tests-sdk/tests/15-sdk-unit.test.ts.
 *
 * Pure-logic unit tests that don't need a validator: input validation
 * (size checks, u16 overflow guards), resolveSecp256r1 short-circuit
 * with overrides, WalletAuthorityRecord type contract.
 */
import { describe, it, expect } from 'vitest';
import * as crypto from 'node:crypto';
import {
  generateKeyPairSigner,
  type Address,
} from '@solana/kit';
import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  buildAuthPayload,
  buildSecp256r1PrecompileIx,
  type WalletAuthorityRecord,
} from '@lazorkit/sdk';

/** Strict mock RPC that throws on any call — for short-circuit assertions. */
function strictNoRpc() {
  const trap = (name: string) => () => {
    throw new Error(`${name} was called — expected short-circuit`);
  };
  return {
    getSlot: () => ({ send: trap('getSlot') }),
    getAccountInfo: () => ({ send: trap('getAccountInfo') }),
    getProgramAccounts: () => ({ send: trap('getProgramAccounts') }),
  };
}

function makeClient(rpc: unknown): LazorKit {
  return new LazorKit(rpc as never, PROGRAM_ID_DEVNET);
}

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
    const oversized = new Uint8Array(0x10000);
    expect(() =>
      buildSecp256r1PrecompileIx(goodPubkey, oversized, goodSig),
    ).toThrow(/must fit in u16/);
  });

  it('accepts valid sizes', () => {
    const ix = buildSecp256r1PrecompileIx(goodPubkey, goodMsg, goodSig);
    expect(ix.data!.length).toBe(16 + 64 + 33 + 1 + goodMsg.length);
    expect(ix.accounts).toHaveLength(0);
  });
});

describe('buildAuthPayload — u16 overflow guards', () => {
  const base = { slot: 0n, counter: 0, sysvarIxIndex: 0 };

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
    const out = buildAuthPayload({
      ...base,
      authenticatorData: new Uint8Array(65535),
      clientDataJson: new Uint8Array(100),
    });
    expect(out.length).toBe(14 + 2 + 65535 + 2 + 100);
  });
});

describe('createWallet — input validation', () => {
  it('rejects userSeed != 32 bytes', async () => {
    const client = makeClient(strictNoRpc());
    const payer = (await generateKeyPairSigner()).address;
    const owner = (await generateKeyPairSigner()).address;

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
    const client = makeClient(strictNoRpc());
    const payer = (await generateKeyPairSigner()).address;
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
    const client = makeClient(strictNoRpc());
    const payer = (await generateKeyPairSigner()).address;
    await expect(
      client.createWallet({
        payer,
        userSeed: new Uint8Array(32),
        owner: {
          type: 'secp256r1',
          credentialIdHash: new Uint8Array(32),
          compressedPubkey: new Uint8Array(32),
          rpId: 'example.com',
        },
      }),
    ).rejects.toThrow(/compressedPubkey must be exactly 33 bytes/);
  });
});

describe('findWalletsByAuthority — input validation', () => {
  it('rejects credential of wrong length before any RPC call', async () => {
    const client = makeClient(strictNoRpc());
    await expect(
      client.findWalletsByAuthority(new Uint8Array(31)),
    ).rejects.toThrow(/credential must be exactly 32 bytes/);
    await expect(
      client.findWalletsByAuthority(new Uint8Array(33), 'ed25519'),
    ).rejects.toThrow(/credential must be exactly 32 bytes/);
  });
});

describe('resolveSecp256r1 — input validation entries', () => {
  it('rejects credentialIdHash of wrong size at entry (no RPC)', async () => {
    const client = makeClient(strictNoRpc());
    const walletPda = (await generateKeyPairSigner()).address;
    const payer = (await generateKeyPairSigner()).address;

    await expect(
      client.prepareExecute({
        payer,
        walletPda,
        secp256r1: { credentialIdHash: new Uint8Array(31) },
        instructions: [],
      }),
    ).rejects.toThrow(/credentialIdHash must be exactly 32 bytes/);
  });

  it('rejects publicKeyBytes of wrong size at entry (no RPC)', async () => {
    const client = makeClient(strictNoRpc());
    const walletPda = (await generateKeyPairSigner()).address;
    const payer = (await generateKeyPairSigner()).address;

    await expect(
      client.prepareExecute({
        payer,
        walletPda,
        secp256r1: {
          credentialIdHash: new Uint8Array(32),
          publicKeyBytes: new Uint8Array(32),
        },
        instructions: [],
      }),
    ).rejects.toThrow(/publicKeyBytes must be exactly 33 bytes/);
  });
});

describe('WalletAuthorityRecord type contract', () => {
  it('has the documented field shape', async () => {
    const a = (await generateKeyPairSigner()).address;
    const b = (await generateKeyPairSigner()).address;
    const c = (await generateKeyPairSigner()).address;
    const record: WalletAuthorityRecord = {
      walletPda: a,
      authorityPda: b,
      vaultPda: c,
      role: 0,
      authorityType: 1,
    };
    expect(typeof record.walletPda).toBe('string');
    expect(typeof record.authorityPda).toBe('string');
    expect(typeof record.vaultPda).toBe('string');
    expect(typeof record.role).toBe('number');
    expect(typeof record.authorityType).toBe('number');
  });
});

describe('resolveSecp256r1 — override short-circuit', () => {
  it('makes minimal RPC calls when publicKeyBytes + slotOverride + authorityPda are provided AND protocol disabled', async () => {
    const credentialIdHash = crypto.randomBytes(32);
    const publicKeyBytes = crypto.randomBytes(33);
    publicKeyBytes[0] = 0x02;

    let getAccountInfoCalls = 0;
    const fakeRpc = {
      getSlot: () => ({
        send: async () => {
          throw new Error('should not call getSlot');
        },
      }),
      getAccountInfo: () => ({
        send: async () => {
          getAccountInfoCalls++;
          // Return a synthetic 12-byte buffer:
          //   - For readAuthorityCounter, counter=0 at offset 8 fits.
          //   - For getProtocolConfig (expects 88 bytes + disc=5),
          //     this fails the size check → caches null (no fee path).
          return {
            value: {
              data: [Buffer.alloc(12).toString('base64'), 'base64'],
              owner: PROGRAM_ID_DEVNET,
              executable: false,
              lamports: 0n,
              rentEpoch: 0n,
              space: 12n,
            },
          };
        },
      }),
      getProgramAccounts: () => ({
        send: async () => [],
      }),
    };

    const client = new LazorKit(fakeRpc as never, PROGRAM_ID_DEVNET);
    const [walletPda] = await client.findWallet(crypto.randomBytes(32));
    const [authorityPda] = await client.findAuthority(walletPda, credentialIdHash);
    const payer = (await generateKeyPairSigner()).address;

    const prepared = await client.prepareExecute({
      payer,
      walletPda,
      secp256r1: {
        credentialIdHash,
        publicKeyBytes,
        authorityPda,
        slotOverride: 12_345n,
      },
      instructions: [],
    });

    expect(prepared.challenge.length).toBe(32);
    // At most 2 RPC calls: readAuthorityCounter + getProtocolConfig.
    expect(getAccountInfoCalls).toBeLessThanOrEqual(2);
  });
});
