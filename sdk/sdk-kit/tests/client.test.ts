// Unit tests for the high-level LazorKit class.
//
// These cover the surface that does NOT require an RPC round-trip:
//   - PDA helpers
//   - reclaimDeferred (pure tx assembly)
//   - createWallet (Ed25519): fee suffix present with no config; opt-out omits it
//   - the wallet a prepare* challenge names, behind a stub for the counter read
//
// Anything else requiring `getAccountInfo` / `getSlot` is covered by the
// E2E suite under tests-sdk-kit/ against a live validator.

import { describe, it, expect } from 'vitest';
import { address, getAddressEncoder, type Address } from '@solana/kit';
import {
  DISC_REVOKE_SESSION,
  LazorKit,
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_MAINNET,
  buildAuthPayloadPrefix,
  buildSecp256r1Challenge,
} from '../src/index.js';

const PAYER = address('11111111111111111111111111111112');
const ZERO_ADDRESS = address('11111111111111111111111111111111');
const VAULT = address('So11111111111111111111111111111111111111112');
const KP = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');

// Minimal mock Rpc that throws on use — these tests don't hit RPC.
const mockRpc = new Proxy(
  {},
  {
    get() {
      throw new Error('mock rpc — should not be called from these tests');
    },
  },
);

describe('LazorKit class', () => {
  it('exposes the same constructor under both names (LazorKit + LazorKitClient alias)', () => {
    expect(LazorKitClient).toBe(LazorKit);
  });

  it('stores programId from the constructor', () => {
    const lk = new LazorKit(mockRpc as never, PROGRAM_ID_DEVNET);
    expect(lk.programId).toBe(PROGRAM_ID_DEVNET);
  });

  it('PDA helpers are async and use the configured programId', async () => {
    const lk = new LazorKit(mockRpc as never, PROGRAM_ID_DEVNET);
    const seed = new Uint8Array(16).fill(0xa1);
    const credIdHash = new Uint8Array(32).fill(0x42);

    const [walletPda] = await lk.findWallet(seed);
    const [vaultPda] = await lk.findVault(walletPda);
    const [authorityPda] = await lk.findAuthority(walletPda, credIdHash);
    const [protocolConfig] = await lk.findProtocolConfig();

    expect(walletPda).toBeTypeOf('string');
    expect(vaultPda).toBeTypeOf('string');
    expect(authorityPda).toBeTypeOf('string');
    expect(protocolConfig).toBeTypeOf('string');

    // Different programId → different derived PDAs.
    const lk2 = new LazorKit(mockRpc as never, PROGRAM_ID_MAINNET);
    const [walletPda2] = await lk2.findWallet(seed);
    expect(walletPda2).not.toBe(walletPda);
  });

  it('reclaimDeferred returns a single Instruction with no RPC calls', () => {
    const lk = new LazorKit(mockRpc as never, PROGRAM_ID_DEVNET);
    const { instructions } = lk.reclaimDeferred({
      payer: PAYER,
      deferredExecPda: VAULT,
      refundDestination: KP,
    });
    expect(instructions).toHaveLength(1);
    expect(instructions[0]!.programAddress).toBe(PROGRAM_ID_DEVNET);
    expect(instructions[0]!.data?.[0]).toBe(8); // DISC_RECLAIM_DEFERRED
  });
});

describe('createWallet — Ed25519 owner, protocol not initialised', () => {
  it('still appends the fee suffix, because the program requires it on disc 0', async () => {
    // getProtocolConfig finds no account: the window between an upgrade and
    // InitializeProtocol, or a paused protocol. The program rejects a
    // CreateWallet without the four-account suffix (4008) before it reads the
    // config, and strips it when nothing is charged — so it must be sent.
    const fakeRpc = {
      getAccountInfo: () => ({ send: async () => ({ value: null }) }),
    };
    const lk = new LazorKit(fakeRpc as never, PROGRAM_ID_DEVNET);
    const userSeed = new Uint8Array(32).fill(0x77);
    const result = await lk.createWallet({
      payer: PAYER,
      userSeed,
      owner: { type: 'ed25519', publicKey: KP },
    });
    // No RegisterPayer: with no live fee there is nothing to register.
    expect(result.instructions).toHaveLength(1);
    expect(result.walletPda).toBeTypeOf('string');
    expect(result.vaultPda).toBeTypeOf('string');
    expect(result.authorityPda).toBeTypeOf('string');
    const ix = result.instructions[0]!;
    expect(ix.data?.[0]).toBe(0); // DISC_CREATE_WALLET

    const [configPda] = await lk.findProtocolConfig();
    const [feeRecordPda] = await lk.findFeeRecord(PAYER);
    const [shard0] = await lk.findTreasuryShard(0);
    expect(ix.accounts!.slice(-4).map((a) => a.address)).toEqual([
      configPda,
      feeRecordPda,
      shard0,
      '11111111111111111111111111111111',
    ]);
  });

  it('omits the suffix, with no RPC at all, only when built with { protocolFees: false }', async () => {
    const throwingRpc = {
      getAccountInfo: () => ({
        send: async () => {
          throw new Error('a fee-less client must not probe the protocol config');
        },
      }),
    };
    const lk = new LazorKit(throwingRpc as never, PROGRAM_ID_DEVNET, { protocolFees: false });
    const result = await lk.createWallet({
      payer: PAYER,
      userSeed: new Uint8Array(32).fill(0x78),
      owner: { type: 'ed25519', publicKey: KP },
    });
    const [configPda] = await lk.findProtocolConfig();
    expect(result.instructions[0]!.accounts!.map((a) => a.address)).not.toContain(configPda);
  });

  it('rejects an all-zero Ed25519 owner key', async () => {
    const lk = new LazorKit(mockRpc as never, PROGRAM_ID_DEVNET);
    await expect(
      lk.createWallet({
        payer: PAYER,
        userSeed: new Uint8Array(32).fill(0x88),
        owner: { type: 'ed25519', publicKey: ZERO_ADDRESS },
      }),
    ).rejects.toThrow('publicKey must not be all zero bytes');
  });

  it('rejects all-zero Secp256r1 owner identity bytes', async () => {
    const lk = new LazorKit(mockRpc as never, PROGRAM_ID_DEVNET);
    await expect(
      lk.createWallet({
        payer: PAYER,
        userSeed: new Uint8Array(32).fill(0x99),
        owner: {
          type: 'secp256r1',
          credentialIdHash: new Uint8Array(32),
          compressedPubkey: new Uint8Array(33),
          rpId: 'lazor.dev',
        },
      }),
    ).rejects.toThrow('credentialIdHash must not be all zero bytes');
  });
});

// The attack the wallet binding closes: RevokeSession's signed payload is the
// session and refund address, neither of which names a wallet. Before, the
// same passkey revoking the same session address at the same counter, slot
// and payer on two wallets signed identical bytes.
describe('prepare* — the challenge names the wallet', () => {
  it('binds the wallet the authority belongs to', async () => {
    const SLOT = 12_345n;
    // Answers readAuthorityCounter: counter 0 at offset 8, so the next is 1.
    const rpc = {
      getAccountInfo: () => ({
        send: async () => ({ value: { data: [Buffer.alloc(12).toString('base64'), 'base64'] } }),
      }),
    };
    const lk = new LazorKit(rpc as never, PROGRAM_ID_DEVNET);
    const credentialIdHash = new Uint8Array(32).fill(0xc1);
    const sessionPda = VAULT;
    const prepare = async (walletPda: Address) =>
      lk.prepareRevokeSession({
        payer: PAYER,
        walletPda,
        secp256r1: {
          credentialIdHash,
          publicKeyBytes: new Uint8Array(33).fill(0x02),
          authorityPda: (await lk.findAuthority(walletPda, credentialIdHash))[0],
          slotOverride: SLOT,
        },
        sessionPda,
      });
    const [walletA] = await lk.findWallet(new Uint8Array(32).fill(0xa1));
    const [walletB] = await lk.findWallet(new Uint8Array(32).fill(0xb2));
    const [a, b] = [await prepare(walletA), await prepare(walletB)];

    expect(a.challenge).not.toEqual(b.challenge);
    const enc = getAddressEncoder();
    const signedPayload = new Uint8Array(64);
    signedPayload.set(enc.encode(sessionPda), 0);
    signedPayload.set(enc.encode(PAYER), 32);
    expect(a.challenge).toEqual(
      buildSecp256r1Challenge({
        discriminator: new Uint8Array([DISC_REVOKE_SESSION]),
        // 5: the sysvar-instructions account's index in RevokeSession.
        authPayload: buildAuthPayloadPrefix({ slot: SLOT, counter: 1, sysvarIxIndex: 5 }),
        signedPayload,
        payer: PAYER,
        wallet: walletA,
        counter: 1,
        programId: PROGRAM_ID_DEVNET,
      }),
    );
  });
});
