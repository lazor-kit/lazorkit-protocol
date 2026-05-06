// Unit tests for the high-level LazorKit class.
//
// These cover the surface that does NOT require an RPC round-trip:
//   - PDA helpers
//   - reclaimDeferred (pure tx assembly)
//   - createWallet (Ed25519, no fee accounts)
//
// Anything requiring `getAccountInfo` / `getSlot` is covered by the
// E2E suite under tests-sdk-kit/ against a live validator.

import { describe, it, expect } from 'vitest';
import { address } from '@solana/kit';
import {
  LazorKit,
  LazorKitClient,
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_MAINNET,
} from '../src/index.js';

const PAYER = address('11111111111111111111111111111112');
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

describe('createWallet — Ed25519 owner, fee disabled (no RPC needed)', () => {
  it('builds a single CreateWallet instruction with derived PDAs', async () => {
    // For the no-fee path, getProtocolConfig must return null. Wire a
    // mockRpc that returns { value: null } from getAccountInfo.
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
    expect(result.instructions).toHaveLength(1);
    expect(result.walletPda).toBeTypeOf('string');
    expect(result.vaultPda).toBeTypeOf('string');
    expect(result.authorityPda).toBeTypeOf('string');
    // Discriminator at byte 0.
    expect(result.instructions[0]!.data?.[0]).toBe(0); // DISC_CREATE_WALLET
  });
});
