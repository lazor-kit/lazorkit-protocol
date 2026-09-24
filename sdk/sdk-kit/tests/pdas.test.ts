// Smoke test for K0 — verifies that:
//   1. The package builds + imports cleanly under @solana/kit primitives.
//   2. PDA derivation outputs are byte-identical with sdk-legacy's
//      PublicKey.findProgramAddressSync. If these ever drift, every
//      LazorKit instruction the SDK builds will reference the wrong
//      account and fail on-chain — so this is a critical invariant.

import { describe, it, expect } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import {
  PROGRAM_ID_DEVNET,
  PROGRAM_ID_MAINNET,
  PROGRAM_ADDRESS_DEVNET,
  findAuthorityPda,
  findDeferredExecPda,
  findFeeRecordPda,
  findProtocolConfigPda,
  findSessionPda,
  findTreasuryShardPda,
  findVaultPda,
  findWalletPda,
} from '../src/index.js';

const DEVNET_PROGRAM = new PublicKey(PROGRAM_ADDRESS_DEVNET);

// Deterministic test fixtures — picked to exercise non-trivial seed shapes.
const userSeed = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10,
]);
const credentialIdHash = new Uint8Array(32).fill(0xab);
const sessionKey = new Uint8Array(32).fill(0xcd);
const payer = new PublicKey('11111111111111111111111111111112');

describe('PDA derivation parity with sdk-legacy', () => {
  it('wallet PDA matches PublicKey.findProgramAddressSync', async () => {
    const [legacyPda, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:wallet'), userSeed],
      DEVNET_PROGRAM,
    );
    const [kitPda, kitBump] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    expect(kitPda).toBe(legacyPda.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('vault PDA matches', async () => {
    const [walletPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:wallet'), userSeed],
      DEVNET_PROGRAM,
    );
    const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:vault'), walletPda.toBuffer()],
      DEVNET_PROGRAM,
    );
    const [kitWallet] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    const [kit, kitBump] = await findVaultPda(kitWallet, PROGRAM_ID_DEVNET);
    expect(kit).toBe(legacy.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('authority PDA matches', async () => {
    const [walletPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:wallet'), userSeed],
      DEVNET_PROGRAM,
    );
    const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:authority'), walletPda.toBuffer(), credentialIdHash],
      DEVNET_PROGRAM,
    );
    const [kitWallet] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    const [kit, kitBump] = await findAuthorityPda(
      kitWallet,
      credentialIdHash,
      PROGRAM_ID_DEVNET,
    );
    expect(kit).toBe(legacy.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('session PDA matches', async () => {
    const [walletPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:wallet'), userSeed],
      DEVNET_PROGRAM,
    );
    const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:session'), walletPda.toBuffer(), sessionKey],
      DEVNET_PROGRAM,
    );
    const [kitWallet] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    const [kit, kitBump] = await findSessionPda(
      kitWallet,
      sessionKey,
      PROGRAM_ID_DEVNET,
    );
    expect(kit).toBe(legacy.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('protocol config PDA matches', async () => {
    const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:protocol_config')],
      DEVNET_PROGRAM,
    );
    const [kit, kitBump] = await findProtocolConfigPda(PROGRAM_ID_DEVNET);
    expect(kit).toBe(legacy.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('fee record PDA matches', async () => {
    const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:fee_record'), payer.toBuffer()],
      DEVNET_PROGRAM,
    );
    const [kit, kitBump] = await findFeeRecordPda(
      payer.toBase58() as never, // Address is a branded string; toBase58() yields the raw form
      PROGRAM_ID_DEVNET,
    );
    expect(kit).toBe(legacy.toBase58());
    expect(kitBump).toBe(legacyBump);
  });

  it('treasury shard PDA matches', async () => {
    for (const shardId of [0, 1, 7, 255]) {
      const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
        [Buffer.from('lk2:treasury_shard'), Buffer.from([shardId])],
        DEVNET_PROGRAM,
      );
      const [kit, kitBump] = await findTreasuryShardPda(
        shardId,
        PROGRAM_ID_DEVNET,
      );
      expect(kit).toBe(legacy.toBase58());
      expect(kitBump).toBe(legacyBump);
    }
  });

  it('deferred exec PDA matches (counter is u32 LE)', async () => {
    const [walletPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:wallet'), userSeed],
      DEVNET_PROGRAM,
    );
    const [authorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('lk2:authority'), walletPda.toBuffer(), credentialIdHash],
      DEVNET_PROGRAM,
    );

    for (const counter of [0, 1, 0xffffffff]) {
      const counterBuf = Buffer.alloc(4);
      counterBuf.writeUInt32LE(counter);
      const [legacy, legacyBump] = PublicKey.findProgramAddressSync(
        [
          Buffer.from('lk2:deferred'),
          walletPda.toBuffer(),
          authorityPda.toBuffer(),
          counterBuf,
        ],
        DEVNET_PROGRAM,
      );
      const [kitWallet] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
      const [kitAuthority] = await findAuthorityPda(
        kitWallet,
        credentialIdHash,
        PROGRAM_ID_DEVNET,
      );
      const [kit, kitBump] = await findDeferredExecPda(
        kitWallet,
        kitAuthority,
        counter,
        PROGRAM_ID_DEVNET,
      );
      expect(kit).toBe(legacy.toBase58());
      expect(kitBump).toBe(legacyBump);
    }
  });
});

describe('Constants sanity', () => {
  it('mainnet program id is the canonical vanity address', () => {
    expect(PROGRAM_ID_MAINNET.toString()).toBe(
      'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi',
    );
  });

  it('devnet program id is the commercial-binary devnet address', () => {
    expect(PROGRAM_ID_DEVNET.toString()).toBe(PROGRAM_ADDRESS_DEVNET);
  });
});
