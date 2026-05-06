// Account decoder parity test against sdk-legacy.
//
// Both SDKs read the same on-chain bytes. They must produce equivalent
// field values for every layout this module covers (Wallet, Authority
// header, Session header). Parity is verified on hand-constructed byte
// fixtures so the test does not depend on a live validator.

import { describe, it, expect } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import {
  AuthorityAccount as LegacyAuthority,
  SessionAccount as LegacySession,
} from '../../sdk-legacy/src/utils/accounts.js';
import {
  decodeAuthorityAccount,
  decodeSessionAccount,
  decodeWalletAccount,
} from '../src/codecs/accounts.js';

const WALLET_BASE58 = '11111111111111111111111111111112';
const SESSION_KEY_BASE58 = 'SysvarRent111111111111111111111111111111111';
const WALLET_PK = new PublicKey(WALLET_BASE58);
const SESSION_KEY_PK = new PublicKey(SESSION_KEY_BASE58);

function buildAuthorityHeader(opts: {
  discriminator: number;
  authorityType: number;
  role: number;
  bump: number;
  version: number;
  counter: number;
  wallet: PublicKey;
}): Buffer {
  const buf = Buffer.alloc(48);
  buf.writeUInt8(opts.discriminator, 0);
  buf.writeUInt8(opts.authorityType, 1);
  buf.writeUInt8(opts.role, 2);
  buf.writeUInt8(opts.bump, 3);
  buf.writeUInt8(opts.version, 4);
  // 5..8 = padding
  buf.writeUInt32LE(opts.counter, 8);
  // 12..16 = padding
  opts.wallet.toBuffer().copy(buf, 16);
  return buf;
}

function buildSessionHeader(opts: {
  discriminator: number;
  bump: number;
  version: number;
  wallet: PublicKey;
  sessionKey: PublicKey;
  expiresAt: bigint;
}): Buffer {
  const buf = Buffer.alloc(80);
  buf.writeUInt8(opts.discriminator, 0);
  buf.writeUInt8(opts.bump, 1);
  buf.writeUInt8(opts.version, 2);
  // 3..8 = padding
  opts.wallet.toBuffer().copy(buf, 8);
  opts.sessionKey.toBuffer().copy(buf, 40);
  buf.writeBigUInt64LE(opts.expiresAt, 72);
  return buf;
}

describe('Authority decoder parity', () => {
  it('matches sdk-legacy on representative fixture', () => {
    const fixture = buildAuthorityHeader({
      discriminator: 2,
      authorityType: 1, // secp256r1
      role: 0, // owner
      bump: 254,
      version: 1,
      counter: 7,
      wallet: WALLET_PK,
    });
    const kit = decodeAuthorityAccount(fixture);
    const legacy = LegacyAuthority.fromBuffer(fixture);
    expect(kit.discriminator).toBe(legacy.discriminator);
    expect(kit.authorityType).toBe(legacy.authorityType);
    expect(kit.role).toBe(legacy.role);
    expect(kit.bump).toBe(legacy.bump);
    expect(kit.version).toBe(legacy.version);
    expect(kit.counter).toBe(legacy.counter);
    expect(kit.wallet).toBe(legacy.wallet.toBase58());
  });

  it('decodes counter as u32 little-endian (high 24 bits non-zero)', () => {
    const fixture = buildAuthorityHeader({
      discriminator: 2,
      authorityType: 0,
      role: 1,
      bump: 255,
      version: 0,
      counter: 0x01020304,
      wallet: WALLET_PK,
    });
    const kit = decodeAuthorityAccount(fixture);
    expect(kit.counter).toBe(0x01020304);
    expect(kit.counter).toBe(LegacyAuthority.fromBuffer(fixture).counter);
  });

  it('throws on undersized buffer', () => {
    expect(() => decodeAuthorityAccount(new Uint8Array(47))).toThrow();
  });
});

describe('Session decoder parity', () => {
  it('matches sdk-legacy on representative fixture', () => {
    const fixture = buildSessionHeader({
      discriminator: 3,
      bump: 250,
      version: 1,
      wallet: WALLET_PK,
      sessionKey: SESSION_KEY_PK,
      expiresAt: 1_700_000_000n,
    });
    const kit = decodeSessionAccount(fixture);
    const legacy = LegacySession.fromBuffer(fixture);
    expect(kit.discriminator).toBe(legacy.discriminator);
    expect(kit.bump).toBe(legacy.bump);
    expect(kit.version).toBe(legacy.version);
    expect(kit.wallet).toBe(legacy.wallet.toBase58());
    expect(kit.sessionKey).toBe(legacy.sessionKey.toBase58());
    expect(kit.expiresAt).toBe(legacy.expiresAt);
  });

  it('throws on undersized buffer', () => {
    expect(() => decodeSessionAccount(new Uint8Array(79))).toThrow();
  });
});

describe('Wallet decoder', () => {
  it('extracts header fields', () => {
    const buf = Buffer.alloc(8);
    buf.writeUInt8(1, 0); // discriminator
    buf.writeUInt8(255, 1); // bump
    buf.writeUInt8(2, 2); // version
    const decoded = decodeWalletAccount(buf);
    expect(decoded.discriminator).toBe(1);
    expect(decoded.bump).toBe(255);
    expect(decoded.version).toBe(2);
  });

  it('throws on undersized buffer', () => {
    expect(() => decodeWalletAccount(new Uint8Array(7))).toThrow();
  });
});
