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
  authorityPolicyOffset,
  decodeAuthorityAccount,
  decodeSessionAccount,
  decodeWalletAccount,
  recordedRentPayer,
  sessionActionsOffset,
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
      discriminator: 0x22, // Authority
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
      discriminator: 0x22, // Authority
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
      discriminator: 0x23, // Session
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

// ─── Layout revision 2: the rent payer ───────────────────────────────
//
// From revision 2 an authority and a session record the account that paid
// their rent, 32 bytes after the fixed part and before the policy. Every
// instruction that closes one refunds only to it. Both SDKs must read it, and
// the policy after it, the same way.

describe('Rent payer (layout revision 2)', () => {
  const SPONSOR = new PublicKey(new Uint8Array(32).fill(0x99));
  const POLICY = Uint8Array.from([1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]);

  function authority(authorityType: number, version: number, withPolicy: boolean): Buffer {
    const keyEnd = authorityType === 0 ? 80 : 145;
    const payer = version === 2 ? 32 : 0;
    const policy = withPolicy ? POLICY : new Uint8Array();
    const buf = Buffer.alloc(keyEnd + payer + policy.length);
    buildAuthorityHeader({
      discriminator: 0x22,
      authorityType,
      role: 2,
      bump: 250,
      version,
      counter: 3,
      wallet: WALLET_PK,
    }).copy(buf, 0);
    buf.writeUInt16LE(policy.length, 12);
    if (payer) SPONSOR.toBuffer().copy(buf, keyEnd);
    Buffer.from(policy).copy(buf, keyEnd + payer);
    return buf;
  }

  function session(version: number, withActions: boolean): Buffer {
    const payer = version === 2 ? 32 : 0;
    const actions = withActions ? POLICY : new Uint8Array();
    const buf = Buffer.alloc(80 + payer + actions.length);
    buildSessionHeader({
      discriminator: 0x23,
      bump: 250,
      version,
      wallet: WALLET_PK,
      sessionKey: SESSION_KEY_PK,
      expiresAt: 1_700_000_000n,
    }).copy(buf, 0);
    if (payer) SPONSOR.toBuffer().copy(buf, 80);
    Buffer.from(actions).copy(buf, 80 + payer);
    return buf;
  }

  it('an authority records it after its key material, then its policy', () => {
    for (const type of [0, 1]) {
      const data = authority(type, 2, true);
      const kit = decodeAuthorityAccount(data);
      const legacy = LegacyAuthority.fromBuffer(data);
      expect(kit.rentPayer).toBe(SPONSOR.toBase58());
      expect(legacy.rentPayer?.toBase58()).toBe(SPONSOR.toBase58());
      expect(recordedRentPayer(data)).toBe(SPONSOR.toBase58());
      expect(kit.policyOffset).toBe((type === 0 ? 80 : 145) + 32);
      expect(legacy.policyOffset).toBe(kit.policyOffset);
      expect(Buffer.from(data.subarray(kit.policyOffset!))).toEqual(Buffer.from(POLICY));
    }
  });

  it('a session records it after its header, then its actions', () => {
    const data = session(2, true);
    const kit = decodeSessionAccount(data);
    const legacy = LegacySession.fromBuffer(data);
    expect(kit.rentPayer).toBe(SPONSOR.toBase58());
    expect(legacy.rentPayer?.toBase58()).toBe(SPONSOR.toBase58());
    expect(Buffer.from(kit.actions)).toEqual(Buffer.from(POLICY));
    expect(Buffer.from(legacy.actions)).toEqual(Buffer.from(POLICY));
    expect(sessionActionsOffset(2)).toBe(112);
  });

  it('revision 1 records none, and its policy sits right after the fixed part', () => {
    const a = authority(0, 1, true);
    expect(decodeAuthorityAccount(a).rentPayer).toBeNull();
    expect(LegacyAuthority.fromBuffer(a).rentPayer).toBeNull();
    expect(decodeAuthorityAccount(a).policyOffset).toBe(80);
    const s = session(1, true);
    expect(decodeSessionAccount(s).rentPayer).toBeNull();
    expect(Buffer.from(decodeSessionAccount(s).actions)).toEqual(Buffer.from(POLICY));
    expect(authorityPolicyOffset(1, 1)).toBe(145);
  });

  it('an unknown revision or type resolves to nothing', () => {
    expect(authorityPolicyOffset(0, 3)).toBeNull();
    expect(authorityPolicyOffset(9, 2)).toBeNull();
    expect(sessionActionsOffset(0)).toBeNull();
    const future = session(2, false);
    future[2] = 3;
    expect(recordedRentPayer(future)).toBeNull();
    expect(decodeSessionAccount(future).actions).toHaveLength(0);
  });

  it('a recording account too short to hold the payer reads as recording none', () => {
    const short = session(2, false).subarray(0, 100);
    expect(recordedRentPayer(short)).toBeNull();
  });
});
