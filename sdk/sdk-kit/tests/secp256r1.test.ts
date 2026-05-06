// Secp256r1 / WebAuthn helper parity tests against sdk-legacy.
//
// Every byte produced by these helpers ends up either:
//   - hashed into the challenge the passkey signs, OR
//   - included in the transaction's auth_payload byte-for-byte, OR
//   - included in the Secp256r1 precompile instruction data.
//
// Any drift between SDKs means a wallet would build a tx that the
// on-chain program rejects as InvalidMessageHash. Test on canonical
// fixtures so the result is reproducible.

import { describe, it, expect } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import { address } from '@solana/kit';

// kit (this package)
import {
  generateAuthenticatorData,
  buildAuthPayload,
  buildAuthPayloadPrefix,
  buildSecp256r1Challenge,
  prepareSecp256r1,
  finalizeSecp256r1,
  buildDataPayloadForAdd,
  buildDataPayloadForTransfer,
  buildDataPayloadForSession,
  buildSecp256r1PrecompileIx,
  AUTH_TYPE_SECP256R1,
  ROLE_OWNER,
  ROLE_SPENDER,
} from '../src/index.js';

// sdk-legacy (sibling)
import {
  generateAuthenticatorData as legacyGenAuthenticatorData,
  buildAuthPayload as legacyBuildAuthPayload,
  buildAuthPayloadPrefix as legacyBuildAuthPayloadPrefix,
  buildSecp256r1Challenge as legacyBuildSecp256r1Challenge,
} from '../../sdk-legacy/src/utils/secp256r1.js';
import {
  prepareSecp256r1 as legacyPrepare,
  finalizeSecp256r1 as legacyFinalize,
  buildDataPayloadForAdd as legacyBuildAdd,
  buildDataPayloadForTransfer as legacyBuildTransfer,
  buildDataPayloadForSession as legacyBuildSession,
  buildSecp256r1PrecompileIx as legacyBuildPrecompile,
} from '../../sdk-legacy/src/utils/signing.js';

const PROGRAM_BASE58 = '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS';
const PAYER_BASE58 = '11111111111111111111111111111112';

const KIT_PROGRAM = address(PROGRAM_BASE58);
const KIT_PAYER = address(PAYER_BASE58);
const PK_PROGRAM = new PublicKey(PROGRAM_BASE58);
const PK_PAYER = new PublicKey(PAYER_BASE58);

const SLOT = 234_567_890n;
const COUNTER = 42;
const SYSVAR_IX_INDEX = 1;

const credIdHash = new Uint8Array(32).fill(0xaa);
const compressedPubkey = new Uint8Array(33);
compressedPubkey[0] = 0x02;
for (let i = 1; i < 33; i++) compressedPubkey[i] = i;
const ed25519Pubkey = new Uint8Array(32).fill(0x33);
const sessionKey = new Uint8Array(32).fill(0x99);
const signedPayload = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34]);
const discriminator = new Uint8Array([4]);

const authenticatorData = (() => {
  // 37-byte canonical WebAuthn authenticator data.
  const buf = new Uint8Array(37);
  buf.fill(0xbb, 0, 32);
  buf[32] = 0x01;
  return buf;
})();
const clientDataJson = new TextEncoder().encode(
  '{"type":"webauthn.get","challenge":"AA","origin":"https://lazor.dev"}',
);
const clientDataJsonHash = new Uint8Array(32).fill(0xee);
const signature = new Uint8Array(64);
for (let i = 0; i < 64; i++) signature[i] = i;

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('generateAuthenticatorData', () => {
  it('byte-parity for canonical RP IDs', () => {
    for (const rpId of ['lazor.dev', 'localhost', 'wallet.example.com']) {
      const a = generateAuthenticatorData(rpId);
      const b = legacyGenAuthenticatorData(rpId);
      expect(bytesEqual(a, b)).toBe(true);
      expect(a.length).toBe(37);
      expect(a[32]).toBe(0x01);
    }
  });
});

describe('buildAuthPayloadPrefix', () => {
  it('14-byte parity', () => {
    const a = buildAuthPayloadPrefix({
      slot: SLOT,
      counter: COUNTER,
      sysvarIxIndex: SYSVAR_IX_INDEX,
    });
    const b = legacyBuildAuthPayloadPrefix({
      slot: SLOT,
      counter: COUNTER,
      sysvarIxIndex: SYSVAR_IX_INDEX,
    });
    expect(a.length).toBe(14);
    expect(bytesEqual(a, b)).toBe(true);
    // Reserved byte is always 0x80
    expect(a[13]).toBe(0x80);
  });
});

describe('buildAuthPayload', () => {
  it('full payload byte-parity', () => {
    const a = buildAuthPayload({
      slot: SLOT,
      counter: COUNTER,
      sysvarIxIndex: SYSVAR_IX_INDEX,
      authenticatorData,
      clientDataJson,
    });
    const b = legacyBuildAuthPayload({
      slot: SLOT,
      counter: COUNTER,
      sysvarIxIndex: SYSVAR_IX_INDEX,
      authenticatorData,
      clientDataJson,
    });
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('rejects oversize fields', () => {
    expect(() =>
      buildAuthPayload({
        slot: 0n,
        counter: 0,
        sysvarIxIndex: 0,
        authenticatorData: new Uint8Array(0x10000),
        clientDataJson: new Uint8Array(1),
      }),
    ).toThrow();
  });
});

describe('buildSecp256r1Challenge', () => {
  it('SHA256 parity (fundamental: this is what the passkey signs)', () => {
    const authPayloadPrefix = buildAuthPayloadPrefix({
      slot: SLOT,
      counter: COUNTER,
      sysvarIxIndex: SYSVAR_IX_INDEX,
    });
    const a = buildSecp256r1Challenge({
      discriminator,
      authPayload: authPayloadPrefix,
      signedPayload,
      payer: KIT_PAYER,
      counter: COUNTER,
      programId: KIT_PROGRAM,
    });
    const b = legacyBuildSecp256r1Challenge({
      discriminator,
      authPayload: authPayloadPrefix,
      signedPayload,
      slot: SLOT, // legacy takes slot but doesn't use it (verified in source comment)
      payer: PK_PAYER,
      counter: COUNTER,
      programId: PK_PROGRAM,
    });
    expect(a.length).toBe(32);
    expect(bytesEqual(a, b)).toBe(true);
  });
});

describe('prepareSecp256r1 + finalizeSecp256r1', () => {
  it('two-phase parity end-to-end', () => {
    const params = {
      discriminator,
      signedPayload,
      sysvarIxIndex: SYSVAR_IX_INDEX,
      slot: SLOT,
      counter: COUNTER,
      publicKeyBytes: compressedPubkey,
    };
    const kitPrep = prepareSecp256r1({ ...params, payer: KIT_PAYER, programId: KIT_PROGRAM });
    const legacyPrep = legacyPrepare({ ...params, payer: PK_PAYER, programId: PK_PROGRAM });
    expect(bytesEqual(kitPrep.challenge, legacyPrep.challenge)).toBe(true);

    const response = {
      signature,
      authenticatorData,
      clientDataJsonHash,
      clientDataJson,
    };
    const kitFin = finalizeSecp256r1(kitPrep, response);
    const legacyFin = legacyFinalize(legacyPrep, response);
    expect(bytesEqual(kitFin.authPayload, legacyFin.authPayload)).toBe(true);
    expect(bytesEqual(kitFin.precompileIx.data!, new Uint8Array(legacyFin.precompileIx.data!))).toBe(true);
  });
});

describe('buildDataPayloadForAdd', () => {
  it('Ed25519 spender path', () => {
    const a = buildDataPayloadForAdd(0, ROLE_SPENDER, ed25519Pubkey);
    const b = legacyBuildAdd(0, ROLE_SPENDER, ed25519Pubkey);
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('Secp256r1 owner path with rpId', () => {
    const a = buildDataPayloadForAdd(
      AUTH_TYPE_SECP256R1,
      ROLE_OWNER,
      credIdHash,
      compressedPubkey,
      'lazor.dev',
    );
    const b = legacyBuildAdd(
      AUTH_TYPE_SECP256R1,
      ROLE_OWNER,
      credIdHash,
      compressedPubkey,
      'lazor.dev',
    );
    expect(bytesEqual(a, b)).toBe(true);
  });
});

describe('buildDataPayloadForTransfer', () => {
  it('Secp256r1 path', () => {
    const a = buildDataPayloadForTransfer(
      AUTH_TYPE_SECP256R1,
      credIdHash,
      compressedPubkey,
      'lazor.dev',
    );
    const b = legacyBuildTransfer(
      AUTH_TYPE_SECP256R1,
      credIdHash,
      compressedPubkey,
      'lazor.dev',
    );
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('Ed25519 path', () => {
    const a = buildDataPayloadForTransfer(0, ed25519Pubkey);
    const b = legacyBuildTransfer(0, ed25519Pubkey);
    expect(bytesEqual(a, b)).toBe(true);
  });
});

describe('buildDataPayloadForSession', () => {
  it('with action buffer', () => {
    const actionsBuffer = new Uint8Array(43).fill(0x77);
    const a = buildDataPayloadForSession(sessionKey, 1_700_000_000n, actionsBuffer);
    const b = legacyBuildSession(sessionKey, 1_700_000_000n, actionsBuffer);
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('without action buffer', () => {
    const a = buildDataPayloadForSession(sessionKey, 1_700_000_000n);
    const b = legacyBuildSession(sessionKey, 1_700_000_000n);
    expect(bytesEqual(a, b)).toBe(true);
  });
});

describe('buildSecp256r1PrecompileIx', () => {
  it('precompile ix data byte-parity', () => {
    const message = new TextEncoder().encode('hello-precompile');
    const a = buildSecp256r1PrecompileIx(compressedPubkey, message, signature);
    const b = legacyBuildPrecompile(compressedPubkey, message, signature);
    expect(bytesEqual(a.data!, new Uint8Array(b.data!))).toBe(true);
  });

  it('rejects bad signature length', () => {
    expect(() =>
      buildSecp256r1PrecompileIx(compressedPubkey, new Uint8Array(0), new Uint8Array(63)),
    ).toThrow();
  });

  it('rejects bad pubkey length', () => {
    expect(() =>
      buildSecp256r1PrecompileIx(new Uint8Array(32), new Uint8Array(0), signature),
    ).toThrow();
  });
});
