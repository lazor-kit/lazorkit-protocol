/**
 * Mock Secp256r1 (passkey) signer for the kit-flavored test harness.
 * Uses the `ecdsa-secp256r1` package to generate keys + sign challenges
 * locally. Returns a Secp256r1Signer the SDK can drive via the
 * prepareSecp256r1 / finalizeSecp256r1 flow as if the browser
 * authenticator had spoken.
 */
import * as crypto from 'node:crypto';
// @ts-ignore — package has no types
import ECDSA from 'ecdsa-secp256r1';
import {
  generateAuthenticatorData,
  type Secp256r1Signer,
  type WebAuthnResponse,
} from '@lazorkit/sdk';

// Secp256r1 curve order (NIST P-256, also called secp256r1).
const SECP256R1_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = SECP256R1_N / 2n;

export interface MockSecp256r1Key {
  privateKey: any;
  publicKeyBytes: Uint8Array;
  credentialIdHash: Uint8Array;
  rpId: string;
}

export async function generateMockSecp256r1Key(
  rpId = 'example.com',
  credentialIdHash?: Uint8Array,
): Promise<MockSecp256r1Key> {
  const privateKey = await ECDSA.generateKey();
  const pubKeyBase64 = privateKey.toCompressedPublicKey();
  const compressedPubKey = new Uint8Array(Buffer.from(pubKeyBase64, 'base64'));
  const credHash = credentialIdHash ?? crypto.randomBytes(32);

  return {
    privateKey,
    publicKeyBytes: compressedPubKey,
    credentialIdHash: new Uint8Array(credHash),
    rpId,
  };
}

/** Normalise s to the lower half of the curve order — required by the precompile. */
function enforceLowS(rawSig: Uint8Array): Uint8Array {
  if (rawSig.length < 64) {
    const padded = new Uint8Array(64);
    padded.set(rawSig, 64 - rawSig.length);
    rawSig = padded;
  }
  const sBytes = rawSig.slice(32, 64);
  let s = 0n;
  for (let i = 0; i < 32; i++) s = (s << 8n) + BigInt(sBytes[i]!);

  if (s > HALF_N) {
    s = SECP256R1_N - s;
    for (let i = 31; i >= 0; i--) {
      sBytes[i] = Number(s & 0xffn);
      s >>= 8n;
    }
    rawSig.set(sBytes, 32);
  }
  return rawSig;
}

function bytesToBase64UrlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Make a Secp256r1Signer the SDK can drive — simulates a real browser
 * authenticator by producing matching authenticatorData + clientDataJSON
 * and a valid ECDSA signature over their concatenation.
 */
export function createMockSigner(key: MockSecp256r1Key): Secp256r1Signer {
  return {
    publicKeyBytes: key.publicKeyBytes,
    credentialIdHash: key.credentialIdHash,
    rpId: key.rpId,
    async sign(challenge: Uint8Array) {
      return fakeWebAuthnSign(key, challenge);
    },
  };
}

/**
 * Same machinery, returned as a one-shot helper for tests that want
 * to drive prepare/finalize directly rather than via the signer
 * callback contract.
 */
export async function fakeWebAuthnSign(
  key: MockSecp256r1Key,
  challenge: Uint8Array,
): Promise<WebAuthnResponse> {
  const authenticatorData = generateAuthenticatorData(key.rpId);
  const clientDataJson = JSON.stringify({
    type: 'webauthn.get',
    challenge: bytesToBase64UrlNoPad(challenge),
    origin: `https://${key.rpId}`,
    crossOrigin: false,
  });
  const clientDataJsonBytes = new Uint8Array(
    Buffer.from(clientDataJson, 'utf-8'),
  );
  const clientDataJsonHash = new Uint8Array(
    crypto.createHash('sha256').update(clientDataJsonBytes).digest(),
  );

  const messageToSign = Buffer.concat([authenticatorData, clientDataJsonHash]);
  const signatureBase64 = await key.privateKey.sign(Buffer.from(messageToSign));
  const signature = enforceLowS(
    new Uint8Array(Buffer.from(signatureBase64, 'base64')),
  );

  return {
    signature,
    authenticatorData,
    clientDataJsonHash,
    clientDataJson: clientDataJsonBytes,
  };
}
