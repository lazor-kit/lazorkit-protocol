/**
 * The passkey challenge domains, in both SDKs.
 *
 * A passkey signs whatever WebAuthn challenge it is handed, and the LazorKit
 * programs approve a transaction by the challenge in a passkey signature. So
 * each kind of challenge has its own shape: a transaction challenge is a
 * 32-byte hash, a message challenge 58 bytes under one tag, an ownership-proof
 * challenge 59 under another. The bytes are those of `@lazorkit/wallet` 3.3.1
 * and `@lazorkit/wallet-mobile-adapter` 2.3.1 (lazor-kit #113), pinned by
 * test-vectors/challenge-domains.json.
 *
 * The tagged ownership challenge is a new function, createTaggedOwnershipChallenge.
 * createOwnershipChallenge still returns 32 bare random bytes: those wallet
 * packages depend on sdk-legacy ^1.3.0 and, where globalThis.crypto is missing,
 * take it as their random source and throw on any other length.
 *
 * sdk-legacy has no test runner of its own in CI, so its implementation is
 * checked here too, from source, against the same vectors.
 */
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, it, expect, vi } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2';
import { Keypair, PublicKey } from '@solana/web3.js';
import { address } from '@solana/kit';

import {
  OWNERSHIP_PROOF_DOMAIN,
  PROGRAM_ID_DEVNET,
  SIGNED_MESSAGE_DOMAIN,
  buildSecp256r1Challenge,
  createOwnershipChallenge,
  createTaggedOwnershipChallenge,
  resolvePasskeyPublicKey,
  signedMessageChallenge,
  verifyOwnershipProof,
  type OwnershipProof,
} from '../src/index.js';
import {
  OWNERSHIP_PROOF_DOMAIN as LEGACY_OWNERSHIP_PROOF_DOMAIN,
  SIGNED_MESSAGE_DOMAIN as LEGACY_SIGNED_MESSAGE_DOMAIN,
  buildSecp256r1Challenge as legacyBuildSecp256r1Challenge,
  createOwnershipChallenge as legacyCreateOwnershipChallenge,
  createTaggedOwnershipChallenge as legacyCreateTaggedOwnershipChallenge,
  resolvePasskeyPublicKey as legacyResolvePasskeyPublicKey,
  signedMessageChallenge as legacySignedMessageChallenge,
  verifyOwnershipProof as legacyVerifyOwnershipProof,
} from '../../sdk-legacy/src/utils/index.js';

type Vectors = {
  transaction: { challengeLength: number };
  signedMessage: {
    domain: string;
    domainHex: string;
    challengeLength: number;
    vectors: { name: string; utf8?: string; hex?: string; challengeHex: string }[];
  };
  ownershipProof: { domain: string; domainHex: string; nonceLength: number; challengeLength: number };
};

const VECTORS: Vectors = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../test-vectors/challenge-domains.json', import.meta.url)),
    'utf8',
  ),
);

const RP_ID = 'portal.lazor.sh';
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const MESSAGE_TAG = Buffer.from(VECTORS.signedMessage.domainHex, 'hex');
const PROOF_TAG = Buffer.from(VECTORS.ownershipProof.domainHex, 'hex');

/** tag || SHA-256(tag || message), computed with node:crypto: a third implementation. */
function expectedMessageChallenge(message: Uint8Array): string {
  const digest = createHash('sha256').update(MESSAGE_TAG).update(message).digest();
  return Buffer.concat([MESSAGE_TAG, digest]).toString('hex');
}

const IMPLEMENTATIONS = [
  {
    sdk: 'sdk-kit',
    SIGNED_MESSAGE_DOMAIN,
    OWNERSHIP_PROOF_DOMAIN,
    signedMessageChallenge,
    createOwnershipChallenge,
    createTaggedOwnershipChallenge,
    verifyOwnershipProof,
    resolvePasskeyPublicKey,
  },
  {
    sdk: 'sdk-legacy',
    SIGNED_MESSAGE_DOMAIN: LEGACY_SIGNED_MESSAGE_DOMAIN,
    OWNERSHIP_PROOF_DOMAIN: LEGACY_OWNERSHIP_PROOF_DOMAIN,
    signedMessageChallenge: legacySignedMessageChallenge,
    createOwnershipChallenge: legacyCreateOwnershipChallenge,
    createTaggedOwnershipChallenge: legacyCreateTaggedOwnershipChallenge,
    verifyOwnershipProof: legacyVerifyOwnershipProof,
    resolvePasskeyPublicKey: legacyResolvePasskeyPublicKey,
  },
] as const;

/** A browser-shaped assertion by `secretKey` over `signedChallenge` (DER, as browsers return it). */
function assertion(secretKey: Uint8Array, signedChallenge: Uint8Array): Omit<OwnershipProof, 'challenge'> {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(new TextEncoder().encode(RP_ID)), 0);
  authenticatorData[32] = 0x05; // UP | UV
  const clientDataJson = new TextEncoder().encode(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(signedChallenge).toString('base64url'),
      origin: `https://${RP_ID}`,
      crossOrigin: false,
    }),
  );
  const digest = sha256(new Uint8Array([...authenticatorData, ...sha256(clientDataJson)]));
  const signature = p256.sign(digest, secretKey, { prehash: false, lowS: true }).toDERRawBytes();
  return { signature, authenticatorData, clientDataJson };
}

const passkey = (() => {
  const secretKey = p256.utils.randomPrivateKey();
  return { secretKey, candidates: [{ id: 'mine', publicKey: p256.getPublicKey(secretKey, true) }] };
})();

describe.each(IMPLEMENTATIONS)('signedMessageChallenge, format v1 ($sdk)', (impl) => {
  it("has the wallet packages' domain tag", () => {
    expect(impl.SIGNED_MESSAGE_DOMAIN).toBe(VECTORS.signedMessage.domain);
    expect(Buffer.from(impl.SIGNED_MESSAGE_DOMAIN, 'utf8').toString('hex')).toBe(VECTORS.signedMessage.domainHex);
    expect(MESSAGE_TAG.length).toBe(26);
  });

  for (const vector of VECTORS.signedMessage.vectors) {
    it(`gives the wallet packages' bytes: ${vector.name}`, () => {
      const message = vector.utf8 ?? new Uint8Array(Buffer.from(vector.hex!, 'hex'));
      const challenge = impl.signedMessageChallenge(message);
      expect(hex(challenge)).toBe(vector.challengeHex);
      expect(challenge).toHaveLength(VECTORS.signedMessage.challengeLength);
    });
  }

  it('signs a string as its UTF-8 bytes, a lone surrogate as U+FFFD as Buffer does', () => {
    for (const text of ['Sign in to app.test, nonce 42', 'héllo ✓', '', 'a\ud800b']) {
      const bytes = new Uint8Array(Buffer.from(text, 'utf8'));
      expect(hex(impl.signedMessageChallenge(text))).toBe(hex(impl.signedMessageChallenge(bytes)));
      expect(hex(impl.signedMessageChallenge(text))).toBe(expectedMessageChallenge(bytes));
    }
  });

  it('takes any typed-array view as the bytes it covers', () => {
    const backing = new Uint8Array(randomBytes(80));
    const view = backing.subarray(7, 47);
    const copy = new Uint8Array(view);
    expect(hex(impl.signedMessageChallenge(view))).toBe(hex(impl.signedMessageChallenge(copy)));
    expect(hex(impl.signedMessageChallenge(Buffer.from(copy)))).toBe(hex(impl.signedMessageChallenge(copy)));
    expect(hex(impl.signedMessageChallenge(copy))).toBe(expectedMessageChallenge(copy));
  });

  it('never passes a message through: 58 bytes under the tag, whatever its length, 32 included', () => {
    for (const length of [0, 1, 16, 31, 32, 33, 58, 59, 64, 1000]) {
      for (let i = 0; i < 10; i++) {
        const message = new Uint8Array(randomBytes(length));
        const challenge = impl.signedMessageChallenge(message);
        expect(challenge).toHaveLength(58);
        expect(Buffer.from(challenge.subarray(0, 26)).equals(MESSAGE_TAG)).toBe(true);
        expect(hex(challenge)).not.toBe(hex(message));
        expect(hex(challenge)).toBe(expectedMessageChallenge(message));
      }
    }
  });

  it('refuses anything but a string or bytes, with its own TypeError', () => {
    // The function's own refusal, not any TypeError: calling a missing export,
    // or reading `.length` of undefined past a removed guard, throws one too.
    expect(impl.signedMessageChallenge).toBeTypeOf('function');
    for (const bad of [undefined, null, 42, [1, 2, 3], { length: 32 }, new ArrayBuffer(32)]) {
      const call = () => impl.signedMessageChallenge(bad as unknown as Uint8Array);
      expect(call).toThrow(TypeError);
      expect(call).toThrow('A message to sign must be a string or a Uint8Array');
    }
  });
});

/**
 * `createOwnershipChallenge` of `@lazorkit/wallet` 3.3.1 and
 * `@lazorkit/wallet-mobile-adapter` 2.3.1, as written in lazor-kit 22e0ec2
 * (packages/react/core/message/ownershipProof.ts, the same in react-native),
 * with `randomBytes32` standing for the sdk-legacy `createOwnershipChallenge`
 * it imports under that name.
 */
function walletOwnershipChallenge(randomBytes32: () => Uint8Array): Uint8Array {
  const NONCE_LENGTH = 32;
  const source = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  let nonce: Uint8Array;
  if (source && typeof source.getRandomValues === 'function') {
    nonce = source.getRandomValues(new Uint8Array(NONCE_LENGTH));
  } else {
    nonce = randomBytes32();
    if (nonce.length !== NONCE_LENGTH) throw new Error('No source of random bytes for an ownership challenge');
  }
  const challenge = new Uint8Array(PROOF_TAG.length + NONCE_LENGTH);
  challenge.set(PROOF_TAG, 0);
  challenge.set(nonce, PROOF_TAG.length);
  return challenge;
}

describe.each(IMPLEMENTATIONS)('createTaggedOwnershipChallenge, format v1 ($sdk)', (impl) => {
  it("has the wallet packages' domain tag", () => {
    expect(impl.OWNERSHIP_PROOF_DOMAIN).toBe(VECTORS.ownershipProof.domain);
    expect(Buffer.from(impl.OWNERSHIP_PROOF_DOMAIN, 'utf8').toString('hex')).toBe(VECTORS.ownershipProof.domainHex);
    expect(PROOF_TAG.length).toBe(27);
  });

  it('is the tag, then 32 fresh random bytes: 59 in all', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const challenge = impl.createTaggedOwnershipChallenge();
      expect(challenge).toBeInstanceOf(Uint8Array);
      expect(challenge).toHaveLength(VECTORS.ownershipProof.challengeLength);
      expect(hex(challenge.subarray(0, PROOF_TAG.length))).toBe(VECTORS.ownershipProof.domainHex);
      const nonce = challenge.subarray(PROOF_TAG.length);
      expect(nonce).toHaveLength(VECTORS.ownershipProof.nonceLength);
      seen.add(hex(nonce));
    }
    expect(seen.size).toBe(50);
  });

  it("is the wallet packages' format: the same length, the same bytes but the nonce", () => {
    const ours = impl.createTaggedOwnershipChallenge();
    const theirs = walletOwnershipChallenge(impl.createOwnershipChallenge);
    expect(ours).toHaveLength(theirs.length);
    expect(hex(ours.subarray(0, PROOF_TAG.length))).toBe(hex(theirs.subarray(0, PROOF_TAG.length)));
  });

  it("verifies a proof over the tagged challenge, and one over the wallet packages' challenge", () => {
    const challenges = [impl.createTaggedOwnershipChallenge(), walletOwnershipChallenge(impl.createOwnershipChallenge)];
    for (const challenge of challenges) {
      const proof = { challenge, ...assertion(passkey.secretKey, challenge) };
      expect(impl.verifyOwnershipProof(passkey.candidates, proof, RP_ID).map((c) => c.id)).toEqual(['mine']);
      // Over exactly that challenge: not over its nonce alone.
      const nonceOnly = { ...proof, challenge: challenge.subarray(PROOF_TAG.length) };
      expect(impl.verifyOwnershipProof(passkey.candidates, nonceOnly, RP_ID)).toEqual([]);
    }
  });

  it('resolvePasskeyPublicKey pins the signer from two tagged challenges, or a tagged and a bare one', () => {
    // The key-recovery path its JSDoc and the READMEs give: two assertions, each
    // over its own createTaggedOwnershipChallenge(). Every tagged challenge
    // shares its first 27 bytes; only an identical challenge counts as a repeat.
    const proofOver = (challenge: Uint8Array): OwnershipProof => ({
      challenge,
      ...assertion(passkey.secretKey, challenge),
    });
    const mine = hex(passkey.candidates[0]!.publicKey);
    const tagged = [impl.createTaggedOwnershipChallenge(), impl.createTaggedOwnershipChallenge()].map(proofOver);
    expect(hex(impl.resolvePasskeyPublicKey(tagged, RP_ID)!)).toBe(mine);
    const mixed = [proofOver(impl.createTaggedOwnershipChallenge()), proofOver(impl.createOwnershipChallenge())];
    expect(hex(impl.resolvePasskeyPublicKey(mixed, RP_ID)!)).toBe(mine);
    expect(impl.resolvePasskeyPublicKey([tagged[0]!, tagged[0]!], RP_ID)).toBeNull();
  });
});

describe.each(IMPLEMENTATIONS)('createOwnershipChallenge is unchanged ($sdk)', (impl) => {
  it('returns 32 fresh random bytes, no tag', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const challenge = impl.createOwnershipChallenge();
      expect(challenge).toBeInstanceOf(Uint8Array);
      expect(challenge).toHaveLength(32);
      seen.add(hex(challenge));
    }
    expect(seen.size).toBe(50);
  });

  it('still verifies a proof over its bytes', () => {
    const bare = impl.createOwnershipChallenge();
    const proof = { challenge: bare, ...assertion(passkey.secretKey, bare) };
    expect(impl.verifyOwnershipProof(passkey.candidates, proof, RP_ID).map((c) => c.id)).toEqual(['mine']);
  });
});

// Node 18 has no global WebCrypto by default. There the wallet packages take
// sdk-legacy's createOwnershipChallenge as their 32 random bytes, and a fresh
// install of them resolves sdk-legacy ^1.3.0 to the newest 1.x: this one.
describe('sdk-legacy without globalThis.crypto, where the wallet packages fall back to it', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('createOwnershipChallenge returns 32 fresh random bytes', () => {
    vi.stubGlobal('crypto', undefined);
    expect(globalThis.crypto).toBeUndefined();
    const a = legacyCreateOwnershipChallenge();
    const b = legacyCreateOwnershipChallenge();
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a).toHaveLength(32);
    expect(hex(a)).not.toBe(hex(b));
  });

  it("the wallet packages' ownership challenge, built on it, is made and verifies", () => {
    vi.stubGlobal('crypto', undefined);
    const challenge = walletOwnershipChallenge(legacyCreateOwnershipChallenge);
    expect(challenge).toHaveLength(VECTORS.ownershipProof.challengeLength);
    expect(hex(challenge.subarray(0, PROOF_TAG.length))).toBe(VECTORS.ownershipProof.domainHex);
    const proof = { challenge, ...assertion(passkey.secretKey, challenge) };
    expect(legacyVerifyOwnershipProof(passkey.candidates, proof, RP_ID).map((c) => c.id)).toEqual(['mine']);
  });

  it('would throw if it returned the tagged form: why createOwnershipChallenge stays 32 bytes', () => {
    vi.stubGlobal('crypto', undefined);
    expect(legacyCreateTaggedOwnershipChallenge()).toHaveLength(59);
    expect(() => walletOwnershipChallenge(legacyCreateTaggedOwnershipChallenge)).toThrow(
      'No source of random bytes for an ownership challenge',
    );
  });
});

describe('no challenge of one kind is another', () => {
  const programId = PROGRAM_ID_DEVNET;
  const payer = address(Keypair.generate().publicKey.toBase58());
  const wallet = address(Keypair.generate().publicKey.toBase58());

  it('a transaction challenge is 32 bytes, a message challenge 58 and a proof challenge 59, in both SDKs', () => {
    const tx = {
      discriminator: new Uint8Array([4]),
      authPayload: new Uint8Array(14),
      signedPayload: new Uint8Array(randomBytes(40)),
      counter: 7,
    };
    const kitTx = buildSecp256r1Challenge({ ...tx, payer, wallet, programId });
    const legacyTx = legacyBuildSecp256r1Challenge({
      ...tx,
      slot: 0n,
      payer: new PublicKey(payer),
      wallet: new PublicKey(wallet),
      programId: new PublicKey(programId),
    });
    expect(hex(kitTx)).toBe(hex(legacyTx));
    expect(kitTx).toHaveLength(VECTORS.transaction.challengeLength);

    const lengths = new Set([
      kitTx.length,
      signedMessageChallenge(kitTx).length,
      createTaggedOwnershipChallenge().length,
    ]);
    expect([...lengths].sort((a, b) => a - b)).toEqual([32, 58, 59]);
    // And the two tags differ within the shorter one, so neither is a prefix of the other.
    expect(MESSAGE_TAG.equals(PROOF_TAG.subarray(0, MESSAGE_TAG.length))).toBe(false);
  });

  it('a message signature verifies only over its message challenge, never over the raw bytes', () => {
    for (const impl of IMPLEMENTATIONS) {
      const message = new Uint8Array(randomBytes(32)); // the length of a transaction challenge
      const challenge = impl.signedMessageChallenge(message);
      const overChallenge = { challenge, ...assertion(passkey.secretKey, challenge) };
      expect(impl.verifyOwnershipProof(passkey.candidates, overChallenge, RP_ID)).toHaveLength(1);

      // A passkey that signed the raw bytes made no LazorKit message signature.
      const overRaw = { challenge, ...assertion(passkey.secretKey, message) };
      expect(impl.verifyOwnershipProof(passkey.candidates, overRaw, RP_ID)).toEqual([]);
      // Nor is a message signature an ownership proof over the message bytes.
      expect(impl.verifyOwnershipProof(passkey.candidates, { ...overChallenge, challenge: message }, RP_ID)).toEqual([]);
    }
  });
});
