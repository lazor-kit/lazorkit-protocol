/**
 * LazorKit signed messages, format v1.
 *
 * A passkey signs a WebAuthn challenge, and the LazorKit programs approve a
 * transaction by the challenge in a passkey signature. So a message is never
 * signed as the challenge itself: a message signature must not be usable as
 * anything else the passkey approves. Nothing in this SDK asks a passkey to
 * sign a message — `Secp256r1Signer.sign` and the `prepare*` methods sign
 * transaction challenges only — but an app that has a passkey sign one signs
 * this challenge, as every `signMessage` in `@lazorkit/wallet` 3.3.1 and
 * `@lazorkit/wallet-mobile-adapter` 2.3.1 does:
 *
 *     tag       = UTF-8 "LazorKit signed message v1"   (26 bytes)
 *     challenge = tag || SHA-256(tag || message)      (58 bytes)
 *
 * Every transaction challenge the programs accept is a 32-byte hash, and an
 * ownership-proof challenge is 59 bytes with its own tag (see
 * `createTaggedOwnershipChallenge`): a message challenge can never be one of
 * them.
 *
 * Mirrors sdk-legacy/src/utils/signedMessage.ts: same names, same bytes as
 * `signedMessageChallenge` in those packages. The fixed vectors in
 * test-vectors/challenge-domains.json pin them for both SDKs.
 */
import { sha256 } from '@noble/hashes/sha2';

/** The domain tag every LazorKit message challenge starts with (format v1). */
export const SIGNED_MESSAGE_DOMAIN = 'LazorKit signed message v1';

/** A message to sign: a string (signed as its UTF-8 bytes) or bytes. */
export type SignedMessageInput = string | Uint8Array;

const utf8 = new TextEncoder();
const SIGNED_MESSAGE_TAG = utf8.encode(SIGNED_MESSAGE_DOMAIN);

/**
 * Pure. The WebAuthn challenge a passkey signs for `message`:
 * `tag || SHA-256(tag || message)`, 58 bytes, where `tag` is
 * {@link SIGNED_MESSAGE_DOMAIN} in UTF-8. Hand it to
 * `navigator.credentials.get({ publicKey: { challenge, ... } })` in place of
 * the message. Throws a `TypeError` for anything but a string or bytes.
 *
 * The message itself never reaches the passkey: whatever its length, the
 * challenge is 58 bytes and starts with the tag, so a 32-byte message cannot
 * be signed as a transaction challenge. An assertion over the raw message
 * bytes is not a LazorKit message signature.
 *
 * To check a signature, take the passkey's key from the chain, never from the
 * client: `verifyWalletMessage` in `@lazorkit/wallet` does. It takes the
 * signature as 64-byte r||s (low-S or not), not the DER a browser returns, and
 * clientDataJSON and authenticatorData as base64. With this SDK, which takes
 * DER or r||s: keep the `findPasskeyWalletCandidates` hits whose wallet or
 * vault is the claimed one, pass them to `verifyOwnershipProof` with this
 * challenge as the proof's `challenge` (it checks a `webauthn.get` over
 * exactly that, under `rpId`, with the user present), and check that the
 * wallet account of the one it keeps still exists (a migrated v1 wallet leaves
 * its authorities behind).
 */
export function signedMessageChallenge(message: SignedMessageInput): Uint8Array {
  const bytes = messageBytes(message);
  const preimage = new Uint8Array(SIGNED_MESSAGE_TAG.length + bytes.length);
  preimage.set(SIGNED_MESSAGE_TAG, 0);
  preimage.set(bytes, SIGNED_MESSAGE_TAG.length);
  const challenge = new Uint8Array(SIGNED_MESSAGE_TAG.length + 32);
  challenge.set(SIGNED_MESSAGE_TAG, 0);
  challenge.set(sha256(preimage), SIGNED_MESSAGE_TAG.length);
  return challenge;
}

function messageBytes(message: SignedMessageInput): Uint8Array {
  if (typeof message === 'string') return utf8.encode(message);
  // Any typed-array view, as its bytes: the wallet packages take one the same way.
  if (ArrayBuffer.isView(message)) {
    return new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
  }
  throw new TypeError('A message to sign must be a string or a Uint8Array');
}
