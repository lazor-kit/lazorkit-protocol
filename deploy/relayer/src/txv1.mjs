// SIMD-0385 transaction v1: the wire layout this relayer needs and its
// byte-level signing. The v1 policy is in policy.mjs (inspectTxV1).
//
// web3.js 1.99 reads a v1 transaction (VersionedTransaction.deserialize gives
// a MessageV1 with its transactionConfig) but cannot write one:
// MessageV1.serialize(), and so VersionedTransaction.serialize() and .sign(),
// throw. So the relayer signs the bytes it was given. They are also the bytes
// it inspected and simulated, so what it signs is exactly what it checked.
//
// Layout (SIMD-0385). The message comes first and the signatures last, where
// legacy and v0 put them first:
//
//   0x81 | numRequiredSignatures u8 | numReadonlySigned u8 | numReadonlyUnsigned u8
//   | configMask u32 LE | recentBlockhash [32] | numInstructions u8 | numAddresses u8
//   | addresses [32 × numAddresses]
//   | config values, in bit order: priority fee u64 (bits 0+1), compute-unit
//     limit u32 (bit 2), loaded-accounts-data size limit u32 (bit 3), heap u32 (bit 4)
//   | per instruction: programIndex u8, numAccounts u8, dataLength u16 LE
//   | per instruction: account indexes, data
//   | signatures [64 × numRequiredSignatures]
//
// Signature slot i belongs to address i. The fee payer is address 0, so its
// slot starts right after the message.

import crypto from 'node:crypto';

export const TX_V1_PREFIX = 0x81;
export const TX_V1_MAX_BYTES = 4096;
export const TX_V1_MAX_ADDRESSES = 64;

// The ComputeBudget maximums a v1 config value is held to.
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
export const MAX_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 64 * 1024 * 1024;

const SIGNATURE_BYTES = 64;
const ADDRESS_BYTES = 32;
// 0x81, the three header bytes, the mask, the blockhash and the two counts.
const ADDRESSES_AT = 42;
const CONFIG_MASK_AT = 4;
const ADDRESS_COUNT_AT = 41;
// The priority fee's two config mask bits: both are set, or neither.
const PRIORITY_FEE_BITS = 0b11;

/** True for v1 wire bytes: the first byte is 0x81. */
export function isTxV1(raw) {
  return raw.length > 0 && raw[0] === TX_V1_PREFIX;
}

/**
 * { signers, messageLength } of v1 wire bytes. The message is everything before
 * the signatures, which are the last 64 × signers bytes.
 */
export function txV1Layout(raw) {
  if (!isTxV1(raw)) throw new Error('txv1: not a v1 transaction (the first byte is not 0x81)');
  const signers = raw.length > 1 ? raw[1] : 0;
  const messageLength = raw.length - SIGNATURE_BYTES * signers;
  if (messageLength < ADDRESSES_AT + ADDRESS_BYTES) {
    throw new Error(`txv1: ${raw.length} bytes cannot hold a message and ${signers} signatures`);
  }
  return { signers, messageLength };
}

/**
 * The priority fee of v1 wire bytes as a bigint, or null when the config mask
 * does not set both fee bits or the bytes end before the fee. It is the first
 * config value: a u64 right after the addresses.
 *
 * web3.js 1.99 decodes it as a Number and throws on a fee over 2^53 - 1, which
 * the cluster accepts (any u64). The relayer reads such a fee here, so that it
 * is refused by the fee rule (policy.mjs) and not as undecodable bytes.
 */
export function txV1PriorityFee(raw) {
  if (!isTxV1(raw) || raw.length < ADDRESSES_AT) return null;
  const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.length);
  if ((bytes.readUInt32LE(CONFIG_MASK_AT) & PRIORITY_FEE_BITS) !== PRIORITY_FEE_BITS) return null;
  const at = ADDRESSES_AT + ADDRESS_BYTES * bytes[ADDRESS_COUNT_AT];
  return bytes.length < at + 8 ? null : bytes.readBigUInt64LE(at);
}

/** The 64-byte signature in slot `index` (a view into `raw`). */
export function txV1Signature(raw, index) {
  const { signers, messageLength } = txV1Layout(raw);
  if (!Number.isInteger(index) || index < 0 || index >= signers) {
    throw new Error(`txv1: no signature slot ${index}; the transaction has ${signers}`);
  }
  const at = messageLength + SIGNATURE_BYTES * index;
  return raw.subarray(at, at + SIGNATURE_BYTES);
}

/**
 * A copy of `raw` with `keypair`'s signature in the fee payer's slot: ed25519
 * over the message, written at offset messageLength. Every other byte is left
 * as it was, including the other signers' signatures. Deterministic (RFC 8032),
 * so the same bytes and key always give the same signature, and the same
 * transaction id.
 *
 * Throws unless address 0, the fee payer, is `keypair`'s public key and a
 * required signer. The policy has already checked both; this keeps the
 * relayer from ever writing its signature into another signer's slot.
 */
export function signTxV1AsFeePayer(raw, keypair) {
  const { signers, messageLength } = txV1Layout(raw);
  if (signers < 1) throw new Error('txv1: the transaction requires no signatures, so its fee payer cannot sign');
  const feePayer = raw.subarray(ADDRESSES_AT, ADDRESSES_AT + ADDRESS_BYTES);
  if (!Buffer.from(feePayer).equals(Buffer.from(keypair.publicKey.toBytes()))) {
    throw new Error(`txv1: the fee payer (address 0) is not ${keypair.publicKey.toBase58()}`);
  }
  const signed = Uint8Array.from(raw);
  signed.set(ed25519Sign(keypair, signed.subarray(0, messageLength)), messageLength);
  return signed;
}

// node:crypto takes an ed25519 private key as PKCS#8 DER: this prefix, then the
// 32-byte seed (the first half of a Solana secret key).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX_LENGTH = 12;
const privateKeys = new WeakMap();

function ed25519Sign(keypair, message) {
  let key = privateKeys.get(keypair);
  if (!key) {
    const seed = Buffer.from(keypair.secretKey.subarray(0, 32));
    key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(SPKI_ED25519_PREFIX_LENGTH);
    if (!publicKey.equals(Buffer.from(keypair.publicKey.toBytes()))) {
      throw new Error('txv1: the keypair\'s secret key does not belong to its public key');
    }
    privateKeys.set(keypair, key);
  }
  return new Uint8Array(crypto.sign(null, Buffer.from(message), key));
}
