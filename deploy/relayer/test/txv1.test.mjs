// U13, offline: the relayer's v1 signing and v1 policy, against the golden
// vectors the wallets' writer is tested against (test/helpers/vectors.mjs),
// v1 transactions that landed on devnet, and @solana/kit 8.4.0 when present.
//
//   npm test
//   TXV1_ORACLE_DIR=<lazor-kit>/tools/txv1-oracle npm test    # also the kit checks
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import bs58 from 'bs58';
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import { isTxV1, txV1Layout, txV1Signature, signTxV1AsFeePayer, txV1PriorityFee } from '../src/txv1.mjs';
import { inspectTransaction, inspectTxV1, checkTxV1PriorityFee, PolicyError, ERR } from '../src/policy.mjs';
import { COMPUTE_BUDGET_PROGRAM, LAZORKIT_V2_DEVNET, SECP256R1_PROGRAM } from '../src/allowlist.mjs';
import { buildTxV1, instructionsFromJson } from '../scripts/txv1-build.mjs';
import { vectors, vector, fitting, testKey, walletSent, fullySigned } from './helpers/vectors.mjs';
import { loadKit } from './helpers/kit.mjs';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const payer = testKey('payer');

function verifyEd25519(publicKey, message, signature) {
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey)]);
  return crypto.verify(null, Buffer.from(message), crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }), Buffer.from(signature));
}

// ─── The vectors and the test builder ───────────────────────────────────────

test('the vectors are the ones the wallets test against, and their keys derive from their labels', () => {
  assert.equal(vectors.oracle['@solana/kit'], '8.4.0');
  for (const [label, address] of Object.entries(vectors.keys)) assert.equal(testKey(label).publicKey.toBase58(), address, label);
  assert.ok(fitting().length >= 10, 'expected at least 10 fitting vectors');
});

test('the test builder reproduces every vector byte for byte', () => {
  for (const v of vectors.vectors) {
    const built = buildTxV1({ ...v.input, instructions: instructionsFromJson(v.input.instructions) });
    assert.equal(built.wire.length, v.expected.bytes, `${v.name}: size`);
    assert.equal(built.addresses, v.expected.addresses, `${v.name}: addresses`);
    if (v.expected.fits) {
      assert.equal(b64(built.wire), v.expected.unsigned, `${v.name}: bytes`);
      assert.equal(built.messageLength, v.expected.messageLength, `${v.name}: message length`);
    }
  }
});

// ─── Y3: byte-level signing ─────────────────────────────────────────────────

test('Y3: the relayer fills the fee payer slot only, with the signature the wallet writer made', () => {
  let checked = 0;
  for (const v of fitting()) {
    if (v.sign[0] !== 'payer') continue;
    const sent = walletSent(v);
    const before = Uint8Array.from(sent);
    const signed = signTxV1AsFeePayer(sent, payer);
    // Every byte equals the writer's fully signed transaction: the message and
    // the other signers' slots unchanged, the fee payer's slot its signature.
    assert.deepEqual(signed, fullySigned(v), v.name);
    assert.deepEqual(sent, before, `${v.name}: the input is not modified`);
    const { signers, messageLength } = txV1Layout(signed);
    assert.equal(signers, v.expected.signers, v.name);
    assert.equal(messageLength, v.expected.messageLength, v.name);
    assert.equal(b64(txV1Signature(signed, 0)), v.expected.signatures[0], v.name);
    assert.ok(verifyEd25519(payer.publicKey.toBytes(), signed.subarray(0, messageLength), txV1Signature(signed, 0)), `${v.name}: verifies`);
    // web3.js 1.99 reads it back as v1, with the signature in the fee payer's place.
    const read = VersionedTransaction.deserialize(signed);
    assert.equal(read.version, 1, v.name);
    assert.deepEqual(new Uint8Array(read.signatures[0]), new Uint8Array(txV1Signature(signed, 0)), v.name);
    checked++;
  }
  assert.ok(checked >= 10, `checked ${checked} vectors`);
});

test('Y3: signing is deterministic, so a resend of the same bytes gets the same transaction id', () => {
  const sent = walletSent(vector('passkey-execute-1-transfer'));
  const a = signTxV1AsFeePayer(sent, payer);
  const b = signTxV1AsFeePayer(Uint8Array.from(sent), payer);
  assert.deepEqual(a, b);
  // Signing already-signed bytes again changes nothing either.
  assert.deepEqual(signTxV1AsFeePayer(a, payer), a);
});

test('Y3: the layout and signature slots agree with v1 transactions that landed on devnet', () => {
  for (const l of vectors.landed) {
    const raw = new Uint8Array(Buffer.from(l.wire, 'base64'));
    assert.ok(isTxV1(raw), l.name);
    const tx = VersionedTransaction.deserialize(raw);
    const { signers, messageLength } = txV1Layout(raw);
    assert.equal(signers, tx.message.header.numRequiredSignatures, l.name);
    assert.equal(bs58.encode(txV1Signature(raw, 0)), l.signature, `${l.name}: slot 0 is the transaction id`);
    for (let i = 0; i < signers; i++) {
      const key = tx.message.staticAccountKeys[i].toBytes();
      assert.ok(verifyEd25519(key, raw.subarray(0, messageLength), txV1Signature(raw, i)), `${l.name}: signature ${i} verifies over the message`);
    }
  }
});

test('Y3: the relayer never signs for another fee payer, or without a slot', () => {
  const sent = walletSent(vector('passkey-execute-1-transfer'));
  assert.throws(() => signTxV1AsFeePayer(sent, Keypair.generate()), /fee payer \(address 0\) is not/);
  const noSigners = Uint8Array.from(sent.subarray(0, sent.length - 64));
  noSigners[1] = 0;
  assert.throws(() => signTxV1AsFeePayer(noSigners, payer), /requires no signatures/);
  assert.throws(() => signTxV1AsFeePayer(Uint8Array.of(0x80, 1, 2, 3), payer), /not a v1 transaction/);
  assert.throws(() => txV1Layout(Uint8Array.of(0x81, 1)), /cannot hold/);
});

test('U13: kit 8.4.0 partiallySignTransaction gives the relayer\'s bytes', async (t) => {
  const { kit, why, from } = await loadKit();
  if (!kit) return t.skip(why);
  t.diagnostic(`kit from ${from}`);
  const kitPayer = await kit.createKeyPairFromPrivateKeyBytes(payer.secretKey.slice(0, 32));
  let checked = 0;
  for (const v of fitting()) {
    if (v.sign[0] !== 'payer') continue;
    const sent = walletSent(v);
    const decoded = kit.getTransactionDecoder().decode(sent);
    const kitSigned = new Uint8Array(kit.getTransactionEncoder().encode(await kit.partiallySignTransaction([kitPayer], decoded)));
    assert.deepEqual(signTxV1AsFeePayer(sent, payer), kitSigned, v.name);
    checked++;
  }
  t.diagnostic(`${checked} vectors equal kit's bytes`);
});

// ─── Y6: the v1 policy ──────────────────────────────────────────────────────

const base = vector('passkey-execute-1-transfer').input;
const [secp, lazorkit] = instructionsFromJson(base.instructions);
const RELAYER = payer.publicKey.toBase58();

function v1(changes = {}) {
  const { wire } = buildTxV1({
    payer: base.payer,
    blockhash: base.blockhash,
    instructions: changes.instructions ?? [secp, lazorkit],
    config: changes.config ?? base.config,
    mask: changes.mask,
  });
  return wire;
}

function inspect(raw, { maxPriorityFeeLamports = 0, relayer = RELAYER } = {}) {
  const tx = VersionedTransaction.deserialize(raw);
  return inspectTransaction(tx, { relayer, signerKey: null, maxSignatures: 4, requireLazorkit: true, raw, maxPriorityFeeLamports });
}

function refused(raw, rule, options) {
  assert.throws(
    () => inspect(raw, options),
    (e) => {
      assert.ok(e instanceof PolicyError, `a PolicyError, not ${e}`);
      assert.equal(e.code, ERR.REJECTED);
      assert.equal(e.data?.rule, rule, e.message);
      return true;
    },
  );
}

test('Y6: a well-formed passkey Execute passes, and its config is returned for the log', () => {
  const summary = inspect(v1());
  assert.deepEqual(summary.txV1, { computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840, priorityFee: 0 });
  assert.deepEqual(inspect(v1({ config: { computeUnitLimit: 1, loadedAccountsDataSizeLimit: 1 } })).txV1.priorityFee, 0);
  assert.ok(inspect(v1({ config: { computeUnitLimit: 1_400_000, loadedAccountsDataSizeLimit: 67_108_864 } })));
  // A priority fee of 0 with both fee bits set is no fee.
  assert.ok(inspect(v1({ config: { ...base.config, priorityFeeLamports: 0n } })));
});

test('Y6: every v1 shape that landed on devnet passes with its own fee payer, its fee within the cap', () => {
  let withFee = 0;
  for (const l of vectors.landed) {
    const raw = new Uint8Array(Buffer.from(l.wire, 'base64'));
    const tx = VersionedTransaction.deserialize(raw);
    const relayer = tx.message.staticAccountKeys[0].toBase58();
    const fee = tx.message.transactionConfig.priorityFee ?? 0;
    assert.equal(inspect(raw, { relayer, maxPriorityFeeLamports: fee }).txV1.priorityFee, fee, l.name);
    // Under the default cap of 0, the ones that paid a priority fee are refused.
    if (fee > 0) {
      withFee++;
      refused(raw, 'tx_v1_priority_fee', { relayer });
    }
  }
  assert.ok(withFee > 0 && withFee < vectors.landed.length);
});

test('Y6: an unset, zero or too large compute-unit limit is refused', () => {
  const lad = base.config.loadedAccountsDataSizeLimit;
  refused(v1({ config: { loadedAccountsDataSizeLimit: lad } }), 'tx_v1_compute_unit_limit');
  refused(v1({ config: { computeUnitLimit: 0, loadedAccountsDataSizeLimit: lad } }), 'tx_v1_compute_unit_limit');
  refused(v1({ config: { computeUnitLimit: 1_400_001, loadedAccountsDataSizeLimit: lad } }), 'tx_v1_compute_unit_limit');
});

test('Y6: an unset, zero or too large loaded-accounts-data limit is refused', () => {
  const cu = base.config.computeUnitLimit;
  refused(v1({ config: { computeUnitLimit: cu } }), 'tx_v1_loaded_accounts_data_size_limit');
  refused(v1({ config: { computeUnitLimit: cu, loadedAccountsDataSizeLimit: 0 } }), 'tx_v1_loaded_accounts_data_size_limit');
  refused(v1({ config: { computeUnitLimit: cu, loadedAccountsDataSizeLimit: 67_108_865 } }), 'tx_v1_loaded_accounts_data_size_limit');
  refused(v1({ config: {} }), 'tx_v1_compute_unit_limit');
});

test('Y6: a heap request is refused', () => {
  refused(v1({ config: { ...base.config, heapSize: 32 * 1024 } }), 'tx_v1_heap_size');
  refused(v1({ config: { ...base.config, heapSize: 256 * 1024 } }), 'tx_v1_heap_size');
});

test('Y6: a priority fee over the cap is refused (default cap 0)', () => {
  refused(v1({ config: { ...base.config, priorityFeeLamports: 1n } }), 'tx_v1_priority_fee');
  refused(v1({ config: { ...base.config, priorityFeeLamports: 5001n } }), 'tx_v1_priority_fee', { maxPriorityFeeLamports: 5000 });
  assert.equal(inspect(v1({ config: { ...base.config, priorityFeeLamports: 5000n } }), { maxPriorityFeeLamports: 5000 }).txV1.priorityFee, 5000);
});

test('Y6: the priority fee is read from the bytes as a u64, past where web3.js 1.99 can decode it', () => {
  const config = { computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840 };
  assert.equal(txV1PriorityFee(v1({ config })), null, 'no fee bits');
  for (const fee of [0n, 1n, 5000n, 2n ** 53n - 1n, 2n ** 53n, 2n ** 64n - 1n]) {
    const raw = v1({ config: { ...config, priorityFeeLamports: fee } });
    assert.equal(txV1PriorityFee(raw), fee, String(fee));
    assert.equal(txV1PriorityFee(Buffer.from(raw)), fee, `${fee}, as a Buffer`);
  }
  // After 64 addresses too: the fee is the first config value, right after them.
  const v = vector('execute-64-addresses');
  const wide = buildTxV1({ ...v.input, config: { ...v.input.config, priorityFeeLamports: 2n ** 64n - 2n }, instructions: instructionsFromJson(v.input.instructions) }).wire;
  assert.equal(wide[41], 64);
  assert.equal(txV1PriorityFee(wide), 2n ** 64n - 2n);
  // web3.js 1.99 cannot decode the fee past 2^53 - 1; the cluster takes any u64.
  assert.equal(VersionedTransaction.deserialize(v1({ config: { ...config, priorityFeeLamports: 2n ** 53n - 1n } })).message.transactionConfig.priorityFee, 2 ** 53 - 1);
  assert.throws(() => VersionedTransaction.deserialize(v1({ config: { ...config, priorityFeeLamports: 2n ** 53n } })), /safe integer range/);
  // A single fee bit, bytes that end before the fee, not v1: no fee.
  assert.equal(txV1PriorityFee(v1({ config: { ...config, priorityFeeLamports: 7n }, mask: 0b01101 })), null);
  assert.equal(txV1PriorityFee(v1({ config: { ...config, priorityFeeLamports: 7n } }).subarray(0, 42 + 32 * 2 + 7)), null);
  assert.equal(txV1PriorityFee(Uint8Array.of(0x80, 1, 0, 0, 3, 0, 0, 0)), null);
});

test('Y6: the fee rule takes a bigint fee, and refuses one over the cap with JSON-safe data', () => {
  assert.doesNotThrow(() => checkTxV1PriorityFee(null, 0));
  assert.doesNotThrow(() => checkTxV1PriorityFee(0, 0));
  assert.doesNotThrow(() => checkTxV1PriorityFee(5000n, 5000));
  for (const [fee, cap, shown] of [
    [1, 0, 1],
    [5001n, 5000, 5001],
    [2n ** 53n, Number.MAX_SAFE_INTEGER, '9007199254740992'],
    [2n ** 64n - 1n, 0, '18446744073709551615'],
  ]) {
    assert.throws(
      () => checkTxV1PriorityFee(fee, cap),
      (e) => {
        assert.ok(e instanceof PolicyError);
        assert.equal(e.code, ERR.REJECTED);
        assert.deepEqual(e.data, { rule: 'tx_v1_priority_fee', priorityFee: shown, maxPriorityFeeLamports: cap });
        assert.doesNotThrow(() => JSON.stringify(e.data));
        assert.match(e.message, new RegExp(`pays a priority fee of ${fee} lamports?, over this relayer's cap of ${cap} \\(--max-priority-fee-lamports\\)`));
        return true;
      },
      String(fee),
    );
  }
});

test('Y6: any top-level ComputeBudget instruction is refused', () => {
  const cu = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 });
  refused(v1({ instructions: [cu, secp, lazorkit] }), 'tx_v1_compute_budget_instruction');
  refused(v1({ instructions: [secp, lazorkit, ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 })] }), 'tx_v1_compute_budget_instruction');
  refused(v1({ instructions: [ComputeBudgetProgram.requestHeapFrame({ bytes: 64 * 1024 }), secp, lazorkit] }), 'tx_v1_compute_budget_instruction');
  // Between the precompile and its LazorKit instruction (Custom 3003 on chain).
  refused(v1({ instructions: [secp, cu, lazorkit] }), 'tx_v1_compute_budget_instruction');
});

test('Y6: a Secp256r1 instruction not followed directly by LazorKit v2 is refused', () => {
  const transfer = SystemProgram.transfer({ fromPubkey: testKey('signer-1').publicKey, toPubkey: testKey('signer-2').publicKey, lamports: 1 });
  refused(v1({ instructions: [lazorkit, secp] }), 'tx_v1_precompile_order');
  refused(v1({ instructions: [secp, transfer, lazorkit] }), 'tx_v1_precompile_order');
  refused(v1({ instructions: [secp, secp, lazorkit] }), 'tx_v1_precompile_order');
  // Two precompile + LazorKit pairs are fine.
  assert.ok(inspect(v1({ instructions: [secp, lazorkit, secp, lazorkit] })));
});

test('Y6: over 4,096 bytes or 64 addresses is refused', () => {
  for (const [name, what] of [
    ['over-4097-bytes', 'bytes'],
    ['over-65-addresses', 'addresses'],
  ]) {
    const v = vector(name);
    const { wire } = buildTxV1({ ...v.input, instructions: instructionsFromJson(v.input.instructions) });
    assert.equal(wire.length, v.expected.bytes);
    assert.throws(
      () => inspect(wire),
      (e) => e instanceof PolicyError && e.data?.rule === 'tx_v1_size' && e.data[what] === v.expected[what],
      name,
    );
  }
});

test('Y6: a fee payer that is not a writable signer is refused', () => {
  const raw = v1();
  raw[2] = 1; // numReadonlySignedAccounts = numRequiredSignatures: the fee payer read-only
  refused(raw, 'fee_payer');
});

test('Y1: web3.js 1.99 refuses a single fee bit or an unknown config bit at decode', () => {
  assert.throws(() => VersionedTransaction.deserialize(v1({ mask: 0b01101 })), /priority fee bits/);
  assert.throws(() => VersionedTransaction.deserialize(v1({ mask: 0b101100 })), /Unexpected bits/);
});

test('inspectTxV1 holds its rules on its own too', () => {
  const raw = v1({ config: { computeUnitLimit: 5 } });
  assert.throws(() => inspectTxV1(VersionedTransaction.deserialize(raw), raw), (e) => e.data?.rule === 'tx_v1_loaded_accounts_data_size_limit');
  assert.throws(() => inspectTxV1(VersionedTransaction.deserialize(v1()), undefined), (e) => e.data?.rule === 'tx_v1_size');
});

test('legacy and v0 are untouched by the v1 rules', () => {
  const ixs = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 5 }),
    lazorkit,
    secp, // a precompile last: refused in v1, not a v0 rule
  ];
  const v0 = new VersionedTransaction(new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: base.blockhash, instructions: ixs }).compileToV0Message());
  const summary = inspectTransaction(v0, { relayer: RELAYER, signerKey: null, maxSignatures: 4, requireLazorkit: true });
  assert.equal(summary.version, 0);
  assert.equal(summary.txV1, undefined);
  assert.deepEqual(summary.programs, [COMPUTE_BUDGET_PROGRAM, COMPUTE_BUDGET_PROGRAM, LAZORKIT_V2_DEVNET, SECP256R1_PROGRAM]);

  const legacy = new Transaction().add(...ixs);
  legacy.feePayer = payer.publicKey;
  legacy.recentBlockhash = base.blockhash;
  const decoded = VersionedTransaction.deserialize(legacy.serialize({ requireAllSignatures: false, verifySignatures: false }));
  assert.equal(inspectTransaction(decoded, { relayer: RELAYER, signerKey: null, maxSignatures: 4, requireLazorkit: true }).version, 'legacy');
  assert.equal(isTxV1(legacy.serialize({ requireAllSignatures: false, verifySignatures: false })), false);
  assert.equal(new PublicKey(RELAYER).toBase58(), RELAYER);
});
