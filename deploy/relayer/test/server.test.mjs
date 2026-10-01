// U13, offline: the relayer process end to end, against a stub JSON-RPC node
// (test/helpers/relayer.mjs). Its fee payer is the vectors' test key "payer",
// so the vectors' transactions are addressed to it.
//
// - Y7: without --tx-v1, a v1 transaction is answered -32051 and the relayer
//   makes no RPC call for it at all.
// - Y6: with --tx-v1, every v1 refusal comes before the balance read, the
//   simulation and the signature: no RPC call either.
// - Y1-Y5: a v1 transaction is simulated as received, signed at the byte level
//   (the wallet writer's bytes), sent as those bytes, and a resend of bytes
//   that already landed is answered with the landed signature.
// - Legacy and v0 come back and go out byte for byte as web3.js signs them,
//   with --tx-v1 on or off.
// - Mainnet is refused at startup.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import bs58 from 'bs58';
import { ComputeBudgetProgram, SystemProgram, Transaction, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import { buildTxV1, instructionsFromJson } from '../scripts/txv1-build.mjs';
import { signTxV1AsFeePayer, txV1Signature } from '../src/txv1.mjs';
import { fitting, fullySigned, testKey, vector, walletSent } from './helpers/vectors.mjs';
import { call, MAINNET_GENESIS, runRelayerToExit, startRelayer, startStubRpc, writeKeypair } from './helpers/relayer.mjs';

const payer = testKey('payer');
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const SIGNING_RPC = ['getBalance', 'simulateTransaction', 'sendTransaction'];

const base = vector('passkey-execute-1-transfer');
const [secp, lazorkit] = instructionsFromJson(base.input.instructions);
const v1 = (config, instructions = [secp, lazorkit]) =>
  buildTxV1({ payer: base.input.payer, blockhash: base.input.blockhash, instructions, config }).wire;

// Legacy and v0 the way the wallets build them: a ComputeBudget limit, then the payload.
const legacyAndV0 = () => {
  const ixs = [ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }), secp, lazorkit];
  const legacy = new Transaction().add(...ixs);
  legacy.feePayer = payer.publicKey;
  legacy.recentBlockhash = base.input.blockhash;
  const v0 = new VersionedTransaction(new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: base.input.blockhash, instructions: ixs }).compileToV0Message());
  return [
    ['legacy', new Uint8Array(legacy.serialize({ requireAllSignatures: false, verifySignatures: false }))],
    ['v0', v0.serialize()],
  ];
};
// What the relayer must return for legacy/v0: web3.js's own signature as fee payer.
const web3Signed = (raw) => {
  const tx = VersionedTransaction.deserialize(raw);
  tx.sign([payer]);
  return tx.serialize();
};

let keypair;
before(() => {
  keypair = writeKeypair(payer);
});
after(() => keypair?.remove());

describe('without --tx-v1', () => {
  let stub;
  let relayer;
  before(async () => {
    stub = await startStubRpc();
    relayer = await startRelayer({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--any-cluster'] });
  });
  after(async () => {
    await relayer?.stop();
    await stub?.close();
  });

  test('Y7: a v1 transaction is refused with -32051, before any RPC call', async () => {
    for (const method of ['signTransaction', 'signAndSendTransaction']) {
      for (const raw of [walletSent(base), Uint8Array.of(0x81, 0xff, 0x00)]) {
        const mark = stub.calls.length;
        const body = await call(relayer.url, method, { transaction: b64(raw), signer_key: payer.publicKey.toBase58() });
        assert.equal(body.error?.code, -32051, JSON.stringify(body));
        assert.equal(body.error.message, 'transaction version 1 is not enabled on this paymaster');
        assert.equal(body.error.data?.rule, 'tx_v1_disabled');
        assert.equal(body.result, undefined);
        assert.deepEqual(stub.since(mark), [], `${method}: no RPC call`);
      }
    }
    assert.equal(stub.sent.length, 0);
    assert.match(relayer.output(), /signAndSendTransaction {2}v1 {2}REJECTED {2}transaction version 1 is not enabled on this paymaster/);
  });

  test('/health and the banner say v1 is off', async () => {
    const health = await (await fetch(`${relayer.url}/health`)).json();
    assert.equal(health.tx_v1, false);
    assert.equal(health.max_priority_fee_lamports, 0);
    assert.match(relayer.output(), /tx v1 {8}off: v1 transactions are refused with -32051/);
  });

  test('legacy and v0 are signed and sent byte for byte as web3.js signs them', async () => {
    for (const [name, raw] of legacyAndV0()) {
      const expected = web3Signed(raw);
      const signed = await call(relayer.url, 'signTransaction', { transaction: b64(raw) });
      assert.equal(signed.result?.signed_transaction, b64(expected), name);
      const sentBefore = stub.sent.length;
      const sent = await call(relayer.url, 'signAndSendTransaction', { transaction: b64(raw), signer_key: payer.publicKey.toBase58() });
      assert.equal(sent.result?.signed_transaction, b64(expected), name);
      assert.equal(sent.result.signature, bs58.encode(VersionedTransaction.deserialize(expected).signatures[0]), name);
      assert.deepEqual(stub.sent.slice(sentBefore).map((s) => b64(s.raw)), [b64(expected)], `${name}: sent once, as signed`);
    }
  });
});

describe('with --tx-v1', () => {
  let stub;
  let relayer;
  before(async () => {
    stub = await startStubRpc();
    relayer = await startRelayer({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--any-cluster', '--tx-v1'] });
  });
  after(async () => {
    await relayer?.stop();
    await stub?.close();
  });

  test('/health and the banner say v1 is on, with a priority-fee cap of 0', async () => {
    const health = await (await fetch(`${relayer.url}/health`)).json();
    assert.equal(health.tx_v1, true);
    assert.equal(health.max_priority_fee_lamports, 0);
    assert.match(relayer.output(), /tx v1 {8}on \(--tx-v1\): compute-unit and loaded-data limits required, priority fee at most 0 lamports/);
  });

  test('Y1-Y3: signTransaction simulates the bytes as received and returns the wallet writer\'s fully signed bytes', async () => {
    let checked = 0;
    for (const v of fitting()) {
      const programs = v.input.instructions.map((ix) => ix.programId);
      // The relayer's allowlist and fee cap: the vectors that call LazorKit and pay no priority fee.
      if (!programs.includes('57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv') || v.input.config.priorityFeeLamports) continue;
      const sent = walletSent(v);
      const mark = stub.calls.length;
      const body = await call(relayer.url, 'signTransaction', { transaction: b64(sent), signer_key: payer.publicKey.toBase58() });
      assert.equal(body.result?.signed_transaction, b64(fullySigned(v)), `${v.name}: ${JSON.stringify(body.error)}`);
      const simulated = stub.calls.slice(mark).filter((c) => c.method === 'simulateTransaction');
      assert.equal(simulated.length, 1, v.name);
      assert.equal(simulated[0].params[0], b64(sent), `${v.name}: simulated as received`);
      assert.equal(simulated[0].params[1].sigVerify, false);
      assert.ok(!stub.since(mark).includes('sendTransaction'), `${v.name}: signTransaction sends nothing`);
      checked++;
    }
    assert.ok(checked >= 4, `checked ${checked} vectors`);
  });

  test('Y5, Y8: signAndSendTransaction sends exactly the signed bytes and logs the v1 config', async () => {
    const sent = walletSent(base);
    const expected = signTxV1AsFeePayer(sent, payer);
    const sentBefore = stub.sent.length;
    const body = await call(relayer.url, 'signAndSendTransaction', { transaction: b64(sent), signer_key: payer.publicKey.toBase58() });
    assert.equal(body.result?.signed_transaction, b64(expected), JSON.stringify(body.error));
    assert.equal(body.result.signature, bs58.encode(txV1Signature(expected, 0)));
    assert.deepEqual(stub.sent.slice(sentBefore).map((s) => b64(s.raw)), [b64(expected)], 'sent once, as signed');
    assert.match(relayer.output(), new RegExp(`signAndSendTransaction {2}v1 cu=60000 lad=163840 fee=0 {2}\\[Secp256r1, LazorKit v2\\].*CONFIRMED ${body.result.signature}`));
  });

  test('Y4: bytes that already landed are answered with the landed signature, and nothing is sent', async () => {
    const sent = walletSent(vector('authorize-tx1'));
    const signature = bs58.encode(txV1Signature(signTxV1AsFeePayer(sent, payer), 0));
    stub.landed.set(signature, { slot: 999, err: null });
    stub.simulate = (tx) => (tx === b64(sent) ? { result: { context: { slot: stub.slot }, value: { err: 'AlreadyProcessed', logs: [], accounts: null, unitsConsumed: 0 } } } : null);
    try {
      const sentBefore = stub.sent.length;
      const body = await call(relayer.url, 'signAndSendTransaction', { transaction: b64(sent), signer_key: payer.publicKey.toBase58() });
      assert.equal(body.result?.signature, signature, JSON.stringify(body.error));
      assert.equal(stub.sent.length, sentBefore, 'nothing sent again');
      assert.match(relayer.output(), new RegExp(`CONFIRMED ${signature} .*a resend of bytes that had landed`));
    } finally {
      stub.simulate = null;
    }
  });

  test('Y6: every v1 refusal comes before the balance read, the simulation and the signature', async () => {
    const lad = 163_840;
    const cu = 60_000;
    const transfer = SystemProgram.transfer({ fromPubkey: testKey('signer-1').publicKey, toPubkey: testKey('signer-2').publicKey, lamports: 1 });
    const over = (name) => {
      const v = vector(name);
      return buildTxV1({ ...v.input, instructions: instructionsFromJson(v.input.instructions) }).wire;
    };
    const cases = [
      ['compute-unit limit unset', v1({ loadedAccountsDataSizeLimit: lad }), 'tx_v1_compute_unit_limit'],
      ['compute-unit limit 0', v1({ computeUnitLimit: 0, loadedAccountsDataSizeLimit: lad }), 'tx_v1_compute_unit_limit'],
      ['compute-unit limit 1,400,001', v1({ computeUnitLimit: 1_400_001, loadedAccountsDataSizeLimit: lad }), 'tx_v1_compute_unit_limit'],
      ['loaded-data limit unset', v1({ computeUnitLimit: cu }), 'tx_v1_loaded_accounts_data_size_limit'],
      ['loaded-data limit 0', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: 0 }), 'tx_v1_loaded_accounts_data_size_limit'],
      ['loaded-data limit over 64 MiB', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: 67_108_865 }), 'tx_v1_loaded_accounts_data_size_limit'],
      ['heap request', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: lad, heapSize: 65_536 }), 'tx_v1_heap_size'],
      ['priority fee 1 (cap 0)', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: lad, priorityFeeLamports: 1n }), 'tx_v1_priority_fee'],
      ['ComputeBudget instruction', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: lad }, [ComputeBudgetProgram.setComputeUnitLimit({ units: cu }), secp, lazorkit]), 'tx_v1_compute_budget_instruction'],
      ['Secp256r1 then System', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: lad }, [secp, transfer, lazorkit]), 'tx_v1_precompile_order'],
      ['Secp256r1 last', v1({ computeUnitLimit: cu, loadedAccountsDataSizeLimit: lad }, [lazorkit, secp]), 'tx_v1_precompile_order'],
      ['4,097 bytes', over('over-4097-bytes'), 'tx_v1_size'],
      ['65 addresses', over('over-65-addresses'), 'tx_v1_size'],
    ];
    for (const method of ['signTransaction', 'signAndSendTransaction']) {
      for (const [name, raw, rule] of cases) {
        const mark = stub.calls.length;
        const body = await call(relayer.url, method, { transaction: b64(raw), signer_key: payer.publicKey.toBase58() });
        assert.equal(body.error?.code, -32003, `${name}: ${JSON.stringify(body)}`);
        assert.equal(body.error.data?.rule, rule, `${name}: ${body.error.message}`);
        assert.deepEqual(stub.since(mark).filter((m) => SIGNING_RPC.includes(m)), [], `${method}, ${name}: refused before any RPC call`);
      }
    }
    assert.match(relayer.output(), /v1 cu=unset lad=163840 fee=0 {2}\[Secp256r1, LazorKit v2\] {2}REJECTED {2}relayer rejected: the v1 transaction sets no compute-unit limit/);
  });

  test('Y6: a priority fee over 2^53 - 1 is refused by the fee rule (-32003), not as undecodable, before any RPC call', async () => {
    // web3.js 1.99 decodes the fee as a Number and throws past 2^53 - 1; the
    // cluster takes any u64. The relayer reads such a fee from the bytes.
    const config = { computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840 };
    for (const fee of [2n ** 53n - 1n, 2n ** 53n, 2n ** 64n - 1n]) {
      for (const method of ['signTransaction', 'signAndSendTransaction']) {
        const mark = stub.calls.length;
        const body = await call(relayer.url, method, { transaction: b64(v1({ ...config, priorityFeeLamports: fee })), signer_key: payer.publicKey.toBase58() });
        assert.equal(body.error?.code, -32003, `${fee}: ${JSON.stringify(body)}`);
        assert.equal(body.error.data?.rule, 'tx_v1_priority_fee', `${fee}: ${body.error.message}`);
        assert.equal(String(body.error.data.priorityFee), String(fee));
        assert.equal(body.error.data.maxPriorityFeeLamports, 0);
        assert.match(body.error.message, new RegExp(`pays a priority fee of ${fee} lamports, over this relayer's cap of 0`));
        assert.deepEqual(stub.since(mark), [], `${method}, fee ${fee}: refused before any RPC call`);
      }
    }
    assert.match(relayer.output(), /signAndSendTransaction {2}v1 {2}REJECTED {2}relayer rejected: the v1 transaction pays a priority fee of 18446744073709551615 lamports/);
  });

  test('Y1: a single fee bit is refused at decode (-32602), before any RPC call', async () => {
    const raw = v1({ computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840 });
    raw[4] |= 0b1; // bit 0 without bit 1
    const mark = stub.calls.length;
    const body = await call(relayer.url, 'signAndSendTransaction', { transaction: b64(raw) });
    assert.equal(body.error?.code, -32602, JSON.stringify(body));
    assert.deepEqual(stub.since(mark), []);
  });

  test('legacy and v0 are signed and sent byte for byte as web3.js signs them', async () => {
    for (const [name, raw] of legacyAndV0()) {
      const expected = web3Signed(raw);
      const signed = await call(relayer.url, 'signTransaction', { transaction: b64(raw) });
      assert.equal(signed.result?.signed_transaction, b64(expected), name);
      const sentBefore = stub.sent.length;
      const sent = await call(relayer.url, 'signAndSendTransaction', { transaction: b64(raw), signer_key: payer.publicKey.toBase58() });
      assert.equal(sent.result?.signed_transaction, b64(expected), name);
      assert.deepEqual(stub.sent.slice(sentBefore).map((s) => b64(s.raw)), [b64(expected)], `${name}: sent once, as signed`);
    }
  });
});

describe('--max-priority-fee-lamports', () => {
  test('a v1 priority fee up to the cap is signed, one lamport over is refused', async () => {
    const stub = await startStubRpc();
    const relayer = await startRelayer({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--any-cluster', '--tx-v1', '--max-priority-fee-lamports', '5000'] });
    try {
      const config = { computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840 };
      const at = await call(relayer.url, 'signTransaction', { transaction: b64(v1({ ...config, priorityFeeLamports: 5000n })) });
      assert.ok(at.result?.signed_transaction, JSON.stringify(at.error));
      const over = await call(relayer.url, 'signTransaction', { transaction: b64(v1({ ...config, priorityFeeLamports: 5001n })) });
      assert.equal(over.error?.data?.rule, 'tx_v1_priority_fee');
      assert.match(relayer.output(), /v1 cu=60000 lad=163840 fee=5000 {2}\[Secp256r1, LazorKit v2\].*SIGNED/);
    } finally {
      await relayer.stop();
      await stub.close();
    }
  });

  test('at the largest cap, 2^53 - 1, that fee is signed and 2^53 is refused by the fee rule', async () => {
    const stub = await startStubRpc();
    const cap = Number.MAX_SAFE_INTEGER;
    const relayer = await startRelayer({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--any-cluster', '--tx-v1', '--max-priority-fee-lamports', String(cap)] });
    try {
      const config = { computeUnitLimit: 60_000, loadedAccountsDataSizeLimit: 163_840 };
      const at = await call(relayer.url, 'signTransaction', { transaction: b64(v1({ ...config, priorityFeeLamports: BigInt(cap) })) });
      assert.ok(at.result?.signed_transaction, JSON.stringify(at.error));
      const mark = stub.calls.length;
      const over = await call(relayer.url, 'signTransaction', { transaction: b64(v1({ ...config, priorityFeeLamports: BigInt(cap) + 1n })) });
      assert.equal(over.error?.code, -32003, JSON.stringify(over));
      assert.equal(over.error.data?.rule, 'tx_v1_priority_fee');
      assert.equal(over.error.data.priorityFee, '9007199254740992');
      assert.equal(over.error.data.maxPriorityFeeLamports, cap);
      assert.deepEqual(stub.since(mark), [], 'refused before any RPC call');
    } finally {
      await relayer.stop();
      await stub.close();
    }
  });
});

describe('startup', () => {
  test('mainnet is refused, with or without --tx-v1 and --any-cluster', async () => {
    const stub = await startStubRpc({ genesis: MAINNET_GENESIS });
    try {
      for (const args of [[], ['--tx-v1'], ['--any-cluster', '--tx-v1']]) {
        const { code, output } = await runRelayerToExit({ rpcUrl: stub.url, keypairFile: keypair.file, args });
        assert.equal(code, 1, `${args.join(' ')}: ${output}`);
        assert.match(output, /is mainnet\. This relayer is for devnet only\./);
        assert.doesNotMatch(output, /listening/);
      }
      assert.ok(stub.calls.every((c) => c.method === 'getGenesisHash'), 'nothing but the genesis hash was read');
    } finally {
      await stub.close();
    }
  });

  test('a cluster that is not devnet needs --any-cluster', async () => {
    const stub = await startStubRpc();
    try {
      const { code, output } = await runRelayerToExit({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--tx-v1'] });
      assert.equal(code, 1, output);
      assert.match(output, /is not devnet/);
    } finally {
      await stub.close();
    }
  });

  test('--max-priority-fee-lamports must be a non-negative integer', async () => {
    const stub = await startStubRpc();
    try {
      const { code, output } = await runRelayerToExit({ rpcUrl: stub.url, keypairFile: keypair.file, args: ['--any-cluster', '--tx-v1', '--max-priority-fee-lamports', '1.5'] });
      assert.equal(code, 1, output);
      assert.match(output, /--max-priority-fee-lamports must be a non-negative integer/);
    } finally {
      await stub.close();
    }
  });
});
