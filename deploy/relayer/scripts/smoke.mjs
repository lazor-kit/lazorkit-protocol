#!/usr/bin/env node
// Smoke test for a running relayer: every JSON-RPC method, one real sponsored
// transaction on devnet, and one rejection per policy rule.
//
//   npm run smoke                               # against http://127.0.0.1:8787
//   npm run smoke -- --url http://192.168.1.5:8787
//   npm run smoke -- --skip-send                # sign only, spend nothing
//
// By default the relayer requires LazorKit v2 in every transaction, so the plain
// transfer below is expected to be REFUSED. Start the relayer with --allow-plain
// to see it signed and landed instead.
//
// The allowed transaction is ComputeBudget + System transfer to a fresh address.
// It moves the rent-exempt minimum for a 0-byte account, not 1 lamport: a new
// account holding 1 lamport fails on-chain with InsufficientFundsForRent. The
// 1-lamport case is kept below as a rejection, caught by the relayer's simulation.

import crypto from 'node:crypto';
import http from 'node:http';
import { parseArgs } from 'node:util';
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';

const { values: opt } = parseArgs({
  options: {
    url: { type: 'string', default: 'http://127.0.0.1:8787' },
    rpc: { type: 'string', default: 'https://api.devnet.solana.com' },
    'skip-send': { type: 'boolean', default: false },
    'api-key': { type: 'string' },
  },
});

const URL_ = opt.url.replace(/\/$/, '');
const conn = new Connection(opt.rpc, 'confirmed');
const results = [];

async function rpc(method, params, extraHeaders = {}) {
  const headers = { 'content-type': 'application/json', ...extraHeaders };
  if (opt['api-key']) headers['x-api-key'] = opt['api-key'];
  const r = await fetch(URL_, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return { status: r.status, body: await r.json() };
}

function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? `\n      ${detail}` : ''}`);
}

function verifyEd25519(pubkey, message, signature) {
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pubkey)]);
  const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
}

const b64v0 = (tx) => Buffer.from(tx.serialize()).toString('base64');
const b64legacy = (tx) => tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');

// ─── Status + plain methods ─────────────────────────────────────────────────
const health = await (await fetch(`${URL_}/health`)).json();
record('GET /health', health.ok === true && typeof health.relayer === 'string', `relayer ${health.relayer}, balance ${health.balance_lamports} lamports, require_lazorkit=${health.require_lazorkit}`);
const strict = Boolean(health.require_lazorkit);

{
  const r = await fetch(URL_, {
    method: 'OPTIONS',
    headers: {
      Origin: 'http://localhost:5173',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,x-api-key',
      'Access-Control-Request-Private-Network': 'true',
    },
  });
  const h = (k) => r.headers.get(k);
  record(
    'CORS preflight from the local dev app (http://localhost:5173)',
    r.status === 204 && !!h('access-control-allow-origin') && /x-api-key/.test(h('access-control-allow-headers') ?? '') && h('access-control-allow-private-network') === 'true',
    `status ${r.status}, allow-origin ${h('access-control-allow-origin')}, allow-headers ${h('access-control-allow-headers')}, private-network ${h('access-control-allow-private-network')}`,
  );
}
{
  // A page on the internet must not get past the preflight (unless --cors-origin '*').
  const r = await fetch(URL_, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://evil.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
      'Access-Control-Request-Private-Network': 'true',
    },
  });
  const acao = r.headers.get('access-control-allow-origin');
  const pna = r.headers.get('access-control-allow-private-network');
  if (health.cors === '*') {
    record('CORS preflight from a public origin (--cors-origin * -> allowed)', acao === '*', `allow-origin ${acao}`);
  } else {
    record('CORS preflight from a public origin (https://evil.example) -> refused', !acao && !pna, `allow-origin ${acao}, private-network ${pna}`);
  }
}
{
  // The no-preflight "simple request" a browser sends from any page.
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { 'content-type': 'text/plain;charset=UTF-8', Origin: 'https://evil.example' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getPayerSigner', params: [] }),
  });
  const body = await r.json();
  record('POST with content-type text/plain -> 415', r.status === 415 && !body.result, `status ${r.status}, ${body.error?.message ?? JSON.stringify(body)}`);
}
{
  // DNS rebinding: same bytes, but a Host this relayer does not listen on.
  const u = new URL(URL_);
  const r = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || 80, path: '/health', method: 'GET', headers: { Host: `rebind.evil.example:${u.port || 80}` } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, data }));
      },
    );
    req.on('error', reject);
    req.end();
  });
  record('request with a foreign Host header (DNS rebinding) -> 421', r.status === 421 && !r.data.includes('"relayer"'), `status ${r.status}`);
}

const ps = await rpc('getPayerSigner', []);
const relayerAddr = ps.body.result?.signer_address;
record('getPayerSigner', relayerAddr === health.relayer && ps.body.result?.payment_address === relayerAddr, JSON.stringify(ps.body.result ?? ps.body.error));
const relayer = new PublicKey(relayerAddr);

const bh = await rpc('getBlockhash', []);
const blockhash = bh.body.result?.blockhash;
record('getBlockhash', typeof blockhash === 'string' && new PublicKey(blockhash).toBytes().length === 32, JSON.stringify(bh.body.result ?? bh.body.error));

{
  const r = await rpc('transferTransaction', {});
  record('unknown method -> -32601', r.body.error?.code === -32601, r.body.error?.message);
}
{
  const r = await rpc('signTransaction', { tx: 'nope' });
  record('bad params -> -32602', r.body.error?.code === -32602, r.body.error?.message);
}
{
  // Checked before anything is signed or counted against the rate limit.
  const r = await rpc('signAndSendTransaction', { transaction: 'AA==', respond_after: 'whenever' });
  record('respond_after outside confirmed|sent|signed -> -32602', r.body.error?.code === -32602 && /respond_after/.test(r.body.error?.message ?? ''), r.body.error?.message);
}

// ─── Builders ───────────────────────────────────────────────────────────────
const rentMin = await conn.getMinimumBalanceForRentExemption(0);
const cu = () => ComputeBudgetProgram.setComputeUnitLimit({ units: 20_000 });
const v0 = (payerKey, ixs) =>
  new VersionedTransaction(new TransactionMessage({ payerKey, recentBlockhash: blockhash, instructions: ixs }).compileToV0Message());

// ─── Allowed: signTransaction (legacy, the shape the web Paymaster.sign uses) ─
{
  const dest = Keypair.generate().publicKey;
  const tx = new Transaction().add(cu(), SystemProgram.transfer({ fromPubkey: relayer, toPubkey: dest, lamports: rentMin }));
  tx.feePayer = relayer;
  tx.recentBlockhash = blockhash;
  const r = await rpc('signTransaction', { transaction: b64legacy(tx), signer_key: relayerAddr });
  if (strict) {
    record('signTransaction: CB + transfer (LazorKit required, the default -> rejected)', r.body.error?.data?.rule === 'require_one_of_programs', r.body.error?.message);
  } else {
    let ok = false;
    let detail = r.body.error?.message;
    if (r.body.result) {
      const signed = VersionedTransaction.deserialize(Buffer.from(r.body.result.signed_transaction, 'base64'));
      ok =
        signed.version === 'legacy' &&
        r.body.result.signer_pubkey === relayerAddr &&
        verifyEd25519(relayer.toBytes(), signed.message.serialize(), signed.signatures[0]);
      detail = `returned a ${signed.version} tx with a valid relayer signature: ${ok}`;
    }
    record('signTransaction: CB + transfer (--allow-plain: signed, not sent)', ok, detail);
  }
}

// ─── Allowed: signAndSendTransaction (v0 + signer_key, like both packages) ───
if (!opt['skip-send'] && !strict) {
  const dest = Keypair.generate().publicKey;
  const tx = v0(relayer, [cu(), SystemProgram.transfer({ fromPubkey: relayer, toPubkey: dest, lamports: rentMin })]);
  const r = await rpc('signAndSendTransaction', { transaction: b64v0(tx), signer_key: relayerAddr });
  const sig = r.body.result?.signature;
  let landed = false;
  let bal = null;
  if (sig) {
    // The relayer answers only once the transaction is confirmed (respond_after
    // 'confirmed', the default), so the status is already there, with no polling.
    const st = (await conn.getSignatureStatuses([sig])).value[0];
    record(
      'signAndSendTransaction answered after confirmation (status confirmed at return)',
      !st?.err && (st?.confirmationStatus === 'confirmed' || st?.confirmationStatus === 'finalized'),
      `status at return: ${st ? `${st.confirmationStatus}, slot ${st.slot}` : 'not found'}`,
    );
    for (let i = 0; i < 40 && !landed; i++) {
      await new Promise((res) => setTimeout(res, 1500));
      const st = (await conn.getSignatureStatuses([sig])).value[0];
      if (st?.err) break;
      landed = st?.confirmationStatus === 'confirmed' || st?.confirmationStatus === 'finalized';
    }
    bal = await conn.getBalance(dest, 'confirmed');
  }
  record(
    'signAndSendTransaction: CB + transfer to fresh address (--allow-plain: landed on devnet)',
    landed && bal === rentMin,
    sig ? `signature ${sig}\n      destination ${dest.toBase58()} balance ${bal} (expected ${rentMin})` : r.body.error?.message,
  );
  if (landed) {
    // The same bytes again, as a client resends them when it never got the answer:
    // answered with the signature that landed, and nothing is sent again.
    const again = await rpc('signAndSendTransaction', { transaction: b64v0(tx), signer_key: relayerAddr });
    const bal2 = await conn.getBalance(dest, 'confirmed');
    record(
      'signAndSendTransaction: the same bytes again after they landed -> the same signature, nothing sent again',
      again.body.result?.signature === sig && bal2 === rentMin,
      again.body.result ? `signature ${again.body.result.signature}, destination balance ${bal2}` : again.body.error?.message,
    );
  }
}

// ─── Rejections ─────────────────────────────────────────────────────────────
async function expectReject(name, method, params, rule) {
  const r = await rpc(method, params);
  // Checks that run after the static ones (simulation, lamport cap) are pre-empted by
  // require_one_of_programs when LazorKit is required (the default).
  const want = strict && ['simulation', 'max_allowed_lamports'].includes(rule) ? 'require_one_of_programs' : rule;
  const got = r.body.error?.data?.rule;
  record(`${name} -> rejected (${want})`, !r.body.result && got === want, r.body.error ? r.body.error.message : `NOT REJECTED: ${JSON.stringify(r.body.result)}`);
}

{
  const dest = Keypair.generate().publicKey;
  const tx = v0(relayer, [cu(), SystemProgram.transfer({ fromPubkey: relayer, toPubkey: dest, lamports: 1 })]);
  await expectReject('1 lamport to a fresh address (fails rent check in simulation)', 'signAndSendTransaction', { transaction: b64v0(tx), signer_key: relayerAddr }, 'simulation');
}
{
  const memo = new TransactionInstruction({
    programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
    keys: [],
    data: Buffer.from('hello from the relayer smoke test'),
  });
  const tx = v0(relayer, [cu(), memo]);
  await expectReject('Memo program (not in allowlist)', 'signAndSendTransaction', { transaction: b64v0(tx), signer_key: relayerAddr }, 'program_not_allowed');
}
{
  const v1 = new TransactionInstruction({ programId: new PublicKey('4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS'), keys: [], data: Buffer.from([0]) });
  const tx = v0(relayer, [v1]);
  await expectReject('LazorKit v1 program (not in allowlist)', 'signTransaction', { transaction: b64v0(tx) }, 'program_not_allowed');
}
{
  const other = Keypair.generate().publicKey;
  const tx = v0(other, [cu(), SystemProgram.transfer({ fromPubkey: other, toPubkey: relayer, lamports: rentMin })]);
  await expectReject('fee payer is not the relayer', 'signAndSendTransaction', { transaction: b64v0(tx) }, 'fee_payer');
}
{
  const tx = v0(relayer, [cu(), SystemProgram.transfer({ fromPubkey: relayer, toPubkey: Keypair.generate().publicKey, lamports: rentMin })]);
  await expectReject('signer_key is not the relayer', 'signTransaction', { transaction: b64v0(tx), signer_key: Keypair.generate().publicKey.toBase58() }, 'signer_key');
}
{
  const tx = v0(relayer, [cu(), SystemProgram.transfer({ fromPubkey: relayer, toPubkey: Keypair.generate().publicKey, lamports: 100_000_000 })]);
  await expectReject('0.1 SOL out of the fee payer (over the lamport cap)', 'signTransaction', { transaction: b64v0(tx) }, 'max_allowed_lamports');
}
{
  const tx = v0(relayer, [SystemProgram.assign({ accountPubkey: relayer, programId: Keypair.generate().publicKey })]);
  await expectReject('System Assign on the fee payer', 'signTransaction', { transaction: b64v0(tx) }, 'fee_payer_policy');
}
{
  const nonce = Keypair.generate().publicKey;
  const tx = v0(relayer, [
    SystemProgram.nonceAdvance({ noncePubkey: nonce, authorizedPubkey: Keypair.generate().publicKey }),
    SystemProgram.transfer({ fromPubkey: relayer, toPubkey: nonce, lamports: rentMin }),
  ]);
  await expectReject('durable-nonce transaction', 'signTransaction', { transaction: b64v0(tx) }, 'durable_nonce');
}
{
  // SPL Token Transfer with the fee payer as the token authority.
  const tokenTransfer = new TransactionInstruction({
    programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
    keys: [
      { pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true },
      { pubkey: Keypair.generate().publicKey, isSigner: false, isWritable: true },
      { pubkey: relayer, isSigner: true, isWritable: false },
    ],
    data: Buffer.from([3, 1, 0, 0, 0, 0, 0, 0, 0]),
  });
  const tx = v0(relayer, [tokenTransfer]);
  await expectReject('SPL Token transfer with the fee payer as authority', 'signTransaction', { transaction: b64v0(tx) }, 'fee_payer_policy');
}

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed${failed.length ? ` — FAILED: ${failed.map((f) => f.name).join('; ')}` : ''}`);
process.exit(failed.length ? 1 : 0);
