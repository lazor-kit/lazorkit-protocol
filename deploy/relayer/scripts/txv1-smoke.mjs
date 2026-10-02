#!/usr/bin/env node
// SIMD-0385 v1 transactions through a running relayer, on a real cluster.
//
//   npm run smoke:txv1                                           # http://127.0.0.1:8787, devnet
//   npm run smoke:txv1 -- --url http://127.0.0.1:18787 --rpc http://127.0.0.1:18899   # a local validator
//
// Relayer started WITHOUT --tx-v1: a v1 transaction must be refused with
// -32051, and the fee payer's balance must not move. That is all it checks.
//
// Relayer started WITH --tx-v1 (and the default --max-priority-fee-lamports 0):
//   1. Every v1 refusal: limits unset, 0 or too large, a heap request, a
//      priority fee, a ComputeBudget instruction, a Secp256r1 instruction not
//      followed by LazorKit, 4,097 bytes. Each is refused before anything is
//      signed: the fee payer's balance does not move.
//   2. CreateWallet for a passkey owner, with a System transfer into the vault
//      (a legacy transaction, as the wallets send it).
//   3. A passkey Execute (vault -> fresh address) as a v1 transaction: no
//      ComputeBudget instruction, the limits in its config, sized from one
//      simulation the way the wallets size them. It must land, and read back as
//      version 1 with that config and a fee of 10,000 lamports (one transaction
//      signature, one precompile signature).
//   4. A second v1 Execute, prepared the moment the relayer answered for the
//      first (it reads the authority counter #3 advanced). It must land.
//   5. #3's exact bytes again: the relayer answers with #3's signature and
//      nothing moves.
//
// The passkey is a software P-256 key making WebAuthn assertions for rpId
// portal.lazor.sh, as in scripts/lazorkit-smoke.mjs. Costs the relayer about
// 0.007 SOL on devnet. The v1 transactions are built by scripts/txv1-build.mjs,
// which the tests hold to the wallets' writer byte for byte.

import crypto from 'node:crypto';
import { parseArgs } from 'node:util';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, VersionedTransaction, ComputeBudgetProgram } from '@solana/web3.js';
import { LazorKitClient, PROGRAM_ID_DEVNET } from '@lazorkit/sdk-legacy';
import { buildTxV1 } from './txv1-build.mjs';

const { values: opt } = parseArgs({
  options: {
    url: { type: 'string', default: 'http://127.0.0.1:8787' },
    rpc: { type: 'string', default: 'https://api.devnet.solana.com' },
    'api-key': { type: 'string' },
  },
});
const URL_ = opt.url.replace(/\/$/, '');
const RP_ID = 'portal.lazor.sh';
const conn = new Connection(opt.rpc, 'confirmed');
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function rpc(method, params) {
  const headers = { 'content-type': 'application/json' };
  if (opt['api-key']) headers['x-api-key'] = opt['api-key'];
  const r = await fetch(URL_, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return r.json();
}
async function rpcResult(method, params) {
  const body = await rpc(method, params);
  if (body.error) throw new Error(`${method}: ${body.error.code} ${body.error.message}`);
  return body.result;
}
// A raw cluster call: web3.js 1.99 cannot simulate a v1 transaction (it serializes it first).
async function clusterCall(method, params) {
  const r = await fetch(opt.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = await r.json();
  if (body.error) throw new Error(`${method}: ${body.error.code} ${body.error.message}`);
  return body.result;
}
function check(ok, what) {
  if (!ok) throw new Error(`FAIL  ${what}`);
  console.log(`PASS  ${what}`);
}
async function waitConfirmed(signature) {
  for (let i = 0; i < 60; i++) {
    const st = (await conn.getSignatureStatuses([signature])).value[0];
    if (st?.err) throw new Error(`${signature} failed: ${JSON.stringify(st.err)}`);
    if (st?.confirmationStatus === 'confirmed' || st?.confirmationStatus === 'finalized') return st.slot;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`${signature} not confirmed after 90 s`);
}

// ─── Software passkey (P-256), WebAuthn assertion shape ─────────────────────
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
function makePasskey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const compressed = new Uint8Array(Buffer.concat([Buffer.from([y[31] & 1 ? 0x03 : 0x02]), x]));
  return { privateKey, compressed, credentialIdHash: new Uint8Array(sha256(crypto.randomBytes(16))) };
}
function webauthnGet(key, challenge) {
  const authenticatorData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x05]), Buffer.alloc(4)]);
  const clientDataJson = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64url(challenge), origin: `https://${RP_ID}`, crossOrigin: false }));
  const rs = crypto.sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJson)]), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  let s = BigInt(`0x${rs.subarray(32).toString('hex')}`);
  if (s > P256_N / 2n) s = P256_N - s; // low-S, as the portal normalizes it
  return {
    signature: new Uint8Array(Buffer.concat([rs.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')])),
    authenticatorData: new Uint8Array(authenticatorData),
    clientDataJsonHash: new Uint8Array(sha256(clientDataJson)),
    clientDataJson: new Uint8Array(clientDataJson),
  };
}

// ─── Limits, as the wallets size them (design §8.2) ─────────────────────────
const CEILING = { computeUnitLimit: 1_400_000, loadedAccountsDataSizeLimit: 64 * 1024 * 1024 };
async function limitsFor(instructions, payer) {
  const { blockhash } = await conn.getLatestBlockhash('confirmed');
  const draft = buildTxV1({ payer, blockhash, instructions, config: CEILING }).wire;
  try {
    const { value } = await clusterCall('simulateTransaction', [
      b64(draft),
      { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed' },
    ]);
    if (value.err || value.unitsConsumed == null || value.loadedAccountsDataSize == null) throw new Error(JSON.stringify(value.err ?? 'missing fields'));
    return {
      computeUnitLimit: Math.min(1_400_000, Math.max(20_000, Math.ceil(value.unitsConsumed * 1.2) + 5_000)),
      loadedAccountsDataSizeLimit: Math.min(CEILING.loadedAccountsDataSizeLimit, Math.max(196_608, Math.ceil((value.loadedAccountsDataSize * 1.1) / 32_768) * 32_768)),
      simulated: { units: value.unitsConsumed, loaded: value.loadedAccountsDataSize },
    };
  } catch (e) {
    console.log(`      simulation unavailable (${e.message}); using the ceilings`);
    return { ...CEILING, simulated: null };
  }
}

// ─── Run ────────────────────────────────────────────────────────────────────
const health = await (await fetch(`${URL_}/health`)).json();
const { signer_address } = await rpcResult('getPayerSigner', []);
const relayer = new PublicKey(signer_address);
console.log(`relayer   ${relayer.toBase58()}  tx_v1=${health.tx_v1}  max_priority_fee_lamports=${health.max_priority_fee_lamports}\nrpc       ${opt.rpc}`);
const balance = () => conn.getBalance(relayer, 'confirmed');

// A LazorKit-shaped v1 transaction for the refusals: the relayer's static checks
// refuse it before anything is simulated, so the instruction data does not matter.
const lazorkitIx = new TransactionInstruction({ programId: PROGRAM_ID_DEVNET, keys: [], data: Buffer.from([0]) });
const secpIx = new TransactionInstruction({ programId: new PublicKey('Secp256r1SigVerify1111111111111111111111111'), keys: [], data: Buffer.from([0]) });
const shaped = async (config, instructions = [secpIx, lazorkitIx]) =>
  buildTxV1({ payer: relayer, blockhash: (await conn.getLatestBlockhash('confirmed')).blockhash, instructions, config }).wire;
const LIMITS = { computeUnitLimit: 50_000, loadedAccountsDataSizeLimit: 196_608 };

if (!health.tx_v1) {
  const before = await balance();
  const body = await rpc('signAndSendTransaction', { transaction: b64(await shaped(LIMITS)), signer_key: relayer.toBase58() });
  check(body.error?.code === -32051 && body.error.message === 'transaction version 1 is not enabled on this paymaster', `relayer without --tx-v1: a v1 transaction is refused with -32051 (${body.error?.code} ${body.error?.message})`);
  check((await balance()) === before, 'the fee payer balance did not move');
  console.log('\nPASS  v1 refused with -32051 by a relayer without --tx-v1. Start it with --tx-v1 to run the v1 landings.');
  process.exit(0);
}

// 1. Refusals, all before signing.
const before = await balance();
const transfer = SystemProgram.transfer({ fromPubkey: Keypair.generate().publicKey, toPubkey: Keypair.generate().publicKey, lamports: 1 });
const big = new TransactionInstruction({ programId: PROGRAM_ID_DEVNET, keys: [], data: Buffer.alloc(1) });
const refusals = [
  ['compute-unit limit unset', { loadedAccountsDataSizeLimit: 196_608 }, undefined, 'tx_v1_compute_unit_limit'],
  ['compute-unit limit 0', { ...LIMITS, computeUnitLimit: 0 }, undefined, 'tx_v1_compute_unit_limit'],
  ['loaded-data limit unset', { computeUnitLimit: 50_000 }, undefined, 'tx_v1_loaded_accounts_data_size_limit'],
  ['loaded-data limit 0', { ...LIMITS, loadedAccountsDataSizeLimit: 0 }, undefined, 'tx_v1_loaded_accounts_data_size_limit'],
  ['priority fee 1 lamport', { ...LIMITS, priorityFeeLamports: 1n }, undefined, 'tx_v1_priority_fee'],
  ['heap request', { ...LIMITS, heapSize: 64 * 1024 }, undefined, 'tx_v1_heap_size'],
  ['ComputeBudget instruction', LIMITS, [ComputeBudgetProgram.setComputeUnitLimit({ units: 50_000 }), secpIx, lazorkitIx], 'tx_v1_compute_budget_instruction'],
  ['Secp256r1 not followed by LazorKit', LIMITS, [secpIx, transfer, lazorkitIx], 'tx_v1_precompile_order'],
];
if (health.max_priority_fee_lamports > 0) refusals.splice(4, 1);
for (const [what, config, instructions, rule] of refusals) {
  const body = await rpc('signAndSendTransaction', { transaction: b64(await shaped(config, instructions)), signer_key: relayer.toBase58() });
  check(body.error?.code === -32003 && body.error.data?.rule === rule, `refused before signing: ${what} (${body.error?.data?.rule ?? JSON.stringify(body.result)})`);
}
{
  // 4,097 bytes: one LazorKit instruction padded to one byte over the limit.
  const size = (await shaped(LIMITS, [secpIx, big])).length;
  big.data = Buffer.alloc(1 + 4097 - size);
  const raw = await shaped(LIMITS, [secpIx, big]);
  const body = await rpc('signAndSendTransaction', { transaction: b64(raw), signer_key: relayer.toBase58() });
  check(raw.length === 4097 && body.error?.data?.rule === 'tx_v1_size', `refused before signing: ${raw.length} bytes (${body.error?.data?.rule})`);
}
check((await balance()) === before, 'the fee payer balance did not move through the refusals');

// 2. CreateWallet (+ fund the vault), legacy, like the wallets' connect path.
const client = new LazorKitClient(conn, PROGRAM_ID_DEVNET);
const key = makePasskey();
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: relayer,
  userSeed: new Uint8Array(crypto.randomBytes(32)),
  owner: { type: 'secp256r1', credentialIdHash: key.credentialIdHash, compressedPubkey: key.compressed, rpId: RP_ID },
});
const createTx = new Transaction().add(...instructions, SystemProgram.transfer({ fromPubkey: relayer, toPubkey: vaultPda, lamports: 3_000_000 }));
createTx.feePayer = relayer;
createTx.recentBlockhash = (await conn.getLatestBlockhash('confirmed')).blockhash;
const created = await rpcResult('signAndSendTransaction', {
  transaction: createTx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64'),
  signer_key: relayer.toBase58(),
});
console.log(`\n2. CreateWallet (legacy)  ${created.signature}  slot ${await waitConfirmed(created.signature)}`);

// 3. A passkey Execute as v1.
const dest = Keypair.generate().publicKey;
const amount = await conn.getMinimumBalanceForRentExemption(0);
const secp256r1 = { credentialIdHash: key.credentialIdHash, publicKeyBytes: key.compressed, authorityPda };
async function executeV1() {
  const prepared = await client.prepareExecute({
    payer: relayer,
    walletPda,
    secp256r1,
    instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: dest, lamports: amount })],
  });
  const { instructions: ixs } = client.finalizeExecute(prepared, webauthnGet(key, prepared.challenge));
  const limits = await limitsFor(ixs, relayer);
  const { blockhash } = await conn.getLatestBlockhash('confirmed');
  const config = { computeUnitLimit: limits.computeUnitLimit, loadedAccountsDataSizeLimit: limits.loadedAccountsDataSizeLimit };
  return { wire: buildTxV1({ payer: relayer, blockhash, instructions: ixs, config }).wire, config, limits };
}
const first = await executeV1();
const res1 = await rpcResult('signAndSendTransaction', { transaction: b64(first.wire), signer_key: relayer.toBase58() });
// 4. Prepared the moment the relayer answered: it reads the counter #3 advanced.
const second = await executeV1();
const res2 = await rpcResult('signAndSendTransaction', { transaction: b64(second.wire), signer_key: relayer.toBase58() });
const slot1 = await waitConfirmed(res1.signature);
const slot2 = await waitConfirmed(res2.signature);

for (const [n, sent, res, slot] of [
  [3, first, res1, slot1],
  [4, second, res2, slot2],
]) {
  const got = await clusterCall('getTransaction', [res.signature, { encoding: 'base64', commitment: 'confirmed', maxSupportedTransactionVersion: 1 }]);
  const landed = VersionedTransaction.deserialize(Buffer.from(got.transaction[0], 'base64'));
  const c = landed.message.transactionConfig;
  const programs = landed.message.compiledInstructions.map((ix) => landed.message.staticAccountKeys[ix.programIdIndex].toBase58().slice(0, 8));
  console.log(`\n${n}. Execute (v1)  ${res.signature}  slot ${slot}`);
  console.log(`   ${Buffer.from(got.transaction[0], 'base64').length} bytes, version ${got.version}, config ${JSON.stringify(c)}, fee ${got.meta.fee}, ${got.meta.computeUnitsConsumed} CU, programs [${programs.join(', ')}]`);
  if (sent.limits.simulated) console.log(`   simulated ${sent.limits.simulated.units} CU, ${sent.limits.simulated.loaded} bytes loaded`);
  check(got.version === 1 && landed.version === 1, `#${n} landed as version 1`);
  check(got.meta.err === null, `#${n} succeeded on chain`);
  check(c.computeUnitLimit === sent.config.computeUnitLimit && c.loadedAccountsDataSizeLimit === sent.config.loadedAccountsDataSizeLimit && c.priorityFee === null && c.heapSize === null, `#${n} carries the config it was built with, no fee, no heap`);
  check(got.meta.fee === 10_000, `#${n} fee is 10,000 lamports (one transaction signature, one precompile signature)`);
  check(!programs.includes('ComputeB'), `#${n} has no ComputeBudget instruction`);
  check(b64(Buffer.from(got.transaction[0], 'base64')) === res.signed_transaction, `#${n} landed exactly as the relayer signed it`);
}
check((await conn.getBalance(dest, 'confirmed')) === 2 * amount, `the destination holds 2 x ${amount} lamports`);

// 5. #3's bytes again.
const again = await rpcResult('signAndSendTransaction', { transaction: b64(first.wire), signer_key: relayer.toBase58() });
check(again.signature === res1.signature, `#3's bytes again -> #3's signature (${again.signature})`);
check((await conn.getBalance(dest, 'confirmed')) === 2 * amount, 'nothing moved again');

console.log(`\nrelayer spent ${(before - (await balance())) / 1e9} SOL`);
console.log('PASS  v1 refusals before signing; passkey Executes landed as v1 through the relayer; back-to-back landed; resend answered with its signature');
