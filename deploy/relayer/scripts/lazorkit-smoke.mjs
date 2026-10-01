#!/usr/bin/env node
// Real LazorKit v2 transactions on devnet, sponsored through a running relayer,
// built the way @lazorkit/wallet 3.0.2 builds them (released @lazorkit/sdk-legacy 1.2.0):
//
//   1. CreateWallet for a passkey owner (legacy tx, signer_key = fee payer), with
//      a small System transfer relayer -> vault in the same tx so the vault can pay
//      for step 2.
//   2. Execute: vault -> fresh address, signed by the passkey (Secp256r1 precompile
//      + wallet-bound challenge), v0 tx through signAndSendTransaction.
//   3. A second Execute prepared the moment the relayer answered for the first
//      (back-to-back, as the wallet does): must land, not fail with 3006.
//   4. Execute whose inner CPI goes to Memo (not allowlisted): must be refused.
//   5. Step 2's exact bytes again, as a client resends them when it never got the
//      answer: the relayer answers with the signature that landed, sends nothing.
//
// It also checks that the relayer reads the slot the passkey signed from the SDK's
// Execute bytes (policy.mjs passkeySignedSlot; the 3006/3007 retries are pinned there).
//
// The "passkey" is a software P-256 key producing WebAuthn-shaped assertions for
// rpId portal.lazor.sh — the same bytes an authenticator returns, minus the device.
// It proves the relayer's allowlist, simulation and inner-call checks pass real
// v2 traffic; the web and mobile apps prove the real-passkey + portal path.
//
//   npm run smoke:lazorkit                         # against http://127.0.0.1:8787
//   npm run smoke:lazorkit -- --url http://192.168.1.5:8787
//
// Costs the relayer about 0.007 devnet SOL (rent for the wallet accounts + 0.003 to the vault).

import crypto from 'node:crypto';
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
import { LazorKitClient, PROGRAM_ID_DEVNET } from '@lazorkit/sdk-legacy';
import { passkeySignedSlot } from '../src/policy.mjs';

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

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function rpc(method, params) {
  const headers = { 'content-type': 'application/json' };
  if (opt['api-key']) headers['x-api-key'] = opt['api-key'];
  const r = await fetch(URL_, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = await r.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

async function waitConfirmed(signature) {
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    const st = (await conn.getSignatureStatuses([signature])).value[0];
    if (st?.err) throw new Error(`${signature} failed: ${JSON.stringify(st.err)}`);
    if (st?.confirmationStatus === 'confirmed' || st?.confirmationStatus === 'finalized') return st.slot;
  }
  throw new Error(`${signature} not confirmed after 60s`);
}

// ─── Software passkey (P-256), WebAuthn assertion shape ─────────────────────
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
function makePasskey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const compressed = new Uint8Array(Buffer.concat([Buffer.from([y[31] & 1 ? 0x03 : 0x02]), x]));
  const credentialId = crypto.randomBytes(16);
  return { privateKey, compressed, credentialIdHash: new Uint8Array(sha256(credentialId)) };
}
function webauthnGet(key, challenge) {
  const authenticatorData = Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x05]), Buffer.alloc(4)]);
  const clientDataJson = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge: b64url(challenge), origin: `https://${RP_ID}`, crossOrigin: false }),
  );
  const signed = Buffer.concat([authenticatorData, sha256(clientDataJson)]);
  const rs = crypto.sign('sha256', signed, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  let s = BigInt(`0x${rs.subarray(32).toString('hex')}`);
  if (s > P256_N / 2n) s = P256_N - s; // low-S, as the portal normalizes it
  const signature = Buffer.concat([rs.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
  return {
    signature: new Uint8Array(signature),
    authenticatorData: new Uint8Array(authenticatorData),
    clientDataJsonHash: new Uint8Array(sha256(clientDataJson)),
    clientDataJson: new Uint8Array(clientDataJson),
  };
}

// ─── Run ────────────────────────────────────────────────────────────────────
const { signer_address } = await rpc('getPayerSigner', []);
const relayer = new PublicKey(signer_address);
const client = new LazorKitClient(conn, PROGRAM_ID_DEVNET);
console.log(`relayer   ${relayer.toBase58()}\nprogram   ${client.programId.toBase58()}`);
const relayerBefore = await conn.getBalance(relayer, 'confirmed');

// 1. CreateWallet (+ fund the vault), legacy tx like the web wallet's connect path.
const key = makePasskey();
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: relayer,
  userSeed: new Uint8Array(crypto.randomBytes(32)),
  owner: { type: 'secp256r1', credentialIdHash: key.credentialIdHash, compressedPubkey: key.compressed, rpId: RP_ID },
});
const VAULT_FUNDING = 3_000_000; // two rent-exempt sends out of it, and its own rent
const createTx = new Transaction().add(
  ...instructions,
  SystemProgram.transfer({ fromPubkey: relayer, toPubkey: vaultPda, lamports: VAULT_FUNDING }),
);
createTx.feePayer = relayer;
createTx.recentBlockhash = (await conn.getLatestBlockhash('confirmed')).blockhash;
const createRes = await rpc('signAndSendTransaction', {
  transaction: createTx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64'),
  signer_key: relayer.toBase58(),
});
const createSlot = await waitConfirmed(createRes.signature);
console.log(`\n1. CreateWallet  ${createRes.signature}  (slot ${createSlot})`);
console.log(`   wallet ${walletPda.toBase58()}  vault ${vaultPda.toBase58()}`);
const auth = await conn.getAccountInfo(authorityPda, 'confirmed');
if (!auth || !auth.owner.equals(client.programId)) throw new Error('authority account missing after CreateWallet');

// 2. Execute: vault -> fresh address, passkey-signed, v0 tx like signAndSendTransaction.
const dest = Keypair.generate().publicKey;
const amount = await conn.getMinimumBalanceForRentExemption(0);
const prepared = await client.prepareExecute({
  payer: relayer,
  walletPda,
  secp256r1: { credentialIdHash: key.credentialIdHash, publicKeyBytes: key.compressed, authorityPda },
  instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: dest, lamports: amount })],
});
const { instructions: execIxs } = client.finalizeExecute(prepared, webauthnGet(key, prepared.challenge));
const { blockhash } = await conn.getLatestBlockhash('confirmed');
const execTx = new VersionedTransaction(
  new TransactionMessage({
    payerKey: relayer,
    recentBlockhash: blockhash,
    instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ...execIxs],
  }).compileToV0Message(),
);
// The slot the relayer reads out of the auth payload is the one the SDK signed.
const parsedSlot = passkeySignedSlot(execTx);
const signedSlot = Number(prepared._internal.signing._internal.slot);
if (parsedSlot !== signedSlot) throw new Error(`relayer reads signed slot ${parsedSlot} from the Execute, the SDK signed ${signedSlot}`);
const execRes = await rpc('signAndSendTransaction', {
  transaction: Buffer.from(execTx.serialize()).toString('base64'),
  signer_key: relayer.toBase58(),
});

// 3. Back-to-back: a second passkey Execute, prepared the moment the relayer answered
//    for the first, as @lazorkit/wallet 3.0.2 does (it never confirms on its own).
//    prepareExecute reads the authority counter and the passkey signs counter+1, so
//    this passes only if the first Execute was confirmed before that read. A relayer
//    that answers at "sent" makes it fail with LazorKit 3006 SignatureReused.
const prepared2 = await client.prepareExecute({
  payer: relayer,
  walletPda,
  secp256r1: { credentialIdHash: key.credentialIdHash, publicKeyBytes: key.compressed, authorityPda },
  // The same rent-exempt amount to the same address: valid whether or not #1 has
  // landed, so the only thing that can fail it is the passkey counter.
  instructions: [SystemProgram.transfer({ fromPubkey: vaultPda, toPubkey: dest, lamports: amount })],
});
// The relayer answers once the Execute is confirmed (Kora's default, respond_after
// 'confirmed'), so its status is there already. Checked after the counter read
// above so the check itself cannot give the first Execute time to land.
const execStatus = (await conn.getSignatureStatuses([execRes.signature])).value[0];
const answeredConfirmed = !execStatus?.err && ['confirmed', 'finalized'].includes(execStatus?.confirmationStatus);
const { instructions: exec2Ixs } = client.finalizeExecute(prepared2, webauthnGet(key, prepared2.challenge));
const exec2Tx = new VersionedTransaction(
  new TransactionMessage({
    payerKey: relayer,
    recentBlockhash: (await conn.getLatestBlockhash('confirmed')).blockhash,
    instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ...exec2Ixs],
  }).compileToV0Message(),
);
const exec2Res = await rpc('signAndSendTransaction', {
  transaction: Buffer.from(exec2Tx.serialize()).toString('base64'),
  signer_key: relayer.toBase58(),
});

const execSlot = await waitConfirmed(execRes.signature);
const exec2Slot = await waitConfirmed(exec2Res.signature);
const destBal = await conn.getBalance(dest, 'confirmed');
console.log(`\n2. Execute       ${execRes.signature}  (slot ${execSlot}, ${execStatus?.confirmationStatus ?? 'not yet visible'} right after the relayer answered)`);
console.log(`   passkey signed slot ${signedSlot}; the relayer reads ${parsedSlot} from the auth payload`);
console.log(`\n3. Execute #2    ${exec2Res.signature}  (slot ${exec2Slot}, prepared right after #1's answer)`);
console.log(`   ${dest.toBase58()} received ${destBal} lamports (expected 2 x ${amount})`);
if (destBal !== 2 * amount) throw new Error('destination balance mismatch');
if (!answeredConfirmed) throw new Error(`relayer answered before Execute #1 was confirmed: status ${JSON.stringify(execStatus)}`);

// 4. Execute whose inner call is NOT allowlisted (Memo via the vault). Kora checks
//    programs that only appear in simulation; so does this relayer. Expect a refusal.
{
  const memoIx = new TransactionInstruction({
    programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
    keys: [],
    data: Buffer.from('inner call the relayer must refuse'),
  });
  const prep = await client.prepareExecute({
    payer: relayer,
    walletPda,
    secp256r1: { credentialIdHash: key.credentialIdHash, publicKeyBytes: key.compressed, authorityPda },
    instructions: [memoIx],
  });
  const { instructions: ixs } = client.finalizeExecute(prep, webauthnGet(key, prep.challenge));
  const tx = new VersionedTransaction(
    new TransactionMessage({
      payerKey: relayer,
      recentBlockhash: (await conn.getLatestBlockhash('confirmed')).blockhash,
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), ...ixs],
    }).compileToV0Message(),
  );
  let refused = null;
  try {
    const r = await rpc('signAndSendTransaction', { transaction: Buffer.from(tx.serialize()).toString('base64'), signer_key: relayer.toBase58() });
    throw new Error(`relayer SENT a transaction with an inner Memo call: ${r.signature}`);
  } catch (e) {
    if (!/inner call to Memo/.test(e.message)) throw e;
    refused = e.message;
  }
  console.log(`\n4. Execute with an inner Memo CPI -> refused\n   ${refused}`);
}

// 5. Step 2's bytes again, after they landed.
{
  const again = await rpc('signAndSendTransaction', {
    transaction: Buffer.from(execTx.serialize()).toString('base64'),
    signer_key: relayer.toBase58(),
  });
  const destAfter = await conn.getBalance(dest, 'confirmed');
  console.log(`\n5. Execute #1's bytes again -> ${again.signature}\n   ${dest.toBase58()} holds ${destAfter} lamports`);
  if (again.signature !== execRes.signature) throw new Error(`a resend of landed bytes got signature ${again.signature}, not ${execRes.signature}`);
  if (destAfter !== 2 * amount) throw new Error('a resend of landed bytes moved funds again');
}

const relayerAfter = await conn.getBalance(relayer, 'confirmed');
console.log(`\nrelayer spent ${(relayerBefore - relayerAfter) / 1e9} SOL for the three transactions`);
console.log('PASS  real LazorKit v2 CreateWallet + passkey Execute sponsored; back-to-back Execute landed; inner non-allowlisted CPI refused; resend of landed bytes answered with its signature');
