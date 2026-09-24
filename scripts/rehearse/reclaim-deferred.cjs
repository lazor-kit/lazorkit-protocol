#!/usr/bin/env node
// Reclaim expired DeferredExec accounts, through the paymaster that paid for
// them.
//
// `ReclaimDeferred` refunds an expired authorization's rent, and only the
// original payer may call it. On every sponsored authorization that payer is
// the Kora fee payer — a key that lives inside the relayer's environment, not
// on an operator's laptop. So this does not need the key: it builds the
// transactions with the sponsor as fee payer and asks the relayer to sign and
// send them, which is exactly what the relayer exists to do.
//
// This matters because the window closes. After the v2 upgrade no instruction
// in the binary accepts a v1 discriminator, and every unclaimed account keeps
// its rent forever.
//
//   NODE_PATH=... node scripts/rehearse/reclaim-deferred.cjs            # dry run
//   NODE_PATH=... node scripts/rehearse/reclaim-deferred.cjs --execute
//
// Env:
//   RPC_URL       default https://api.devnet.solana.com
//   PROGRAM_ID    default the devnet v1 program
//   PAYMASTER_URL default https://kora.devnet.lazorkit.com
//   KORA_API_KEY  sent as x-api-key when set
//   SPONSOR       the payer to match, when no relayer is up to ask. A dry run
//                 then needs no paymaster at all — useful for a cluster whose
//                 relayer does not exist yet.
//   BATCH         instructions per transaction (default 8)
'use strict';
const {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
} = require('@solana/web3.js');

const RPC_URL = process.env.RPC_URL ?? 'https://api.devnet.solana.com';
const PROGRAM_ID = new PublicKey(
  process.env.PROGRAM_ID ?? '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS',
);
const PAYMASTER_URL = process.env.PAYMASTER_URL ?? 'https://kora.devnet.lazorkit.com';
const BATCH = Number(process.env.BATCH ?? 8);
const EXECUTE = process.argv.includes('--execute');

// v1 and v2 agree on this one: ReclaimDeferred is instruction 8.
const DISC_RECLAIM_DEFERRED = 8;
// v1 DeferredExec: disc | version | bump | pad(5) | instructions_hash(32) |
// accounts_hash(32) | wallet(32) | authority(32) | payer(32) | expires_at(u64)
const DISC_DEFERRED = 4;
const OFF_PAYER = 136;
const OFF_EXPIRES = 168;
const LEN_DEFERRED = 176;

const sol = (lamports) => (lamports / 1e9).toFixed(6);

async function kora(method, params) {
  const res = await fetch(PAYMASTER_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(process.env.KORA_API_KEY ? { 'x-api-key': process.env.KORA_API_KEY } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`${method}: ${json.error.message ?? JSON.stringify(json.error)}`);
  return json.result;
}

function reclaimIx(payer, deferredPda, refundDestination) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: false },
      { pubkey: deferredPda, isSigner: false, isWritable: true },
      { pubkey: refundDestination, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([DISC_RECLAIM_DEFERRED]),
  });
}

(async () => {
  const connection = new Connection(RPC_URL, 'confirmed');

  // Ask the relayer who it signs as, unless we were told — a dry run against a
  // cluster with no relayer yet still has a question worth answering.
  const sponsor = process.env.SPONSOR
    ? new PublicKey(process.env.SPONSOR)
    : new PublicKey((await kora('getPayerSigner', [])).signer_address);
  console.log(`paymaster    ${process.env.SPONSOR && !EXECUTE ? '(not consulted — SPONSOR given)' : PAYMASTER_URL}`);
  console.log(`sponsor      ${sponsor.toBase58()}`);
  console.log(`program      ${PROGRAM_ID.toBase58()}`);

  const slot = await connection.getSlot();
  const accounts = await connection.getProgramAccounts(PROGRAM_ID, {
    filters: [{ memcmp: { offset: 0, bytes: '5' } }], // base58 of [4]
  });

  const mine = [];
  const others = new Map();
  let otherPayer = 0;
  let notExpired = 0;
  for (const { pubkey, account } of accounts) {
    const d = account.data;
    if (d.length < LEN_DEFERRED || d[0] !== DISC_DEFERRED) continue;
    const payer = new PublicKey(d.subarray(OFF_PAYER, OFF_PAYER + 32));
    const expiresAt = Number(d.readBigUInt64LE(OFF_EXPIRES));
    if (!payer.equals(sponsor)) {
      otherPayer++;
      const row = others.get(payer.toBase58()) ?? { count: 0, lamports: 0 };
      row.count++;
      row.lamports += account.lamports;
      others.set(payer.toBase58(), row);
      continue;
    }
    // The program refuses a reclaim before expiry, so filter here rather than
    // discovering it one failed transaction at a time.
    if (expiresAt >= slot) {
      notExpired++;
      continue;
    }
    mine.push({ pubkey, lamports: account.lamports, expiresAt });
  }

  const total = mine.reduce((n, a) => n + a.lamports, 0);
  console.log(`\ndeferred accounts   ${accounts.length}`);
  console.log(`  sponsor's, expired ${mine.length}  →  ${sol(total)} SOL`);
  console.log(`  another payer      ${otherPayer}  (only that payer can reclaim them)`);
  for (const [payer, row] of [...others.entries()].sort((a, b) => b[1].lamports - a[1].lamports)) {
    console.log(`      ${payer}  ${row.count} account(s)  ${sol(row.lamports)} SOL`);
  }
  console.log(`  not yet expired    ${notExpired}  (current slot ${slot})`);
  if (!mine.length) return;

  if (!EXECUTE) {
    console.log('\ndry run — pass --execute to send. Would reclaim:');
    for (const a of mine.slice(0, 10)) {
      console.log(`  ${a.pubkey.toBase58()}  ${sol(a.lamports)} SOL  expired at slot ${a.expiresAt}`);
    }
    if (mine.length > 10) console.log(`  … and ${mine.length - 10} more`);
    return;
  }

  let reclaimed = 0;
  for (let i = 0; i < mine.length; i += BATCH) {
    const batch = mine.slice(i, i + BATCH);
    const { blockhash } = await connection.getLatestBlockhash('confirmed');
    const tx = new Transaction({ feePayer: sponsor, recentBlockhash: blockhash });
    for (const a of batch) tx.add(reclaimIx(sponsor, a.pubkey, sponsor));
    const serialized = tx
      .serialize({ verifySignatures: false, requireAllSignatures: false })
      .toString('base64');

    try {
      const result = await kora('signAndSendTransaction', {
        transaction: serialized,
        signer_key: sponsor.toBase58(),
      });
      const signature = result.signature ?? result;
      console.log(`  batch ${i / BATCH + 1}: ${batch.length} account(s)  ${signature}`);
      reclaimed += batch.reduce((n, a) => n + a.lamports, 0);
    } catch (e) {
      console.error(`  batch ${i / BATCH + 1} failed: ${e.message}`);
    }
  }

  // Prove it rather than assume it: the accounts should be gone.
  const after = await connection.getMultipleAccountsInfo(mine.map((a) => a.pubkey));
  const left = after.filter(Boolean).length;
  console.log(`\nreclaimed ${sol(reclaimed)} SOL; ${left} of ${mine.length} account(s) still present`);
})().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
