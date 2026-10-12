#!/usr/bin/env node
// Close expired sessions and return their rent.
//
// `CloseExpiredSession` (instruction 18) is permissionless once a session is
// past `expires_at`, so this is a keeper, not an admin tool. A v2 session at
// layout revision 2 records the account that paid its rent, and the program
// sends the rent there and nowhere else (3039 otherwise): a relayer runs this
// to sweep the sessions it sponsored (`PAID_BY` limits the run to them). A
// session that records no payer — v1, or v2 before revision 2 — goes to
// whoever arrives first with a destination of their choice (`REFUND`).
//
// It closes **v1** sessions as well as v2 ones. That is where the money is
// today: the upgrade leaves v1 sessions that no v1 instruction can reach any
// more, and on mainnet that is 133 accounts worth about 0.29 SOL.
//
//   NODE_PATH=... node scripts/rehearse/close-expired-sessions.cjs            # dry run
//   NODE_PATH=... node scripts/rehearse/close-expired-sessions.cjs --execute
//
// Env:
//   RPC_URL     default https://api.devnet.solana.com
//   PROGRAM_ID  the upgraded (v2) program — instruction 18 only exists there
//   KEEPER      keypair file; signs and pays the fees
//   REFUND      where the rent of a session that records no payer goes
//               (default: the keeper); a recording session's rent always goes
//               to its recorded payer
//   PAID_BY     only close sessions whose recorded payer is this key
//   BATCH       sessions per transaction (default 12)
'use strict';
const fs = require('fs');
const {
  Connection,
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} = require('@solana/web3.js');

const RPC_URL = process.env.RPC_URL ?? 'https://api.devnet.solana.com';
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID ?? '');
const BATCH = Number(process.env.BATCH ?? 12);
const EXECUTE = process.argv.includes('--execute');

const DISC_CLOSE_EXPIRED_SESSION = 18;
// Session, in both protocol versions. The headers are identical apart from this
// byte, which is exactly why one instruction can close either.
const DISC_SESSION_V1 = 3;
const DISC_SESSION_V2 = 0x23;
// base58 of the single-byte filter for each.
const FILTER_BYTES = { [DISC_SESSION_V1]: '4', [DISC_SESSION_V2]: 'c' };
const OFF_EXPIRES_AT = 72;
const SESSION_HEADER = 80;
// Layout revision 2 records the rent payer at 80..112 (program/src/state/rent_payer.rs).
const OFF_VERSION = 2;
const RENT_PAYER_REVISION = 2;

/** The rent payer a v2 session records, or null (v1, or v2 revision 1). */
function recordedPayer(disc, data) {
  if (disc !== DISC_SESSION_V2 || data[OFF_VERSION] < RENT_PAYER_REVISION) return null;
  if (data.length < SESSION_HEADER + 32) return null;
  return new PublicKey(data.subarray(SESSION_HEADER, SESSION_HEADER + 32));
}

const sol = (lamports) => (lamports / 1e9).toFixed(6);

function closeIx(caller, session, refund) {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: caller, isSigner: true, isWritable: true },
      { pubkey: session, isSigner: false, isWritable: true },
      { pubkey: refund, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([DISC_CLOSE_EXPIRED_SESSION]),
  });
}

(async () => {
  const connection = new Connection(RPC_URL, 'confirmed');
  const keeper = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(process.env.KEEPER, 'utf8'))),
  );
  const refund = process.env.REFUND ? new PublicKey(process.env.REFUND) : keeper.publicKey;
  const paidBy = process.env.PAID_BY ? new PublicKey(process.env.PAID_BY) : null;

  console.log(`program   ${PROGRAM_ID.toBase58()}`);
  console.log(`keeper    ${keeper.publicKey.toBase58()}`);
  console.log(`refund    ${refund.toBase58()} (sessions that record no payer)`);
  if (paidBy) console.log(`paid by   ${paidBy.toBase58()} only`);

  // The program compares a v2 session's expiry with the clock's Unix time and a
  // v1 session's (a slot, as v1 wrote it) with its slot; read both from one
  // Clock sysvar so the filter below makes the same split. (The sunset binary
  // owns v1 sessions only, and reads every expiry as a slot.)
  const clockInfo = await connection.getAccountInfo(SYSVAR_CLOCK_PUBKEY);
  if (!clockInfo || clockInfo.data.length < 40) throw new Error('cannot read the Clock sysvar');
  const slot = clockInfo.data.readBigUInt64LE(0);
  const unixTimestamp = clockInfo.data.readBigInt64LE(32);
  const found = [];
  let live = 0;
  // One scan per discriminator: memcmp filters are ANDed, so a single call
  // cannot ask for "either of these two bytes".
  for (const disc of [DISC_SESSION_V1, DISC_SESSION_V2]) {
    const accounts = await connection.getProgramAccounts(PROGRAM_ID, {
      filters: [{ memcmp: { offset: 0, bytes: FILTER_BYTES[disc] } }],
    });
    for (const { pubkey, account } of accounts) {
      if (account.data.length < SESSION_HEADER) continue;
      const expiresAt = account.data.readBigUInt64LE(OFF_EXPIRES_AT);
      // The program will not close a session that is still live — through its
      // final second (v2) or its final slot (v1) — so filter the same way
      // rather than spending a transaction to be told.
      const now = disc === DISC_SESSION_V2 ? unixTimestamp : slot;
      if (expiresAt >= now) {
        live++;
        continue;
      }
      const payer = recordedPayer(disc, account.data);
      if (paidBy && !(payer && payer.equals(paidBy))) continue;
      found.push({
        pubkey,
        lamports: account.lamports,
        version: disc === DISC_SESSION_V1 ? 1 : 2,
        refund: payer ?? refund,
      });
    }
  }

  const byVersion = (v) => found.filter((s) => s.version === v);
  const sum = (rows) => rows.reduce((n, s) => n + s.lamports, 0);
  console.log(`\nslot ${slot}, Unix time ${unixTimestamp}`);
  console.log(`  expired v1 sessions ${byVersion(1).length}  →  ${sol(sum(byVersion(1)))} SOL`);
  console.log(`  expired v2 sessions ${byVersion(2).length}  →  ${sol(sum(byVersion(2)))} SOL`);
  console.log(`  still live          ${live}  (left alone)`);
  if (!found.length) return;

  if (!EXECUTE) {
    console.log(`\ndry run — pass --execute to collect ${sol(sum(found))} SOL.`);
    for (const s of found.slice(0, 10)) {
      console.log(`  ${s.pubkey.toBase58()}  v${s.version}  ${sol(s.lamports)} SOL  → ${s.refund.toBase58()}`);
    }
    if (found.length > 10) console.log(`  … and ${found.length - 10} more`);
    return;
  }

  let closed = 0;
  for (let i = 0; i < found.length; i += BATCH) {
    const batch = found.slice(i, i + BATCH);
    const tx = new Transaction();
    for (const s of batch) tx.add(closeIx(keeper.publicKey, s.pubkey, s.refund));
    try {
      const signature = await sendAndConfirmTransaction(connection, tx, [keeper], {
        commitment: 'confirmed',
      });
      console.log(`  batch ${i / BATCH + 1}: ${batch.length} session(s)  ${signature}`);
      closed += batch.length;
    } catch (e) {
      // A session someone else closed first is not an error worth stopping for:
      // this is a race by design, and the next batch is still worth sending.
      console.error(`  batch ${i / BATCH + 1} failed: ${(e.message ?? e).split('\n')[0]}`);
    }
  }

  console.log(`\nclosed ${closed}/${found.length} session(s)`);
})().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
