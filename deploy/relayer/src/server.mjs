#!/usr/bin/env node
// Local Kora-compatible fee payer for testing LazorKit v2 on Solana devnet.
//
// Implements the Kora JSON-RPC methods that @lazorkit/wallet 3.0.2 and
// @lazorkit/wallet-mobile-adapter 2.0.0 call:
//   getPayerSigner          both packages, before every transaction
//   signAndSendTransaction  both packages, every transaction
//   getBlockhash            web Paymaster class (defined, not on the main path)
//   signTransaction         web Paymaster class (defined, not on the main path)
//
// Signs only when every instruction (top-level and inner) calls an allowlisted
// program and the fee payer is this relayer. signAndSendTransaction answers once
// the transaction is confirmed, like Kora's default (respond_after "confirmed"):
// @lazorkit/wallet 3.0.2 does not confirm on its own, and a passkey's next
// signature reads the authority counter this one advances. See README.md.
//
// SIMD-0385 v1 transactions are signed only with --tx-v1, at the byte level
// (src/txv1.mjs), after the v1 rules in policy.mjs. Without the flag they are
// refused with -32051 before anything else happens.

import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { Connection, Keypair, PublicKey, SendTransactionError, VersionedTransaction } from '@solana/web3.js';
import bs58 from 'bs58';
import {
  ALLOWED_PROGRAMS,
  LAZORKIT_V2_DEVNET,
  DEVNET_GENESIS,
  MAINNET_GENESIS,
  programLabel,
} from './allowlist.mjs';
import {
  inspectTransaction,
  checkSimulation,
  explainTxError,
  passkeySignedSlot,
  PolicyError,
  ERR,
  RPC_TIMEOUT_MS,
  MIN_CONTEXT_SLOT_NOT_REACHED,
} from './policy.mjs';
import { isTxV1, signTxV1AsFeePayer, txV1Signature } from './txv1.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// ─── Options ────────────────────────────────────────────────────────────────
const HELP = `Usage: npm start -- [options]

  --port <n>              Port to listen on (default 8787, env RELAYER_PORT)
  --lan                   Also listen on the LAN interface, for phones on the same Wi-Fi
  --lan-ip <addr>         LAN address to bind with --lan (default: auto-detected)
  --rpc <url>             Solana RPC (default https://api.devnet.solana.com, env RELAYER_RPC_URL)
  --keypair <path>        Fee payer keypair (default ./relayer-keypair.json, env RELAYER_KEYPAIR)
  --max-lamports <n>      Most the fee payer may lose per transaction (default 50000000 = 0.05 SOL)
  --max-tx-per-hour <n>   Signed transactions per rolling hour, all callers (default 300)
  --allow-plain           Also sponsor transactions that do not call LazorKit v2 (env RELAYER_ALLOW_PLAIN=1).
                          Off by default: like Kora's require_one_of_programs, every transaction must call
                          LazorKit v2. Only the smoke test's plain transfer needs this.
  --require-lazorkit      The default; accepted so older instructions keep working
  --confirm-timeout <s>   How long signAndSendTransaction waits for 'confirmed'. Past it, it answers with the
                          signature anyway, for the caller to confirm (default 30, env RELAYER_CONFIRM_TIMEOUT)
  --api-key <key>         Require x-api-key on signTransaction/signAndSendTransaction (env RELAYER_API_KEY)
  --cors-origin <list>    Comma-separated allowed browser origins, or '*' for any
                          (default: pages served from this machine: localhost, 127.0.0.1, ::1, its own IPs)
  --any-cluster           Allow a non-devnet RPC (e.g. a local validator). Mainnet is always refused.
  --tx-v1                 Also sign SIMD-0385 v1 transactions (env RELAYER_TX_V1=1). Off by default: a v1
                          transaction is then refused with code -32051 before anything is signed.
  --max-priority-fee-lamports <n>
                          v1 only: the largest priority fee (total lamports, paid by the fee payer) a v1
                          transaction may carry (default 0, env RELAYER_MAX_PRIORITY_FEE_LAMPORTS)
  -h, --help              Show this help
`;

let args;
try {
  ({ values: args } = parseArgs({
    options: {
      port: { type: 'string' },
      lan: { type: 'boolean', default: false },
      'lan-ip': { type: 'string' },
      rpc: { type: 'string' },
      keypair: { type: 'string' },
      'max-lamports': { type: 'string' },
      'max-tx-per-hour': { type: 'string' },
      'allow-plain': { type: 'boolean', default: false },
      'require-lazorkit': { type: 'boolean', default: false },
      'confirm-timeout': { type: 'string' },
      'api-key': { type: 'string' },
      'cors-origin': { type: 'string' },
      'any-cluster': { type: 'boolean', default: false },
      'tx-v1': { type: 'boolean', default: false },
      'max-priority-fee-lamports': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  }));
} catch (e) {
  console.error(`${e.message}\n\n${HELP}`);
  process.exit(2);
}
if (args.help) {
  console.log(HELP);
  process.exit(0);
}

const env = process.env;
const int = (name, v, def) => {
  if (v == null || v === '') return def;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) fail(`--${name} must be a non-negative integer, got "${v}"`);
  return n;
};
function fail(msg) {
  console.error(`relayer: ${msg}`);
  process.exit(1);
}

const cfg = {
  port: int('port', args.port ?? env.RELAYER_PORT, 8787),
  lan: args.lan,
  lanIp: args['lan-ip'],
  rpcUrl: args.rpc ?? env.RELAYER_RPC_URL ?? 'https://api.devnet.solana.com',
  keypairPath: path.resolve(args.keypair ?? env.RELAYER_KEYPAIR ?? path.join(ROOT, 'relayer-keypair.json')),
  maxLamports: int('max-lamports', args['max-lamports'] ?? env.RELAYER_MAX_LAMPORTS, 50_000_000),
  maxTxPerHour: int('max-tx-per-hour', args['max-tx-per-hour'], 300),
  // On unless --allow-plain: kora.devnet.toml has require_one_of_programs = [v2].
  requireLazorkit: !(args['allow-plain'] || env.RELAYER_ALLOW_PLAIN === '1'),
  confirmTimeoutMs: 1000 * int('confirm-timeout', args['confirm-timeout'] ?? env.RELAYER_CONFIRM_TIMEOUT, 30),
  apiKey: args['api-key'] ?? env.RELAYER_API_KEY ?? null,
  // null = pages served from this machine (see originAllowed); '*' = any; else an exact list.
  corsOrigins: args['cors-origin'] ? args['cors-origin'].split(',').map((s) => s.trim()).filter(Boolean) : null,
  anyCluster: args['any-cluster'],
  maxSignatures: 4, // kora.devnet.toml max_signatures
  txV1: args['tx-v1'] || env.RELAYER_TX_V1 === '1',
  maxPriorityFeeLamports: int('max-priority-fee-lamports', args['max-priority-fee-lamports'] ?? env.RELAYER_MAX_PRIORITY_FEE_LAMPORTS, 0),
};
if (cfg.port < 1 || cfg.port > 65535) fail(`--port must be 1-65535`);
if (cfg.confirmTimeoutMs < 1000 || cfg.confirmTimeoutMs > 300_000) fail(`--confirm-timeout must be 1-300 (seconds)`);
if (args['allow-plain'] && args['require-lazorkit']) fail('--allow-plain and --require-lazorkit contradict each other.');
if (cfg.corsOrigins && cfg.corsOrigins.includes('*') && cfg.corsOrigins.length > 1) {
  fail(`--cors-origin '*' cannot be combined with a list of origins.`);
}
const corsAny = cfg.corsOrigins?.[0] === '*';

// ─── Keypair (the relayer's OWN key — never the CLI default or a deploy key) ──
function loadKeypair(p) {
  const home = os.homedir();
  const forbidden = [path.join(home, '.config', 'solana', 'id.json')];
  const real = fs.existsSync(p) ? fs.realpathSync(p) : p;
  if (forbidden.includes(real) || real.split(path.sep).includes('keys')) {
    fail(`refusing to use ${p}: the relayer must run on its own keypair, not the CLI default or a keys/ file.`);
  }
  if (!fs.existsSync(p)) {
    fail(
      `no keypair at ${p}. Create one with:\n  solana-keygen new --no-bip39-passphrase --silent -o ${p} && chmod 600 ${p}`,
    );
  }
  const mode = fs.statSync(p).mode & 0o777;
  if (mode & 0o077) fail(`${p} is readable by other users (mode ${mode.toString(8)}). Run: chmod 600 ${p}`);
  try {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(p, 'utf8'))));
  } catch {
    fail(`${p} is not a Solana keypair file.`);
  }
}
const payer = loadKeypair(cfg.keypairPath);
const relayer = payer.publicKey.toBase58();
// Each RPC request gives up after RPC_TIMEOUT_MS, so a node that hangs cannot
// hold an answer open (web3.js has no timeout of its own).
const connection = new Connection(cfg.rpcUrl, {
  commitment: 'confirmed',
  fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(RPC_TIMEOUT_MS) }),
});

// ─── Logging ────────────────────────────────────────────────────────────────
const ts = () => new Date().toISOString().replace('T', ' ').replace('Z', '');
const log = (...parts) => console.log([ts(), ...parts.filter((p) => p !== '' && p != null)].join('  '));
const labels = (ids) => `[${ids.map(programLabel).join(', ')}]`;
const ver = (v) => (v == null ? '' : v === 'legacy' ? 'legacy' : `v${v}`);
// A v1 transaction's config is logged with its version: what the relayer agreed to pay for.
const txV1Text = (c) =>
  `v1 cu=${c.computeUnitLimit ?? 'unset'} lad=${c.loadedAccountsDataSizeLimit ?? 'unset'} fee=${c.priorityFee ?? 0}` +
  (c.heapSize != null ? ` heap=${c.heapSize}` : '');
const versionText = (ctx) => (ctx.txV1Config ? txV1Text(ctx.txV1Config) : ver(ctx.version));
const sol = (lamports) => `${(lamports / 1e9).toFixed(6)} SOL`;

// ─── Rate limit (Kora usage_limit: transaction rule, global here) ───────────
const signedAt = [];
function takeRateSlot() {
  const now = Date.now();
  while (signedAt.length && now - signedAt[0] > 3_600_000) signedAt.shift();
  if (signedAt.length >= cfg.maxTxPerHour) {
    throw new PolicyError(
      ERR.RATE_LIMITED,
      `relayer rejected: ${cfg.maxTxPerHour} transactions signed in the last hour (--max-tx-per-hour).`,
      { rule: 'usage_limit' },
    );
  }
  signedAt.push(now);
}

// ─── The sign path shared by signTransaction and signAndSendTransaction ─────
// Returns the decoded transaction and its wire bytes as received (`raw`).
function decodeParams(params, ctx) {
  if (!params || typeof params !== 'object' || Array.isArray(params) || typeof params.transaction !== 'string') {
    throw new PolicyError(ERR.INVALID_PARAMS, 'invalid params: expected { transaction: <base64>, signer_key?: <address> }');
  }
  const raw = Buffer.from(params.transaction, 'base64');
  // A v1 transaction starts with 0x81. Without --tx-v1 it is refused here,
  // before it is decoded, inspected, simulated or signed, with a code of its
  // own: wallets with v1 support do not retry it, and send later ones as v0.
  if (isTxV1(raw) && !cfg.txV1) {
    ctx.version = 1;
    throw new PolicyError(ERR.TX_V1_DISABLED, 'transaction version 1 is not enabled on this paymaster', { rule: 'tx_v1_disabled' });
  }
  let tx;
  try {
    tx = VersionedTransaction.deserialize(raw);
  } catch (e) {
    throw new PolicyError(ERR.INVALID_PARAMS, `invalid params: transaction is not a base64 Solana transaction (${e.message})`);
  }
  return { tx, raw, signerKey: params.signer_key ?? null };
}

async function vetAndSign(params, ctx) {
  const { tx, raw, signerKey } = decodeParams(params, ctx);
  // For the log line, whatever the verdict.
  ctx.version = tx.version;
  if (tx.version === 1) ctx.txV1Config = tx.message.transactionConfig;
  ctx.programs = tx.message.compiledInstructions.map((ix) => tx.message.staticAccountKeys[ix.programIdIndex]?.toBase58() ?? '(lookup)');
  inspectTransaction(tx, {
    relayer,
    signerKey,
    maxSignatures: cfg.maxSignatures,
    requireLazorkit: cfg.requireLazorkit,
    raw,
    maxPriorityFeeLamports: cfg.maxPriorityFeeLamports,
  });

  // v1: the bytes as received, which are the ones signed below (web3.js cannot
  // serialize a v1 message). Legacy and v0: re-serialized from the decoded message.
  const txBase64 = Buffer.from(tx.version === 1 ? raw : tx.serialize()).toString('base64');
  // From a bank at or past slotFloor, like the simulation, so both see the
  // relayer's own last transaction (its fee and rent) or neither does.
  let preBalance;
  try {
    preBalance = await atSlotFloor((minContextSlot) => connection.getBalance(payer.publicKey, { commitment: 'confirmed', minContextSlot }));
  } catch (e) {
    if (!isMinContextSlotError(e)) throw e;
    throw new PolicyError(
      ERR.SIMULATION_FAILED,
      `relayer could not read its own balance: its RPC has not reached slot ${slotFloor} (its own last confirmed transaction) yet. ` +
        'Nothing was signed. Sending the same transaction again may pass once it catches up.',
      { rule: 'simulation', reason: 'rpc_behind', minContextSlot: slotFloor },
    );
  }
  let sim;
  try {
    sim = await checkSimulation({
      rpcUrl: cfg.rpcUrl,
      txBase64,
      relayer,
      maxLamports: cfg.maxLamports,
      preBalance,
      programs: ctx.programs,
      slotFloor,
      signedSlot: passkeySignedSlot(tx),
    });
  } catch (e) {
    if (e instanceof PolicyError && e.data?.rule === 'simulation' && e.data.err) await explainIfAlreadySent(tx, raw, e, ctx.programs);
    throw e;
  }
  ctx.inner = sim.innerPrograms;
  ctx.payerDelta = sim.payerDelta;
  ctx.units = sim.unitsConsumed;
  ctx.contextSlot = sim.contextSlot;

  takeRateSlot();
  return signAsFeePayer(tx, raw);
}

// Adds the relayer's signature as fee payer and returns { tx, raw, signature }:
// the decoded transaction, the signed wire bytes and the signature in base58.
// Legacy and v0: web3.js signs `tx` and re-serializes it. v1: a signed copy of
// the bytes as received; `tx` and `raw` are left as they are.
function signAsFeePayer(tx, raw) {
  if (tx.version === 1) {
    const signed = signTxV1AsFeePayer(raw, payer);
    return { tx, raw: signed, signature: bs58.encode(txV1Signature(signed, 0)) };
  }
  tx.sign([payer]);
  return { tx, raw: tx.serialize(), signature: bs58.encode(tx.signatures[0]) };
}

// A client resends the same bytes when it never got the first answer (a
// dropped connection, a send error after the RPC had already forwarded them;
// @lazorkit/wallet retries every error twice). If the first attempt has landed,
// the simulation now fails (already processed, a used counter), which would
// read as a new failure. The relayer's signature is deterministic, so it can
// tell: if the signature it would produce is already on chain, the answer is
// the one the first attempt gets. Landed without an error: e.landed carries
// the transaction, and signAndSendTransaction answers with its signature as a
// success. Landed and failed: the same -32005 transaction_failed. Nothing new
// is signed for the caller or sent, and only a signature that is already
// public on chain is ever given out. A v1 transaction is signed at the byte
// level here too, so it gets the same answer.
async function explainIfAlreadySent(tx, raw, e, programs) {
  try {
    // A signed copy: `tx` stays unsigned (v1 always signs a copy).
    const copy = signAsFeePayer(tx.version === 1 ? tx : VersionedTransaction.deserialize(tx.serialize()), raw);
    const { signature } = copy;
    const st = await lookUp(signature);
    if (!st) return;
    if (!st.err) {
      const confirmed = st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized';
      e.landed = { signed: copy, signature, slot: st.slot, confirmed };
      return;
    }
    e.code = ERR.SEND_FAILED;
    e.message = `transaction ${signature} landed in slot ${st.slot} but failed on chain: ${JSON.stringify(st.err)}${explainTxError(st.err, programs)}`;
    e.data = { rule: 'transaction_failed', signature, slot: st.slot, err: st.err };
  } catch {
    /* keep the simulation error as it is */
  }
}

// vetAndSign, except that bytes which already landed without an error give
// back that landed transaction (ctx.resent) instead of the simulation's error.
async function vetAndSignOrLanded(params, ctx) {
  try {
    return await vetAndSign(params, ctx);
  } catch (e) {
    if (e?.data?.rule === 'transaction_failed') ctx.sent = true; // landed earlier, and failed
    if (!e?.landed) throw e;
    ctx.resent = { slot: e.landed.slot, confirmed: e.landed.confirmed };
    return e.landed.signed;
  }
}

// ─── Sending and confirming ─────────────────────────────────────────────────
// The newest slot one of this relayer's own transactions confirmed in. The
// simulation and the balance read before it never use a bank older than this.
let slotFloor = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sendErrorText = (e) => (e?.transactionMessage ?? e?.message ?? String(e)).split('\n')[0];
// Preflight answers that mean "the RPC node is behind", not "the transaction is wrong".
const LAG_SEND_ERROR = /minimum context slot|blockhash not found|node is behind|node is unhealthy/i;
const ALREADY_PROCESSED = /already been processed/i;
const isMinContextSlotError = (e) => e?.code === MIN_CONTEXT_SLOT_NOT_REACHED || /minimum context slot/i.test(e?.message ?? '');

// `read(minContextSlot)` from a node at or past slotFloor. A node behind it
// answers -32016, and the read is retried (500 ms apart, at most 5 times).
async function atSlotFloor(read) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await read(slotFloor || undefined);
    } catch (e) {
      if (attempt >= 5 || !isMinContextSlotError(e)) throw e;
      await sleep(500);
    }
  }
}

// `promise`, or `fallback` once `ms` have passed, whichever comes first.
function within(promise, ms, fallback) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(fallback), Math.max(0, ms));
    promise.then(
      (v) => (clearTimeout(timer), resolve(v)),
      (e) => (clearTimeout(timer), reject(e)),
    );
  });
}

// `signature`'s status if the cluster knows it (processed or later, failed or
// not), else null. Throws when the RPC does not answer.
async function lookUp(signature) {
  return (await connection.getSignatureStatuses([signature], { searchTransactionHistory: true })).value[0];
}

// Sends with preflight. minContextSlot = the slot the simulation ran at, so the
// preflight never runs on an older bank; a node that is behind answers -32016
// (or "Blockhash not found") and the send is retried briefly, as is a send the
// RPC never answered (a timeout, an HTTP 5xx). Resending the same bytes is
// safe: the network deduplicates by signature. A send that fails because these
// bytes were already processed, or whose signature the cluster already knows,
// was sent: the confirmation wait reports how it ended.
async function sendWithLagRetry(raw, minContextSlot, signature) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await connection.sendRawTransaction(raw, {
        skipPreflight: false,
        preflightCommitment: 'confirmed',
        maxRetries: 5,
        ...(minContextSlot ? { minContextSlot } : {}),
      });
    } catch (e) {
      const text = sendErrorText(e);
      // SendTransactionError or an HTTP 4xx: the RPC answered. Anything else (a
      // timeout, a dropped connection, an HTTP 5xx): it may or may not have
      // forwarded the bytes.
      const answered = e instanceof SendTransactionError || /^4\d\d\b/.test(e?.message ?? '');
      if (attempt < 4 && (LAG_SEND_ERROR.test(text) || !answered)) {
        await sleep(500);
        continue;
      }
      if (ALREADY_PROCESSED.test(text) || (await lookUp(signature).catch(() => null))) return signature;
      const logs = e.transactionLogs ?? (Array.isArray(e.logs) ? e.logs : []);
      const tail = logs.slice(-6);
      throw new PolicyError(ERR.SEND_FAILED, `relayer could not send the transaction: ${text}${tail.length ? ` | logs: ${tail.join(' / ')}` : ''}`, {
        rule: 'send',
        logs,
      });
    }
  }
}

// Polls until the transaction is confirmed or failed at 'confirmed', its
// blockhash expires with no trace of it, or the timeout passes. The timeout
// bounds the whole wait: an RPC call still running at the deadline is not
// waited for. `minContextSlot` (the slot the simulation ran at, where the
// blockhash was valid) keeps a node that is behind that slot, and so may not
// know the blockhash yet, from calling it expired.
async function waitConfirmed(signature, blockhash, minContextSlot) {
  const deadline = Date.now() + cfg.confirmTimeoutMs;
  const left = () => deadline - Date.now();
  const TIMED_OUT = Symbol('timed out');
  let polls = 0;
  let expiredSeen = 0;
  while (left() > 0) {
    await sleep(Math.min(polls < 10 ? 500 : 1000, Math.max(0, left())));
    polls++;
    try {
      const statuses = await within(connection.getSignatureStatuses([signature]), left(), TIMED_OUT);
      if (statuses === TIMED_OUT) break;
      const st = statuses.value[0];
      const settled = st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized');
      if (settled) return st.err ? { status: 'failed', err: st.err, slot: st.slot } : { status: 'confirmed', slot: st.slot };
      if (st) {
        expiredSeen = 0; // processed: it is on a fork, keep waiting
        continue;
      }
      if (polls % 4) continue;
      // Not seen yet: every 2 s, ask whether it still can land. Two "expired"
      // answers in a row (2 s apart) before calling it, then one last look in
      // the status history.
      const valid = await within(
        connection.isBlockhashValid(blockhash, { commitment: 'confirmed', ...(minContextSlot ? { minContextSlot } : {}) }),
        left(),
        TIMED_OUT,
      );
      if (valid === TIMED_OUT) break;
      expiredSeen = valid.value ? 0 : expiredSeen + 1;
      if (expiredSeen >= 2) {
        const last = await within(lookUp(signature), left(), TIMED_OUT);
        if (last === TIMED_OUT) break;
        if (!last) return { status: 'expired' };
        expiredSeen = 0;
      }
    } catch {
      /* transient RPC error, or a node behind minContextSlot (-32016): keep polling */
    }
  }
  return { status: 'timeout' };
}

// ─── Background confirmation, so the console shows how each send landed ────
async function watch(signature) {
  const started = Date.now();
  while (Date.now() - started < 90_000) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const { value } = await connection.getSignatureStatuses([signature]);
      const st = value[0];
      if (st?.err) return log('FAILED   ', signature, JSON.stringify(st.err));
      if (st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized')) {
        slotFloor = Math.max(slotFloor, st.slot);
        return log('confirmed', signature, `slot ${st.slot}`);
      }
    } catch {
      /* transient RPC error: keep polling */
    }
  }
  log('unconfirmed after 90s', signature);
}

// ─── Methods ────────────────────────────────────────────────────────────────
const PROTECTED = new Set(['signTransaction', 'signAndSendTransaction']);
const methods = {
  async getPayerSigner() {
    return { signer_address: relayer, payment_address: relayer };
  },
  async getBlockhash() {
    const { blockhash } = await connection.getLatestBlockhash('confirmed');
    return { blockhash };
  },
  async signTransaction(params, ctx) {
    const signed = await vetAndSignOrLanded(params, ctx);
    ctx.signature = signed.signature;
    return { signed_transaction: Buffer.from(signed.raw).toString('base64'), signer_pubkey: relayer };
  },
  async signAndSendTransaction(params, ctx) {
    // Kora's respond_after: 'confirmed' (the default), 'sent', or 'signed'.
    const respondAfter = (params && typeof params === 'object' && !Array.isArray(params) ? params.respond_after : undefined) ?? 'confirmed';
    if (!RESPOND_AFTER.includes(respondAfter)) {
      throw new PolicyError(ERR.INVALID_PARAMS, `invalid params: respond_after must be one of ${RESPOND_AFTER.join(', ')}`);
    }
    ctx.respondAfter = respondAfter;
    const { tx, raw, signature } = await vetAndSignOrLanded(params, ctx);
    ctx.signature = signature;
    const result = { signature, signed_transaction: Buffer.from(raw).toString('base64'), signer_pubkey: relayer };

    if (respondAfter === 'signed' && !ctx.resent) {
      // Answer now and broadcast in the background (Kora: the caller rebroadcasts if it never lands).
      sendWithLagRetry(raw, ctx.contextSlot, signature).then(
        () => watch(signature),
        (e) => log('FAILED   ', signature, `background send: ${e.message}`),
      );
      return result;
    }

    if (!ctx.resent) await sendWithLagRetry(raw, ctx.contextSlot, signature);
    ctx.sent = true;
    if (respondAfter !== 'confirmed') {
      if (!ctx.resent) watch(signature);
      return result;
    }
    if (ctx.resent?.confirmed) {
      ctx.slot = ctx.resent.slot;
      ctx.confirmMs = 0;
      return result;
    }

    // Default: answer only once the transaction is confirmed, so the caller's
    // next read (a passkey counter, a balance) sees what this one changed.
    const t0 = Date.now();
    const landed = await waitConfirmed(signature, tx.message.recentBlockhash, ctx.contextSlot ?? slotFloor);
    ctx.confirmMs = Date.now() - t0;
    if (landed.status === 'confirmed') {
      slotFloor = Math.max(slotFloor, landed.slot);
      ctx.slot = landed.slot;
      return result;
    }
    if (landed.status === 'failed') {
      throw new PolicyError(
        ERR.SEND_FAILED,
        `transaction ${signature} landed in slot ${landed.slot} but failed on chain: ${JSON.stringify(landed.err)}${explainTxError(landed.err, ctx.programs)}`,
        { rule: 'transaction_failed', signature, slot: landed.slot, err: landed.err },
      );
    }
    if (landed.status === 'expired') {
      throw new PolicyError(
        ERR.SEND_FAILED,
        `transaction ${signature} was sent but never landed, and its blockhash has expired, so it cannot land any more. Build and sign it again.`,
        { rule: 'blockhash_expired', signature },
      );
    }
    // Not confirmed within --confirm-timeout: it was sent and may still land.
    // Answer with its signature, as respond_after 'sent' does, rather than an
    // error, so the caller has it to wait for. The released mobile adapter
    // (2.0.0) confirms a signature it is given but reads only error.message;
    // @lazorkit/wallet after 3.0.2 follows the signature either way and holds
    // the passkey's next challenge until it settles.
    ctx.unconfirmed = true;
    watch(signature); // keep watching, so the console still shows how it ends
    return result;
  },
};
const RESPOND_AFTER = ['confirmed', 'sent', 'signed'];

// ─── HTTP ───────────────────────────────────────────────────────────────────
const MAX_BODY = 64 * 1024;

// Hostnames (no brackets, lower case) that belong to this machine, right now.
const unbracket = (h) => h.replace(/^\[(.*)\]$/, '$1').toLowerCase();
function machineHostnames() {
  const names = new Set(['localhost', '127.0.0.1', '::1']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list ?? []) names.add(a.address.replace(/%.*$/, '').toLowerCase());
  }
  return names;
}

// Browsers may call the relayer only from these origins. By default: pages
// served from this machine (the Vite app on any port, over http or https, by
// localhost or by one of the Mac's own addresses). A page on the internet gets
// no Access-Control-Allow-Origin, so the browser never sends its request.
function originAllowed(origin) {
  if (!origin || origin === 'null') return false;
  if (cfg.corsOrigins) return corsAny || cfg.corsOrigins.includes(origin);
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return (url.protocol === 'http:' || url.protocol === 'https:') && machineHostnames().has(unbracket(url.hostname));
}

function corsHeaders(req) {
  const origin = req.headers.origin;
  const h = {
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, x-api-key',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
  if (corsAny) h['Access-Control-Allow-Origin'] = '*';
  else if (originAllowed(origin)) h['Access-Control-Allow-Origin'] = origin;
  // Chrome's Private Network Access / Local Network Access preflight: answered
  // only for an allowed origin, so a public page cannot reach this relayer.
  if (req.headers['access-control-request-private-network'] === 'true' && h['Access-Control-Allow-Origin']) {
    h['Access-Control-Allow-Private-Network'] = 'true';
  }
  return h;
}

// DNS rebinding guard: a page on evil.example whose name later resolves to
// 127.0.0.1 is "same origin" with the relayer and skips CORS entirely. Its
// requests still carry Host: evil.example, so only the names this server
// listens on are accepted. Filled in once the listeners are up.
const allowedHosts = new Set(['localhost']);
function hostAllowed(req) {
  const host = req.headers.host;
  if (!host) return false;
  const name = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
  return allowedHosts.has(unbracket(name));
}

function send(res, req, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json', ...corsHeaders(req) });
  res.end(JSON.stringify(obj));
}

async function status() {
  let balance = null;
  try {
    balance = await connection.getBalance(payer.publicKey, 'confirmed');
  } catch {
    /* report null */
  }
  return {
    ok: true,
    service: 'lazorkit-devnet-relayer',
    relayer,
    balance_lamports: balance,
    rpc: cfg.rpcUrl,
    methods: Object.keys(methods),
    allowed_programs: [...ALLOWED_PROGRAMS].map(([id, name]) => ({ id, name })),
    require_lazorkit: cfg.requireLazorkit,
    cors: corsAny ? '*' : cfg.corsOrigins ?? 'this-machine',
    max_allowed_lamports: cfg.maxLamports,
    max_signatures: cfg.maxSignatures,
    max_tx_per_hour: cfg.maxTxPerHour,
    respond_after_default: 'confirmed',
    confirm_timeout_ms: cfg.confirmTimeoutMs,
    api_key_required: Boolean(cfg.apiKey),
    tx_v1: cfg.txV1,
    max_priority_fee_lamports: cfg.maxPriorityFeeLamports,
  };
}

async function handle(req, res) {
  const peer = req.socket.remoteAddress?.replace(/^::ffff:/, '') ?? '?';

  if (!hostAllowed(req)) {
    log(peer, 'REJECTED', `Host "${req.headers.host ?? ''}" is not an address this relayer listens on`);
    res.writeHead(421, { 'content-type': 'application/json' });
    return res.end(
      JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `misdirected request: Host must be one of ${[...allowedHosts].join(', ')}` } }),
    );
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(req));
    return res.end();
  }
  if (req.method === 'GET') {
    if (req.url === '/' || req.url === '/health' || req.url.startsWith('/?')) return send(res, req, 200, await status());
    return send(res, req, 404, { error: 'not found' });
  }
  if (req.method !== 'POST') return send(res, req, 405, { error: 'method not allowed' });

  // Both SDKs send application/json. Requiring it means a cross-origin browser
  // request always needs the CORS preflight above; a text/plain "simple" POST,
  // which a browser sends from any page without asking, is refused here.
  const contentType = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    log(peer, 'REJECTED', `content-type "${req.headers['content-type'] ?? ''}" (must be application/json)`);
    return send(res, req, 415, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'content-type must be application/json' } });
  }

  // Read the body, bounded.
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) {
      log(peer, 'REJECTED', `request body over ${MAX_BODY} bytes`);
      return send(res, req, 413, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'request too large' } });
    }
    chunks.push(c);
  }

  let rpc;
  try {
    rpc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    log(peer, '(parse error)');
    return send(res, req, 200, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
  }
  if (Array.isArray(rpc) || !rpc || typeof rpc.method !== 'string') {
    log(peer, '(invalid request)');
    return send(res, req, 200, {
      jsonrpc: '2.0',
      id: rpc?.id ?? null,
      error: { code: -32600, message: 'invalid request (batches are not supported)' },
    });
  }

  const { id = null, method, params } = rpc;
  const fn = Object.prototype.hasOwnProperty.call(methods, method) ? methods[method] : null;
  if (!fn) {
    log(peer, method, 'REJECTED', 'method not found');
    return send(res, req, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
  }
  if (cfg.apiKey && PROTECTED.has(method) && req.headers['x-api-key'] !== cfg.apiKey) {
    log(peer, method, 'REJECTED', 'missing or wrong x-api-key');
    return send(res, req, 401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'unauthorized: missing or wrong x-api-key' } });
  }

  const ctx = {};
  try {
    const result = await fn(params, ctx);
    if (PROTECTED.has(method)) {
      log(
        peer,
        method,
        versionText(ctx),
        labels(ctx.programs),
        ctx.inner?.length ? `inner=${labels(ctx.inner)}` : 'inner=[]',
        typeof ctx.payerDelta === 'number' ? `payer ${ctx.payerDelta <= 0 ? '-' : '+'}${sol(Math.abs(ctx.payerDelta))}` : '',
        ctx.units != null ? `${ctx.units} CU` : '',
        ctx.slot != null
          ? `CONFIRMED ${ctx.signature}  slot ${ctx.slot} (${(ctx.confirmMs / 1000).toFixed(1)} s after send)${ctx.resent ? ' (a resend of bytes that had landed: nothing sent again)' : ''}`
          : ctx.unconfirmed
            ? `UNCONFIRMED ${ctx.signature} after ${cfg.confirmTimeoutMs / 1000} s: answered with the signature, still watching`
            : ctx.resent
              ? `LANDED ${ctx.signature} (a resend of bytes that had landed: nothing sent again)`
              : ctx.sent
                ? `SENT ${ctx.signature}`
                : `SIGNED ${ctx.signature}${ctx.respondAfter === 'signed' ? ' (sending in the background)' : ''}`,
      );
    } else {
      log(peer, method, 'ok');
    }
    return send(res, req, 200, { jsonrpc: '2.0', id, result });
  } catch (e) {
    const code = e instanceof PolicyError ? e.code : -32000;
    const message = e instanceof PolicyError ? e.message : `internal error: ${e.message}`;
    // FAILED: sent, then failed on chain, expired, or timed out. REJECTED: nothing was sent.
    log(peer, method, versionText(ctx), ctx.programs ? labels(ctx.programs) : '', ctx.sent ? 'FAILED' : 'REJECTED', message);
    return send(res, req, 200, { jsonrpc: '2.0', id, error: { code, message, ...(e.data ? { data: e.data } : {}) } });
  }
}

// ─── Startup checks ─────────────────────────────────────────────────────────
async function preflight() {
  let genesis;
  try {
    genesis = await connection.getGenesisHash();
  } catch (e) {
    fail(`cannot reach RPC ${cfg.rpcUrl}: ${e.message}`);
  }
  if (genesis === MAINNET_GENESIS) fail(`${cfg.rpcUrl} is mainnet. This relayer is for devnet only.`);
  if (genesis !== DEVNET_GENESIS && !cfg.anyCluster) {
    fail(`${cfg.rpcUrl} is not devnet (genesis ${genesis}). Pass --any-cluster for a local validator.`);
  }

  // The relayer must never be the program's upgrade authority.
  const program = await connection.getAccountInfo(new PublicKey(LAZORKIT_V2_DEVNET), { dataSlice: { offset: 0, length: 36 } });
  let programNote = `LazorKit v2 ${LAZORKIT_V2_DEVNET}`;
  if (!program) {
    programNote += ' — NOT DEPLOYED on this cluster';
  } else if (program.owner.toBase58() === 'BPFLoaderUpgradeab1e11111111111111111111111') {
    const programData = new PublicKey(program.data.subarray(4, 36));
    const pd = await connection.getAccountInfo(programData, { dataSlice: { offset: 0, length: 45 } });
    if (pd && pd.data[12] === 1) {
      const authority = new PublicKey(pd.data.subarray(13, 45)).toBase58();
      if (authority === relayer) fail(`this keypair is the program's upgrade authority. Use a separate relayer keypair.`);
    }
    programNote += ' (deployed; relayer is not its upgrade authority)';
  }

  const balance = await connection.getBalance(payer.publicKey, 'confirmed');
  return { genesis, balance, programNote };
}

function lanAddress() {
  if (cfg.lanIp) return cfg.lanIp;
  const ifaces = os.networkInterfaces();
  const names = Object.keys(ifaces).sort((a, b) => (a.startsWith('en') ? 0 : 1) - (b.startsWith('en') ? 0 : 1) || a.localeCompare(b));
  const isPrivate = (ip) => /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
  for (const name of names) {
    for (const a of ifaces[name] ?? []) {
      if (a.family === 'IPv4' && !a.internal && isPrivate(a.address)) return a.address;
    }
  }
  return null;
}

function listen(host) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      handle(req, res).catch((e) => {
        log('internal error', e.stack ?? e);
        if (!res.headersSent) send(res, req, 500, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'internal error' } });
      });
    });
    server.once('error', reject);
    server.listen(cfg.port, host, () => resolve(server));
  });
}

const { genesis, balance, programNote } = await preflight();

const servers = [];
const urls = [];
try {
  servers.push(await listen('127.0.0.1'));
  urls.push(`http://127.0.0.1:${cfg.port}`);
  allowedHosts.add('127.0.0.1');
} catch (e) {
  fail(`cannot listen on 127.0.0.1:${cfg.port}: ${e.message}`);
}
try {
  servers.push(await listen('::1')); // so http://localhost:<port> works when localhost resolves to ::1
  urls.push(`http://localhost:${cfg.port}`);
  allowedHosts.add('::1');
} catch {
  /* no IPv6 loopback: 127.0.0.1 is enough */
}
if (cfg.lan) {
  const ip = lanAddress();
  if (!ip) fail('--lan: no private IPv4 address found. Pass --lan-ip <addr>.');
  try {
    servers.push(await listen(ip));
    urls.push(`http://${ip}:${cfg.port}   <- use this one on a phone (same Wi-Fi)`);
    allowedHosts.add(unbracket(ip));
  } catch (e) {
    fail(`cannot listen on ${ip}:${cfg.port}: ${e.message}`);
  }
}

const exposure = [cfg.lan && 'the LAN (--lan)', corsAny && 'every web page (--cors-origin *)'].filter(Boolean);
const plainWarning =
  !cfg.requireLazorkit && exposure.length
    ? `\n  WARNING      --allow-plain while reachable from ${exposure.join(' and ')}: anyone there can have this\n               relayer pay for plain System transfers (up to ${sol(cfg.maxLamports)} each, ${cfg.maxTxPerHour}/hour).\n`
    : '';

console.log(`
LazorKit devnet relayer (local Kora stand-in)
  fee payer    ${relayer}
  balance      ${sol(balance)}${balance < 50_000_000 ? '   <- LOW: fund it with `solana transfer ' + relayer + ' 1 -u devnet`' : ''}
  rpc          ${cfg.rpcUrl} (${genesis === DEVNET_GENESIS ? 'devnet' : `genesis ${genesis}`})
  program      ${programNote}
  allowlist    ${[...ALLOWED_PROGRAMS.values()].join(', ')}
  policy       fee payer = relayer; max ${sol(cfg.maxLamports)} out of the fee payer per tx; max ${cfg.maxSignatures} signatures;
               no durable nonces; ${cfg.maxTxPerHour} signed tx/hour; require LazorKit v2: ${cfg.requireLazorkit ? 'yes' : 'NO (--allow-plain)'}
  tx v1        ${
    cfg.txV1
      ? `on (--tx-v1): compute-unit and loaded-data limits required, priority fee at most ${cfg.maxPriorityFeeLamports} lamports,\n               no heap request, no ComputeBudget instruction, Secp256r1 followed directly by LazorKit v2`
      : 'off: v1 transactions are refused with -32051 before anything is signed (--tx-v1 turns them on)'
  }
  sends        signAndSendTransaction answers once the tx is confirmed (after ${cfg.confirmTimeoutMs / 1000} s unconfirmed: with the signature, for the caller to confirm)
  api key      ${cfg.apiKey ? 'required (x-api-key)' : 'not required'}
  cors         ${corsAny ? 'any origin (--cors-origin *)' : cfg.corsOrigins ? cfg.corsOrigins.join(', ') : 'pages served from this machine only (localhost, 127.0.0.1, ::1, its own IPs; any port)'}
  hosts        ${[...allowedHosts].join(', ')}   (any other Host header is refused)
  listening    ${urls.join('\n               ')}
  methods      ${Object.keys(methods).join(', ')}   (GET /health for status)
${plainWarning}`);

const shutdown = () => {
  log('shutting down');
  for (const s of servers) s.close();
  setTimeout(() => process.exit(0), 200).unref();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
