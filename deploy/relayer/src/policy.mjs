// Transaction policy: what this relayer is willing to sign as fee payer.
//
// Two stages, both must pass before the relayer signs anything:
//   1. inspectTransaction — static checks on the message (no network).
//   2. checkSimulation    — simulate on the cluster (retrying briefly when the
//                            answer only shows that the RPC node is behind), then
//                            check inner (CPI) programs and how many lamports the
//                            fee payer loses.
//
// A failure throws PolicyError; its message is what the client sees, so every
// message names the instruction and the rule.

import {
  ALLOWED_PROGRAMS,
  REQUIRE_ONE_OF,
  LAZORKIT_V2_DEVNET,
  SECP256R1_PROGRAM,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  ALT_PROGRAM,
  programLabel,
} from './allowlist.mjs';

export class PolicyError extends Error {
  constructor(code, message, data) {
    super(message);
    this.code = code; // JSON-RPC error code
    this.data = data;
  }
}

// JSON-RPC error codes this relayer returns.
export const ERR = {
  INVALID_PARAMS: -32602,
  REJECTED: -32003, // policy refused to sign
  SIMULATION_FAILED: -32004,
  SEND_FAILED: -32005, // refused at send, failed on chain, or expired unlanded
  RATE_LIMITED: -32029,
};

// Every RPC request the relayer makes gives up after this long, so a node that
// never answers cannot hold a caller's answer open.
export const RPC_TIMEOUT_MS = 10_000;

// JSON-RPC -32016: the node's bank is older than the minContextSlot asked for.
export const MIN_CONTEXT_SLOT_NOT_REACHED = -32016;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ─── LazorKit program errors worth explaining to the caller ────────────────
// SignatureReused (3006): the counter the passkey signed is not the authority's
// next one. InvalidSignatureAge (3007): the slot the passkey signed is ahead of
// the bank, or 150+ slots old. Both are also what a bank that lags the node the
// wallet read from produces, so the simulation retries them (at most twice) at a
// fresher slot before giving up (see checkSimulation).
const SIGNATURE_REUSED = 3006;
const INVALID_SIGNATURE_AGE = 3007;

/**
 * { index, code } of a Custom error raised by LazorKit v2 itself, else null.
 * An error a program raises inside a CPI is reported at the index of the
 * top-level instruction that made the call, so a LazorKit Execute whose inner
 * (e.g. Anchor) program fails with its own 3006 (AccountNotMutable) looks the
 * same. With the logs at hand, the first program that failed decides.
 */
function lazorkitError(err, programs, logs) {
  const [index, inner] = err?.InstructionError ?? [];
  const code = inner?.Custom;
  if (typeof code !== 'number') return null;
  if (programs && programs[index] !== LAZORKIT_V2_DEVNET) return null;
  const firstFailure = (logs ?? []).map((l) => /^Program (\w{32,44}) failed: custom program error: /.exec(l)).find(Boolean);
  if (firstFailure && firstFailure[1] !== LAZORKIT_V2_DEVNET) return null;
  return { index, code };
}

/** A sentence that says what a transaction error means for the caller, or ''. */
export function explainTxError(err, programs, logs) {
  if (err === 'BlockhashNotFound') {
    return ' (the relayer\'s RPC does not know the transaction\'s blockhash: it has expired, or it came from a node this RPC has not caught up with)';
  }
  const lk = lazorkitError(err, programs, logs);
  if (lk?.code === SIGNATURE_REUSED) {
    return (
      ' (LazorKit SignatureReused: the passkey signed a counter that is not the authority\'s next one. Usually the wallet ' +
      'read the counter before its previous transaction confirmed, so it signed a counter that transaction has now used. ' +
      'A new passkey signature is needed; resending these bytes cannot pass.)'
    );
  }
  if (lk?.code === INVALID_SIGNATURE_AGE) {
    return ' (LazorKit InvalidSignatureAge: the slot the passkey signed is ahead of the chain or more than 150 slots old. Sign again.)';
  }
  return '';
}

// System program instruction discriminators (u32 LE).
const SYS = {
  0: 'CreateAccount',
  1: 'Assign',
  2: 'Transfer',
  3: 'CreateAccountWithSeed',
  4: 'AdvanceNonceAccount',
  5: 'WithdrawNonceAccount',
  6: 'InitializeNonceAccount',
  7: 'AuthorizeNonceAccount',
  8: 'Allocate',
  9: 'AllocateWithSeed',
  10: 'AssignWithSeed',
  11: 'TransferWithSeed',
  12: 'UpgradeNonceAccount',
};
// Mirrors [validation.fee_payer_policy.system] in kora.devnet.toml: the fee payer
// may fund transfers (protocol fee) and account creation (rent), nothing else.
const SYSTEM_FEE_PAYER_ALLOWED = new Set([0, 2, 3]);

/**
 * Static checks. Returns a summary used for logging and for the next stage.
 * @param {import('@solana/web3.js').VersionedTransaction} tx
 */
export function inspectTransaction(tx, { relayer, signerKey, maxSignatures, requireLazorkit }) {
  const msg = tx.message;
  const keys = msg.staticAccountKeys;
  const feePayer = keys[0]?.toBase58();

  if (feePayer !== relayer) {
    throw new PolicyError(
      ERR.REJECTED,
      `relayer rejected: fee payer is ${feePayer}, not this relayer (${relayer}). Build the transaction with payerKey = the address from getPayerSigner.`,
      { rule: 'fee_payer' },
    );
  }
  if (signerKey != null && signerKey !== relayer) {
    throw new PolicyError(
      ERR.REJECTED,
      `relayer rejected: signer_key ${signerKey} is not this relayer (${relayer}).`,
      { rule: 'signer_key' },
    );
  }
  const numSigs = msg.header.numRequiredSignatures;
  if (numSigs > maxSignatures) {
    throw new PolicyError(
      ERR.REJECTED,
      `relayer rejected: transaction needs ${numSigs} signatures, the limit is ${maxSignatures}.`,
      { rule: 'max_signatures' },
    );
  }

  const ixs = msg.compiledInstructions;
  if (ixs.length === 0) {
    throw new PolicyError(ERR.REJECTED, 'relayer rejected: transaction has no instructions.', { rule: 'empty' });
  }

  const programs = [];
  ixs.forEach((ix, i) => {
    const pk = keys[ix.programIdIndex];
    if (!pk) {
      throw new PolicyError(ERR.REJECTED, `relayer rejected: instruction #${i} takes its program id from a lookup table.`, {
        rule: 'program_not_allowed',
        index: i,
      });
    }
    const programId = pk.toBase58();
    programs.push(programId);
    if (!ALLOWED_PROGRAMS.has(programId)) {
      throw new PolicyError(
        ERR.REJECTED,
        `relayer rejected: instruction #${i} calls ${programLabel(programId)} (${programId}), which is not in the relayer allowlist.`,
        { rule: 'program_not_allowed', index: i, programId },
      );
    }

    const touchesPayer = ix.accountKeyIndexes.includes(0);
    const data = ix.data;

    if (programId === SYSTEM_PROGRAM) {
      const kind = data.length >= 4 ? Buffer.from(data).readUInt32LE(0) : -1;
      if (kind === 4) {
        // Kora: allow_durable_transactions = false. A durable-nonce transaction
        // never expires, so a signature on it could be replayed at any time.
        throw new PolicyError(
          ERR.REJECTED,
          `relayer rejected: instruction #${i} is System AdvanceNonceAccount — durable-nonce transactions are not sponsored.`,
          { rule: 'durable_nonce', index: i },
        );
      }
      if (touchesPayer && !SYSTEM_FEE_PAYER_ALLOWED.has(kind)) {
        throw new PolicyError(
          ERR.REJECTED,
          `relayer rejected: instruction #${i} is System ${SYS[kind] ?? `#${kind}`} on the fee payer — only Transfer and CreateAccount may use the fee payer.`,
          { rule: 'fee_payer_policy', index: i },
        );
      }
    } else if (touchesPayer && (programId === TOKEN_PROGRAM || programId === TOKEN_2022_PROGRAM || programId === ALT_PROGRAM)) {
      // Kora: every spl_token / token_2022 / alt fee-payer flag is false. The
      // fee payer is never a token authority or a lookup-table payer in LazorKit.
      throw new PolicyError(
        ERR.REJECTED,
        `relayer rejected: instruction #${i} (${programLabel(programId)}) uses the fee payer as an account — the fee payer may not be a token or lookup-table authority.`,
        { rule: 'fee_payer_policy', index: i },
      );
    }
  });

  if (requireLazorkit && !programs.some((p) => REQUIRE_ONE_OF.includes(p))) {
    throw new PolicyError(
      ERR.REJECTED,
      `relayer rejected: transaction does not call LazorKit v2 (${REQUIRE_ONE_OF.join(', ')}). Every sponsored transaction must (start the relayer with --allow-plain to lift this).`,
      { rule: 'require_one_of_programs' },
    );
  }

  return { feePayer, numSigs, programs, version: tx.version };
}

// One JSON-RPC call. Public devnet answers bursts with HTTP 429 ("Connection rate
// limits exceeded"): back off a few times instead of failing a transaction the
// user has already signed with their passkey.
async function rpcCall(rpcUrl, method, params) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (res.status === 429 && attempt < 3) {
      await sleep(500 * 2 ** attempt);
      continue;
    }
    return res.json();
  }
}

async function simulateOnce(rpcUrl, txBase64, relayer, minContextSlot) {
  try {
    return await rpcCall(rpcUrl, 'simulateTransaction', [
      txBase64,
      {
        encoding: 'base64',
        sigVerify: false,
        replaceRecentBlockhash: false,
        commitment: 'confirmed',
        innerInstructions: true,
        accounts: { encoding: 'base64', addresses: [relayer] },
        ...(minContextSlot ? { minContextSlot } : {}),
      },
    ]);
  } catch (e) {
    throw new PolicyError(ERR.SIMULATION_FAILED, `relayer could not simulate the transaction: ${e.message}`, { rule: 'simulation' });
  }
}

/**
 * Why a simulation answer may only mean "this RPC node is behind", or null.
 * - 'slot':      -32016, the node has not reached the minContextSlot asked for.
 * - 'blockhash': BlockhashNotFound, the wallet got its blockhash from a newer node.
 * - 'counter':   LazorKit 3006/3007, the bank may predate the transaction the
 *                wallet's counter/slot read already saw.
 */
function lagKind(body, programs) {
  if (body.error?.code === MIN_CONTEXT_SLOT_NOT_REACHED) return 'slot';
  const err = body.result?.value?.err;
  if (err === 'BlockhashNotFound') return 'blockhash';
  const code = lazorkitError(err, programs, body.result?.value?.logs)?.code;
  if (code === SIGNATURE_REUSED || code === INVALID_SIGNATURE_AGE) return 'counter';
  return null;
}

const INSTRUCTIONS_SYSVAR = 'Sysvar1nstructions1111111111111111111111111';

/**
 * The newest slot a passkey signed over in this transaction, or null.
 *
 * A LazorKit secp256r1 auth payload is the tail of its instruction's data
 * (program/src/auth/secp256r1/mod.rs; every processor passes
 * `instruction_data[k..]`):
 *   [slot u64][counter u32][sysvarIxIdx u8][reserved u8]
 *   [authDataLen u16][authenticatorData][cdjLen u16][clientDataJSON]
 * It is read from the end: the clientDataJSON is a JSON object whose u16
 * length precedes it, the authenticator data (37+ bytes) has its u16 length
 * before it, sysvarIxIdx names the Instructions sysvar among the instruction's
 * accounts, and the instruction before it is the Secp256r1 precompile. Data
 * that does not fit all of that gives null, and the simulation retries work as
 * they would without it.
 */
export function passkeySignedSlot(tx) {
  const keys = tx.message.staticAccountKeys.map((k) => k.toBase58());
  const ixs = tx.message.compiledInstructions;
  let newest = null;
  ixs.forEach((ix, i) => {
    if (i === 0 || keys[ix.programIdIndex] !== LAZORKIT_V2_DEVNET || keys[ixs[i - 1].programIdIndex] !== SECP256R1_PROGRAM) return;
    const d = Buffer.from(ix.data);
    const end = d.length;
    if (end < 16 + 37 + 2 + 2 || d[end - 1] !== 0x7d) return; // '}'
    for (let n = 2; n <= Math.min(end - 16 - 37 - 2, 0xffff); n++) {
      const cdj = end - n;
      if (d[cdj] !== 0x7b || d.readUInt16LE(cdj - 2) !== n) continue; // '{'
      for (let m = 37; m <= 1024 && cdj - 2 - m - 16 >= 0; m++) {
        const o = cdj - 2 - m - 16;
        if (d.readUInt16LE(o + 14) !== m) continue;
        const account = ix.accountKeyIndexes[d[o + 12]];
        // A sysvar loaded from a lookup table cannot be told apart here; accept it.
        if (account === undefined || (account < keys.length && keys[account] !== INSTRUCTIONS_SYSVAR)) continue;
        const slot = Number(d.readBigUInt64LE(o));
        newest = Math.max(newest ?? 0, slot);
        return;
      }
    }
  });
  return newest;
}

// How far past the RPC's confirmed slot a signed slot may be and still be
// waited for. A wallet's RPC can be a few slots ahead of the relayer's; a
// passkey slot further out than this fails with 3007 whatever the relayer does.
const SIGNED_SLOT_AHEAD_MAX = 150;

/**
 * Simulates the unsigned-by-relayer transaction and checks what it actually does.
 * `programs` are the top-level program ids by instruction index; `slotFloor` is
 * the newest slot this relayer has seen one of its own transactions confirm in;
 * `signedSlot` is the slot the transaction's passkey signed over (or null).
 * Returns { innerPrograms, payerDelta, unitsConsumed, logs, contextSlot }.
 */
export async function checkSimulation({ rpcUrl, txBase64, relayer, maxLamports, preBalance, programs, slotFloor, signedSlot }) {
  // Every simulation runs on a bank at least as new as the relayer's own last
  // confirmed transaction (slotFloor): a node behind a load balancer that has
  // not executed it answers -32016 instead of failing a transaction that
  // depends on it (ExecuteDeferred after Authorize, an Execute after
  // CreateWallet).
  //
  // Lag retry, bounded (at most 5 retries, 500 ms apart; at most 2 for 3006/3007).
  // A lag-looking answer is retried against a bank at least as new as the
  // newest confirmed slot the RPC reports, and, for 3006/3007, the slot the
  // passkey signed: the state the wallet read its counter from. A stale counter
  // the wallet really signed stays a 3006 and is reported below: only a new
  // passkey signature fixes that.
  let minContextSlot = slotFloor || null;
  let body = await simulateOnce(rpcUrl, txBase64, relayer, minContextSlot);
  let lastResult = body.result ? body : null;
  for (let retries = 0, counterRetries = 0; retries < 5; retries++) {
    const lag = lagKind(body, programs);
    if (!lag || (lag === 'counter' && counterRetries++ >= 2)) break;
    await sleep(500);
    if (lag !== 'slot') {
      const head = (await rpcCall(rpcUrl, 'getSlot', [{ commitment: 'confirmed' }]).catch(() => null))?.result ?? 0;
      const signed = lag === 'counter' && signedSlot && head && signedSlot <= head + SIGNED_SLOT_AHEAD_MAX ? signedSlot : 0;
      minContextSlot = Math.max(minContextSlot ?? 0, slotFloor ?? 0, head, signed) || null;
    }
    body = await simulateOnce(rpcUrl, txBase64, relayer, minContextSlot);
    if (body.result) lastResult = body;
  }

  if (body.error?.code === MIN_CONTEXT_SLOT_NOT_REACHED) {
    // The retries ran out while the RPC was still behind the slot asked for.
    // Nothing is known to be wrong with the transaction itself, so this is not
    // reported as the older bank's answer, anywhere in the error: a 3006 there
    // reads as a stale counter (wallets search the message and error.data for
    // it) and ends the wallet's retries, while the same bytes may pass once
    // the RPC catches up.
    throw new PolicyError(
      ERR.SIMULATION_FAILED,
      `relayer could not simulate the transaction: its RPC has not reached slot ${minContextSlot} ` +
        '(the newest of: its own last confirmed transaction, the confirmed slot it reported, the slot the passkey signed) yet. ' +
        'Nothing was signed. Sending the same transaction again may pass once it catches up.',
      { rule: 'simulation', reason: 'rpc_behind', minContextSlot, rpcError: body.error },
    );
  }
  if (body.error && lastResult) body = lastResult;

  if (body.error) {
    throw new PolicyError(ERR.SIMULATION_FAILED, `relayer could not simulate the transaction: ${body.error.message}`, {
      rule: 'simulation',
      rpcError: body.error,
    });
  }
  const v = body.result.value;
  const logs = v.logs ?? [];
  if (v.err) {
    const tail = logs.slice(-6);
    const reason = lazorkitError(v.err, programs, logs)?.code === SIGNATURE_REUSED ? { reason: 'stale_counter' } : {};
    throw new PolicyError(
      ERR.SIMULATION_FAILED,
      `relayer rejected: simulation failed: ${JSON.stringify(v.err)}${explainTxError(v.err, programs, logs)}${tail.length ? ` | logs: ${tail.join(' / ')}` : ''}`,
      { rule: 'simulation', err: v.err, logs, ...reason },
    );
  }

  // Inner instructions (CPIs) must be on the allowlist too.
  const innerPrograms = [];
  for (const group of v.innerInstructions ?? []) {
    for (const ix of group.instructions ?? []) {
      const programId = ix.programId;
      if (!innerPrograms.includes(programId)) innerPrograms.push(programId);
      if (!ALLOWED_PROGRAMS.has(programId)) {
        throw new PolicyError(
          ERR.REJECTED,
          `relayer rejected: instruction #${group.index} makes an inner call to ${programLabel(programId)} (${programId}), which is not in the relayer allowlist.`,
          { rule: 'program_not_allowed', index: group.index, programId, inner: true },
        );
      }
    }
  }

  // How much the fee payer loses (fee + anything the transaction moves out of it).
  const post = v.accounts?.[0]?.lamports;
  let payerDelta = null;
  if (typeof post === 'number' && typeof preBalance === 'number') {
    payerDelta = post - preBalance; // negative = spent
    if (-payerDelta > maxLamports) {
      throw new PolicyError(
        ERR.REJECTED,
        `relayer rejected: the fee payer would lose ${-payerDelta} lamports, over the ${maxLamports}-lamport cap.`,
        { rule: 'max_allowed_lamports', payerDelta, maxLamports },
      );
    }
  } else {
    throw new PolicyError(ERR.SIMULATION_FAILED, 'relayer rejected: simulation did not report the fee payer balance.', {
      rule: 'simulation',
    });
  }

  return { innerPrograms, payerDelta, unitsConsumed: v.unitsConsumed ?? null, logs, contextSlot: body.result.context?.slot ?? null };
}
