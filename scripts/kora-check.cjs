#!/usr/bin/env node
// Check a Kora paymaster against what protocol v2 needs, from the outside.
//
// Everything here is a read: `getConfig`, and a GET for the metrics path. It
// sends no transaction and needs no key — which is itself the first finding,
// because a relayer that answers `getConfig` to a stranger is a relayer with no
// authentication.
//
//   node scripts/kora-check.cjs <url> [--cluster mainnet|devnet] [--key <api key>]
//
// Exit code is 1 if anything FAILs, so it can gate a deploy.
'use strict';

const SYSTEM = '11111111111111111111111111111111';
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
const SECP256R1 = 'Secp256r1SigVerify1111111111111111111111111';
const LAZORKIT = {
  mainnet: 'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi',
  devnet: '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS',
};

// Every program a sponsored v2 transaction can name. Kora matches each
// instruction's program id exactly, with no exemption for precompiles, so a
// missing entry here is a refusal at the relayer — before anything reaches the
// chain.
function required(cluster) {
  return [
    [LAZORKIT[cluster], 'the LazorKit program itself'],
    [SECP256R1, 'the passkey precompile — every v2 user action carries one'],
    [SYSTEM, 'account creation and lamport transfers'],
    [TOKEN, 'SPL token transfers'],
    [ATA, 'creating the destination token account'],
    [COMPUTE_BUDGET, 'the compute-limit instruction the SDK prepends'],
  ];
}

const optional = [
  [TOKEN_2022, 'Token-2022 mints; a wallet holding one cannot migrate without it'],
];

async function rpc(url, method, apiKey) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* not JSON — an HTML error page from the host, say */
  }
  return { status: res.status, json, text };
}

function main() {
  const args = process.argv.slice(2);
  const url = args.find((a) => !a.startsWith('--'));
  const cluster = args.includes('--cluster') ? args[args.indexOf('--cluster') + 1] : 'devnet';
  const apiKey = args.includes('--key') ? args[args.indexOf('--key') + 1] : process.env.KORA_API_KEY;
  if (!url || !LAZORKIT[cluster]) {
    console.error('usage: kora-check.cjs <url> [--cluster mainnet|devnet] [--key <api key>]');
    process.exit(2);
  }
  return run(url, cluster, apiKey);
}

let failures = 0;
const line = (state, label, detail) => {
  if (state === false) failures++;
  const tag = state === false ? 'FAIL' : state === true ? 'PASS' : state === 'warn' ? 'WARN' : 'INFO';
  console.log(`${tag}  ${label.padEnd(20)} ${detail}`);
};

async function run(url, cluster, apiKey) {
  console.log(`${url}  (${cluster})\n`);

  // 1. Authentication. `liveness` is exempt from both auth layers by name, so
  //    it proves nothing; `getConfig` is the honest probe.
  const anonymous = await rpc(url, 'getConfig');
  const authed = apiKey ? await rpc(url, 'getConfig', apiKey) : null;
  if (anonymous.status === 200 && anonymous.json?.result) {
    line(false, 'authentication', 'none — getConfig answers a stranger with no x-api-key');
  } else if (anonymous.status === 401) {
    line(true, 'authentication', 'anonymous getConfig is refused (401)');
    if (authed && authed.status !== 200) {
      line(false, 'api key', `the supplied key was also refused (${authed.status})`);
    } else if (authed) {
      line(true, 'api key', 'the supplied key is accepted');
    }
  } else {
    line('warn', 'authentication', `anonymous getConfig answered ${anonymous.status}`);
  }

  const config = (authed?.json?.result ?? anonymous.json?.result) || null;
  if (!config) {
    line(false, 'getConfig', `no config readable (${anonymous.status}); pass --key to check the rest`);
    return finish();
  }

  const validation = config.validation_config ?? config.validation ?? {};
  const programs = validation.allowed_programs ?? [];

  for (const [id, why] of required(cluster)) {
    line(programs.includes(id), `program`, `${id.slice(0, 12)}…  ${why}`);
  }
  for (const [id, why] of optional) {
    line(programs.includes(id) ? true : 'warn', 'program', `${id.slice(0, 12)}…  ${why}`);
  }
  const extra = programs.filter(
    (p) => !required(cluster).some(([id]) => id === p) && !optional.some(([id]) => id === p),
  );
  if (extra.length) {
    line('warn', 'extra programs', `${extra.length} beyond what v2 needs: ${extra.join(', ')}`);
  }

  // 2. The cap. Kora simulates first and counts what the fee payer actually
  //    loses, so wallet creation (Wallet + Authority rent, plus the one-time
  //    FeeRecord) has to fit under it.
  const cap = Number(validation.max_allowed_lamports ?? 0);
  const needed = 4_000_000; // ~0.00285 SOL of rent + the FeeRecord's ~0.00111
  line(
    cap >= needed,
    'lamport cap',
    `${(cap / 1e9).toFixed(4)} SOL per transaction` +
      (cap >= needed ? '' : ` — below the ~${(needed / 1e9).toFixed(4)} SOL a wallet creation costs the payer`),
  );

  const signers = Number(validation.max_signatures ?? 0);
  line(signers >= 2 ? true : 'warn', 'max signatures', String(signers));

  const price = validation.price?.type ?? validation.price_source ?? 'unknown';
  line(price === 'free' ? 'warn' : null, 'price policy', `${price}${price === 'free' ? ' — the sponsor pays for everything' : ''}`);

  // 3. What the fee payer itself is allowed to be used for. Our own flows need
  //    the payer to fund PDAs and to pay the protocol fee, so `system.transfer`
  //    and `system.create_account` have to stay open — which means the cap and
  //    the usage limit are the only things bounding a stranger, and an
  //    unauthenticated relayer with a permissive policy is a faucet.
  const policy = validation.fee_payer_policy ?? {};
  const permissive = [];
  for (const [section, flags] of Object.entries(policy)) {
    if (!flags || typeof flags !== 'object') continue;
    for (const [flag, value] of Object.entries(flags)) {
      if (value === true) permissive.push(`${section}.${flag}`);
    }
  }
  const drains = permissive.filter((p) =>
    /^(system\.allow_transfer|spl_token\.allow_(transfer|mint_to|set_authority|close_account)|token_2022\.allow_(transfer|mint_to|set_authority|close_account))$/.test(p),
  );
  const openRelayer = anonymous.status === 200 && !!anonymous.json?.result;
  line(
    drains.length === 0 ? true : openRelayer ? false : 'warn',
    'fee payer policy',
    drains.length === 0
      ? 'the payer cannot be the source of a transfer'
      : `${drains.join(', ')}` +
        (openRelayer
          ? ` — with no authentication, anyone can spend up to the cap per transaction, repeatedly`
          : ' — bounded only by the cap and the usage limit'),
  );

  const limit = validation.usage_limit ?? config.usage_limit ?? null;
  line(
    limit && limit.enabled ? true : 'warn',
    'usage limit',
    limit && limit.enabled ? `max ${limit.max_transactions} per user` : 'disabled — no per-caller ceiling',
  );

  const methods = config.enabled_methods ?? {};
  const signing = ['sign_transaction', 'sign_and_send_transaction', 'transfer_transaction'].filter((m) => methods[m]);
  line(null, 'signing methods', signing.join(', ') || 'none enabled');

  // 3. Metrics share the RPC port when they are mounted before the auth layer,
  //    which makes them readable by anyone who can reach the relayer.
  const metrics = await fetch(new URL('/metrics', url).toString()).then(
    (r) => r.status,
    () => null,
  );
  line(
    metrics === 200 ? 'warn' : true,
    'metrics',
    metrics === 200
      ? 'served on the RPC port, outside the auth layer'
      : `not on the RPC port (${metrics ?? 'unreachable'})`,
  );

  return finish();
}

function finish() {
  console.log('');
  console.log(failures === 0 ? 'no failures' : `${failures} FAIL`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
