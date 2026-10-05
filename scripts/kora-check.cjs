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
// v2 ids. The v1 ids are listed separately: a relayer sponsoring migrations
// has to allow them too, because MigrateWallet executes against the v1 program.
const LAZORKIT = {
  mainnet: 'LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8',
  devnet: '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv',
};
const LAZORKIT_V1 = {
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

// The v1 program belongs on this relayer only once it runs the sunset binary
// (MigrateWallet executes there). Before that it is full v1, whose Execute
// forwards every outer signer into its CPIs — sponsoring it would let any v1
// wallet conscript this relayer's fee payer (H-3).
function migrationPrograms(cluster) {
  return [[LAZORKIT_V1[cluster], 'the v1 program']];
}

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

// The build we have read and reasoned about. Older ones are missing fixes we
// depend on; newer ones we simply have not checked.
const EXPECTED_VERSION = '2.2.0-beta.8';

async function run(url, cluster, apiKey) {
  console.log(`${url}  (${cluster})\n`);

  // 0. Which build is answering. `getVersion` needs no key on any build, and
  //    the controls below only behave as documented on beta.8 or later.
  const version = await rpc(url, 'getVersion', apiKey);
  const running = version.json?.result?.version ?? null;
  line(
    running === EXPECTED_VERSION ? true : running ? 'warn' : null,
    'version',
    running
      ? `${running}${running === EXPECTED_VERSION ? '' : ` — expected ${EXPECTED_VERSION}; older builds ignore the --api-key flag, key usage limits non-atomically, and leak the RPC URL's query string in error messages`}`
      : `not reported (${version.status})`,
  );

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
  for (const [id, why] of migrationPrograms(cluster)) {
    line(
      programs.includes(id) ? 'warn' : null,
      'v1 program',
      programs.includes(id)
        ? `${id.slice(0, 12)}… allowed — safe only if it already runs the sunset binary; full v1 lets a wallet conscript this fee payer (H-3)`
        : `${id.slice(0, 12)}… not allowed — add it once the sunset binary is live, for sponsored migrations`,
    );
  }
  const known = [...required(cluster), ...optional, ...migrationPrograms(cluster)];
  const extra = programs.filter((p) => !known.some(([id]) => id === p));
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
  //    and `system.create_account` have to stay open — which means a stranger
  //    is bounded only by `require_one_of_programs`, authentication, the cap
  //    and the payer's balance (usage limits are off in deploy/kora, and
  //    beta.8 applies `rate_limit` per connection, so it caps neither the total
  //    rate nor the spend; its README says more), and an unauthenticated
  //    relayer with a permissive policy is a faucet.
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
          : ' — bounded by authentication, the cap and the payer balance'),
  );

  // Usage limits. beta.8's getConfig returns only `fee_payers`,
  // `validation_config` and `enabled_methods`; `[kora.usage_limit]` lives
  // under `kora`, which it does not return. So on beta.8 this line cannot tell
  // on from off, and says so. If a build does expose the table, read it in
  // beta.8's shape: `enabled` plus `rules[]` of {type, max, window_seconds,
  // program?, instruction?}. Either way off is a WARN, because it is true:
  // there is no per-caller ceiling. deploy/kora/README.md says why ours is off.
  const limit = config.usage_limit ?? config.kora?.usage_limit ?? validation.usage_limit ?? null;
  const rules = Array.isArray(limit?.rules) ? limit.rules : [];
  const rule = (r) =>
    `${r.type === 'instruction' ? `${String(r.program).slice(0, 8)}…:${r.instruction}` : r.type} ` +
    `max ${r.max}${r.window_seconds ? `/${r.window_seconds}s` : ' lifetime'}`;
  if (!limit) {
    line(
      'warn',
      'usage limit',
      'not in getConfig (beta.8 does not expose it), so not checkable from here; ' +
        'the deploy/kora configs keep it off — see deploy/kora/README.md',
    );
  } else if (!limit.enabled) {
    line('warn', 'usage limit', 'disabled — no per-caller ceiling; see deploy/kora/README.md for why');
  } else if (price === 'free') {
    // beta.8 refuses any signing request without a `user_id` in this mode,
    // and neither @lazorkit/wallet nor @lazorkit/wallet-mobile-adapter sends one.
    line(
      'warn',
      'usage limit',
      `on (${rules.map(rule).join('; ') || 'no rules'}) with free pricing — every signing request must carry a user_id; see deploy/kora/README.md`,
    );
  } else {
    line(true, 'usage limit', `on — ${rules.map(rule).join('; ') || 'no rules'}`);
  }

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
