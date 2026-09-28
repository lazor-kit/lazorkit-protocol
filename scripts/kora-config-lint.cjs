#!/usr/bin/env node
// Static check of the Kora configs in deploy/kora against the two-id rollout.
//
// kora-check.cjs probes a live relayer; this reads the files that relayers are
// built from, so a wrong id is caught in review rather than in production. On
// 2026-09-28 the mainnet file allowed the v2 id but still *required* the v1 one
// — a relayer that would have refused every transaction, v1 and v2 alike.
//
//   node scripts/kora-config-lint.cjs            # exit 1 on any failure
'use strict';
const fs = require('fs');
const path = require('path');

const FILES = {
  mainnet: { v2: 'LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8', v1: 'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi' },
  devnet: { v2: '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv', v1: '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS' },
};

/** The uncommented string entries of a TOML array `key = [ ... ]`. */
function arrayEntries(toml, key) {
  const m = toml.match(new RegExp(`^${key}\\s*=\\s*\\[([\\s\\S]*?)^\\]`, 'm'));
  if (!m) return null;
  return m[1]
    .split('\n')
    .map((l) => l.replace(/#.*$/, ''))
    .flatMap((l) => [...l.matchAll(/"([^"]+)"/g)].map((x) => x[1]));
}

let failed = 0;
for (const [cluster, ids] of Object.entries(FILES)) {
  const file = path.join(__dirname, '..', 'deploy', 'kora', `kora.${cluster}.toml`);
  const toml = fs.readFileSync(file, 'utf8');
  for (const key of ['allowed_programs', 'require_one_of_programs']) {
    const entries = arrayEntries(toml, key);
    const fail = (why) => {
      failed++;
      console.log(`FAIL  ${cluster} ${key}: ${why}`);
    };
    if (!entries) {
      fail('missing');
      continue;
    }
    if (!entries.includes(ids.v2)) fail(`does not list the v2 program ${ids.v2}`);
    // The v1 id belongs here only once it runs the sunset binary (H-3); that
    // is a deliberate edit at phase B, so it fails until the file says so.
    if (entries.includes(ids.v1) && !/PHASE_B_SUNSET_LIVE/.test(toml)) {
      fail(`lists the v1 program ${ids.v1} before phase B`);
    }
    if (entries.includes(ids.v2) && !(entries.includes(ids.v1) && !/PHASE_B_SUNSET_LIVE/.test(toml))) {
      console.log(`ok    ${cluster} ${key}`);
    }
  }
}
process.exit(failed ? 1 : 0);
