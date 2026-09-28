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

/**
 * The string entries of a TOML array `key = [ ... ]`, comments ignored. Scans
 * character by character so an inline array, an indented `]`, or a `]`
 * inside a comment cannot make it read into the next table.
 */
function arrayEntries(toml, key) {
  const start = toml.search(new RegExp(`^\\s*${key}\\s*=\\s*\\[`, 'm'));
  if (start < 0) return null;
  const entries = [];
  let i = toml.indexOf('[', start) + 1;
  while (i < toml.length) {
    const c = toml[i];
    if (c === '#') i = toml.indexOf('\n', i) < 0 ? toml.length : toml.indexOf('\n', i);
    else if (c === '"') {
      const end = toml.indexOf('"', i + 1);
      entries.push(toml.slice(i + 1, end));
      i = end + 1;
    } else if (c === ']') return entries;
    else i++;
  }
  return null;
}

let failed = 0;
for (const [cluster, ids] of Object.entries(FILES)) {
  const file = path.join(__dirname, '..', 'deploy', 'kora', `kora.${cluster}.toml`);
  const toml = fs.readFileSync(file, 'utf8');
  const phaseB = /PHASE_B_SUNSET_LIVE/.test(toml);
  const fail = (why) => {
    failed++;
    console.log(`FAIL  ${cluster}: ${why}`);
  };
  const allowed = arrayEntries(toml, 'allowed_programs');
  const required = arrayEntries(toml, 'require_one_of_programs');
  if (!allowed) fail('allowed_programs missing');
  if (!required) fail('require_one_of_programs missing');
  if (!allowed || !required) continue;

  for (const [name, list] of [['allowed_programs', allowed], ['require_one_of_programs', required]]) {
    if (!list.includes(ids.v2)) fail(`${name} does not list the v2 program ${ids.v2}`);
    // The v1 id belongs here only once it runs the sunset binary (H-3); that
    // is a deliberate edit at phase B, so it fails until the file says so.
    if (list.includes(ids.v1) && !phaseB) fail(`${name} lists the v1 program ${ids.v1} before phase B`);
  }
  // A required program the relayer does not allow refuses every transaction
  // that needs it; the two lists have to move together.
  for (const id of required) {
    if (!allowed.includes(id)) fail(`require_one_of_programs lists ${id}, which allowed_programs does not`);
  }
  if (allowed.includes(ids.v1) !== required.includes(ids.v1)) {
    fail(`the v1 program ${ids.v1} is in one list but not the other`);
  }
  if (!failed) console.log(`ok    ${cluster}`);
}
process.exit(failed ? 1 : 0);
