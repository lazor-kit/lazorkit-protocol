#!/usr/bin/env node
// Static check of the deploy commands the docs tell an operator to paste.
//
// Every `solana program deploy` or `solana program write-buffer` in a fenced
// code block has to name a program under target/artifacts/: the directory the
// release builds write with --sbf-out-dir, from a fresh target dir
// (mainnet-deploy-checklist.md §2, check-release-hashes.sh with OUT). Never
// target/deploy/: with CARGO_TARGET_DIR set (the cargo wrapper on the deploy
// machine points it at .git/shared-target) a bare `cargo build-sbf` writes
// elsewhere, and target/deploy/ keeps whatever was last copied there. On
// 2026-09-27 that file was a full-v2 build where the sunset one was meant, and
// until 2026-09-30 upgrade-procedure.md §6 still deployed it to mainnet.
//
// History (CHANGELOG.md, reviews, audits) records what was run, and is not
// checked.
//
//   node scripts/deploy-docs-lint.cjs            # exit 1 on any failure
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const HISTORY = [/^CHANGELOG\.md$/, /^audits\//, /^docs\/reviews\//, /^docs\/audit[^/]*\//, /^docs\/security-review-/];

/** The tracked Markdown files, history left out. */
function docs() {
  return execFileSync('git', ['ls-files', '*.md'], { cwd: root, encoding: 'utf8' })
    .split('\n')
    .filter((f) => f && !f.includes('node_modules/') && !HISTORY.some((re) => re.test(f)));
}

/**
 * The shell commands in the fenced code blocks of `md`, one per logical line
 * (backslash continuations joined), with the line each starts on.
 */
function fencedCommands(md) {
  const out = [];
  let fence = null;
  let pending = null;
  md.split('\n').forEach((raw, i) => {
    const line = raw.replace(/^\s*(?:[-*] \[[ x]\] )?/, '');
    const marker = line.match(/^(`{3,}|~{3,})/);
    if (marker) {
      if (!fence) fence = marker[1];
      else if (line.startsWith(fence)) {
        fence = null;
        pending = null;
      }
      return;
    }
    if (!fence) return;
    const text = raw.trim();
    if (pending) {
      pending.text += ' ' + text.replace(/\\$/, '');
    } else {
      pending = { line: i + 1, text: text.replace(/\\$/, '') };
    }
    if (!text.endsWith('\\')) {
      out.push(pending);
      pending = null;
    }
  });
  return out;
}

let failed = 0;
let checked = 0;
for (const file of docs()) {
  const md = fs.readFileSync(path.join(root, file), 'utf8');
  for (const { line, text } of fencedCommands(md)) {
    const cmd = text.replace(/#.*$/, '');
    if (!/\bsolana\s+program\s+(deploy|write-buffer)\b/.test(cmd)) continue;
    checked++;
    const so = cmd.split(/\s+/).find((w) => /\.so$/.test(w));
    if (!so) {
      failed++;
      console.log(`FAIL  ${file}:${line}: names no .so: ${text}`);
    } else if (!/^(\.\/)?target\/artifacts\//.test(so)) {
      failed++;
      console.log(`FAIL  ${file}:${line}: deploys ${so}, not a built artifact under target/artifacts/`);
    }
  }
}
console.log(failed ? `${failed} of ${checked} deploy commands fail` : `ok    ${checked} deploy commands`);
process.exit(failed ? 1 : 0);
