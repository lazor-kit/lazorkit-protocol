#!/usr/bin/env node
// Fails the build when `@lazorkit/sdk-legacy/approval` reaches anything but
// itself, @noble/hashes and @noble/curves.
//
// The portal and React Native bundle this entry point on its own, without the
// polyfills @solana/web3.js and `buffer` need, so one stray import of the main
// SDK (which pulls both in) would break them only at bundle time, elsewhere.
// This walks the compiled module graph from dist/approval/index.js, following
// every require() and the noble entry points it names, and refuses any other
// package, any Node builtin, and any relative path that leaves dist/approval.
// It also requires the dist/approval files to load with no other module
// cached, then prints what the graph holds.

'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const entryDir = path.join(root, 'dist', 'approval');
const entry = path.join(entryDir, 'index.js');
const ALLOWED_PACKAGES = [/^@noble\/hashes(\/.*)?$/, /^@noble\/curves(\/.*)?$/];

if (!fs.existsSync(entry)) {
  console.error(`check-approval-imports: ${path.relative(root, entry)} not built`);
  process.exit(1);
}

const problems = [];
const seen = new Set();
const packages = new Set();
const queue = [entry];

while (queue.length) {
  const file = queue.pop();
  if (seen.has(file)) continue;
  seen.add(file);
  const src = fs.readFileSync(file, 'utf8');
  if (/\bimport\s*\(/.test(src)) problems.push(`${path.relative(root, file)}: dynamic import()`);
  const re = /\brequire\(\s*(['"])([^'"]+)\1\s*\)/g;
  let m;
  while ((m = re.exec(src))) {
    const spec = m[2];
    if (spec.startsWith('.')) {
      let target = path.resolve(path.dirname(file), spec);
      if (!target.endsWith('.js')) target = fs.existsSync(`${target}.js`) ? `${target}.js` : path.join(target, 'index.js');
      if (!target.startsWith(entryDir + path.sep)) {
        problems.push(`${path.relative(root, file)}: requires ${spec}, outside dist/approval`);
        continue;
      }
      queue.push(target);
    } else if (ALLOWED_PACKAGES.some((r) => r.test(spec))) {
      packages.add(spec);
    } else {
      problems.push(`${path.relative(root, file)}: requires "${spec}"`);
    }
  }
}

// Load it in isolation: nothing outside dist/approval and @noble may be loaded.
if (problems.length === 0) {
  require(entry);
  const loaded = Object.keys(require.cache).filter((f) => f !== __filename);
  for (const f of loaded) {
    const inside = f.startsWith(entryDir + path.sep);
    const noble = /[\\/]node_modules[\\/]@noble[\\/](hashes|curves)[\\/]/.test(f);
    if (!inside && !noble) problems.push(`loading the entry point loaded ${path.relative(root, f)}`);
  }
}

if (problems.length) {
  console.error('check-approval-imports: @lazorkit/sdk-legacy/approval must import only @noble/hashes and @noble/curves:');
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(
  `check-approval-imports: ok (${seen.size} modules; packages: ${[...packages].sort().join(', ')})`,
);
