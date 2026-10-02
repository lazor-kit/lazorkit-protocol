// @solana/kit 8.4.0, the oracle the wallets' v1 writer is checked against. It
// is not a dependency of the relayer: the tests that use it run when it can be
// found, and are skipped otherwise. Point them at an install with
//   TXV1_ORACLE_DIR=<lazor-kit>/tools/txv1-oracle   (after pnpm install there)
// or install @solana/kit@8.4.0 next to the relayer.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export const KIT_VERSION = '8.4.0';

/** { kit, version, from } or { kit: null, why }. */
export async function loadKit() {
  const bases = [process.env.TXV1_ORACLE_DIR, process.cwd()].filter(Boolean);
  for (const base of bases) {
    let resolved;
    try {
      resolved = createRequire(path.join(path.resolve(base), 'package.json')).resolve('@solana/kit');
    } catch {
      continue;
    }
    const version = packageVersion(resolved);
    if (version !== KIT_VERSION) return { kit: null, why: `@solana/kit ${version} found at ${resolved}, ${KIT_VERSION} is needed` };
    const mod = await import(pathToFileURL(resolved).href);
    return { kit: mod.getTransactionDecoder ? mod : mod.default, version, from: resolved };
  }
  return { kit: null, why: `@solana/kit ${KIT_VERSION} not found (set TXV1_ORACLE_DIR to lazor-kit's tools/txv1-oracle)` };
}

function packageVersion(file) {
  for (let dir = path.dirname(file); dir !== path.dirname(dir); dir = path.dirname(dir)) {
    const pj = path.join(dir, 'package.json');
    if (!fs.existsSync(pj)) continue;
    const json = JSON.parse(fs.readFileSync(pj, 'utf8'));
    if (json.name === '@solana/kit') return json.version;
  }
  return null;
}
