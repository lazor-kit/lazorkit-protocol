#!/usr/bin/env npx tsx
/**
 * Per-wallet detail for the v1 survey.
 *
 * `survey-v1.ts` answers "is the upgrade safe" with totals. This answers "who is
 * actually there": per wallet, what the vault holds in SOL *and in SPL tokens*,
 * what kind of key controls it, and when it was last used.
 *
 * The token part matters on its own. The first survey counted lamports only, so
 * a vault holding USDC and no SOL reads as empty — which would understate what
 * an in-place upgrade strands.
 *
 * Read-only. Touches no keys, signs nothing.
 *
 *   npx tsx scripts/survey-v1-wallets.ts                    # mainnet
 *   npx tsx scripts/survey-v1-wallets.ts --cluster devnet
 *   npx tsx scripts/survey-v1-wallets.ts --json > out.json
 */

import { Connection, PublicKey } from '@solana/web3.js';

const CLUSTERS = {
  mainnet: {
    programId: 'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi',
    rpc: 'https://api.mainnet-beta.solana.com',
  },
  devnet: {
    programId: '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS',
    rpc: 'https://api.devnet.solana.com',
  },
} as const;

const TOKEN_PROGRAM = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const TOKEN_2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');

// v1 discriminators.
const DISC_WALLET = 1;
const DISC_AUTHORITY = 2;
const DISC_SESSION = 3;

const AUTH_TYPE = ['ed25519', 'passkey'] as const;
const RANK = ['Owner', 'Admin', 'Spender'] as const;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Public RPC rate-limits hard; back off rather than losing rows. */
async function retry<T>(label: string, fn: () => Promise<T>, attempts = 6): Promise<T> {
  let wait = 400;
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i >= attempts - 1) throw new Error(`${label}: ${(e as Error).message}`);
      await sleep(wait);
      wait *= 2;
    }
  }
}

interface WalletRow {
  wallet: string;
  vault: string;
  lamports: number;
  tokens: { mint: string; amount: string; decimals: number; program: string }[];
  authorities: { pda: string; type: string; rank: string; counter: number; key: string }[];
  sessions: number;
  lastActivity: string | null;
}

async function main() {
  const argv = process.argv.slice(2);
  const json = argv.includes('--json');
  const ci = argv.indexOf('--cluster');
  const cluster = (ci >= 0 ? argv[ci + 1] : 'mainnet') as keyof typeof CLUSTERS;
  const cfg = CLUSTERS[cluster];
  if (!cfg) throw new Error(`unknown cluster: ${cluster}`);

  const rpcI = argv.indexOf('--rpc');
  const conn = new Connection(rpcI >= 0 ? argv[rpcI + 1]! : cfg.rpc, 'confirmed');
  const programId = new PublicKey(cfg.programId);

  const log = (...a: unknown[]) => { if (!json) console.log(...a); };

  log(`fetching program accounts on ${cluster}…`);
  const all = await retry('getProgramAccounts', () => conn.getProgramAccounts(programId));

  const wallets: PublicKey[] = [];
  const authorities: { pda: PublicKey; data: Buffer }[] = [];
  const sessionsByWallet = new Map<string, number>();

  for (const { pubkey, account } of all) {
    const d = account.data as Buffer;
    if (d.length === 0) continue;
    if (d[0] === DISC_WALLET) wallets.push(pubkey);
    else if (d[0] === DISC_AUTHORITY) authorities.push({ pda: pubkey, data: d });
    else if (d[0] === DISC_SESSION && d.length >= 40) {
      const w = new PublicKey(d.subarray(8, 40)).toBase58();
      sessionsByWallet.set(w, (sessionsByWallet.get(w) ?? 0) + 1);
    }
  }
  log(`  ${wallets.length} wallets, ${authorities.length} authorities`);

  // Authority header (v1): [disc(1)][type(1)][role(1)][bump(1)][ver(1)][pad(3)]
  //                       [counter(4)][pad(4)][wallet(32)] then key material.
  const authByWallet = new Map<string, WalletRow['authorities']>();
  for (const { pda, data } of authorities) {
    if (data.length < 48) continue;
    const wallet = new PublicKey(data.subarray(16, 48)).toBase58();
    const type = data[1]!;
    const key =
      type === 0
        ? new PublicKey(data.subarray(48, 80)).toBase58()
        : Buffer.from(data.subarray(48, 80)).toString('hex').slice(0, 16) + '… (cred hash)';
    const list = authByWallet.get(wallet) ?? [];
    list.push({
      pda: pda.toBase58(),
      type: AUTH_TYPE[type] ?? `unknown(${type})`,
      rank: RANK[data[2]!] ?? `unknown(${data[2]})`,
      counter: data.readUInt32LE(8),
      key,
    });
    authByWallet.set(wallet, list);
  }

  const vaults = wallets.map(
    (w) => PublicKey.findProgramAddressSync([Buffer.from('vault'), w.toBuffer()], programId)[0],
  );

  log('reading vault balances…');
  const lamports = new Map<string, number>();
  for (let i = 0; i < vaults.length; i += 100) {
    const chunk = vaults.slice(i, i + 100);
    const infos = await retry('getMultipleAccounts', () => conn.getMultipleAccountsInfo(chunk));
    infos.forEach((info, j) => lamports.set(chunk[j]!.toBase58(), info?.lamports ?? 0));
    await sleep(150);
  }

  log(`reading token accounts for ${vaults.length} vaults (this is the slow part)…`);
  const tokens = new Map<string, WalletRow['tokens']>();
  for (let i = 0; i < vaults.length; i++) {
    const v = vaults[i]!;
    const held: WalletRow['tokens'] = [];
    for (const [prog, name] of [
      [TOKEN_PROGRAM, 'spl-token'],
      [TOKEN_2022, 'token-2022'],
    ] as const) {
      const res = await retry(`getTokenAccountsByOwner ${v.toBase58()}`, () =>
        conn.getParsedTokenAccountsByOwner(v, { programId: prog }),
      );
      for (const { account } of res.value) {
        const info = (account.data as { parsed: { info: Record<string, any> } }).parsed.info;
        const amt = info.tokenAmount;
        if (amt.amount === '0') continue;
        held.push({
          mint: info.mint,
          amount: amt.uiAmountString ?? amt.amount,
          decimals: amt.decimals,
          program: name,
        });
      }
      await sleep(80);
    }
    if (held.length) tokens.set(v.toBase58(), held);
    if (!json && (i + 1) % 25 === 0) log(`  ${i + 1}/${vaults.length}`);
  }

  log('reading last activity per wallet…');
  const lastActivity = new Map<string, string | null>();
  for (let i = 0; i < wallets.length; i++) {
    const w = wallets[i]!;
    const sigs = await retry(`getSignaturesForAddress ${w.toBase58()}`, () =>
      conn.getSignaturesForAddress(w, { limit: 1 }),
    );
    const bt = sigs[0]?.blockTime;
    lastActivity.set(w.toBase58(), bt ? new Date(bt * 1000).toISOString().slice(0, 10) : null);
    await sleep(80);
    if (!json && (i + 1) % 25 === 0) log(`  ${i + 1}/${wallets.length}`);
  }

  const rows: WalletRow[] = wallets.map((w, i) => {
    const wk = w.toBase58();
    const vk = vaults[i]!.toBase58();
    return {
      wallet: wk,
      vault: vk,
      lamports: lamports.get(vk) ?? 0,
      tokens: tokens.get(vk) ?? [],
      authorities: authByWallet.get(wk) ?? [],
      sessions: sessionsByWallet.get(wk) ?? 0,
      lastActivity: lastActivity.get(wk) ?? null,
    };
  });
  rows.sort((a, b) => b.lamports - a.lamports);

  if (json) {
    console.log(JSON.stringify({ cluster, programId: cfg.programId, surveyedAt: new Date().toISOString(), wallets: rows }, null, 2));
    return;
  }

  const sol = (l: number) => (l / 1e9).toFixed(9).padStart(13);
  const funded = rows.filter((r) => r.lamports > 0);
  const withTokens = rows.filter((r) => r.tokens.length > 0);

  console.log(`\n─── ${cluster}: ${rows.length} wallets ───\n`);
  console.log('  SOL              tokens  auth              last use   wallet');
  for (const r of rows) {
    if (r.lamports === 0 && !r.tokens.length) continue;
    const kinds = r.authorities.map((a) => `${a.type[0]}:${a.rank[0]}`).join(',') || '—';
    console.log(
      `  ${sol(r.lamports)}  ${String(r.tokens.length).padStart(6)}  ${kinds.padEnd(16)}  ${(r.lastActivity ?? '—').padEnd(9)}  ${r.wallet}`,
    );
  }

  console.log(`\n  funded (SOL):     ${funded.length} of ${rows.length}`);
  console.log(`  holding tokens:   ${withTokens.length}`);
  console.log(`  empty entirely:   ${rows.length - new Set([...funded, ...withTokens].map((r) => r.wallet)).size}`);
  console.log(`  total SOL:        ${(funded.reduce((s, r) => s + r.lamports, 0) / 1e9).toFixed(9)}`);

  if (withTokens.length) {
    console.log('\n  token holdings:');
    for (const r of withTokens) {
      for (const t of r.tokens) {
        console.log(`    ${t.amount.padStart(20)}  ${t.mint}  (${t.program})  vault ${r.vault}`);
      }
    }
  }
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
