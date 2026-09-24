#!/usr/bin/env npx tsx
/**
 * The v1 estate as a ledger: how many accounts, how much rent sits in them, what
 * the vaults still hold, and — the part that decides the upgrade order — which
 * of it has a close path after v2 lands and which does not.
 *
 * Rent is not a detail here. Every v1 PDA holds its rent exemption, and the
 * upgraded binary does not understand v1 discriminators, so an account with no
 * close path before the upgrade keeps its rent forever.
 *
 * What closes, and who gets the lamports:
 *   Wallet + Authority   `MigrateWallet`, authorised by the wallet's Owner. The
 *                        rent goes to that transaction's refund destination —
 *                        the payer, which for a sponsored migration is us.
 *   Vault                not closed; emptied. Its SOL and tokens move to the
 *                        user's v2 vault. This is the user's money, never ours.
 *   Session              `RevokeSession` on the *v1* binary. After the upgrade
 *                        there is no instruction that will touch it again.
 *   DeferredExec         `ReclaimDeferred` on the v1 binary, same story.
 *
 * Read-only. Touches no keys, signs nothing.
 *
 *   npx tsx scripts/survey-v1-rent.ts --cluster mainnet
 *   npx tsx scripts/survey-v1-rent.ts --rpc https://...   # gPA-friendly endpoint
 *   npx tsx scripts/survey-v1-rent.ts --json > report.json
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
type ClusterName = keyof typeof CLUSTERS;

// v1 discriminators. v2 renumbers every one of them into the 0x2N range, which
// is what makes these accounts unreadable after the upgrade.
const DISC_NAMES: Record<number, string> = {
  1: 'Wallet',
  2: 'Authority',
  3: 'Session',
  4: 'DeferredExec',
  5: 'ProtocolConfig',
  6: 'FeeRecord',
  7: 'TreasuryShard',
};

// Which instruction closes each type, and whether that instruction still exists
// after the upgrade.
const CLOSE_PATH: Record<string, { how: string; survivesUpgrade: boolean }> = {
  Wallet: { how: 'MigrateWallet (Owner)', survivesUpgrade: true },
  Authority: { how: 'MigrateWallet (Owner)', survivesUpgrade: true },
  Session: { how: 'RevokeSession (v1 only)', survivesUpgrade: false },
  DeferredExec: { how: 'ReclaimDeferred (v1 only)', survivesUpgrade: false },
  ProtocolConfig: { how: 'none — reused by v2 under a new seed', survivesUpgrade: false },
  FeeRecord: { how: 'none', survivesUpgrade: false },
  TreasuryShard: { how: 'WithdrawTreasury drains it; the account stays', survivesUpgrade: false },
};

const TOKEN_PROGRAMS = [
  new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
  new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'),
];

const sol = (lamports: number) => (lamports / 1e9).toFixed(6);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Public RPCs rate-limit hard on the per-vault calls; retry rather than lose the run. */
async function withRetry<T>(label: string, fn: () => Promise<T>, tries = 5): Promise<T> {
  let lastError: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e) {
      lastError = e;
      await sleep(400 * 2 ** i);
    }
  }
  throw new Error(`${label} failed after ${tries} tries: ${(lastError as Error)?.message}`);
}

interface TypeRow {
  type: string;
  count: number;
  bytes: number;
  lamports: number;
  how: string;
  survivesUpgrade: boolean;
}

interface TokenRow {
  mint: string;
  accounts: number;
  amount: string;
  /** Rent held by the token accounts themselves — reclaimed when they close. */
  lamports: number;
}

async function survey(cluster: ClusterName, rpcOverride?: string) {
  const { programId: programIdStr, rpc: defaultRpc } = CLUSTERS[cluster];
  const programId = new PublicKey(programIdStr);
  const connection = new Connection(rpcOverride ?? defaultRpc, 'confirmed');

  const accounts = await withRetry('getProgramAccounts', () =>
    connection.getProgramAccounts(programId),
  );

  const byType = new Map<string, TypeRow>();
  const wallets: PublicKey[] = [];
  let unknown = 0;
  let unknownLamports = 0;

  for (const { pubkey, account } of accounts) {
    const name = DISC_NAMES[account.data[0]];
    if (!name) {
      unknown++;
      unknownLamports += account.lamports;
      continue;
    }
    const row = byType.get(name) ?? {
      type: name,
      count: 0,
      bytes: 0,
      lamports: 0,
      ...CLOSE_PATH[name],
    };
    row.count++;
    row.bytes += account.data.length;
    row.lamports += account.lamports;
    byType.set(name, row);
    if (name === 'Wallet') wallets.push(pubkey);
  }

  // Vaults are system-owned, so they never come back from getProgramAccounts.
  const vaults = wallets.map(
    (w) => PublicKey.findProgramAddressSync([Buffer.from('vault'), w.toBuffer()], programId)[0],
  );
  let vaultLamports = 0;
  let fundedVaults = 0;
  for (let i = 0; i < vaults.length; i += 100) {
    const infos = await withRetry('getMultipleAccounts', () =>
      connection.getMultipleAccountsInfo(vaults.slice(i, i + 100)),
    );
    for (const info of infos) {
      const lamports = info?.lamports ?? 0;
      if (lamports > 0) {
        vaultLamports += lamports;
        fundedVaults++;
      }
    }
  }

  // Tokens, one owner at a time — there is no batch form of this call. Both
  // token programs, because a Token-2022 balance is just as stranded.
  const tokens = new Map<string, TokenRow>();
  let vaultsWithTokens = 0;
  let tokenAccountLamports = 0;
  let tokenAccounts = 0;
  for (const vault of vaults) {
    let found = false;
    for (const programIdToken of TOKEN_PROGRAMS) {
      const res = await withRetry(`getTokenAccountsByOwner ${vault.toBase58()}`, () =>
        connection.getParsedTokenAccountsByOwner(vault, { programId: programIdToken }),
      );
      for (const { account } of res.value) {
        const info = (account.data as unknown as { parsed: { info: Record<string, unknown> } })
          .parsed.info;
        const mint = String(info.mint);
        const amount = String(
          (info.tokenAmount as { amount: string; uiAmountString?: string }).amount,
        );
        const row = tokens.get(mint) ?? { mint, accounts: 0, amount: '0', lamports: 0 };
        row.accounts++;
        row.amount = (BigInt(row.amount) + BigInt(amount)).toString();
        row.lamports += account.lamports;
        tokens.set(mint, row);
        tokenAccountLamports += account.lamports;
        tokenAccounts++;
        found = true;
      }
      await sleep(120);
    }
    if (found) vaultsWithTokens++;
  }

  const rows = [...byType.values()].sort((a, b) => b.lamports - a.lamports);
  const reclaimable = rows.filter((r) => r.survivesUpgrade).reduce((n, r) => n + r.lamports, 0);
  const strandedIfNotClosedFirst = rows
    .filter((r) => !r.survivesUpgrade)
    .reduce((n, r) => n + r.lamports, 0);

  return {
    cluster,
    programId: programIdStr,
    surveyedAt: new Date().toISOString(),
    accounts: accounts.length,
    unknown,
    unknownLamports,
    rows,
    wallets: wallets.length,
    fundedVaults,
    vaultLamports,
    vaultsWithTokens,
    tokenAccounts,
    tokenAccountLamports,
    tokens: [...tokens.values()].sort((a, b) => b.accounts - a.accounts),
    reclaimable,
    strandedIfNotClosedFirst,
  };
}

function print(r: Awaited<ReturnType<typeof survey>>) {
  console.log(`\n=== ${r.cluster} — ${r.programId} ===`);
  console.log(`surveyed ${r.surveyedAt}\n`);
  console.log('account            count      bytes        rent (SOL)   closed by');
  for (const row of r.rows) {
    console.log(
      `${row.type.padEnd(16)} ${String(row.count).padStart(6)} ${String(row.bytes).padStart(10)} ${sol(
        row.lamports,
      ).padStart(14)}   ${row.how}${row.survivesUpgrade ? '' : '  ← v1 only'}`,
    );
  }
  if (r.unknown) console.log(`(${r.unknown} accounts with an unrecognised discriminator)`);

  console.log(`\nvaults: ${r.fundedVaults} of ${r.wallets} hold SOL — ${sol(r.vaultLamports)} SOL`);
  console.log(
    `        ${r.vaultsWithTokens} hold tokens — ${r.tokenAccounts} token accounts, ${sol(
      r.tokenAccountLamports,
    )} SOL of rent in them`,
  );
  for (const t of r.tokens) {
    console.log(`        ${t.mint}  ${t.accounts} account(s)  raw amount ${t.amount}`);
  }

  console.log('\nrent ledger');
  console.log(
    `  reclaimable through migration      ${sol(r.reclaimable).padStart(12)} SOL  (to whoever pays each migration)`,
  );
  console.log(
    `  stranded unless closed before v2   ${sol(r.strandedIfNotClosedFirst).padStart(12)} SOL  (Session, DeferredExec, and the rest)`,
  );
  console.log(
    `  user assets in vaults              ${sol(r.vaultLamports).padStart(12)} SOL + tokens — moved by migration, never ours`,
  );

  if (r.strandedIfNotClosedFirst > 0) {
    console.log(
      `\n  UPGRADE ORDER: close the v1-only accounts BEFORE the upgrade. After it,` +
        `\n  no instruction in the binary will accept a v1 discriminator, and that` +
        `\n  ${sol(r.strandedIfNotClosedFirst)} SOL stays where it is permanently.`,
    );
  }
}

async function main() {
  const args = process.argv.slice(2);
  const cluster = (args.includes('--cluster')
    ? args[args.indexOf('--cluster') + 1]
    : 'mainnet') as ClusterName;
  const rpc = args.includes('--rpc') ? args[args.indexOf('--rpc') + 1] : undefined;
  if (!CLUSTERS[cluster]) throw new Error(`unknown cluster ${cluster}`);

  const report = await survey(cluster, rpc);
  if (args.includes('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    print(report);
  }
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
