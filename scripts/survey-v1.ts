#!/usr/bin/env npx tsx
/**
 * Survey the deployed v1 program before the v2 upgrade.
 *
 * Keeping the vanity program ID means v1 PDAs stay at addresses the upgraded
 * binary owns but no longer understands. Anything a v1 vault still holds becomes
 * unreachable the moment v2 lands, because the only spend path is `Execute` with
 * a live v1 authority. So this has to run, and any funded vault has to be swept
 * through the legitimate Owner path on the *current* binary, before the upgrade.
 *
 * It also answers the C-1 question: is ProtocolConfig initialized, and who holds
 * `admin`. On an uninitialized deployment that slot is claimable by anyone.
 *
 * Read-only. Touches no keys, signs nothing.
 *
 *   npx tsx scripts/survey-v1.ts                      # both clusters
 *   npx tsx scripts/survey-v1.ts --cluster mainnet
 *   npx tsx scripts/survey-v1.ts --rpc https://...    # custom endpoint
 *   npx tsx scripts/survey-v1.ts --json > docs/survey-v1.json
 */

import { Connection, PublicKey } from '@solana/web3.js';

// v1 discriminators (state/mod.rs). v2 renumbers these; these are the old values.
const DISC_WALLET = 1;
const DISC_AUTHORITY = 2;
const DISC_SESSION = 3;
const DISC_DEFERRED = 4;
const DISC_PROTOCOL_CONFIG = 5;
const DISC_FEE_RECORD = 6;
const DISC_TREASURY_SHARD = 7;

const DISC_NAMES: Record<number, string> = {
  [DISC_WALLET]: 'Wallet',
  [DISC_AUTHORITY]: 'Authority',
  [DISC_SESSION]: 'Session',
  [DISC_DEFERRED]: 'DeferredExec',
  [DISC_PROTOCOL_CONFIG]: 'ProtocolConfig',
  [DISC_FEE_RECORD]: 'FeeRecord',
  [DISC_TREASURY_SHARD]: 'TreasuryShard',
};

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

interface VaultRow {
  wallet: string;
  vault: string;
  lamports: number;
}

interface ClusterReport {
  cluster: ClusterName;
  programId: string;
  rpc: string;
  programDeployed: boolean;
  accountsByType: Record<string, number>;
  unknownDiscriminators: Record<string, number>;
  wallets: number;
  fundedVaults: VaultRow[];
  totalVaultLamports: number;
  protocolConfig:
    | { initialized: false }
    | {
        initialized: true;
        address: string;
        admin: string;
        treasury: string;
        enabled: number;
        numShards: number;
        creationFee: string;
        executionFee: string;
      };
}

function parseArgs() {
  const argv = process.argv.slice(2);
  const json = argv.includes('--json');
  const clusterIdx = argv.indexOf('--cluster');
  const rpcIdx = argv.indexOf('--rpc');
  const cluster = clusterIdx >= 0 ? (argv[clusterIdx + 1] as ClusterName) : undefined;
  const rpcOverride = rpcIdx >= 0 ? argv[rpcIdx + 1] : undefined;

  if (cluster && !(cluster in CLUSTERS)) {
    throw new Error(`unknown cluster "${cluster}" — expected mainnet or devnet`);
  }
  return { json, cluster, rpcOverride };
}

async function surveyCluster(
  cluster: ClusterName,
  rpcOverride?: string,
): Promise<ClusterReport> {
  const { programId: programIdStr, rpc: defaultRpc } = CLUSTERS[cluster];
  const rpc = rpcOverride ?? defaultRpc;
  const programId = new PublicKey(programIdStr);
  const connection = new Connection(rpc, 'confirmed');

  const programInfo = await connection.getAccountInfo(programId);
  const programDeployed = Boolean(programInfo?.executable);

  // One pass over every account the program owns. Public RPC endpoints often
  // refuse unfiltered getProgramAccounts; --rpc lets you point at one that won't.
  const accounts = await connection.getProgramAccounts(programId);

  const accountsByType: Record<string, number> = {};
  const unknownDiscriminators: Record<string, number> = {};
  const walletKeys: PublicKey[] = [];
  let protocolConfig: ClusterReport['protocolConfig'] = { initialized: false };

  for (const { pubkey, account } of accounts) {
    const disc = account.data[0];
    const name = DISC_NAMES[disc];
    if (!name) {
      const key = `0x${disc.toString(16).padStart(2, '0')}`;
      unknownDiscriminators[key] = (unknownDiscriminators[key] ?? 0) + 1;
      continue;
    }
    accountsByType[name] = (accountsByType[name] ?? 0) + 1;

    if (disc === DISC_WALLET) walletKeys.push(pubkey);

    if (disc === DISC_PROTOCOL_CONFIG && account.data.length >= 88) {
      const d = account.data;
      protocolConfig = {
        initialized: true,
        address: pubkey.toBase58(),
        admin: new PublicKey(d.subarray(8, 40)).toBase58(),
        treasury: new PublicKey(d.subarray(40, 72)).toBase58(),
        enabled: d[3],
        numShards: d[4],
        creationFee: d.readBigUInt64LE(72).toString(),
        executionFee: d.readBigUInt64LE(80).toString(),
      };
    }
  }

  // Vaults are system-owned, so they never appear in getProgramAccounts. Derive
  // one per wallet and read its balance directly.
  const fundedVaults: VaultRow[] = [];
  let totalVaultLamports = 0;

  for (let i = 0; i < walletKeys.length; i += 100) {
    const batch = walletKeys.slice(i, i + 100);
    const vaults = batch.map(
      (w) => PublicKey.findProgramAddressSync([Buffer.from('vault'), w.toBuffer()], programId)[0],
    );
    const infos = await connection.getMultipleAccountsInfo(vaults);
    infos.forEach((info, j) => {
      const lamports = info?.lamports ?? 0;
      if (lamports > 0) {
        fundedVaults.push({
          wallet: batch[j].toBase58(),
          vault: vaults[j].toBase58(),
          lamports,
        });
        totalVaultLamports += lamports;
      }
    });
  }

  fundedVaults.sort((a, b) => b.lamports - a.lamports);

  return {
    cluster,
    programId: programIdStr,
    rpc,
    programDeployed,
    accountsByType,
    unknownDiscriminators,
    wallets: walletKeys.length,
    fundedVaults,
    totalVaultLamports,
    protocolConfig,
  };
}

function printReport(r: ClusterReport) {
  const sol = (l: number) => (l / 1e9).toFixed(9);

  console.log(`\n─── ${r.cluster} ──────────────────────────────────────────`);
  console.log(`program   ${r.programId}`);
  console.log(`rpc       ${r.rpc}`);
  console.log(`deployed  ${r.programDeployed ? 'yes' : 'NO'}`);

  console.log('\naccounts owned by the program:');
  const types = Object.entries(r.accountsByType);
  if (types.length === 0) {
    console.log('  (none)');
  } else {
    for (const [name, n] of types.sort((a, b) => b[1] - a[1])) {
      console.log(`  ${name.padEnd(16)} ${n}`);
    }
  }
  for (const [disc, n] of Object.entries(r.unknownDiscriminators)) {
    console.log(`  ${`unknown ${disc}`.padEnd(16)} ${n}`);
  }

  console.log('\nProtocolConfig:');
  if (!r.protocolConfig.initialized) {
    console.log('  NOT INITIALIZED — the admin slot is claimable by anyone (C-1).');
  } else {
    const c = r.protocolConfig;
    console.log(`  address       ${c.address}`);
    console.log(`  admin         ${c.admin}`);
    console.log(`  treasury      ${c.treasury}`);
    console.log(`  enabled       ${c.enabled}`);
    console.log(`  num_shards    ${c.numShards}`);
    console.log(`  creation_fee  ${c.creationFee}`);
    console.log(`  execution_fee ${c.executionFee}`);
  }

  console.log(`\nvaults: ${r.fundedVaults.length} funded of ${r.wallets} wallets`);
  console.log(`total:  ${r.totalVaultLamports} lamports (${sol(r.totalVaultLamports)} SOL)`);
  for (const v of r.fundedVaults.slice(0, 20)) {
    console.log(`  ${v.vault}  ${sol(v.lamports).padStart(14)} SOL   (wallet ${v.wallet})`);
  }
  if (r.fundedVaults.length > 20) {
    console.log(`  … and ${r.fundedVaults.length - 20} more`);
  }

  if (r.totalVaultLamports > 0) {
    console.log(
      `\n  UPGRADE GATE: ${sol(r.totalVaultLamports)} SOL is still held in v1 vaults.\n` +
        `  Sweep it through the legitimate Owner path on the CURRENT binary before\n` +
        `  upgrading — v2 namespaces its PDA seeds, so these vaults become unreachable.`,
    );
  } else {
    console.log('\n  UPGRADE GATE: clear. No v1 vault holds lamports.');
  }
}

async function main() {
  const { json, cluster, rpcOverride } = parseArgs();
  const targets: ClusterName[] = cluster ? [cluster] : ['mainnet', 'devnet'];

  const reports: ClusterReport[] = [];
  for (const c of targets) {
    reports.push(await surveyCluster(c, rpcOverride));
  }

  if (json) {
    console.log(JSON.stringify({ surveyedAt: new Date().toISOString(), reports }, null, 2));
    return;
  }

  console.log('LazorKit v1 pre-upgrade survey');
  reports.forEach(printReport);
  console.log('');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
