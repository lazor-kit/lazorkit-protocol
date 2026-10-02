// Presentational card for the migration flow. Drop it near your wallet UI; it
// renders nothing until it detects a v1 wallet, then walks the user through the
// one action that moves their assets to v2. Restyle freely — this is a skeleton.

import { useV1Migration, type UseV1MigrationParams, type MigrationAssets } from './useV1Migration';

const LAMPORTS_PER_SOL = 1_000_000_000n;

function formatSol(lamports: bigint): string {
  const whole = lamports / LAMPORTS_PER_SOL;
  const frac = (lamports % LAMPORTS_PER_SOL).toString().padStart(9, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

function short(addr: string): string {
  return `${addr.slice(0, 4)}…${addr.slice(-4)}`;
}

function AssetList({ assets }: { assets: MigrationAssets }) {
  return (
    <ul style={{ listStyle: 'none', padding: 0, margin: '12px 0', display: 'grid', gap: 6 }}>
      <li style={{ display: 'flex', justifyContent: 'space-between' }}>
        <span>SOL</span>
        <span>{formatSol(assets.sol)}</span>
      </li>
      {assets.tokens.map((t) => (
        <li key={t.mint} style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span>{short(t.mint)}</span>
          <span>{t.amount.toString()}</span>
        </li>
      ))}
    </ul>
  );
}

export function MigrateWalletCard(props: UseV1MigrationParams) {
  const { status, migrate, refresh } = useV1Migration(props);

  // Nothing to migrate, or still checking — show no banner.
  if (status.phase === 'none' || status.phase === 'detecting') return null;

  const card: React.CSSProperties = {
    border: '1px solid #e5e3db',
    borderRadius: 12,
    padding: 16,
    maxWidth: 420,
    fontFamily: 'system-ui, sans-serif',
  };

  if (status.phase === 'done') {
    return (
      <div style={card} role="status">
        <strong>Wallet migrated</strong>
        <p style={{ margin: '8px 0 0', color: '#5f5e5a' }}>
          Your assets are in your v2 wallet. You can transact normally now.
        </p>
      </div>
    );
  }

  const busy = status.phase === 'migrating';
  const assets = status.phase === 'ready' || status.phase === 'migrating' ? status.assets : status.assets;

  return (
    <div style={card}>
      <strong>Migrate your wallet</strong>
      <p style={{ margin: '8px 0 0', color: '#5f5e5a' }}>
        A protocol upgrade moved your wallet to v2. Approve once to move everything across — it
        stays safe in the meantime.
      </p>

      {assets && <AssetList assets={assets} />}

      {status.phase === 'error' && (
        <p style={{ color: '#a32d2d', margin: '8px 0 0' }}>{status.message}</p>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <button
          type="button"
          onClick={migrate}
          disabled={busy}
          style={{
            padding: '10px 16px',
            borderRadius: 8,
            border: 'none',
            background: busy ? '#b4b2a9' : '#1d1d1b',
            color: '#fff',
            cursor: busy ? 'default' : 'pointer',
          }}
        >
          {busy
            ? status.step === 'setup'
              ? 'Preparing…'
              : 'Approve in your passkey…'
            : status.phase === 'error'
              ? 'Try again'
              : 'Migrate now'}
        </button>
        {status.phase === 'error' && (
          <button type="button" onClick={refresh} style={{ padding: '10px 16px', borderRadius: 8 }}>
            Refresh
          </button>
        )}
      </div>
    </div>
  );
}
