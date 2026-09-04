#!/usr/bin/env bash
# Live rehearsal of the v1 -> v2 in-place upgrade + MigrateWallet, on a local
# validator. Proves the two things the unit tests cannot: that a real
# `solana program deploy --upgrade` swaps the binary in place at a fixed
# address, and that v2's MigrateWallet then moves real SOL and SPL tokens out of
# a v1 vault it now owns but no longer natively understands.
#
# v1 accounts are preloaded at genesis (exact v1 bytes) rather than created by
# v1's fee/protocol ceremony — the ceremony is orthogonal to what we're proving.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/lazorkit-rehearse}"
mkdir -p "$SCRATCH"
OUT_DIR="$SCRATCH/rehearse"
PROGRAM_ID="4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS"   # devnet id (v2 M-2 pins this)
# The two binaries to swap between. Build v2 from HEAD and v1 from the commit
# before the seed rename (see docs/migration-v1-to-v2.md), then point these at
# them — or drop them in $SCRATCH as lazorkit_v{1,2}.so.
V1_SO="${V1_SO:-$SCRATCH/lazorkit_v1.so}"
V2_SO="${V2_SO:-$SCRATCH/lazorkit_v2.so}"
NODE_PATH="$REPO/tests-sdk/node_modules"
export NODE_PATH REPO OUT_DIR PROGRAM_ID
LEDGER="$SCRATCH/rehearse-ledger"

for f in "$V1_SO" "$V2_SO"; do
  [ -f "$f" ] || { echo "missing $f — build v1/v2 .so first"; exit 1; }
done
echo "v1 .so $(shasum -a 256 "$V1_SO" | cut -d' ' -f1)  ($(stat -f %z "$V1_SO") bytes)"
echo "v2 .so $(shasum -a 256 "$V2_SO" | cut -d' ' -f1)  ($(stat -f %z "$V2_SO") bytes)"

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"
node "$REPO/scripts/rehearse/gen-accounts.cjs" || exit 1

UA="$OUT_DIR/upgrade-authority.json"
solana-keygen new --no-bip39-passphrase -s -o "$UA" >/dev/null 2>&1
PAYER="$OUT_DIR/payer.json"
solana-keygen new --no-bip39-passphrase -s -o "$PAYER" >/dev/null 2>&1

# Stop any running validator, wait for the port to free.
pkill -f solana-test-validator 2>/dev/null
for _ in $(seq 1 30); do solana cluster-version -u localhost >/dev/null 2>&1 || break; sleep 1; done

# The preload dir must hold ONLY account JSONs, and must exist before launch —
# genesis reads it at start.
mkdir -p "$OUT_DIR/preload"
for a in wallet authority vault mint source_ata destination dest_ata; do
  cp "$OUT_DIR/$a.json" "$OUT_DIR/preload/"
done

echo "starting validator with v1 deployed upgradeable + preloaded v1 accounts…"
solana-test-validator --reset --quiet --ledger "$LEDGER" \
  --upgradeable-program "$PROGRAM_ID" "$V1_SO" "$(solana-keygen pubkey "$UA")" \
  --account-dir "$OUT_DIR/preload" >/dev/null 2>&1 &
VALIDATOR_PID=$!

cleanup() { kill "$VALIDATOR_PID" 2>/dev/null; }
trap cleanup EXIT

for _ in $(seq 1 60); do
  curl -s -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' http://127.0.0.1:8899 2>/dev/null | grep -q ok && break
  sleep 2
done
solana config set -u localhost -k "$PAYER" >/dev/null 2>&1
solana airdrop 100 >/dev/null 2>&1

echo
echo "=== BEFORE upgrade: program is v1 ==="
solana program show "$PROGRAM_ID" 2>/dev/null | grep -E 'Data Length|Last Deployed'

echo
echo "=== in-place upgrade to v2 ==="
solana program deploy "$V2_SO" --program-id "$PROGRAM_ID" \
  --upgrade-authority "$UA" 2>&1 | tail -2

echo
echo "=== AFTER upgrade: program is v2 ==="
solana program show "$PROGRAM_ID" 2>/dev/null | grep -E 'Data Length|Last Deployed'

echo
node "$REPO/scripts/rehearse/migrate.cjs"
RESULT=$?
exit $RESULT
