#!/bin/bash

# Sync Program ID across Rust and SDK from the deploy keypair.
#
# Usage:
#   ./scripts/sync-program-id.sh              # Read ID from target/deploy keypair
#   ./scripts/sync-program-id.sh <program_id> # Use explicit ID

set -e

if [ -n "$1" ]; then
    NEW_ID="$1"
else
    KEYPAIR="target/deploy/lazorkit_program-keypair.json"
    if [ ! -f "$KEYPAIR" ]; then
        echo "No keypair at $KEYPAIR. Run 'cargo build-sbf' first or pass ID explicitly."
        exit 1
    fi
    NEW_ID=$(solana-keygen pubkey "$KEYPAIR")
fi

# Detect OLD_ID from assertions/src/lib.rs
OLD_ID=$(grep -oE "declare_id\!\(\"[A-Za-z0-9]+\"\)" assertions/src/lib.rs | sed -E 's/declare_id\!\(\"([A-Za-z0-9]+)\"\)/\1/')

if [ -z "$OLD_ID" ]; then
    echo "Could not detect current Program ID from assertions/src/lib.rs"
    exit 1
fi

if [ "$OLD_ID" == "$NEW_ID" ]; then
    echo "Program ID already $NEW_ID. Nothing to do."
    exit 0
fi

echo "Syncing: $OLD_ID -> $NEW_ID"

# 1. Rust (source of truth)
sed -i '' "s/$OLD_ID/$NEW_ID/g" assertions/src/lib.rs
echo "  assertions/src/lib.rs"

# 2. SDK constants (TypeScript source of truth — tests import from here)
sed -i '' "s/$OLD_ID/$NEW_ID/g" sdk/sdk-legacy/src/constants.ts
echo "  sdk/sdk-legacy/src/constants.ts"

echo ""
echo "Done. Tests and validator script read from these automatically."
echo "Now run: cargo build-sbf"
