#!/bin/bash

# Sync Program ID across all files
#
# Usage: ./scripts/sync-program-id.sh <new_program_id>

if [ -z "$1" ]; then
    echo "Usage: $0 <new_program_id>"
    exit 1
fi

NEW_ID=$1

# Detect OLD_ID from assertions/src/lib.rs
OLD_ID=$(grep -oE "declare_id\!\(\"[A-Za-z0-9]+\"\)" assertions/src/lib.rs | sed -E 's/declare_id\!\(\"([A-Za-z0-9]+)\"\)/\1/')

if [ -z "$OLD_ID" ]; then
    echo "Could not detect current Program ID from assertions/src/lib.rs"
    exit 1
fi

if [ "$OLD_ID" == "$NEW_ID" ]; then
    echo "Program ID is already $NEW_ID. Skipping."
    exit 0
fi

echo "Syncing Program ID: $OLD_ID -> $NEW_ID"

# 1. Rust assertions
sed -i '' "s/$OLD_ID/$NEW_ID/g" assertions/src/lib.rs

# 2. SDK constants
sed -i '' "s/$OLD_ID/$NEW_ID/g" sdk/sdk-legacy/src/constants.ts

# 3. Tests
sed -i '' "s/$OLD_ID/$NEW_ID/g" tests-sdk/tests/common.ts 2>/dev/null || true
sed -i '' "s/$OLD_ID/$NEW_ID/g" tests-sdk/package.json

echo "Done. Now run: cargo build-sbf"
