#!/bin/bash
set -e

# Full build workflow: build program → generate IDL → build SDK
#
# Usage:
#   ./scripts/build-all.sh                    # Use existing program ID
#   ./scripts/build-all.sh <new_program_id>   # Sync program ID first

ROOT_DIR=$(pwd)
PROGRAM_DIR="$ROOT_DIR/program"
SDK_DIR="$ROOT_DIR/sdk/sdk-legacy"

# Step 0: Optionally sync program ID
if [ -n "$1" ]; then
    echo "[0/3] Syncing Program ID to $1..."
    ./scripts/sync-program-id.sh "$1"
fi

# Step 1: Build Rust Program
echo "[1/3] Building Rust Program (BPF)..."
cargo build-sbf

# Step 2: Generate IDL using Shank
echo "[2/3] Generating IDL..."
PROGRAM_ID=$(grep -A1 'declare_id' "$PROGRAM_DIR/src/lib.rs" 2>/dev/null | grep -oE '[A-HJ-NP-Za-km-z1-9]{32,44}' | head -1 || echo "FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao")
cd "$PROGRAM_DIR"
if command -v shank &> /dev/null; then
    shank idl -o . --out-filename idl.json -p "$PROGRAM_ID"
else
    echo "⚠️  shank CLI not found (install: cargo install shank-cli). Skipping IDL generation."
fi

# Step 3: Build SDK
echo "[3/3] Building SDK..."
cd "$SDK_DIR"
npm run build

echo ""
echo "✅ Build complete!"
echo ""
echo "To test locally:"
echo "  cd tests-sdk && npm run test:local"
echo ""
echo "To deploy to devnet:"
echo "  solana program deploy target/deploy/lazorkit_program.so -u d"
