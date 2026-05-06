#!/bin/bash
# Build the Rust program for a chosen cluster, derive the program ID from
# the resulting keypair, regenerate IDL, rebuild the SDK.
#
# Usage:
#   ./scripts/build-all.sh devnet     # builds with --features devnet (4h3X...)
#   ./scripts/build-all.sh mainnet    # builds with --features mainnet (LazorjRF...)
#
# After this script the .so + keypair live at target/deploy/. Deploy with:
#   solana program deploy target/deploy/lazorkit_program.so -u <cluster>
set -e

CLUSTER=$1
ROOT_DIR=$(pwd)
PROGRAM_DIR="$ROOT_DIR/program"
SDK_DIR="$ROOT_DIR/sdk/sdk-legacy"

if [ "$CLUSTER" != "mainnet" ] && [ "$CLUSTER" != "devnet" ]; then
    echo "Usage: $0 <mainnet|devnet>"
    exit 1
fi

echo "--- 🚀 LazorKit build (cluster: $CLUSTER) ---"

# Step 1: Build Rust Program with the chosen cluster feature.
# This embeds the right declare_id! at compile time via assertions/src/lib.rs.
echo "[1/3] Building Rust Program (cargo build-sbf --features $CLUSTER)..."
cd "$PROGRAM_DIR"
cargo build-sbf --features "$CLUSTER"

# Step 2: Generate IDL using Shank, picking the program ID from the keypair
# the build emitted at target/deploy/lazorkit_program-keypair.json.
echo "[2/3] Generating IDL..."
PROGRAM_ID=$(solana-keygen pubkey ../target/deploy/lazorkit_program-keypair.json)
echo "  resolved program ID: $PROGRAM_ID"
if command -v shank &> /dev/null; then
    shank idl -o . --out-filename idl.json -p "$PROGRAM_ID"
else
    echo "⚠️  shank CLI not found (install: cargo install shank-cli). Skipping IDL generation."
fi

# Step 3: Build SDK.
echo "[3/3] Building SDK..."
cd "$SDK_DIR"
npm run build

echo "--- ✅ Done ($CLUSTER) ---"
echo "Deploy:  solana program deploy target/deploy/lazorkit_program.so -u $([ "$CLUSTER" = "mainnet" ] && echo m || echo d)"
