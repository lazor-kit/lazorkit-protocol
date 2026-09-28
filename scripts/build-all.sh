#!/bin/bash
# Build the Rust program for a chosen cluster, derive the program ID from
# the resulting keypair, regenerate IDL, rebuild the SDK.
#
# Usage:
#   ./scripts/build-all.sh devnet     # v2 at 57bTNW... (--features devnet)
#   ./scripts/build-all.sh mainnet    # v2 at LazorFroi...
#
# Neither builds anything deployable at a v1 id (LazorjRF..., 4h3X...): those
# take the sunset binary, `--features mainnet-v1` / `devnet-v1` — see
# docs/mainnet-deploy-checklist.md §2.
#
# After this script the .so lives at target/deploy/ (forced with --sbf-out-dir,
# whatever CARGO_TARGET_DIR says). This is a dev convenience: for a real deploy,
# follow the checklist, which builds, hashes and deploys named artifacts.
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
cargo build-sbf --features "$CLUSTER" --sbf-out-dir "$ROOT_DIR/target/deploy"

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
