#!/usr/bin/env bash
#
# Build everything the C-1 / H-1 reproduction tests need.
#
#   1. the LazorKit program itself  -> target/deploy/lazorkit_program.so
#   2. the CPI wrapper fixture      -> test-fixtures/malicious-cpi/target/deploy/malicious_cpi.so
#
# Then:
#   cargo test-sbf --features devnet --test repro_c1_admin_freeze
#   cargo test-sbf --features devnet --test repro_h1_cpi_bypass
#
# Requires the Solana toolchain (`cargo build-sbf`). Install with:
#   sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
#
# `--arch v0` is explicit because cargo-build-sbf 4.4.0 changed the default to
# v3, and litesvm 0.6 cannot load a v3 binary: every test that loads the
# program then panics inside litesvm (lib.rs:700, InvalidAccountData). v0 is
# also what the program deploys as (docs/mainnet-deploy-checklist.md §2).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo-build-sbf >/dev/null 2>&1; then
  echo "error: cargo-build-sbf not found on PATH." >&2
  echo "       install the Solana toolchain, then re-run this script." >&2
  exit 1
fi

echo "==> building lazorkit-program (devnet)"
( cd "$repo_root" && cargo build-sbf --features devnet --arch v0 )

echo "==> building malicious-cpi fixture"
( cd "$repo_root/test-fixtures/malicious-cpi" && cargo build-sbf --arch v0 )

echo
echo "artifacts:"
find "$repo_root/target/deploy" \
     "$repo_root/test-fixtures/malicious-cpi/target" \
     -name '*.so' 2>/dev/null | sed 's/^/  /'
