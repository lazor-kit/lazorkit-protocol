#!/usr/bin/env bash
# Run the program's litesvm suites against the binaries they are for.
#
# Two builds, because the program id is compiled in (M-2) and a sunset binary
# refuses everything but three instructions:
#   devnet        full v2 — every suite except the sunset one
#   rehearsal-v1  the sunset binary — only tests/sunset_tests.rs
# The devnet artifact is rebuilt last so the tree is left the way the rest of
# the tooling expects it.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=sbf-toolchain.sh
. scripts/sbf-toolchain.sh
sbf_toolchain_check warn
TOOLS="${SBF_TOOLS_VERSION:-$SBF_PLATFORM_TOOLS_VERSION}"
# v0 explicitly: cargo-build-sbf 4.4.0 defaults to v3, which litesvm 0.6 cannot
# load (see scripts/build-repro-fixtures.sh).

build() {
  ( cd program && cargo build-sbf --features "$1" --tools-version "$TOOLS" --arch v0 >/dev/null )
  # build-sbf may write to a shared target dir; the harness reads target/deploy.
  local shared=".git/shared-target/deploy/lazorkit_program.so"
  if [ -f "$shared" ] && [ "$shared" -nt target/deploy/lazorkit_program.so ]; then
    mkdir -p target/deploy && cp "$shared" target/deploy/lazorkit_program.so
  fi
}

echo "== sunset binary (rehearsal-v1) =="
build rehearsal-v1
cargo test --features rehearsal-v1 -p lazorkit-program --test sunset_tests

echo "== full v2 (devnet) =="
build devnet
cargo test --features devnet -p lazorkit-program --tests
