#!/usr/bin/env bash
#
# Build the program and (re)start a local solana-test-validator with it preloaded.
#
# Idempotent on purpose. `pkill` returns as soon as the signal is delivered, not
# when the process is gone, so a stop-then-start sequence races: the new
# validator loses the port bind, exits, and the suite silently runs against the
# OLD validator with leftover state from the previous run. That surfaces as
# different tests failing on every invocation — usually 4002 InvalidProtocolAdmin,
# because the shared admin keypair from this process does not match the
# ProtocolConfig the previous one left behind. So: kill, then wait for the RPC to
# actually stop answering, and only then start.
#
# The program is loaded at the devnet vanity address rather than at
# `$(solana-keygen pubkey target/deploy/lazorkit_program-keypair.json)`, because
# target/ is gitignored and that keypair therefore differs on every checkout,
# while the SDK's PROGRAM_ID_DEVNET is a fixed constant. Deriving it from the
# keypair loaded the binary at an address the tests never talked to.
#
# Used by `validator:start` in tests-sdk and tests-sdk-kit.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROGRAM_ID="${LAZORKIT_PROGRAM_ID:-4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS}"
LEDGER="${VALIDATOR_LEDGER:-$HOME/test-ledger}"
SHUTDOWN_TIMEOUT="${VALIDATOR_SHUTDOWN_TIMEOUT:-30}"

for bin in solana solana-test-validator cargo-build-sbf; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "error: $bin not on PATH" >&2
    exit 1
  fi
done

# 1. Stop anything already running, and wait for it to actually be gone.
if pgrep -f solana-test-validator >/dev/null 2>&1; then
  echo "stopping existing solana-test-validator…"
  pkill -f solana-test-validator || true

  stopped=0
  for _ in $(seq 1 "$SHUTDOWN_TIMEOUT"); do
    if ! pgrep -f solana-test-validator >/dev/null 2>&1 &&
       ! solana cluster-version -u localhost >/dev/null 2>&1; then
      stopped=1
      break
    fi
    sleep 1
  done

  if [ "$stopped" -ne 1 ]; then
    echo "error: previous solana-test-validator still alive after ${SHUTDOWN_TIMEOUT}s." >&2
    echo "       A new one would fail to bind and the suite would run against stale state." >&2
    exit 1
  fi
fi

# 2. Build the SBF artifact the validator is about to preload.
( cd "$REPO_ROOT/program" && cargo build-sbf --features devnet ) || exit 1

SO="$REPO_ROOT/target/deploy/lazorkit_program.so"
if [ ! -f "$SO" ]; then
  echo "error: $SO not produced by cargo build-sbf" >&2
  exit 1
fi

# 3. Launch detached. `--reset` wipes the shared ledger, which is what makes it
#    safe for this repo and the sibling program-v2 repo to share $HOME/test-ledger.
echo "starting solana-test-validator with program at $PROGRAM_ID"
solana-test-validator \
  --ledger "$LEDGER" \
  --bpf-program "$PROGRAM_ID" "$SO" \
  --reset \
  --quiet &

disown 2>/dev/null || true
