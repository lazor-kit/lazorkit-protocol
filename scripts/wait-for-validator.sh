#!/usr/bin/env bash
#
# Block until a local solana-test-validator is actually usable.
#
# Two gates, because the first one alone is not enough: `cluster-version`
# answers as soon as the RPC port is listening, which happens before the
# validator is producing blocks. A suite that starts in that window fails with
# "Unable to obtain a new blockhash" partway through — a flake that looks like a
# test bug. So also require the block height to advance at least once.
#
# Used by `validator:wait` in tests-sdk and tests-sdk-kit.

set -uo pipefail

RPC="${RPC_URL:-localhost}"
RPC_TIMEOUT="${VALIDATOR_RPC_TIMEOUT:-60}"
BLOCK_TIMEOUT="${VALIDATOR_BLOCK_TIMEOUT:-30}"

if ! command -v solana >/dev/null 2>&1; then
  echo "error: solana CLI not on PATH" >&2
  exit 1
fi

# Gate 1 — RPC answering.
for _ in $(seq 1 "$RPC_TIMEOUT"); do
  if solana cluster-version -u "$RPC" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! solana cluster-version -u "$RPC" >/dev/null 2>&1; then
  echo "error: solana-test-validator RPC never came up at $RPC after ${RPC_TIMEOUT}s" >&2
  exit 1
fi

# Gate 2 — blocks advancing.
start_height=$(solana block-height -u "$RPC" 2>/dev/null || echo 0)
for _ in $(seq 1 "$BLOCK_TIMEOUT"); do
  height=$(solana block-height -u "$RPC" 2>/dev/null || echo 0)
  if [ "$height" -gt "$start_height" ]; then
    echo "validator ready at $RPC (block height $height)"
    exit 0
  fi
  sleep 1
done

echo "error: solana-test-validator is up at $RPC but not producing blocks after ${BLOCK_TIMEOUT}s" >&2
exit 1
