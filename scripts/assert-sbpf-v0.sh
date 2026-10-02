#!/usr/bin/env bash
#
# Refuse any program binary that is not SBPF v0.
#
#   ./scripts/assert-sbpf-v0.sh target/artifacts/v2/lazorkit_program.so [more.so …]
#
# The program deploys as SBPF v0 (docs/mainnet-deploy-checklist.md §2), and
# litesvm 0.6 loads only v0. cargo-build-sbf 4.4.0 (2026-09-22) made v3 its
# default, so every build here passes `--arch v0`; a build that lost the flag,
# or ran on a toolchain that ignores it, still produces a binary that looks
# fine: the size check passes and a local test validator loads it. This reads
# the version the linker recorded: ELF e_flags, the little-endian u32 at 0x30,
# is 0 for v0 and 3 for v3 (tests/common::assert_sbpf_v0 does the same).

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <program.so> [...]" >&2
  exit 2
fi

status=0
for so in "$@"; do
  if [ ! -f "$so" ]; then
    echo "error: $so: no such file" >&2
    status=1
    continue
  fi
  magic="$(od -An -tx1 -N4 "$so" | tr -d ' \n')"
  if [ "$magic" != "7f454c46" ]; then
    echo "error: $so is not an ELF file" >&2
    status=1
    continue
  fi
  # Bytes 0x30..0x34, assembled little-endian whatever the host's byte order.
  read -r b0 b1 b2 b3 < <(od -An -tu1 -j48 -N4 "$so")
  e_flags=$(( b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) ))
  if [ "$e_flags" -ne 0 ]; then
    printf 'error: %s is not SBPF v0 (ELF e_flags 0x%x; a v3 build has 0x3).\n' "$so" "$e_flags" >&2
    echo "       rebuild with --arch v0: cargo build-sbf --features <cluster> --arch v0" >&2
    status=1
    continue
  fi
  echo "$so: SBPF v0"
done
exit "$status"
