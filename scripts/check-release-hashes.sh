#!/usr/bin/env bash
#
# Rebuild the release artifacts from this checkout and compare each with the
# size and SHA-256 recorded in scripts/release-hashes.txt.
#
#   ./scripts/check-release-hashes.sh                     # mainnet mainnet-v1 devnet devnet-v1
#   ./scripts/check-release-hashes.sh mainnet devnet      # some of them
#   OUT=/some/dir ./scripts/check-release-hashes.sh       # keep the .so files, OUT/<feature>/
#
# Every build runs as docs/mainnet-deploy-checklist.md §2 has it: the pinned
# toolchain (scripts/sbf-toolchain.sh; refused if cargo-build-sbf is another
# version), `--tools-version`, `--arch v0`, and one fresh CARGO_TARGET_DIR for
# this run, so no object compiled by another toolchain is reused
# (`--tools-version` does not invalidate cargo's cache). Each binary is checked
# to be SBPF v0, then against the record.
#
# The record is for macOS on Apple silicon ($SBF_RELEASE_HOST in
# sbf-toolchain.sh): platform-tools' std embeds the paths it was built under,
# and its Linux package builds other bytes. On another host the script refuses
# to run; SBF_ANY_HOST=1 builds and compares anyway (expect a mismatch).
#
# Exit status: 0 all match, 1 a mismatch or a failed build, 2 usage,
# 3 not the pinned cargo-build-sbf, or not the release host.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=sbf-toolchain.sh
. "$root/scripts/sbf-toolchain.sh"
record="$root/scripts/release-hashes.txt"

features=("$@")
if [ "${#features[@]}" -eq 0 ]; then
  features=(mainnet mainnet-v1 devnet devnet-v1)
fi
for f in "${features[@]}"; do
  if ! awk -v f="$f" '$1 == f { found = 1 } END { exit !found }' "$record"; then
    echo "error: no recorded hash for '$f' in scripts/release-hashes.txt" >&2
    exit 2
  fi
done

sbf_toolchain_check strict || exit 3
if [ "$(sbf_host)" != "$SBF_RELEASE_HOST" ] && [ "${SBF_ANY_HOST:-}" != 1 ]; then
  echo "error: the recorded hashes are for $SBF_RELEASE_HOST builds; this host is $(sbf_host)." >&2
  echo "       platform-tools $SBF_PLATFORM_TOOLS_VERSION is a separate build per host and its std embeds" >&2
  echo "       the paths it was built under, so this host builds other bytes. SBF_ANY_HOST=1 compares anyway." >&2
  exit 3
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="${OUT:-$work/out}"
mkdir -p "$out"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

echo "toolchain: $(cargo-build-sbf --version | head -1), platform-tools $SBF_PLATFORM_TOOLS_VERSION, --arch v0, on $(sbf_host)"
echo "commit:    $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"

status=0
for f in "${features[@]}"; do
  dir="$out/$f"
  rm -rf "$dir"
  mkdir -p "$dir"
  echo "== $f"
  if ! (cd "$root/program" &&
        CARGO_TARGET_DIR="$work/target" command cargo build-sbf \
          --features "$f" \
          --tools-version "$SBF_PLATFORM_TOOLS_VERSION" \
          --arch v0 \
          --sbf-out-dir "$dir"); then
    echo "FAIL $f: build failed" >&2
    status=1
    continue
  fi
  # cargo-build-sbf leaves a throwaway program keypair next to the binary.
  rm -f "$dir"/*-keypair.json
  so="$dir/lazorkit_program.so"
  if ! "$root/scripts/assert-sbpf-v0.sh" "$so"; then
    status=1
    continue
  fi
  bytes="$(wc -c < "$so" | tr -d ' ')"
  sha="$(sha256 "$so")"
  read -r want_bytes want_sha < <(awk -v f="$f" '$1 == f { print $2, $3 }' "$record")
  if [ "$bytes" = "$want_bytes" ] && [ "$sha" = "$want_sha" ]; then
    echo "ok   $f  $bytes  $sha"
  else
    echo "FAIL $f  built $bytes $sha" >&2
    echo "          recorded $want_bytes $want_sha" >&2
    # Build paths compiled in (panic locations) are the usual host-specific bytes.
    if command -v strings >/dev/null 2>&1; then
      echo "     absolute paths in the binary:" >&2
      strings -n 8 "$so" | grep '^/' | sed 's/^/       /' >&2 || true
    fi
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'EOF'

A release artifact does not match scripts/release-hashes.txt.
  - If this change is meant to change the program, rebuild with this script
    on the pinned toolchain, record the new sizes and hashes here and in the
    tables of docs/mainnet-deploy-checklist.md, and rehearse (§3) again.
  - If it is not, the build is not reproducible here (another toolchain, a
    stale object, a changed dependency): do not deploy from it.
EOF
fi
exit "$status"
