# shellcheck shell=bash
#
# The SBF toolchain the release artifacts are built with. Sourced by the build
# scripts and by CI; docs/mainnet-deploy-checklist.md §2 names the same.
#
#   Agave release v4.2.2   ->  cargo-build-sbf 4.1.0
#   platform-tools v1.53   (cargo build-sbf --tools-version v1.53)
#   --arch v0              (the program deploys as SBPF v0)
#
# Why pinned: the bytes depend on cargo-build-sbf as much as on the compiler.
# cargo-build-sbf 4.4.0, which the Agave stable installer brings since
# 2026-09-22, turns link-time optimisation off for a crate that is both
# `cdylib` and `lib` (this one: the litesvm tests link it as a library) and
# says so in a warning. Its mainnet build is 622142f5…, not 4cb80304…, and the
# mainnet-v1 sunset grows from 45856 to 140200 bytes, which §2's "a sunset over
# 100 KB is the wrong file" check would stop. With --tools-version unpinned the
# compiler moves too (v1.54 builds differ from v1.53 ones).
#
# Changing any of these changes every artifact: rebuild with
# scripts/check-release-hashes.sh, re-record scripts/release-hashes.txt and the
# tables in the checklist, and re-rehearse (§3) with the new files.

SBF_AGAVE_RELEASE=v4.2.2
SBF_CARGO_BUILD_SBF_VERSION=4.1.0
SBF_PLATFORM_TOOLS_VERSION=v1.53

# The version cargo-build-sbf on PATH reports ("cargo-build-sbf 4.1.0" -> 4.1.0),
# or nothing when it is not installed.
sbf_cargo_build_sbf_version() {
  command -v cargo-build-sbf >/dev/null 2>&1 || return 0
  cargo-build-sbf --version 2>/dev/null | awk 'NR == 1 { print $2 }'
}

# sbf_toolchain_check strict|warn
#   strict: exit 1 unless cargo-build-sbf is the pinned version (release builds
#           and the hash check: any other version builds different bytes).
#   warn:   print a warning and carry on (dev builds, tests).
sbf_toolchain_check() {
  local mode="${1:-warn}" have label=warning
  have="$(sbf_cargo_build_sbf_version)"
  if [ "$have" = "$SBF_CARGO_BUILD_SBF_VERSION" ]; then
    return 0
  fi
  [ "$mode" = strict ] && label=error
  {
    echo "$label: cargo-build-sbf is '${have:-not installed}', the release toolchain is $SBF_CARGO_BUILD_SBF_VERSION"
    echo "       (Agave $SBF_AGAVE_RELEASE; scripts/sbf-toolchain.sh). Other versions build different"
    echo "       bytes: 4.4.0 turns LTO off for this crate. Install the pinned one with"
    echo "         sh -c \"\$(curl -sSfL https://release.anza.xyz/$SBF_AGAVE_RELEASE/install)\""
    echo "       (or \`agave-install init $SBF_AGAVE_RELEASE\`; it switches the active release)."
  } >&2
  [ "$mode" = strict ] && return 1
  return 0
}
