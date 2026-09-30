# LazorKit Development Workflow

## Prerequisites

- The Agave tool suite at the pinned release, **v4.2.2** (its `cargo-build-sbf`
  is 4.1.0): `sh -c "$(curl -sSfL https://release.anza.xyz/v4.2.2/install)"`.
  The stable installer brings cargo-build-sbf 4.4.0, which builds this program
  without LTO, so its binaries are not the ones the release hashes describe.
  See `scripts/sbf-toolchain.sh` and [§A](#a-build-program).
- [Rust](https://www.rust-lang.org/tools/install) (via rustup)
- [Node.js 18+](https://nodejs.org/) & npm
- [shank-cli](https://github.com/metaplex-foundation/shank): `cargo install shank-cli`

## Project Structure

```
/program           Rust smart contract (pinocchio, zero-copy)
/sdk/sdk-kit       Modern TypeScript SDK
/sdk/sdk-legacy    TypeScript SDK (@solana/web3.js v1, hand-written)
/tests-sdk-kit     Integration tests for sdk-kit
/tests-sdk         Integration tests (vitest, ~118 tests across 16 files)
/scripts           Build/deploy automation
/no-padding        Custom NoPadding derive macro
/assertions        Custom assertion helpers
```

## Quick Start

```bash
# Build everything (program + IDL + SDK)
./scripts/build-all.sh

# Run Rust unit tests (~165 tests)
cargo test

# Run SDK integration tests (starts validator, runs tests, stops validator)
cd tests-sdk && npm run test:local
```

## Core Workflows

### A. Build Program

The program ID is chosen at build time by a cluster feature (see
`assertions/src/lib.rs` for the full table). Exactly one must be set; an
unflagged build fails with "pick exactly one cluster feature".

```bash
# v2 on devnet — embeds 57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv
cargo build-sbf --features devnet --tools-version v1.53 --arch v0

# v2 on mainnet — embeds LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8
cargo build-sbf --features mainnet --tools-version v1.53 --arch v0

# The v1 ids build only as the sunset binary (MigrateWallet, ReclaimDeferred,
# CloseExpiredSession; everything else 4018 RetiredDeployment):
cargo build-sbf --features mainnet-v1 --tools-version v1.53 --arch v0   # LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi
cargo build-sbf --features devnet-v1 --tools-version v1.53 --arch v0    # 4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS
```

The release toolchain is pinned in `scripts/sbf-toolchain.sh`: Agave v4.2.2
(`cargo-build-sbf --version` says 4.1.0), platform-tools v1.53, SBPF v0, and
`GITHUB_SHA` / `GITHUB_REF_NAME` unset. All of it changes the bytes:

- **cargo-build-sbf 4.1.0.** 4.4.0 (what the stable installer brings since
  2026-09-22) disables LTO for a crate that is both `cdylib` and `lib`, as this
  one is, and warns about it; the sunset binary grows from 45856 to 140200
  bytes, and no artifact hashes as recorded.
- **`--tools-version v1.53`.** The default follows cargo-build-sbf (v1.54 for
  4.1.0), and a v1.54 build differs.
- **`--arch v0`.** The program deploys as SBPF v0, and cargo-build-sbf 4.4.0
  and later build v3 by default. A v3 binary loads on a local test validator
  and passes the size check, but litesvm refuses it.
  `./scripts/assert-sbpf-v0.sh <file.so>` checks a binary.
- **`GITHUB_SHA` and `GITHUB_REF_NAME` unset.** `program/src/lib.rs`'s
  `security_txt!` compiles them in as `source_revision` / `source_release`.
  The recorded artifacts have both empty; GitHub Actions sets both, and a
  build there is 48 bytes larger. `sbf_release_env` in the pin file unsets
  them.

`./scripts/check-release-hashes.sh` rebuilds mainnet, mainnet-v1, devnet and
devnet-v1 that way in a fresh target dir and compares each with
`scripts/release-hashes.txt`; it refuses to run on another cargo-build-sbf. CI
runs it on ubuntu and on macOS (Apple silicon), where the record was made. A
change that moves a binary must update that file (and the tables in
`docs/mainnet-deploy-checklist.md`) — the SBF cluster check fails until it does.
The build scripts (`build-all.sh`, `build-repro-fixtures.sh`,
`start-validator.sh`, `test-program.sh`) use the same pin and only warn on
another cargo-build-sbf.

For anything you will deploy, add `--sbf-out-dir <dir>` and deploy from that
directory. A `CARGO_TARGET_DIR` override (the maintainer's shell sets one) makes
a bare build write somewhere other than `target/deploy`, which then still holds
the previous binary.

### B. Run Rust Tests

```bash
cargo test --features devnet
```

The `--features devnet` flag is required because the assertions crate's
`compile_error!` fires on un-flagged builds. Choose either feature —
host-side tests use a runtime `program_id: Pubkey::new_unique()`, so the
embedded ID doesn't affect test outcomes.

### C. Run SDK Integration Tests

**One command (recommended):**

```bash
cd tests-sdk && npm run test:local
```

This starts a local validator with the program loaded, runs all ~118 tests, then stops the validator.

**Manual (two terminals):**

```bash
# Terminal 1: Start validator
cd tests-sdk && npm run validator:start

# Terminal 2: Run tests
cd tests-sdk && npm test

# When done
npm run validator:stop
```

### D. Full Build Pipeline

```bash
# Build program + generate IDL + build SDK
./scripts/build-all.sh devnet     # or mainnet
```

### E. SDK

The SDK is fully hand-written (no code generation). After modifying program instruction layouts, update `sdk/sdk-legacy/src/utils/instructions.ts` manually.

### F. IDL Generation (using Shank)

```bash
cd program
PROGRAM_ID=$(solana-keygen pubkey ../target/deploy/lazorkit_program-keypair.json)
shank idl -o . --out-filename idl.json -p "$PROGRAM_ID"
```

### G. Deploy to Devnet

```bash
cargo build-sbf --features devnet --tools-version v1.53 --arch v0
./scripts/assert-sbpf-v0.sh target/deploy/lazorkit_program.so
solana program deploy target/deploy/lazorkit_program.so -u d
```

## Continuous Integration

GitHub Actions runs the `lint` workflow on every pull request and on pushes to
`main` / `develop`:

- Rust: `cargo fmt --all -- --check`, clippy with `devnet` features, and
  `cargo test --features devnet -p lazorkit-program --lib`.
- SDK packages: `sdk/sdk-kit` installs, builds, and runs vitest; `sdk/sdk-legacy`
  installs and builds.
- Integration suites: `tests-sdk-kit` and `tests-sdk` install and typecheck with
  `npx tsc -p tsconfig.json --noEmit`.

The `SBF cluster feature check` workflow also runs on pull requests touching
the program, its crates, `Cargo.lock`, the toolchain pin or the hash record,
and on pushes to `main` / `develop`. It installs the pinned toolchain (Agave
v4.2.2, and checks cargo-build-sbf is 4.1.0), builds both mainnet and devnet
SBF binaries, verifies they differ, verifies invalid feature selections fail at
compile time; a second job runs `scripts/check-release-hashes.sh` on ubuntu
and on macOS: the four release artifacts, rebuilt in a fresh target dir, must
match `scripts/release-hashes.txt`. The `program litesvm integration` job of
`lint` uses the same pinned toolchain.

Local-validator integration tests are still a manual release/audit check:

```bash
cd tests-sdk && npm run test:local
```

For `tests-sdk-kit`, start the validator and run vitest in separate terminals:

```bash
cd tests-sdk-kit && npm run validator:start
cd tests-sdk-kit && npm test
cd tests-sdk-kit && npm run validator:stop
```

### I. Benchmarks

```bash
cd tests-sdk && npm run benchmark
```

## Troubleshooting

- **429 Too Many Requests**: Check RPC credits or use local validator.
- **Already Initialized**: Use fresh userSeed or reset validator with `--reset`.
- **InvalidSeeds**: Verify PDA derivation matches on-chain seeds.
- **0xbc0 (InvalidSessionDuration)**: expires_at must be a future slot, not Unix timestamp.
- **Validator won't start**: Check if port 8899 is in use (`lsof -i :8899`). Run `npm run validator:stop` first.
