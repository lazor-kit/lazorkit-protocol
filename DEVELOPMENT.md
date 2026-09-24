# LazorKit Development Workflow

## Prerequisites

- [Solana Tool Suite](https://docs.solanalabs.com/cli/install) (v2.x+)
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

The program ID is chosen at build time via the `mainnet` / `devnet` cargo
features (see `assertions/src/lib.rs`). Exactly one must be set; an
unflagged build fails with a `compile_error!`.

```bash
# Devnet build — embeds 4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS
cargo build-sbf --features devnet

# Mainnet build — embeds LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi
cargo build-sbf --features mainnet
```

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
cargo build-sbf --features devnet
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
program/assertions code and on pushes to `main` / `develop`. It builds both
mainnet and devnet SBF binaries, verifies they differ, and verifies invalid
feature selections fail at compile time.

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
