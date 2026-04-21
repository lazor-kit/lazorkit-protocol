# LazorKit Development Workflow

## Prerequisites

- [Solana Tool Suite](https://docs.solanalabs.com/cli/install) (v2.x+)
- [Rust](https://www.rust-lang.org/tools/install) (via rustup)
- [Node.js 18+](https://nodejs.org/) & npm
- [shank-cli](https://github.com/metaplex-foundation/shank): `cargo install shank-cli`

## Project Structure

```
/program           Rust smart contract (pinocchio, zero-copy)
/sdk/sdk-legacy    TypeScript SDK (@solana/web3.js v1, hand-written)
/tests-sdk         Integration tests (vitest, ~103 tests)
/scripts           Build/deploy/sync automation
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

```bash
cargo build-sbf
```

### B. Run Rust Tests

```bash
cargo test
```

### C. Run SDK Integration Tests

**One command (recommended):**

```bash
cd tests-sdk && npm run test:local
```

This starts a local validator with the program loaded, runs all ~103 tests, then stops the validator.

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
./scripts/build-all.sh

# Or with a new program ID
./scripts/build-all.sh <NEW_PROGRAM_ID>
```

### E. SDK

The SDK is fully hand-written (no code generation). After modifying program instruction layouts, update `sdk/sdk-legacy/src/utils/instructions.ts` manually.

### F. IDL Generation (using Shank)

```bash
cd program && shank idl -o . --out-filename idl.json -p 4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS
```

### G. Program ID Sync

```bash
./scripts/sync-program-id.sh <NEW_PROGRAM_ID>
```

Updates program ID across: assertions/src/lib.rs, SDK constants, test configs, validator script.

### H. Deploy to Devnet

```bash
cargo build-sbf
solana program deploy target/deploy/lazorkit_program.so -u d
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
