# LazorKit Development Workflow

This document outlines the standard procedures for building, deploying, and testing the LazorKit program and its associated SDK.

## Prerequisites

- [Solana Tool Suite](https://docs.solanalabs.com/cli/install) (v2.x+)
- [Rust](https://www.rust-lang.org/tools/install) (via rustup)
- [Node.js 18+](https://nodejs.org/) & npm
- [shank-cli](https://github.com/metaplex-foundation/shank): `cargo install shank-cli`

## Project Structure

```
/program           Rust smart contract (pinocchio, zero-copy)
/sdk/solita-client  TypeScript SDK (hand-written instruction builders + client API)
/tests-sdk          Integration tests (vitest, @solana/web3.js v1, ~75 tests)
/scripts            Build/deploy automation
/audits             Audit reports
/no-padding         Custom NoPadding derive macro
/assertions         Custom assertion helpers
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

### C. IDL Generation (using Shank)

```bash
cd program && shank idl -o . --out-filename idl.json -p FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao
```

### D. SDK

The SDK is fully hand-written (no code generation). After modifying program instruction layouts, update `sdk/solita-client/src/utils/instructions.ts` manually.

### E. Running Integration Tests

```bash
# Terminal 1: Start local validator with program loaded
cd tests-sdk && npm run validator:start

# Terminal 2: Run all ~75 tests across 12 files
cd tests-sdk && npm test
```

### F. Running Benchmarks

```bash
cd tests-sdk && npm run benchmark
```

Measures CU usage and transaction sizes for all instructions, including deferred execution (Authorize TX1 + ExecuteDeferred TX2).

### G. Program ID Sync

```bash
./scripts/sync-program-id.sh <NEW_PROGRAM_ID>
```

### H. Deploy to Devnet

```bash
cargo build-sbf
solana program deploy target/deploy/lazorkit_program.so -u d
```

## Troubleshooting

- **429 Too Many Requests**: Check RPC credits or use local validator.
- **Already Initialized**: Use fresh userSeed or reset validator with `--reset`.
- **InvalidSeeds**: Verify PDA derivation matches on-chain seeds.
- **0xbc0 (InvalidSessionDuration)**: expires_at must be a future slot, not Unix timestamp.
