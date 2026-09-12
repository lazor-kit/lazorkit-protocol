# Audit brief — LazorKit protocol v2

Entry document for an external security audit. Read this, then
[`threat-model.md`](threat-model.md) and [`internal-review.md`](internal-review.md).

## What this is

A Solana smart-wallet program (pinocchio 0.9, **no Anchor**), deployed on mainnet
at the vanity id `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi`, holding **real
user funds**. Authorities are Ed25519 keys or Secp256r1 passkeys (WebAuthn); a
wallet's assets live in a separate vault PDA the program signs for.

`v2` is an in-place upgrade of the live program. It is **not yet deployed** — this
audit gates the deploy.

## Why the scope is a delta, not a full re-audit

An audit already exists — **Accretion / Solana Foundation, A26SFR1** — but it
covered `program-v2` @ `cd09588d`, a *different* codebase. This repo
(`lazorkit-protocol`) is a fork that added, on top of that base:

- a **protocol fee layer** (`entrypoint::try_collect_fee`, `processor/protocol/*`,
  three state accounts) — **never audited by anyone**;
- **rank/policy** separation and **multiple Owners** per wallet;
- **signer-forwarding** and **accounts-hash privilege binding** changes to the
  wire format;
- **`MigrateWallet`** — a new money path to move v1 funds to v2.

The audit scope is that delta. The base auth primitives are in scope only where
v2 changed them.

## Scope, by priority

### Tier 1 — money paths (must)

| Area | Files | Why |
|---|---|---|
| **MigrateWallet** | `program/src/processor/migrate.rs`, `program/src/legacy.rs`, its reuse of `auth/secp256r1/mod.rs` + `auth/ed25519.rs` | New money path. **Our own review found a HIGH here** (see internal-review). Moves all SOL + SPL tokens and closes PDAs. |
| **Fee layer** | `program/src/entrypoint.rs` (`try_collect_fee`, the C-1 skip, the M-2 program-id check), `program/src/processor/protocol/*`, `program/src/state/{protocol_config,treasury_shard,integrator_record}.rs` | **Never audited.** Runs on every CreateWallet/Execute/ExecuteDeferred; controls fees, admin, treasury. |
| **Execute** | `program/src/processor/execute/{immediate,deferred,actions,authorize}.rs` | Signer forwarding into inner CPIs, the policy engine, the accounts hash, vault PDA signing. |

### Tier 2 — permission & state correctness (should)

| Area | Files |
|---|---|
| Rank / policy | `processor/authority/manage.rs`, `state/policy.rs` (the opaque `PolicyLocation`, note the 80-byte Ed25519-authority == 80-byte session-header collision it resolves), `state/authority.rs`, `processor/authority/transfer_ownership.rs` |
| Multiple Owners | `state/wallet.rs` (`owner_count`), the add/remove logic and the "last Owner cannot be removed" invariant |
| Wire format | `compact.rs` and its two SDK mirrors (`sdk/*/…/{compact,packing}.ts`) |

### Tier 3 — context (changed since the base audit)

- `auth/secp256r1/*` (WebAuthn parse, precompile introspection, the odometer replay guard), `auth/ed25519.rs`
- Version discipline: `seeds.rs` (`lk2:` namespace), `state/mod.rs` (`0x2N` discriminators)

### Out of primary scope

The TypeScript SDKs — verify the wire-format encoders match the program (parity
tests exist under `sdk/sdk-kit/tests/`), but the funds are at risk on-chain.

## The commit to audit

Audit the tip of the `security/high-severity-fixes` branch (PR #36) — or the
merge commit into `develop`. Confirm the exact SHA with the team before starting;
do not audit a moving target.

## Build & run the tests

```bash
# Requires the Anza/Solana toolchain (cargo build-sbf).
( cd program && cargo build-sbf --features devnet )
cargo test --features devnet -p lazorkit-program --lib
./scripts/build-repro-fixtures.sh
cargo test --features devnet -p lazorkit-program --tests   # litesvm integration
```

The five `program/tests/repro_*.rs` are the vulnerability reproductions (each now
proves *rejection*); `program/tests/migrate_v1_tests.rs` covers MigrateWallet
including the regression tests for the internally-found issues. Two TypeScript
validator suites (`tests-sdk`, `tests-sdk-kit`) run against
`solana-test-validator` via `npm run test:local`.

## What to request from the team separately (not in this repo)

- The **current v1 on-chain survey** (`scripts/survey-v1.ts` output) — real
  mainnet wallets, balances, and the ProtocolConfig-admin key. It is deliberately
  kept off this public repo. Ask the team for it privately; it is the real-world
  context for the migration and C-1.

## Reporting

Findings ranked CRITICAL / HIGH / MEDIUM / LOW, each with a concrete failure
scenario (inputs / account layout → wrong outcome) and the affected `file:line`.
We will fix and request a re-review of the fixes before deploy.
