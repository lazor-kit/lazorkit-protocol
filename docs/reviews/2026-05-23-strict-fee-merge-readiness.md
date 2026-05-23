# Strict Fee Enforcement Merge Readiness Review — 2026-05-23

Branch: `feat/strict-fee-enforcement`

Reviewed code commit: `347b135a48b93da485a829c8bdd7138b142a3802`

Main base commit: `b004233ad65ef5597ffff5fbfafb99cfdc85368b`

Verdict: **GO for merge to `main` after PR review.** This is not a mainnet deploy sign-off.

## Scope Freeze

- No Jupiter or v0 transaction-size optimization work was included.
- No fee-unrelated behavior changes were added during readiness verification.
- One mechanical `cargo fmt` pass was committed so the required format gate is green.

## Contract Security Review

`try_collect_fee` was reviewed line by line at the reviewed code commit.

Confirmed:

- Only discriminators `0`, `4`, and `7` enter fee enforcement.
- Missing fee suffix fails with `4008`.
- `ProtocolConfig` must be the canonical PDA, program-owned, correctly discriminated, and large enough.
- Disabled protocol fails with `4003`.
- Zero configured fee fails with `4012`.
- `TreasuryShard` must be program-owned, correctly discriminated, large enough, and canonical for its stored `shard_id`.
- `FeeRecord` must be canonical for the payer.
- System-owned canonical `FeeRecord` is initialized inline with rent, owner, discriminator, payer seed, version, zero counters, and `registered_at`.
- Program-owned `FeeRecord` is checked for discriminator and size.
- Foreign-owned or malformed `FeeRecord` fails with `4011`.
- Fee transfer happens before counter mutation.
- Successful fee-paying instructions always update `total_fees_paid`.
- `CreateWallet` increments `wallet_count`; `Execute` and `ExecuteDeferred` increment `tx_count`.
- The four fee suffix accounts are stripped before processor dispatch.

No high or medium security findings remain open from this review.

## Compatibility Review

Confirmed:

- No migration is required for existing wallet, vault, authority, session, deferred exec, protocol config, fee record, or treasury shard accounts.
- Existing account discriminators remain stable.
- Existing `ProtocolConfig` and initialized `TreasuryShard` accounts remain valid after upgrade.
- First post-upgrade fee transaction for a payer without `FeeRecord` succeeds only when the canonical `FeeRecord` PDA is supplied.
- High-level SDK users should not need client-side account changes for `createWallet`, `execute`, or `executeDeferred`.
- Raw/manual instruction users must include `[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]` for fee-eligible instructions.

## Command Matrix

All commands were run after confirming `origin/main` was an ancestor of the branch.

| Command | Result |
| --- | --- |
| `git fetch origin main` | PASS |
| `git merge-base --is-ancestor origin/main HEAD` | PASS |
| `cargo fmt --check` | PASS after mechanical rustfmt commit |
| `cargo test --features devnet` | PASS |
| `cargo clippy --features devnet --all-targets -- -D warnings -A clippy::op_ref -A clippy::needless_borrow -A clippy::manual_range_contains -A clippy::too_many_arguments` | PASS |
| `cargo build-sbf --features devnet` | PASS |
| `cargo build-sbf --features mainnet` | PASS |
| `cd sdk/sdk-legacy && npm run build` | PASS |
| `cd sdk/sdk-kit && npm run build` | PASS |
| `cd sdk/sdk-kit && npm test` | PASS, 6 files / 66 tests |
| `cd tests-sdk && npx tsc --noEmit -p tsconfig.json` | PASS |
| `cd tests-sdk-kit && npx tsc --noEmit -p tsconfig.json` | PASS |
| `cd tests-sdk && npm test` against local validator | PASS, 16 files / 127 tests |
| `cd tests-sdk-kit && npm test` against local validator | PASS, 16 files / 126 tests |
| `git diff --check` | PASS |

Notes:

- `cargo fmt` prints warnings because `rustfmt.toml` includes nightly-only options; stable rustfmt ignores them and exits successfully.
- `cargo build-sbf` prints existing SBF post-processing warnings about unknown syscalls; build exits successfully.
- `program/idl.json` had no unexpected diff after SBF builds.

## Upgrade Rehearsal

Local validator rehearsal used the devnet program ID `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS`.

Steps completed:

1. Built `origin/main` devnet SBF in a temporary worktree.
2. Started local validator with `origin/main` loaded as an upgradeable program.
3. Ran smoke flow on the `main` binary:
   - `tests/07-e2e.test.ts`
   - `tests/08-deferred.test.ts`
   - Result: PASS, 2 files / 16 tests.
4. Upgraded the same program ID to the strict-fee devnet binary.
5. Re-ran the same smoke flow post-upgrade.
   - Result: PASS, 2 files / 16 tests.
6. Ran targeted inline cold-start check:
   - `tests/12-protocol-fees.test.ts -t "auto-creates FeeRecord inline"`
   - Result: PASS, 1 test.

Upgrade transaction signature:

`4FS4EYniSmR8toXoaMBvhdm4P1bYkfqCZYY5T3Dju6Ca3BQF1pJFza7CkWrKyR7SjvRbeAmnfRNUdLr669KazJ5C`

## SBF Hashes

Strict devnet SBF:

`dd460cb84b8353131da02b3f33c386b8dcc39aee26b9f506ea5cb3ed4f94e871`

Strict mainnet SBF:

`37f626c2f4dcda3a26f3be522de88a5da6560326c3adccf9829a7d6dd3f0e3e4`

Main base devnet SBF used for upgrade rehearsal:

`4bfe56262a178bbcde94e4e5676d48bbc823074ab9730ed7091f9330ab53d25e`

## Known Non-Blockers

- Historical audit docs still describe prior optional `FeeRecord` behavior; they are kept as historical records.
- Jupiter/v0 transaction-size optimization is intentionally deferred to a separate branch.
- Mainnet deployment still needs a separate deploy-day runbook, upgrade-authority/multisig review, monitoring, and rollback procedure.

## Go / No-Go

GO for merge to `main` when PR review accepts this branch.

Do not use this note as final authorization to deploy to Solana mainnet.
