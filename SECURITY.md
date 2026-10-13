# Security Policy

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a
vulnerability.

- **GitHub private vulnerability reporting** is enabled for this repository:
  [report a vulnerability](https://github.com/lazor-kit/lazorkit-protocol/security/advisories/new).
- **Contact:** [SECURITY CONTACT]

Include the affected component, the commit or package version, the cluster
(mainnet or devnet) if the issue concerns a deployment, and steps or a test
that reproduces it.

### Response timeline

- **48 hours** — acknowledgement of report
- **7 days** — initial assessment and severity classification
- **30 days** — target for fix and disclosure

## Scope

In scope:

- The on-chain programs built from `program/`: the full v2 builds (features
  `mainnet`, `devnet`) and the sunset builds that serve the v1 ids (features
  `mainnet-v1`, `devnet-v1`).
- The TypeScript SDKs in this repository: `@lazorkit/sdk-legacy`
  (`sdk/sdk-legacy/`) and `@lazorkit/sdk` (`sdk/sdk-kit/`).
- PDA derivation, signature verification, replay protection and the wire
  format shared by the program and the SDKs.

| Cluster | v2 program id | v1 program id |
|---|---|---|
| mainnet | `LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8` (not yet deployed) | `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` |
| devnet | `57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv` | `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` |

Out of scope here:

- The wallet SDKs (`@lazorkit/wallet`, `@lazorkit/wallet-mobile-adapter`),
  which live in [lazor-kit/lazor-kit](https://github.com/lazor-kit/lazor-kit),
  and the passkey portal, in
  [lazor-kit/portal-v2](https://github.com/lazor-kit/portal-v2). Report those
  in their own repositories.
- Applications built on top of LazorKit.
- Third-party dependencies (please report to upstream).
- Test files and scripts.

## Audit status

**The code in this repository has not been externally audited.**

An earlier codebase, `lazor-kit/program-v2`, was assessed by Accretion for the
Solana Foundation (report A26SFR1, February 2026, in [`audits/`](audits/);
reviewed at `cd09588d`, audited commit `79cfc6c3`). This repository is a fork of that codebase that adds a
protocol fee layer, separate rank and policy, multiple Owners per wallet,
signer forwarding with privilege binding in the accounts hash, and
`MigrateWallet`. Those additions, and the code as a whole as it stands now,
are not covered by that report. The external audit brief for this delta is
[`docs/audit/README.md`](docs/audit/README.md).

What has been done instead:

- **Internal reviews.** Recorded in
  [`docs/security-review-2026-04-21.md`](docs/security-review-2026-04-21.md),
  [`docs/audit-2026-04-28/findings.md`](docs/audit-2026-04-28/findings.md),
  [`docs/audit/internal-review.md`](docs/audit/internal-review.md),
  [`docs/audit/report-2026-08-29-internal.md`](docs/audit/report-2026-08-29-internal.md)
  and [`docs/reviews/`](docs/reviews/), with a threat model in
  [`docs/audit/threat-model.md`](docs/audit/threat-model.md). These reviews
  were done by the team and are not a substitute for an external audit.
- **Test suites.** Program unit tests and litesvm integration tests
  (`program/tests/`, including reproduction tests for issues found in review,
  which now prove rejection), and TypeScript suites against a local validator
  (`tests-sdk/`, `tests-sdk-kit/`). The program tests run in CI.
- **Reproducible builds with recorded hashes.** The SHA-256 of each release
  artifact is recorded in
  [`scripts/release-hashes.txt`](scripts/release-hashes.txt).
  `scripts/check-release-hashes.sh` rebuilds them with the pinned toolchain
  and compares; CI runs it on a macOS arm64 runner.
- **Two-id rehearsal.** The v2 rollout and the v1 migration are rehearsed end
  to end on a local validator at both the mainnet and the devnet ids
  (`scripts/rehearse/two-id-rehearsal.mjs`). The artifacts each rehearsal ran
  on, and whether the current artifacts have been rehearsed, are recorded in
  [`docs/mainnet-deploy-checklist.md`](docs/mainnet-deploy-checklist.md#two-id-rehearsal).

The [CHANGELOG](CHANGELOG.md) records each change, its tests, and the
artifact hashes it moves.

## Program lifecycle

A mainnet program that holds user assets is never closed. When a version is
retired, its program id is upgraded to a **sunset build**: it keeps only the
instructions a wallet needs to move its assets out (for v1: `MigrateWallet`,
`ReclaimDeferred`, `CloseExpiredSession`) and refuses every other instruction
with `RetiredDeployment` (4018). Assets in a retired version stay reachable by
their owners.

Which SDK versions work with which program, and how long each is supported:

- [Versions & compatibility](https://docs.lazorkit.com/versions)
- [Support policy](https://docs.lazorkit.com/support-policy)

## Security mechanisms

- Odometer counter replay protection (monotonic u32 per authority; checked increment never wraps; works with synced passkeys).
- Clock-based slot freshness (150-slot window via `Clock::get()`).
- CPI `stack_height` anti-reentrancy check on every authenticated path.
- Challenge hash binds signature to payer, the signing authority's wallet, accounts, counter, and program ID.
- Authority creation rejects all-zero Ed25519 public keys and all-zero Secp256r1 credential/public-key material.
- Account ownership + discriminator checks on every PDA read.
- Fee-eligible instructions require canonical protocol fee suffix accounts and canonical per-payer `FeeRecord` accounting.
- Transfer-allocate-assign pattern prevents create-account DoS.
- Session action enforcement: expired spending limits are a hard deny; expired whitelists block all programs.
- `SolMaxPerTx` uses per-CPI gross-outflow tracking (DeFi round-trips can't bypass the per-tx cap).
- Vault metadata and token-account invariants enforced for every signer but an Owner — sessions with or without actions, Admins and Delegates, in Execute and ExecuteDeferred (blocks `System::Assign`, SPL Token `SetAuthority`, `Approve`, `CloseAccount`, `FreezeAccount` escapes; a token account that becomes vault-owned during the Execute may carry no delegate or close authority).
- A policy bounds SOL and every mint the vault holds directly: SOL with no `Sol*` action and a mint with no `Token*` action may not leave (3037 / 3038). Balances are summed per mint over every vault token account in the Execute, each counted once, which also prevents the dummy-account bypass.
- Admin-gated protocol instructions verify config ownership before reading admin field.
- Constant-time comparison on the signed challenge field.
- `compact.rs` has runtime assert guards against u8 truncation (not debug-only).
- `actions_len` capped at 2,048 bytes to prevent BPF heap exhaustion.
