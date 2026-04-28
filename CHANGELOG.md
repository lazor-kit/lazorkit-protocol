# Changelog

All notable changes to the LazorKit smart wallet protocol and SDK are
documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — dual-cluster program ID support (SDK 0.2.0)

- **Program — Pattern D feature flags.** The on-chain SBF binary now
  requires exactly one cluster feature at build time:
  - `cargo build-sbf --features mainnet` → binary embeds the mainnet vanity ID
    `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi`
  - `cargo build-sbf --features devnet` → binary embeds the devnet ID
    `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS`
  - Building with neither, or both, produces a clear `compile_error!`. Prevents
    accidental cross-cluster deploys (a binary built for one ID malfunctions if
    deployed to the other slot — internal `crate::ID` checks fail). Implemented
    via `#[cfg(...)]` on the `declare_id!` call in `assertions/src/lib.rs`.

- **SDK — `LazorKitClient` auto-infers program ID from RPC.** The constructor
  now accepts an optional `programId` argument and infers the right one from
  the connection's RPC endpoint when omitted:
  - `mainnet` in URL → `PROGRAM_ID_MAINNET`
  - `devnet` in URL → `PROGRAM_ID_DEVNET`
  - `localhost` / `127.0.0.1` → `PROGRAM_ID_DEVNET` (local-validator convention)
  - anything else → throws with a clear error pointing at the explicit-override path
- **SDK — both cluster constants exported.** `PROGRAM_ADDRESS_MAINNET`,
  `PROGRAM_ADDRESS_DEVNET`, `PROGRAM_ID_MAINNET`, `PROGRAM_ID_DEVNET`.

### Breaking — SDK 0.2.0

- **`PROGRAM_ADDRESS` / `PROGRAM_ID` removed from public exports.** They were
  cluster-ambiguous and would defeat Pattern D's "pick a cluster" intent.
  Use `PROGRAM_ADDRESS_MAINNET` / `_DEVNET` and `PROGRAM_ID_MAINNET` / `_DEVNET`
  instead. Partners on `^0.1.0` are unaffected — npm semver does not auto-pull
  `0.2.0`.
- **Low-level builders now require `programId` explicitly.** All instruction
  builders (`createCreateWalletIx`, `createExecuteIx`, etc.), all PDA helpers
  (`findWalletPda`, `findVaultPda`, etc.) and `buildSecp256r1Challenge` now
  take `programId` as a required argument. This was previously a defaulted
  parameter pointing at the devnet ID — defaults are unsafe in a multi-cluster
  world. The high-level `LazorKitClient` continues to handle this implicitly
  via `this.programId`; only direct callers of the low-level helpers need to
  pass it.

### Migration from SDK 0.1.x

Most apps need no changes:

```diff
- import { Connection } from '@solana/web3.js';
- import { LazorKitClient } from '@lazorkit/sdk-legacy';
- const client = new LazorKitClient(new Connection('https://api.devnet.solana.com'));
+ // Same call — cluster is now auto-inferred from the RPC endpoint
+ const client = new LazorKitClient(new Connection('https://api.devnet.solana.com'));
```

If you were importing `PROGRAM_ID` directly:

```diff
- import { PROGRAM_ID } from '@lazorkit/sdk-legacy';
+ import { PROGRAM_ID_DEVNET } from '@lazorkit/sdk-legacy';   // or PROGRAM_ID_MAINNET
```

If you were calling low-level builders or PDA helpers, add the explicit
`programId` argument:

```diff
- const [walletPda] = findWalletPda(userSeed);
+ const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);

- createCreateWalletIx({ payer, walletPda, vaultPda, authorityPda, ... });
+ createCreateWalletIx({ payer, walletPda, vaultPda, authorityPda, ..., programId: PROGRAM_ID_DEVNET });
```

Partners not ready to migrate can stay on `^0.1.0` — devnet behaviour is
preserved unchanged.

### Operational

- `program/Cargo.toml` now propagates `mainnet` / `devnet` features through
  to `assertions`. The validator-start helper in `tests-sdk/package.json`
  runs `cargo build-sbf --features devnet` automatically before launching.

---

## [0.1.0] — pre-mainnet hardening

This section captures everything on `refactor/sdk-cleanup` that is not yet
in `main` but is staged for the upcoming pre-mainnet release on
`fix/audit-hardening`.

### Added

- **Program — permissionless `RegisterPayer`** (`b722874`). The admin gate
  on the `RegisterPayer` instruction has been dropped. Any payer can now
  register their own `FeeRecord` (the PDA is derived from the payer signer,
  not from instruction data, so attackers cannot register a record at
  someone else's address). Payer pays their own ~0.00112 SOL rent;
  economically self-limiting against spam. Fee collection still works for
  unregistered payers — registration only enables stats tracking.

- **SDK — auto-prepended self-registration**
  ([`client.ts:resolveProtocolFeeWithRegister`](sdk/sdk-legacy/src/utils/client.ts)).
  All four fee-eligible builders (`createWallet`, `prepareExecute`/`finalizeExecute`,
  `execute`, `executeDeferredFromPayload`) now transparently prepend a
  `RegisterPayer` instruction the first time a given payer hits a
  fee-paying transaction. Subsequent calls short-circuit through an
  in-memory cache — one extra `getAccountInfo` per cold payer per process,
  zero overhead after that. Apps no longer need to call `registerPayer`
  manually.

- **SDK — transaction-builder helpers**
  ([`sdk/sdk-legacy/src/utils/transactions.ts`](sdk/sdk-legacy/src/utils/transactions.ts), `6c4b190`).
  Three small standalone utilities so partners stop hand-rolling
  `new Transaction().add(...)` boilerplate and to make v0 + Address Lookup
  Table support trivial:
  - `buildLegacyTx({ payer, instructions, blockhash, signers })` →
    signed legacy `Transaction`
  - `buildV0Tx({ payer, instructions, blockhash, signers, lookupTables? })` →
    signed `VersionedTransaction`
  - `createAndExtendLut({ connection, authority, addresses })` → bootstrap
    a shared Address Lookup Table; handles the slot-finalization quirk,
    chunks extends in groups of 30, waits one slot before returning.
  Empty Address Lookup Tables containing system program, sysvars, the
  `protocol_config` PDA and all treasury-shard PDAs save **~88 B per
  Secp256r1 Execute** (verified in `tests-sdk/tests/benchmark-fees.ts`).

- **Docs — `docs/use-cases/` folder** (`78d83bc`). New home for end-to-end
  integration patterns. First guide
  ([`eoa-with-passkey-spender.md`](docs/use-cases/eoa-with-passkey-spender.md))
  covers the partner-team flow of attaching a passkey as Spender on a
  wallet whose Owner is an existing Ed25519 EOA. Includes role-permission
  table with file:line citations into the program code, mermaid
  end-state diagram, and a sequence diagram for enrollment + daily use +
  recovery.

- **Docs — six mermaid diagrams in Architecture.md** (`0cda41f`):
  PDA relationship map, ER diagram of the account model, RBAC permission
  flowchart with auth-type constraints on edges, Secp256r1 Execute sequence
  (challenge → precompile → counter commit), Spender-calls-Execute
  sequence demonstrating per-instruction role checks, and Deferred
  Execution flow showing the TX1 hash commitment / TX2 reveal-and-execute
  / Reclaim path.

- **Docs — SDK README updated** (`0a9203a`). New "Protocol fees &
  auto-registration" subsection explaining the on-chain fee accounts
  convention, the permissionless `registerPayer({ payer })` API, and the
  `resolveProtocolFee` / `resolveProtocolFeeWithRegister` escape hatches.
  New "Transactions (legacy + v0)" section documenting the three new
  helpers above.

- **Tests — fee-aware benchmark**
  ([`tests-sdk/tests/benchmark-fees.ts`](tests-sdk/tests/benchmark-fees.ts), `aa5050b`).
  Measures CU, legacy tx size, v0+LUT tx size, and lamport cost
  (sig fee + protocol fee + rent delta) for every non-admin LazorKit
  instruction with the protocol fee enabled at 5000/5000. Each fee-eligible
  instruction is benchmarked twice — `cold` (first fee-paying tx for the
  payer; SDK auto-prepends `RegisterPayer`) and `warm` (FeeRecord already
  exists; no auto-prepend). Uses the SDK's `buildLegacyTx` / `buildV0Tx` /
  `createAndExtendLut` helpers so the v0 column reflects the path partners
  will use.

- **Audit — pre-mainnet findings** (`32e58bb`,
  [`docs/audit-2026-04-28/findings.md`](docs/audit-2026-04-28/findings.md)).
  Re-audit of the post-2026-04-21 delta plus full re-walk of high-risk
  paths and threat-model walkthroughs. Verdict: GO with caveats — no
  code-level blockers; ship conditional on the operational checklist
  (Phase E) being completed.

### Changed

- **SDK — `client.registerPayer` signature simplified** (breaking for
  callers that called it directly; `b722874`). Was
  `registerPayer({ payer, admin, targetPayer })`, now
  `registerPayer({ payer })`. The on-chain instruction no longer takes any
  arguments, so the SDK signature reflects that. Most apps never need to
  call this directly — see auto-prepend above.

- **Tests — `12-protocol-fees.test.ts` updated for permissionless
  registration** (`b722874`). The two tests that previously required an
  admin signature now register a payer with no extra signers. The
  duplicate-registration test still expects custom error 4006
  (`IntegratorAlreadyRegistered`).

- **Tests — `devnet-setup-protocol.ts` updated** (`b722874`).
  `EXECUTION_FEE` lifted from `2000n` → `5000n` to match `CREATION_FEE`
  for a uniform 5000-lamport protocol fee. Removed the manual
  `client.registerPayer` step from the setup flow — SDK auto-prepends
  on the first fee-paying tx now.

### Known issues

- **F-1 (Low):** `tests-sdk/tests/12-protocol-fees.test.ts:230` ("charges
  fee for unregistered payer but skips FeeRecord counter update") is now
  stale. It uses the high-level `client.createWallet`, which auto-prepends
  `RegisterPayer`, so the FeeRecord *does* get created instead of staying
  null. The on-chain code path it tested is still correct ([entrypoint.rs:138-147](program/src/entrypoint.rs#L138)) — it is just no longer
  exercised by this specific test. Fix: migrate the test to use the
  lower-level `createCreateWalletIx` builder. **Non-blocking for mainnet.**

- **R-1 (Medium):** The `admin` field in `ProtocolConfig` is **not
  rotatable** via `UpdateProtocol` — only `creation_fee`, `execution_fee`,
  `enabled`, and `treasury` can be changed. Loss of the admin key means
  the protocol cannot be re-administered. **Mitigation:** initialize
  `ProtocolConfig` with `admin = <Squads multisig PDA>` from day 1, so
  signer compromise is handled by Squads governance and the on-chain
  rotation gap becomes a 1% black-swan concern. A code-level fix
  (cosign-style rotation) is recommended within 6 months as cheap
  insurance.

### Operational

These do not change the program or the public SDK, but they affect every
mainnet operator:

- **Fees default uniform 5000/5000 lamports** in the devnet setup script.
  The on-chain default values are still set at `InitializeProtocol` time;
  this only changes the recommended starting values.
- **Audit doc** at [`docs/audit-2026-04-28/findings.md`](docs/audit-2026-04-28/findings.md)
  contains the full Phase E operational checklist (key custody, deploy
  sequence, monitoring, rollback procedures). The companion private
  repo `onspeedhp/lazorkit-admin` ships scripts and runbooks for each
  Phase E item.

---

## Earlier history

For pre-`refactor/sdk-cleanup` history see commit log on `main` and the
prior security review at
[`docs/security-review-2026-04-21.md`](docs/security-review-2026-04-21.md).
