# Changelog

All notable changes to the LazorKit smart wallet protocol and SDK are
documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Protocol v2 (program 2.0.0)

An audit of `program/src` produced 26 findings, five proven by reproduction
tests. The audit that already existed (Accretion / Solana Foundation, A26SFR1,
Feb 2026) covered `program-v2`, **not this repo** — this is a fork that added an
entire fee layer nobody had reviewed, and the heaviest findings all lived in that
delta.

Underneath the individual bugs was a structural problem: `role` answered two
independent questions — what may you *manage* and what may you *spend* — while
gating only the first. That is why "Spender" named a tier with full control of
the vault.

v2 ships every fix and the new permission model as one in-place upgrade at the
existing program ID. **v1 accounts are abandoned, not migrated.**

### Critical and high

- **C-1 — an admin could freeze every user's funds.** The entrypoint reverted
  every `CreateWallet`/`Execute`/`ExecuteDeferred` when the protocol config was
  disabled or its fee was zero, and those are the only paths that move funds out
  of a vault. One admin write, permanent, unrecoverable. Fee collection is now
  *skipped* rather than reverting, the config PDA address is pinned so "not
  configured" cannot be spoofed, and both fees are capped at 0.01 SOL so an
  unpayable fee cannot be a freeze in disguise.
- **H-1 — authentication could be driven from another program.** Both the
  Secp256r1 authenticator and `Execute` now refuse to run below the top level.
- **H-2 — rank governed management and nothing else.** `Execute` never read
  `role`, so a "Spender" spent exactly like an Owner. Rank and policy are now
  separate fields answering separate questions; a Delegate must carry a policy,
  and an authority that carries one may not create authorities at all.
- **H-3 — `Execute` conscripted the paymaster.** Every outer signer was forwarded
  into every inner CPI, so a session limited to 0.001 SOL could move 2 SOL out of
  the fee payer's own wallet. Forwarding is now opt-in per account, never covers
  the fee payer, and on the session path covers only the session's own key.
- **H-4 — token authority escapes** are caught by the pre/post snapshot, which
  now runs for policy-bearing authorities as well as sessions.

### Medium

- **M-2** — the program refuses to run at any address other than the one
  compiled into it.
- **M-3** — the ProtocolConfig PDA address is verified at every read site, not
  just its owner.
- **M-4** — the accounts hash binds each referenced account's
  `is_signer`/`is_writable`, not only its key. A relayer could previously take an
  account approved as read-only and submit it writable.
- **M-5** — an all-zero Secp256r1 pubkey is rejected in `TransferOwnership`.
- **M-6** — `payer.is_signer()` is explicit in the six processors that relied on
  the System Program enforcing it during a CPI that is skipped for a pre-funded
  PDA.
- **M-1, M-7** — documented rather than changed, with the reasoning: an Ed25519
  authority's transaction signature already binds strictly more than a payload
  signature would, and a program whitelist constrains one level of CPI while the
  value limits constrain the whole call graph.

### Added

- **Several Owners per wallet.** Each device holds its own passkey and passkeys
  cannot be copied, so multi-device means multi-authority — and only if they are
  all Owners can a surviving device revoke a lost one. `WalletAccount.owner_count`
  refuses the removal of the last Owner.
- **Per-authority spending policies.** The action buffer that bounded sessions
  now bounds authorities too, on the same engine.
- **Two-step protocol admin rotation** (propose / accept). `UpdateProtocol` could
  not write `admin` at all, and a one-step write would make a typo permanent.
- **Version discipline.** PDA seeds namespaced by protocol major version, account
  discriminators carrying it in their high nibble, and a validated `version` byte
  that is finally read rather than only written. See
  [`docs/upgrade-procedure.md`](docs/upgrade-procedure.md).
- **Golden vectors** for the accounts-hash wire format
  ([`test-vectors/accounts-hash.json`](test-vectors/accounts-hash.json)),
  asserted against by the program and both SDKs.

### Breaking — protocol v2

- **Every PDA address changes.** Seeds are namespaced `lk2:`. v1 wallets, vaults,
  authorities, sessions and the protocol singletons are unreachable from v2 code.
  This is deliberate: the singleton seeds would otherwise collide with accounts
  that already exist, and `initialize_protocol` requires a zero-length account, so
  the protocol would have been permanently un-initialisable.
- **Account discriminators renumbered** to `0x21`–`0x27`. A v1 account fails
  immediately rather than being reinterpreted under a moved layout.
- **Account index bytes cap at 127.** Bit 7 is now the forward-signer flag. An
  index of 128 or above is rejected, not masked.
- **v1 signatures no longer verify.** The accounts hash covers privilege.
- **`AddAuthority` payload gained `[policy_len u16][policy]`** between the key
  material and the auth payload, inside the signed region.
- **`AddAuthority` and `RemoveAuthority` need the wallet account writable.** The
  instruction data is unchanged, so this fails at runtime rather than at compile
  time — and only on the paths that touch an Owner.
- **Serialized `DeferredPayload`s do not cross the version boundary.** They carry
  a version and are rejected on mismatch; re-authorize instead of replaying.

### Migration

There is no account migration path, and none is needed: the protocol had one
integrator running minimal traffic and no finished product, so mainnet was in
practice a test deployment.

**Before upgrading mainnet**, in this order:

1. Run `scripts/survey-v1.ts` and keep its report private (it lists real user
   wallets and balances — operational intel, not repo content).
2. Sweep any v1 vault still holding SOL through the legitimate Owner path **on
   the current binary**. After the upgrade those vaults are unreachable.
3. Confirm `PROTOCOL_INIT_AUTHORITY` for the mainnet build. It defaults to the
   existing deployer key and gates `InitializeProtocol` permanently.
4. Rehearse locally: load the old `.so` into a validator as upgradeable,
   smoke-test, upgrade in place, re-run. Record both SBF SHA-256 hashes.

For clients:

```diff
- const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);
+ // Same call — the seed prefix is internal to the SDK. The address it
+ // returns is different, and any v1 address you cached is stale.
+ const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);
```

```diff
  await client.addAuthority({
    payer, walletPda, adminSigner,
    newAuthority: { type: 'ed25519', publicKey: delegate.publicKey },
    role: ROLE_SPENDER,
+   // A Delegate must carry a policy — this is what makes the name true.
+   policy: serializeActions([Actions.solLimit(1_000_000_000n)]),
  });
```

```diff
+ // Creating an Owner is now possible, and deliberately explicit.
+ await client.addAuthority({
+   payer, walletPda, adminSigner,
+   newAuthority: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
+   role: ROLE_OWNER,
+   allowOwner: true,
+ });
```

If you build instructions with the low-level builders rather than the client,
make the wallet account writable on `AddAuthority` and `RemoveAuthority`.


### Added — foundation devnet support (SDK 0.3.0)

The single source of truth for both LazorKit on-chain builds. `@lazorkit/sdk-legacy`
ships from this repo and is also consumed by the sibling `program-v2` repo
(the foundation, no-fee build that occupies the same mainnet program ID slot
during the foundation contract). These changes let one SDK serve both binaries
at the same mainnet ID and keep dApp DX uniform across the binary swap.

- **`PROGRAM_ID_FOUNDATION_DEVNET`** constant (`FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao`)
  exported from `constants.ts`. Lets devs target the foundation devnet binary
  for testing without overriding `programId` manually. The mainnet ID
  (`LazorjRF…`) and existing commercial devnet ID (`4h3X…`) are unchanged;
  the new constant is additive.
- **Error decoding** in `utils/errors.ts` now covers the additional codes
  emitted by the two builds:
  - `3030 SessionVaultOwnerChanged`, `3031 SessionVaultDataLenChanged`,
    `3032 SessionTokenAuthorityChanged` — vault / token-authority invariant
    defenses against `System::Assign` / `SetAuthority` / `Approve` escapes.
  - `4001 ProtocolAlreadyInitialized` through `4007 InvalidTreasury` —
    protocol-fee management errors emitted by the commercial flow.
  No runtime API changes; existing callers continue to work unmodified.

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
