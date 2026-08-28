# Upgrade procedure

How to change LazorKit's on-chain layout without stranding anybody's funds.

Written after the v1 → v2 upgrade, which surfaced the failure modes below the
hard way. The mechanisms it describes are all in the code; this document exists
so the next upgrade is a checklist rather than a rediscovery.

---

## The constraint everything follows from

**The program keeps its address across versions.** PDA addresses are therefore a
pure function of the seeds, and a new binary deployed to the same address
inherits every account the old one created, at exactly the addresses the new one
would want for itself.

For accounts keyed by random material — `[WALLET, user_seed]` with a 32-byte
random seed — a collision is theoretical. For the singletons it is certain:
`[PROTOCOL_CONFIG]` and `[TREASURY_SHARD, id]` resolve to one address each.

That is not merely untidy. `initialize_protocol` guards with `check_zero_data`,
which requires `data_len() == 0`. An account left behind by the previous version
can never satisfy it, no instruction exists to close it, and the protocol is
permanently un-initialisable. The failure is silent until someone tries to
deploy, and unrecoverable afterwards.

---

## Two levers, and which one to pull

### `PROTOCOL_VERSION` — the major version

`program/src/state/mod.rs`. Encoded in two places, deliberately redundant:

- **PDA seed prefix**: every seed in `program/src/seeds.rs` starts `lk{N}:`.
  Different prefix, disjoint address space, no collision with any other version.
- **Account discriminator high nibble**: `0x{N}{type}`. A previous version's
  account fails on byte 0 rather than being reinterpreted.

The seed namespace handles accounts found by derivation; the discriminator
handles accounts handed to an instruction deliberately. Either alone would
mostly work. Both together mean a stale account cannot be mistaken for a live
one by any route.

**Bump it when** a change alters the meaning of any account's bytes, moves a
field, or changes an instruction's account ordering in a way old clients would
get wrong. Bumping it abandons the previous version's accounts — see the sweep
below.

### `CURRENT_ACCOUNT_VERSION` — the layout revision

Also `program/src/state/mod.rs`. Written into every account at creation and
checked on every read via `state::check_header`, reached through each type's
`check()` — `WalletAccount::check`, `AuthorityAccountHeader::check`, and so on.
An account carrying a different revision is refused with
`ProtocolError::AccountVersionMismatch` (4013), which is distinct from
`InvalidAccountData` so an operator can tell "wrong account" from "account
written by a different build".

**Bump it when** a change is address- and discriminator-compatible but the bytes
mean something new — a field added into existing padding, a field's
interpretation changed. Existing accounts then fail closed with a legible code
instead of being parsed as if nothing happened.

In v1 this byte was written at ten sites and read at none, so it carried no
information and the option of a graceful layout change did not exist. Keep it
read.

### Neither

Adding an instruction, changing internal logic, or tightening a check needs no
version bump at all. Prefer this.

---

## Procedure

### 1. Survey the deployed version — before anything else

```bash
npx tsx scripts/survey-v1.ts --cluster mainnet
```

Reports account counts by type, every vault still holding lamports, and whether
`ProtocolConfig` is initialised and who holds `admin`.

**This gates the upgrade.** A bumped `PROTOCOL_VERSION` makes the previous
version's vaults unreachable: the only path that moves vault funds is `Execute`
signed by a live authority, and after the upgrade the binary no longer
recognises those authorities. Any funded vault must be swept through the
legitimate Owner path **on the current binary** first. Sweeping afterwards is not
possible, and no admin instruction exists to do it for the user — deliberately;
see the note on admin-close below.

### 2. Change the code

- Seeds live in one module (`program/src/seeds.rs`). Never inline a seed literal.
- Discriminators live in one enum. **Never match on a numeric literal** — v1's
  `execute::immediate` matched bare `2` and `3` for Authority and Session, which
  silently stopped matching anything the moment the discriminators moved, and
  every Execute failed with a flat `InvalidAccountData`. Bind to the enum.
- Every read path calls the account type's `check()`. Do not compare `data[0]`
  by hand; that is how v1 ended up with 28 hand-written checks and no version
  gate.

### 3. Mirror it in both SDKs

They share no code, so every change lands twice:

| Concern | sdk-kit | sdk-legacy |
|---|---|---|
| Seeds | `src/pdas.ts` | `src/utils/pdas.ts` |
| Discriminators, versions | `src/constants.ts` | `src/constants.ts` |
| Account decoders | `src/codecs/accounts.ts` | `src/utils/accounts.ts` |
| Instruction builders | `src/instructions/builders.ts` | `src/utils/instructions.ts` |
| Signed payloads | `src/secp256r1/signing.ts` | `src/utils/signing.ts` |

`sdk-kit/tests/` is a cross-SDK differential harness — several files import
sdk-legacy source and assert byte equality — so it catches drift between the two
if the change is covered there. `pdas.test.ts` deliberately re-derives seeds by
hand rather than importing the constants; keep it that way, it is the only
independent oracle for the seed values.

### 4. Verify locally, in this order

```bash
cargo fmt --all -- --check
cargo clippy --features devnet --all-targets -- -D warnings        # see lint.yml for the allow-list
cargo test --features devnet -p lazorkit-program --lib
./scripts/build-repro-fixtures.sh
cargo test --features devnet -p lazorkit-program --tests
cd sdk/sdk-kit && npm test
cd tests-sdk && npm run test:local
cd tests-sdk-kit && npm run test:local
```

`program/tests/v2_namespace_tests.rs` asserts the namespace and version
mechanisms directly: seeds derive disjoint addresses, discriminators carry the
version, a previous-version account is refused, a future layout revision is
refused with 4013. Extend it rather than writing a parallel test.

### 5. Rehearse the upgrade

The recipe in `docs/reviews/2026-05-23-strict-fee-merge-readiness.md` §
"upgrade rehearsal" has been executed once and works: build the old binary in a
worktree, load it into a local validator as upgradeable, create real state,
upgrade in place to the new binary, re-run. Record both SBF SHA256 hashes.

### 6. Deploy

```bash
cargo build-sbf --features mainnet
sha256sum target/deploy/lazorkit_program.so     # record it
solana program deploy target/deploy/lazorkit_program.so -u m
```

Then re-initialise: `InitializeProtocol`, `InitializeTreasuryShard` per shard.
A `PROTOCOL_VERSION` bump moves those PDAs, so they are fresh accounts, not
existing ones — which is the whole point.

---

## Things deliberately not available

**No admin instruction closes user accounts.** It has been proposed as a way to
clean up after an upgrade. It is a permanent backdoor: an instruction that lets a
protocol admin delete a user's wallet stays in the binary forever, would be
flagged critical by any audit, and turns a leaked admin key into total loss. It
is also unnecessary — a version bump already makes old accounts inert — and
actively dangerous, because closing a wallet or authority PDA does not move the
vault's lamports and leaves them permanently unreachable.

The legitimate shape of that feature is `CloseWallet` authorised by the wallet's
**own Owner**, which sweeps the vault to a destination the Owner names.

**No lazy migration of existing accounts.** Considered and rejected for v1 → v2:
it needs a code path that can read both layouts, which is the compatibility
burden the version namespace exists to avoid. Reconsider only if a future
version has real users whose accounts must survive — and then write the
migration as an explicit instruction the user calls, never as a side effect of
an unrelated one.
