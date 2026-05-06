# Strict fee enforcement for `lazorkit-protocol`

- **Status:** Draft — pending audit review
- **Date:** 2026-05-07
- **Author:** internal
- **Audience:** Accretion delta-audit reviewer, lazor-kit core team
- **Affects:** `lazorkit-protocol` (commercial binary). `program-v2` (foundation
  binary) is unaffected — see § 4.
- **Decision required before:** next mainnet deploy of the commercial binary
- **No code is changed by this document.** This is a design proposal to be
  ratified before implementation.

## 0. TL;DR

The commercial binary's fee collection is currently **opt-in at the on-chain
layer** — a transaction that omits the four trailing fee accounts succeeds
without paying a fee. This proposal flips the on-chain enforcement to
**strict**: any fee-eligible instruction (CreateWallet / Execute /
ExecuteDeferred) submitted to the commercial binary after `initialize_protocol`
*must* carry a valid `[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]`
suffix and *must* result in a successful `payer → shard` transfer plus a
`FeeRecord` counter bump. Anything else returns a custom error. The foundation
binary (`program-v2`) is unaffected because the entire fee module is stripped
from its source tree (§ 4).

## 1. Background

### 1.1 The two binaries

LazorKit ships from two sibling repositories:

| Binary | Repo | Purpose | Fee surface |
|---|---|---|---|
| Commercial | `lazorkit-protocol` | Fee-bearing build for the lazor-kit team | Has `try_collect_fee`, `ProtocolConfig`, `TreasuryShard`, `FeeRecord`, etc. |
| Foundation | `program-v2` | No-profit build for the Solana Foundation contract period | Fee surface stripped via `scripts/fee-paths.txt`. Function `try_collect_fee` does not exist. |

Both binaries deploy to the *same* mainnet program ID
(`LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi`); the upgrade authority swaps
between them at the contract boundary. The same `@lazorkit/sdk-legacy` (or
`@lazorkit/sdk`) ships against both — the SDK probes the on-chain
`ProtocolConfig` PDA and conditionally appends fee accounts.

### 1.2 Today's on-chain logic

`program/src/entrypoint.rs` calls `try_collect_fee` for fee-eligible
discriminators (0 = CreateWallet, 4 = Execute, 7 = ExecuteDeferred). The
function's contract today is **"skip when not provided"**:

```rust
fn try_collect_fee(...) -> Result<&[AccountInfo], ProgramError> {
    if accounts.len() < 5                                      { return Ok(accounts); }
    if accounts[n-1].key() != &SYSTEM_PROGRAM_ID               { return Ok(accounts); }
    if accounts[n-4].owner() != program_id                     { return Ok(accounts); }
    if config_data[0] != AccountDiscriminator::ProtocolConfig as u8
                                                               { return Ok(accounts); }
    if config.enabled == 0                                     { return Ok(&accounts[..n-4]); }
    // ... otherwise transfer fee, bump counter ...
}
```

Each `Ok(accounts)` short-circuits the fee path and lets the inner
processor run unmodified. The processors themselves (`create_wallet`,
`execute::immediate`, `execute::deferred`) carry **no independent fee
assertion**. The net behaviour is documented and intended for the
slot-share strategy (see `sdk/sdk-legacy/src/constants.ts` head comment),
but as a side effect it also makes the commercial binary bypassable.

### 1.3 The bypass

A demonstration was run against a freshly-deployed commercial binary with
`ProtocolConfig` initialized and `enabled = 1`:

```
initialize_protocol(creation_fee=5000, execution_fee=2000, num_shards=4)
initialize_treasury_shard × 4
                                          // ProtocolConfig now exists, enabled.
build CreateWallet ix WITHOUT 4 fee accts // (< 5 trailing accounts)
sendTx → SUCCESS
treasury balance delta = 0                // ❌ NO FEE CHARGED
wallet account exists                     // ✅ wallet creation succeeded
```

Reproduction script: `tests-sdk-kit/tests/_bypass-demo.test.ts` (run
locally; not committed). Verified on `lazorkit-protocol`
`feat/sdk-kit` branch, 2026-05-07.

### 1.4 Why the bypass exists

Three independent design decisions compose:

1. **`try_collect_fee` skips on missing pattern** so the same source tree can
   produce both a fee-bearing and a fee-free binary depending on whether
   `ProtocolConfig` is initialized.
2. **Processors don't re-check fee state** — the fee module is the *only* gate.
3. **SDK auto-detects fee state** by probing `ProtocolConfig` and only
   appending fee accounts when it sees an enabled config. Honest SDK
   consumers always pay; hand-rolled or modified-SDK consumers can omit.

Item (1) is essential to slot-share. Items (2) and (3) are conventions, not
guarantees. The proposal flips (1) to be strict at the binary level *only*
in `lazorkit-protocol` — `program-v2` continues to satisfy item (1) by not
having the function at all (§ 4).

## 2. Threat model

### 2.1 In scope

- **T-1: Honest dApp dev with default SDK** — uses `@lazorkit/sdk` /
  `@lazorkit/sdk-legacy` unmodified. Always pays fee. Not a threat.
- **T-2: Adversarial integrator** — modifies the SDK, hand-rolls the tx, or
  uses a different client to omit the fee account suffix. Currently bypasses
  fee. **In scope.**
- **T-3: Bot at scale** — same as T-2 but at high volume; fee revenue loss
  scales linearly. **In scope.**
- **T-4: Misconfigured admin** — calls `initialize_protocol` then forgets to
  call `initialize_treasury_shard`. Currently `try_collect_fee` reaches the
  shard-validation step and returns an error (the existing path handles
  this). Verified working today.
- **T-5: Front-running of `initialize_protocol`** — out of scope (admin key
  is single-signer and signs the deploy tx; race conditions with deploy
  ordering are operational, not protocol-level).

### 2.2 Out of scope

- Attacks on the SDK supply chain (npm registry compromise of
  `@lazorkit/sdk*`). Mitigated by `npm` provenance, CODEOWNERS, branch
  protection.
- The "user pays" UX scenarios — fees are paid by the relayer / integrator,
  end users are not the threat surface.

## 3. Proposed change

### 3.1 New `try_collect_fee` contract

For `discriminator ∈ {0, 4, 7}` on the commercial binary, the function MUST
either return `Ok(&accounts[..n-4])` after a successful fee transfer + record
update, or return an error. **No skip path remains.**

```rust
fn try_collect_fee<'a>(
    program_id: &Pubkey,
    discriminator: u8,
    accounts: &'a [AccountInfo],
) -> Result<&'a [AccountInfo], ProgramError> {
    if accounts.len() < 5 {
        return Err(ProtocolError::FeeAccountsRequired.into());
    }
    let n = accounts.len();
    let payer        = &accounts[0];
    let maybe_config = &accounts[n - 4];
    let maybe_record = &accounts[n - 3];
    let maybe_shard  = &accounts[n - 2];
    let maybe_system = &accounts[n - 1];

    // Trailing-account shape gate.
    if maybe_system.key() != &SYSTEM_PROGRAM_ID {
        return Err(ProtocolError::FeeAccountsRequired.into());
    }

    // ProtocolConfig — must be program-owned + valid + enabled + non-zero fee.
    if maybe_config.owner() != program_id {
        return Err(ProtocolError::ProtocolNotInitialized.into());
    }
    let config_data = maybe_config.try_borrow_data()?;
    if config_data.is_empty()
        || config_data[0] != AccountDiscriminator::ProtocolConfig as u8
        || config_data.len() < core::mem::size_of::<ProtocolConfig>()
    {
        return Err(ProtocolError::ProtocolNotInitialized.into());
    }
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
    if config.enabled == 0 {
        return Err(ProtocolError::ProtocolDisabled.into());
    }
    let fee = match discriminator {
        0     => config.creation_fee,
        4 | 7 => config.execution_fee,
        _     => unreachable!("entrypoint dispatcher restricts caller to 0/4/7"),
    };
    drop(config_data);
    if fee == 0 {
        return Err(ProtocolError::FeeNotConfigured.into());
    }

    // TreasuryShard — must be program-owned + valid.
    if maybe_shard.owner() != program_id {
        return Err(ProtocolError::InvalidTreasuryShard.into());
    }
    {
        let shard_data = maybe_shard.try_borrow_data()?;
        if shard_data.is_empty()
            || shard_data[0] != AccountDiscriminator::TreasuryShard as u8
        {
            return Err(ProtocolError::InvalidTreasuryShard.into());
        }
    }

    // FeeRecord — auto-create if absent, else require program-owned.
    let (expected_record, record_bump) = Pubkey::find_program_address(
        &[b"fee_record", payer.key().as_ref()],
        program_id,
    );
    if maybe_record.key() != &expected_record {
        return Err(ProtocolError::InvalidFeeRecord.into());
    }
    if maybe_record.owner() == &SYSTEM_PROGRAM_ID {
        // First-time payer — create + initialize the FeeRecord PDA inline.
        let space = core::mem::size_of::<FeeRecord>();
        let lamports = Rent::get()?.minimum_balance(space);
        invoke_signed(
            &system_instruction::create_account(
                payer.key(), maybe_record.key(), lamports, space as u64, program_id,
            ),
            &[payer.clone(), maybe_record.clone(), maybe_system.clone()],
            &[&[b"fee_record", payer.key().as_ref(), &[record_bump]]],
        )?;
        let mut data = maybe_record.try_borrow_mut_data()?;
        let rec = unsafe { &mut *(data.as_mut_ptr() as *mut FeeRecord) };
        rec.discriminator   = AccountDiscriminator::FeeRecord as u8;
        rec.bump            = record_bump;
        rec.payer           = *payer.key();
        rec.wallet_count    = 0;
        rec.execute_count   = 0;
        rec.total_paid      = 0;
    } else if maybe_record.owner() != program_id {
        return Err(ProtocolError::InvalidFeeRecord.into());
    }

    // Transfer fee: payer → shard.
    invoke(
        &system_instruction::transfer(payer.key(), maybe_shard.key(), fee),
        &[payer.clone(), maybe_shard.clone(), maybe_system.clone()],
    )?;

    // Bump FeeRecord counters.
    {
        let mut data = maybe_record.try_borrow_mut_data()?;
        let rec = unsafe { &mut *(data.as_mut_ptr() as *mut FeeRecord) };
        match discriminator {
            0     => rec.wallet_count  = rec.wallet_count.checked_add(1).ok_or(ProtocolError::Overflow)?,
            4 | 7 => rec.execute_count = rec.execute_count.checked_add(1).ok_or(ProtocolError::Overflow)?,
            _     => unreachable!(),
        }
        rec.total_paid = rec.total_paid.checked_add(fee).ok_or(ProtocolError::Overflow)?;
    }

    Ok(&accounts[..n - 4])
}
```

### 3.2 New error codes

Added to the existing `ProtocolError` enum (currently 4001..=4006). New
codes 4007..=4012:

| Code | Name | Cause |
|---|---|---|
| 4007 | `FeeAccountsRequired` | tx for disc 0/4/7 has fewer than 5 accounts, or the trailing-system sentinel is missing |
| 4008 | `ProtocolNotInitialized` | `ProtocolConfig` PDA is system-owned or has wrong discriminator |
| 4009 | `ProtocolDisabled` | `ProtocolConfig.enabled == 0` |
| 4010 | `FeeNotConfigured` | resolved fee for the discriminator is `0` (caller-set, but in strict mode this must be > 0) |
| 4011 | `InvalidTreasuryShard` | shard PDA owner ≠ program or wrong discriminator |
| 4012 | `InvalidFeeRecord` | record PDA address doesn't match the canonical seed for the payer, or owner is foreign |

(Code 4006 `PayerAlreadyRegistered` becomes effectively unreachable — see
§ 3.4.)

### 3.3 Bootstrap window

Between deploy and the admin's first `initialize_protocol` call, every
fee-eligible instruction returns `ProtocolNotInitialized` (4008). This is
intended:

1. The window is 1 tx wide. Admin signs `deploy` and `initialize_protocol`
   in immediate succession (§ 6.3 deploy runbook).
2. Pre-init wallet creation is precisely the failure mode we want — it
   forces clean operational hygiene.
3. Foundation builds (`program-v2`) bypass this entirely because the whole
   `try_collect_fee` is stripped (§ 4).

### 3.4 `register_payer` becomes optional / superseded

The current SDK auto-prepends a `RegisterPayer` instruction on the payer's
first fee-paying tx to create the `FeeRecord` PDA. With inline auto-create
(§ 3.1 last block), this is no longer necessary:

- Existing `register_payer` instruction (disc 12) **stays in the program**
  for backward compatibility but is documented as redundant after this
  change. It still works; it's just superfluous.
- SDK simplification: drop the `resolveProtocolFeeWithRegister` path; just
  always pass the canonical `FeeRecord` PDA address.
- Existing test `12-protocol-fees.test.ts` `'rejects duplicate payer
  registration'` (4006 `PayerAlreadyRegistered`) is preserved — calling
  `register_payer` twice still fails.

### 3.5 What stays the same

- All other instructions (1, 2, 3, 5, 6, 8, 9, 10–14) behave identically.
- `ProtocolConfig` layout, `TreasuryShard` layout, `FeeRecord` layout —
  unchanged.
- Action enforcement, secp256r1 challenge construction, account hashing,
  compact-instruction packing — unchanged.
- The SDK's wire format does not change. SDK behavior change is "always
  append fee accts when ProtocolConfig PDA is initialized", which it
  already does.

## 4. Effect on `program-v2` (foundation binary): **none**

`program-v2` strips the fee surface via `scripts/fee-paths.txt`. The
current rules already remove the entire `processor/protocol/` directory,
the three state files, and forbid the symbols `try_collect_fee`,
`ProtocolConfig`, `TreasuryShard`, `FeeRecord`. This proposal adds:

```
# new symbols introduced by this proposal — all forbidden in program-v2
SYMBOL \bFeeAccountsRequired\b
SYMBOL \bProtocolNotInitialized\b
SYMBOL \bProtocolDisabled\b
SYMBOL \bFeeNotConfigured\b
SYMBOL \bInvalidTreasuryShard\b
SYMBOL \bInvalidFeeRecord\b
```

The strip-fee.sh script removes `try_collect_fee` from the entrypoint
when cherry-picking, so program-v2's entrypoint never calls it. Result:

- program-v2 has zero fee enforcement code (compile-time guarantee)
- program-v2 has zero `FeeRecord` creation (the symbol doesn't exist)
- check-no-fee CI guard (`scripts/check-no-fee.sh`) ensures the symbols
  don't reappear via accidental cherry-pick

This is the same separation lazor-kit already relies on for slot-share.

## 5. Test impact + migration

### 5.1 Tests that currently rely on opt-in behaviour

| Test file | Operation | Current pass mechanism | Under strict mode |
|---|---|---|---|
| 01-wallet | CreateWallet | no ProtocolConfig → skip | **fails** with 4008 ProtocolNotInitialized |
| 02-authority | CreateWallet + Add/Remove | same | **fails** at CreateWallet |
| 03-execute | CreateWallet + Execute | same | **fails** |
| 04-session | CreateWallet + CreateSession | session is disc 5 (not fee-eligible), but CreateWallet first → **fails** |
| 05-replay | CreateWallet + Execute (low-level) | same | **fails** |
| 06-counter | CreateWallet (Secp256r1) + Add + Execute | same | **fails** |
| 07-e2e | CreateWallet + … | same | **fails** |
| 08-deferred | CreateWallet + Authorize/ExecuteDeferred | same | **fails** |
| 09-permissions | CreateWallet + boundary checks | same | **fails** |
| 10-session-execute | CreateWallet + Execute | same | **fails** |
| 11-security | CreateWallet (multiple) | same | **fails** |
| 12-session-actions | CreateWallet + many Execute | same | **fails** |
| 13-deferred-client-api | CreateWallet + Authorize + Execute | same | **fails** |
| 14-vault-invariants | CreateWallet + Execute | same | **fails** |
| 15-sdk-unit | (none — pure unit) | — | unaffected |
| **12-protocol-fees** | initializes, then everything | first test inits | **passes** |

Net: 14 of 16 test files break under strict mode.

### 5.2 Two migration paths

**Approach A: Tests always init protocol first.**

Modify `tests-sdk-kit/tests/common.ts::setupTest()` to:

1. Generate `adminSigner` + `treasurySigner`, fund them.
2. Call `initializeProtocol` (idempotent across files because the suite
   runs with a single shared `--reset` validator).
3. Call `initializeTreasuryShard × N`.
4. Hand back the test context.

Every subsequent test file pays a real fee on each CreateWallet/Execute,
which is what mainnet would do. The change is one file, ~30 LOC.

This is the cleanest long-term option — tests reflect production reality.

**Approach B: Cargo feature gates strict mode.**

```toml
[features]
default = []
strict_fee = []
mainnet = ["strict_fee"]   # mainnet always strict
devnet = []                # devnet stays opt-in (legacy behavior)
```

```rust
#[cfg(feature = "strict_fee")]
fn try_collect_fee(...) { /* strict (§ 3.1) */ }

#[cfg(not(feature = "strict_fee"))]
fn try_collect_fee(...) { /* opt-in (legacy) */ }
```

- `cargo build-sbf --features mainnet` → strict (production)
- `cargo build-sbf --features devnet` → opt-in (existing tests pass unchanged)
- `cargo build-sbf --features devnet,strict_fee` → strict on devnet (12-protocol-fees + a new strict-mode bypass-rejection test run here)
- CI gate: mainnet workflow asserts the resulting `.so` contains the
  4008/4011/4012 error markers; rejects deploy if absent.

Approach B preserves existing tests verbatim; Approach A modernises them.

**Recommendation: Approach A, because:**
- Single source of truth for fee behaviour (no two paths to maintain).
- Tests exercise the same code path mainnet does — no "but it works in
  devnet" surprises.
- Audit scope is narrower (one fee-collection function to review, not two).
- Operational cost: ~30 LOC update to `common.ts` + ~3 minutes per test
  run for the extra init txs (acceptable).

Approach B is the fallback if audit objects to behaviour-change-by-default
and the team wants a flag for graceful rollout.

### 5.3 New tests to add

Whether A or B is chosen, the suite gains these strict-mode tests
(co-locate in `tests-sdk-kit/tests/16-strict-fee.test.ts`):

| Test | Expected result |
|---|---|
| CreateWallet with no fee accts after init | error 4007 |
| CreateWallet before initialize_protocol | error 4008 |
| CreateWallet when ProtocolConfig.enabled == 0 | error 4009 |
| CreateWallet with fake ProtocolConfig (System-owned) | error 4008 |
| CreateWallet with fake TreasuryShard | error 4011 |
| CreateWallet with non-canonical FeeRecord PDA | error 4012 |
| First-time CreateWallet auto-creates FeeRecord without separate RegisterPayer | wallet_count = 1, FeeRecord owner == program_id |
| Second CreateWallet from same payer increments wallet_count | wallet_count = 2 |
| Execute charges execution_fee (not creation_fee) | shard delta == execution_fee, execute_count = 1 |
| ExecuteDeferred charges execution_fee | same |

## 6. Operational impact

### 6.1 Compute budget

Inline `FeeRecord` auto-create adds, on the first fee-paying tx per payer:

- `system_instruction::create_account` CPI: ~3000 CU
- `Rent::get` syscall: ~ 200 CU
- Mut borrow + zero-init of FeeRecord struct: ~500 CU

Total: ~3.7k CU on first-tx-per-payer; subsequent txs are unchanged
(~1k CU for the existing fee transfer + counter bump). Budget headroom
on a CreateWallet today is ~140k CU under the default 200k limit, so this
is comfortable. No CU bump request needed.

### 6.2 Deploy runbook

`docs/DEPLOY_RUNBOOK.md` (commercial mainnet section) gets a new step
between "deploy program" and "announce":

```
2.  solana program deploy ... → confirmed
3.  ✱ NEW: initialize protocol (creation_fee, execution_fee, num_shards)
4.  ✱ NEW: initialize_treasury_shard for each of 0..num_shards
5.  Sanity probe: send a CreateWallet from a test payer, verify shard balance increments
6.  Announce
```

Steps 3 + 4 already exist as instructions (`initialize_protocol`,
`initialize_treasury_shard`); they're just promoted to *required* before
public use. Multisig signs steps 3 + 4 via the same path as future
`update_protocol` calls.

### 6.3 Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| Admin forgets step 3/4 | First public CreateWallet returns 4008 | Admin runs steps 3/4, retries |
| Admin sets `enabled = 0` later via update_protocol | Public txs return 4009 | Admin re-enables (multisig sig required) |
| Admin sets fee = 0 | Public txs return 4010 | Admin updates fee to non-zero |

All three are loud failures (custom error code, no silent degradation),
consistent with the rest of the program's failure surface.

## 7. Audit considerations

### 7.1 Surface change for delta audit

| Touched | LOC delta (estimate) | Risk |
|---|---|---|
| `entrypoint.rs::try_collect_fee` | -10 / +90 | High (this is the gate) |
| `error.rs` (add 6 codes) | +6 | None |
| `state/fee_record.rs` (no struct change, init logic moves) | 0 / 0 | None |
| `processor/protocol/register_payer.rs` (becomes redundant, kept for compat) | 0 / +5 doc | None |
| Test suite migration (Approach A) | +30 / 0 in `common.ts` | None |
| `program-v2/scripts/fee-paths.txt` (add 6 forbidden symbols) | +6 | None |

Estimated audit scope: 1 function (the new `try_collect_fee`). The path
is mostly "the existing skip points become returns" plus an inline
account-creation block.

### 7.2 Specific questions for Accretion

1. Inline `system_instruction::create_account` from inside the entrypoint
   (before the inner processor runs) — any concern about CPI-stack-height
   accounting for the inner processor?
2. The new error codes 4007–4012 are returned from the entrypoint, before
   any processor logic. Confirm this is consistent with audit-level
   guidance on early-return error reporting.
3. The `FeeRecord` auto-create reuses the canonical `[b"fee_record", payer]`
   seeds with the bump derived inside the entrypoint. Confirm this matches
   the expectations of finding R-1 (admin-not-rotatable) — there's no
   privilege-escalation path because the seed is payer-bound.
4. Approach A vs B preference, given Accretion's general guidance on
   feature-flag complexity vs single-code-path auditability.

### 7.3 Re-audit scope

A delta audit on a single 90-LOC function should be inexpensive. The
proposal does not touch:

- secp256r1 verification
- session permission enforcement
- compact-instruction packing
- vault invariants (H1 fix)
- admin-pda owner checks (H2 fix)
- counter / replay logic

All of those remain at their previously-audited bytes.

## 8. Open questions

### Q-1: Does `program-v2` need any changes?

No — see § 4. The strip-fee mechanism removes everything. The only delta
is six new forbidden symbols in `fee-paths.txt`, which prevents accidental
cherry-pick of the new error names.

### Q-2: What happens to the `register_payer` permissionless instruction?

It stays in the program (disc 12) for backward compat. After this change
it's effectively a no-op replicated by inline auto-create. Documented as
deprecated; can be removed in a future audit cycle if the team decides.

### Q-3: Does the SDK need to change?

Minimal:

- `@lazorkit/sdk-legacy`: drop the `resolveProtocolFeeWithRegister` cache +
  auto-prepend logic. Just always pass the canonical FeeRecord PDA. Behaves
  the same on opt-in and strict modes.
- `@lazorkit/sdk` (kit flavor): same.
- No change to instruction encoding, byte layouts, or wire format.

### Q-4: How is "strict mode is enabled in this build" verified at deploy time?

`scripts/check-strict-fee.sh` (new, ~10 LOC) greps the built `.so` for the
new error names (4007–4012). CI workflow `sbf-cluster-check.yml` adds a
step that runs this against the `--features mainnet` build. The CI gate
fails the workflow if the markers are missing.

For Approach A, this is replaced by a simpler check — the new error names
exist unconditionally in the source, so no gate is needed; the tests
themselves enforce.

### Q-5: Backwards compatibility for existing on-chain wallets after binary swap

A wallet created on `program-v2` (foundation, no fee) and then operated on
the swapped commercial binary: every Execute pays a fee from the relayer
forward. Wallets are not bricked because the wallet account / authority /
session layouts are identical between binaries (`scripts/check-no-fee.sh`
guards this). Treated as expected behaviour.

## 9. Decision matrix

| Option | Pros | Cons | Recommendation |
|---|---|---|---|
| **9.1 Implement strict mode (Approach A — tests migrate)** | Single source of truth; cleanest audit; production parity in tests | 14 test files affected; admin must always init before public use | **Default recommendation** |
| 9.2 Implement strict mode (Approach B — Cargo feature) | Existing tests unchanged; gradual rollout possible | Two code paths; bigger audit surface; risk of accidental opt-in build to mainnet | Fallback if audit prefers it |
| 9.3 Don't implement; keep opt-in + add SDK / off-chain monitoring | No code change; no audit cost | Bypass remains; revenue at risk; revisits every audit cycle | Only if audit blocks |
| 9.4 Hybrid — strict mode reachable but gated by `ProtocolConfig.enforce_strict: bool` | Operational toggle; admin can flip | New field requires layout migration → blocking audit cost; gates become attack surface | Not recommended — config layout is currently audit-frozen |

## 10. Next steps (sequencing)

1. ✱ **This document → Accretion review.** Estimated 1 week.
2. After sign-off: implement on a feature branch
   `feat/strict-fee-enforcement`. ~3 days code + tests.
3. Open PR; request delta audit on the single function. ~1 week.
4. After audit clean: merge, then mainnet deploy with the new runbook
   (§ 6.2). The very next admin-signed tx after deploy must be
   `initialize_protocol`.
5. After deploy: update `program-v2/scripts/fee-paths.txt` with the new
   forbidden symbols (one-line cherry-pick).

Total elapsed: ~3 weeks calendar from sign-off to mainnet, gated mostly on
audit lead time. No mainnet deploy of the commercial binary should happen
without this fix.

---

## Appendix A — Reference: current `try_collect_fee`

`program/src/entrypoint.rs:189–234` (lazorkit-protocol, branch `main`,
commit at time of writing). Quoted for completeness:

```rust
fn try_collect_fee<'a>(
    program_id: &Pubkey,
    discriminator: u8,
    accounts: &'a [AccountInfo],
) -> Result<&'a [AccountInfo], ProgramError> {
    if accounts.len() < 5 { return Ok(accounts); }
    let n = accounts.len();
    let maybe_config = &accounts[n - 4];
    let maybe_record = &accounts[n - 3];
    let maybe_shard  = &accounts[n - 2];
    let maybe_system = &accounts[n - 1];

    if maybe_system.key() != &SYSTEM_PROGRAM_ID { return Ok(accounts); }
    if maybe_config.owner() != program_id      { return Ok(accounts); }

    let config_data = maybe_config.try_borrow_data()?;
    if config_data.is_empty()
        || config_data[0] != AccountDiscriminator::ProtocolConfig as u8
        || config_data.len() < core::mem::size_of::<ProtocolConfig>()
    {
        drop(config_data);
        return Ok(accounts);
    }
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
    if config.enabled == 0 { drop(config_data); return Ok(&accounts[..n - 4]); }
    let fee = match discriminator {
        0     => config.creation_fee,
        4 | 7 => config.execution_fee,
        _     => 0,
    };
    drop(config_data);
    if fee == 0 { return Ok(&accounts[..n - 4]); }
    // ... fee transfer + counter update ...
}
```

## Appendix B — Reference: existing error codes (`ProtocolError`)

`program/src/processor/protocol/error.rs` (paraphrased):

| Code | Name | Meaning |
|---|---|---|
| 4001 | `AlreadyInitialized` | initialize_protocol called twice |
| 4002 | `Unauthorized` | admin signature missing on update_protocol etc |
| 4003 | `InvalidShardId` | shard_id ≥ num_shards |
| 4004 | `InsufficientShardBalance` | withdraw_treasury below rent-exempt |
| 4005 | `InvalidTreasury` | treasury arg doesn't match config.treasury |
| 4006 | `PayerAlreadyRegistered` | register_payer called twice |

Proposal adds 4007–4012 (§ 3.2).
