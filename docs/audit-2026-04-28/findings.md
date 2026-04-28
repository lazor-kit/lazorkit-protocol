# Pre-mainnet audit findings — 2026-04-28

**Auditor:** automated walk + targeted code review
**Scope:** delta since 2026-04-21 review (`b722874` permissionless RegisterPayer
+ SDK auto-prepend) + full re-walk of highest-risk paths + test suite + threat
model
**SBF artifact:** `target/deploy/lazorkit_program.so` (build needed before
mainnet deploy, see Phase E)
**Prior baseline:** [docs/security-review-2026-04-21.md](../security-review-2026-04-21.md) (signed off as merge-ready)

## Verdict

**🟡 GO with caveats** for mainnet, conditional on Phase E (operational
checklist) being completed by the team. **No code-level blockers.** The
single risk that justifies a "yellow" not "green" is the **single-key
upgrade authority** combined with the **non-rotatable admin field** (new
finding R-1) — both are operational risks, not code bugs, and both have
documented mitigations.

## Findings

### Code-level findings

| ID | Severity | Title | Status |
|---|---|---|---|
| R-1 | Medium | Admin field in ProtocolConfig is not rotatable | New — document in risk register |
| F-1 | Low | Stale test in `12-protocol-fees.test.ts` | New — non-blocking; update before next push |
| NBP-1 | Info | SECURITY.md overclaims CPI guard for Ed25519 | Carried over from prior review |
| NBP-2 | Info | SDK lacks pre-flight action type validation | Carried over from prior review |
| NBP-3 | Info | No CI workflow / cargo-audit | Carried over from prior review |

### Operational findings (Phase E)

| ID | Severity | Title | Status |
|---|---|---|---|
| O-1 | High | Single-key upgrade authority at launch | Mitigation: HW wallet + 30-day multisig migration |
| O-2 | Medium | Admin key controls treasury + cannot be rotated | Mitigation: HW wallet + chain-of-custody doc |
| O-3 | Medium | No deploy-day rollback procedure documented | Plan-required before deploy |
| O-4 | Medium | No live monitoring at deploy time | Plan-required before deploy |

---

## Detailed walkthrough

### Phase A — RegisterPayer delta re-audit ✅ PASS

The only on-chain change since 2026-04-21 is `b722874`. Re-walked
[register_integrator.rs](../../program/src/processor/protocol/register_integrator.rs) line by line.

**A.1 — Code checklist (10/10 passed):**

- ✓ Payer signer flag enforced ([line 51](../../program/src/processor/protocol/register_integrator.rs:51))
- ✓ `target_payer = payer.key()` — derived from signer, not from instruction data ([line 55](../../program/src/processor/protocol/register_integrator.rs:55))
- ✓ Canonical PDA derivation via `find_program_address`; supplied PDA verified ([line 58-62](../../program/src/processor/protocol/register_integrator.rs:58))
- ✓ `check_zero_data` prevents double-init ([line 65-68](../../program/src/processor/protocol/register_integrator.rs:65))
- ✓ System Program pubkey validated inside `initialize_pda_account` ([utils.rs:64](../../program/src/utils.rs:64))
- ✓ Rent calc uses `size_of::<FeeRecord>()` (32 bytes)
- ✓ Discriminator + version + bump correctly written
- ✓ All counters zero-initialized
- ✓ `unsafe { from_raw_parts }` cast is sound (`#[repr(C)]` + `NoPadding`)
- ✓ No reentrancy — only System Program CPIs

**A.2 — Threat model for new instruction (5/5 blocked):**

- ✓ Cannot register FeeRecord at someone else's PDA (seed uses payer signer)
- ✓ Spam economically self-limiting (~0.00112 SOL rent per record)
- ✓ Double-init blocked by `check_zero_data`
- ✓ Race within slot resolved by AccountAlreadyInitialized
- ✓ `_instruction_data: &[u8]` — instruction data fully ignored

**A.3 — SDK auto-prepend safety:**

Two **non-security** UX gotchas to document:
1. **Sticky cache after failure**: comment at [client.ts:447](../../sdk/sdk-legacy/src/utils/client.ts:447) is misleading. `_registeredPayers.add(key)` runs before tx confirmation; if tx fails, cache stays poisoned for the LazorKitClient instance lifetime. Worst case: payer's stats permanently lost (fee still collected — verified).
2. **Concurrent cold-start race**: two parallel txs from a brand-new payer both prepend RegisterPayer; second lands with `IntegratorAlreadyRegistered (4006)`. Workaround: land one tx before parallelizing.

### Phase B — High-risk path re-walk ✅ PASS

#### B.1 Secp256r1 auth ([secp256r1/mod.rs](../../program/src/auth/secp256r1/mod.rs))

| Invariant | Result |
|---|---|
| Slot freshness with clock-skew handling (`slot > current` rejected separately) | ✓ [line 74-79](../../program/src/auth/secp256r1/mod.rs:74) |
| Anti-CPI guard `stack_height > 1` | ✓ [line 67](../../program/src/auth/secp256r1/mod.rs:67) |
| Counter odometer (`wrapping_add`, commit-after-all-checks) | ✓ [line 91, 251](../../program/src/auth/secp256r1/mod.rs:91) |
| 6-element challenge hash, single sha256 syscall | ✓ [line 122-136](../../program/src/auth/secp256r1/mod.rs:122) |
| clientDataJSON length **strict** (`!=` not `<` — no trailing bytes) | ✓ [line 158](../../program/src/auth/secp256r1/mod.rs:158) |
| Constant-time challenge compare | ✓ [line 180](../../program/src/auth/secp256r1/mod.rs:180) + 5 unit tests |
| rpIdHash binding | ✓ [line 212](../../program/src/auth/secp256r1/mod.rs:212) |
| User-presence flag | ✓ [line 204](../../program/src/auth/secp256r1/mod.rs:204) |
| Precompile introspection (current-1, program ID match, bounds, 0xFFFF only) | ✓ 14 unit tests in [introspection.rs:151-373](../../program/src/auth/secp256r1/introspection.rs:151) covering every adversarial offset/index attack |

#### B.2 Execute paths

- ✓ Immediate: `accounts_hash` binding for Secp256r1 ([immediate.rs:133-137](../../program/src/processor/execute/immediate.rs:133))
- ✓ Deferred: close-before-CPI ordering ([deferred.rs:132-141](../../program/src/processor/execute/deferred.rs:132) before loop at [line 157](../../program/src/processor/execute/deferred.rs:157))
- ✓ Self-reentrancy blocked in both paths (`SelfReentrancyNotAllowed (3013)`)
- ✓ Vault PDA signer flag set in CPI metas
- ✓ Hash + expiry verified before close in deferred TX2

#### B.3 Authority management

- ✓ AddAuthority validates `new_role ≤ 2` (no 255-role escape) ([manage.rs:207-212](../../program/src/processor/authority/manage.rs:207))
- ✓ RemoveAuthority: self-removal blocked, Owner-removal blocked, Admin → Spender only, **plus** `target == refund_dest` defensive guard ([manage.rs:423-444](../../program/src/processor/authority/manage.rs:423))
- ✓ Authorize: Secp256r1-only + Owner/Admin-only ([authorize.rs:122-129](../../program/src/processor/execute/authorize.rs:122))

#### B.4 Sessions + actions

- ✓ Pre-CPI snapshots: vault `owner`, `data_len`, token authorities, token balances ([immediate.rs:226-254](../../program/src/processor/execute/immediate.rs:226))
- ✓ Post-CPI invariant checks: `SessionVaultOwnerChanged`, `SessionVaultDataLenChanged`, `SessionTokenAuthorityChanged` ([immediate.rs:321-349](../../program/src/processor/execute/immediate.rs:321))
- ✓ Token authority snap covers `owner` + `delegate` + `close_authority` ([actions.rs:271-310](../../program/src/processor/execute/actions.rs:271))
- ✓ Max session duration enforced: 6,480,000 slots (~30 days) ([create.rs:212](../../program/src/processor/session/create.rs:212))

#### B.5 Fee path entrypoint

- ✓ Layered validation on every fee account: owner + discriminator + length before pointer cast ([entrypoint.rs:71-209](../../program/src/entrypoint.rs:71))
- ✓ Checked arithmetic on lamport sum + counter increments
- ✓ FeeRecord is optional — fee charged regardless ([entrypoint.rs:138-147](../../program/src/entrypoint.rs:138))
- ✓ `enabled = 0` → strips accounts without charging ([entrypoint.rs:105-108](../../program/src/entrypoint.rs:105))
- ✓ All 4 fee accounts trimmed before dispatch to processor

#### B.6 Admin instructions

- ✓ Uniform pattern: `admin.is_signer()` + `config_pda.owner() == program_id` (H2 fix) + discriminator + length + `admin == config.admin`
- ✓ Treasury *is* rotatable via UpdateProtocol ([update_protocol.rs:70](../../program/src/processor/protocol/update_protocol.rs:70))

⚠️ **R-1 (Medium):** The `admin` field is **NOT** rotatable. Only `creation_fee`, `execution_fee`, `enabled`, and `treasury` can be updated ([update_protocol.rs:67-70](../../program/src/processor/protocol/update_protocol.rs:67)). Admin key loss = protocol becomes unmanageable forever.
**Mitigation:** Treat admin key like the upgrade key — HW wallet, backup, multisig migration plan.

### Phase C — Test suite + benchmark ✅ PASS WITH CAVEAT

**Rust tests:** 165 main + 18 helper crates = 183 total, **ALL PASSING** (matches prior baseline of 165).

**SDK integration tests:** 117 of 118 passing.

⚠️ **F-1 (Low, non-blocker):** Test [12-protocol-fees.test.ts:230-284](../../tests-sdk/tests/12-protocol-fees.test.ts:230) ("charges fee for unregistered payer but skips FeeRecord counter update") fails because the new SDK auto-prepends `RegisterPayer`, so the FeeRecord *is* created instead of remaining absent. The on-chain "fee charged without FeeRecord" code path is still correct ([entrypoint.rs:138-147](../../program/src/entrypoint.rs:138)) — it's just no longer exercised by this specific test.
**Fix:** Update the test to use the lower-level `createCreateWalletIx` builder (which doesn't auto-prepend) or add a `disableAutoRegister` SDK option for tests. **Does not block mainnet** — the gate it tested still exists in code.

**Benchmark:** All 19 measured paths execute end-to-end. v0+LUT savings of -88 B for Secp256r1 Execute confirmed. No CU regressions vs prior baseline.

### Phase D — Threat-model walkthrough ✅ PASS

Every row in the original plan has a documented gate at file:line:

| Threat | Gate |
|---|---|
| Compromised upgrade authority | **Operational** — see O-1 |
| Compromised protocol admin | **Operational** — see O-2; on-chain WithdrawTreasury / UpdateProtocol cannot be replayed by non-admin |
| Compromised user EOA Owner | Inherent design risk — documented in [eoa-with-passkey-spender.md](../use-cases/eoa-with-passkey-spender.md) |
| Compromised passkey Spender | Spender can only Execute ([manage.rs:210, 423](../../program/src/processor/authority/manage.rs:210); [authorize.rs:127](../../program/src/processor/execute/authorize.rs:127)) |
| Compromised session key | Spending limits enforced + post-CPI invariants ([actions.rs:271-310](../../program/src/processor/execute/actions.rs:271)); anti-CPI guard ([immediate.rs:158](../../program/src/processor/execute/immediate.rs:158)) |
| Malicious relayer reorders accounts | `accounts_hash` binding ([immediate.rs:133](../../program/src/processor/execute/immediate.rs:133)) |
| Malicious relayer drops precompile | `sysvar_instructions` introspection ([secp256r1/mod.rs:223-241](../../program/src/auth/secp256r1/mod.rs:223)) |
| Malicious relayer wraps Execute in CPI | `stack_height > 1` ([secp256r1/mod.rs:67](../../program/src/auth/secp256r1/mod.rs:67), [immediate.rs:158](../../program/src/processor/execute/immediate.rs:158)) |
| Replay of signed Secp256r1 Execute | Counter odometer ([secp256r1/mod.rs:91-94](../../program/src/auth/secp256r1/mod.rs:91)) |
| External griefer treasury contention | CSPRNG shard selection in SDK ([client.ts:418-422](../../sdk/sdk-legacy/src/utils/client.ts:418)) |
| Malicious payer in deferred swaps ix | `instructions_hash` mismatch ([deferred.rs:110](../../program/src/processor/execute/deferred.rs:110)) |
| Malicious payer in deferred swaps accounts | `accounts_hash` mismatch ([deferred.rs:116](../../program/src/processor/execute/deferred.rs:116)) |
| Deferred TX2 replayed | Account closed-before-CPI ([deferred.rs:132-141](../../program/src/processor/execute/deferred.rs:132)); second tx finds zero-length data |

---

## Phase E — Operational checklist (TEAM ACTION REQUIRED)

These are not auditable from code. The team must complete them before deploy.

### E.1 — Upgrade authority custody (CRITICAL — O-1)

> ⚠️ Single-key upgrade authority is the largest blast radius in the system.
> Whoever holds it can replace the program binary and steal every vault.

- [ ] Upgrade authority key generated **on a hardware wallet** (Ledger or similar)
- [ ] Key never typed, photographed, or stored on internet-connected machines
- [ ] Backup in physically separate offline location (safety-deposit box, fire safe)
- [ ] **Documented 30-day rotation plan** to migrate to a Squads-style multisig
- [ ] Calendar alarm set for "upgrade key in single-key state"
- [ ] On-chain monitoring: any `setUpgradeAuthority` or program-data write triggers PagerDuty

### E.2 — Admin key custody (O-2)

- [ ] Admin key on a separate HW wallet (different person than upgrade key holder)
- [ ] **R-1 mitigation**: treat admin key like upgrade key — backup, custody-of-care doc, eventual multisig migration. Note: admin field is NOT rotatable, so loss = permanent
- [ ] Treasury target pubkey verified by two team members before InitializeProtocol (typo = funds to a black hole, irreversible)
- [ ] Document chain of custody for both upgrade + admin keys

### E.3 — Deploy plan

- [ ] Build: `cd program && cargo build-sbf`
- [ ] Record SHA256 of `target/deploy/lazorkit_program.so` in this file before mainnet deploy
- [ ] Deploy identical SBF to devnet first
- [ ] Run [tests-sdk/tests/devnet-setup-protocol.ts](../../tests-sdk/tests/devnet-setup-protocol.ts) end-to-end against devnet — must succeed
- [ ] Run [tests-sdk/tests/benchmark-fees.ts](../../tests-sdk/tests/benchmark-fees.ts) against devnet — confirm CU + fee math
- [ ] Mainnet deploy command verified by two team members before send

### E.4 — Mainnet initialization sequence

1. Deploy program (upgrade authority = HW key)
2. InitializeProtocol with admin = HW key, treasury = HW pubkey, fees = 5000/5000, num_shards = N
3. InitializeTreasuryShard for each shard 0..N-1
4. (Optional) RegisterPayer for the team's relayer keypair to front-load FeeRecord rent (~0.00112 SOL)
5. Smoke-test: one createWallet + one execute via the team's own keypair
6. Announce launch only after smoke test passes

### E.5 — Post-launch monitoring (O-4 — must be live at deploy)

- [ ] Treasury balance per shard — alert on > X SOL drop in < Y min
- [ ] Program upgrade events — page immediately
- [ ] Admin instruction calls (UpdateProtocol, WithdrawTreasury) — log all
- [ ] CU spikes on Execute — could indicate adversarial accounts_hash collision attempts
- [ ] CreateWallet rate — sudden 100x spike could be spam
- [ ] Top-N authority counter values — sudden jumps indicate replay attempts

### E.6 — Rollback / incident response (O-3 — must be documented before deploy)

- [ ] **Freeze procedure**: admin calls UpdateProtocol with `enabled = 0` — halts fee collection (operations still work). Useful for non-critical findings.
- [ ] **Kill procedure**: upgrade authority deploys a no-op program. Vault PDAs become unspendable until a recovery program is deployed. Use only if program logic is compromised.
- [ ] Communication template ready: status page, Twitter, Discord
- [ ] Direct line to Solana Foundation security contacts pre-established

---

## Risk register (known and accepted)

| ID | Risk | Mitigation |
|---|---|---|
| K-1 | Owner key loss = wallet permanently bricked | Documented in [eoa-with-passkey-spender.md](../use-cases/eoa-with-passkey-spender.md); recommend multisig Owner |
| K-2 | Spender role has no spending limits | Limits are a Session feature; document in onboarding |
| K-3 | Single-key upgrade authority during week 1 (O-1) | HW wallet custody + 30-day multisig migration |
| K-4 | Admin key controls treasury + fee config; not rotatable (R-1) | HW wallet custody + chain-of-custody doc |
| K-5 | Counter wraps at 2^32 ≈ 4B txs per authority | Practically unreachable; documented |

---

## Sign-off matrix

| Item | Status |
|---|---|
| Phase A — RegisterPayer delta re-audit | ✅ PASS |
| Phase B — full code re-walk | ✅ PASS (R-1 added to risk register) |
| Phase C — Rust 183/183 + SDK 117/118 + benchmark | ✅ PASS WITH CAVEAT (F-1, non-blocking) |
| Phase D — threat-model gates documented | ✅ PASS |
| Phase E.1 — upgrade key on HW wallet | ⏳ TEAM TODO |
| Phase E.2 — admin key on HW wallet (separate) | ⏳ TEAM TODO |
| Phase E.3 — devnet deploy + smoke test passing | ⏳ TEAM TODO |
| Phase E.4 — initialization sequence rehearsed | ⏳ TEAM TODO |
| Phase E.5 — monitoring live | ⏳ TEAM TODO |
| Phase E.6 — rollback procedure documented | ⏳ TEAM TODO |
| SBF SHA256 recorded | ⏳ TEAM TODO |

---

## Recommendations

### Before mainnet (must)

1. **Complete every Phase E item.** Sign each off in writing.
2. **Update test F-1** to use `createCreateWalletIx` directly so the on-chain
   "absent FeeRecord" path stays under test coverage.
3. **Update doc claim NBP-1** in SECURITY.md if not already done (auditor's
   carry-over from prior review).

### Within 30 days post-launch (should)

4. **Migrate upgrade authority to multisig** (Squads or similar).
5. **Migrate admin key to multisig.** Even though admin field can't be
   rotated, the *signature* requirement can be a multisig if the admin
   pubkey itself is set to a multisig program PDA.
6. **Add CI workflow** running cargo-test, npm-test, and `cargo audit`
   (NBP-3 from prior review).
7. **Fix UX gotchas** in SDK auto-prepend cache (sticky-after-failure;
   document concurrent-cold-start race in README).

### Before next significant release (nice)

8. **Adversarial property tests** for compact-instruction parser, action
   buffer parser, clientDataJSON parser (Phase C.3 in original plan).
9. **One-shot devnet test** of the upgrade flow itself — upgrade to a
   no-op version, confirm vault PDAs preserved.
10. **Pre-flight action validation in SDK** (NBP-2 from prior review).

---

## Final word

**Code-level: GO.** The 6-day delta since the prior review introduced one
permissionless change that I re-audited line-by-line and verified safe. The
rest of the codebase matches the prior reviewer's verdict.

**Operationally: GO conditional on Phase E.** The single-key upgrade
authority and non-rotatable admin field are real risks, but they're
manageable with the documented mitigations. **Do not skip Phase E to make
the launch window.**

If the Phase E checklist can't be fully signed by the go/no-go meeting,
**slip the launch by one day**. A one-day slip is cheap; a mainnet exploit
is not.
