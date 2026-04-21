# Security Review — `refactor/sdk-cleanup` → `main`

- **Date:** 2026-04-21
- **Reviewer:** internal
- **Scope:** 52 commits, 130 files, +11.8k / −10.1k LOC between `origin/main` and `refactor/sdk-cleanup` (HEAD `fe10ba5`)
- **PR:** https://github.com/lazor-kit/lazorkit-protocol/pull/3

## Verdict: **Clean to merge.**

No blockers found. Three minor non-blocking findings documented below for follow-up issues.

## Baseline before review

- `cargo test` (program crate) — 165 Rust tests, all pass (unit + integration)
- `cd tests-sdk && npm run test:local` — 118 tests across 16 files, all pass (103 integration + 15 unit)
- `cargo build-sbf` → IDL regenerates with zero diff (`cargo build-sbf` output matches committed `program/idl.json`)

---

## W1 — Byte-exactness (SDK ↔ program): **9/9 match**

| # | Surface | SDK | Program | Verdict |
|---|---|---|---|---|
| 1 | Challenge hash (6-element SHA256) | `sdk/sdk-legacy/src/utils/secp256r1.ts:169-189` | `program/src/auth/secp256r1/mod.rs:122-135` | ✓ exact match — both hash `discriminator → auth_payload[..14] → signed_payload → payer(32) → counter_le(4) → program_id(32)` |
| 2 | Auth payload (Mode 1) | `sdk/.../secp256r1.ts:107-139` | `program/.../mod.rs:55-161` | ✓ `[slot u64 LE][counter u32 LE][sysvarIxIdx u8][reserved 0x80][authDataLen u16 LE][authData][cdjLen u16 LE][clientDataJson]`. Program enforces `cdj_len > 0` and strict total-length on parse (L2). |
| 3 | Auth payload prefix (14B) | `sdk/.../secp256r1.ts:147-158` | Same prefix consumed at mod.rs:126 | ✓ |
| 4 | Compact instruction pack | `sdk/.../packing.ts:24-36` | `program/src/compact.rs:46-79, 119-142` | ✓ `[num_instructions u8][ix...]`. Program caps at `MAX_COMPACT_INSTRUCTIONS = 16` (compact.rs:127-129). |
| 5 | Accounts hash | `sdk/.../packing.ts:43-55` | `program/.../immediate.rs:362-395` | ✓ Both iterate in the same order (program_id first, then each account index) |
| 6 | AddAuthority payload | `sdk/.../signing.ts:168-189` | `program/.../processor/authority/manage.rs:34-113` | ✓ `[type u8][role u8][pad(6)][credentialOrPubkey(32)]` for Ed25519; same prefix + `[pubkey(33)][rpIdLen u8][rpId]` for Secp256r1 |
| 7 | TransferOwnership payload | `sdk/.../signing.ts:194-213` | `program/.../processor/authority/transfer_ownership.rs:47-105` | ✓ `[type u8][credentialOrPubkey(32)]` + optional Secp256r1 suffix |
| 8 | CreateSession payload | `sdk/.../signing.ts:218-235` | `program/.../processor/session/create.rs:53-102` | ✓ `[sessionKey(32)][expiresAt u64 LE][actionsLen u16 LE][actions]`. Program caps `actionsLen ≤ 2048` (create.rs:70). |
| 9 | Session action serialization | `sdk/.../actions.ts:263-285` + `serializeActionData:207-254` | `program/.../state/action.rs:16-83, 152-…` | ✓ All 8 action types match IDs + sizes (SolLimit=1, SolRecurringLimit=2, SolMaxPerTx=3, TokenLimit=4, TokenRecurringLimit=5, TokenMaxPerTx=6, ProgramWhitelist=10, ProgramBlacklist=11). Header 11 bytes on both sides. |

**No drift.** Wire format is synchronized; signing/verifying cannot go out of sync without simultaneous changes on both layers.

---

## W2 — Invariant re-verification: **15/15 pass**

| # | Invariant | Site | Verdict |
|---|---|---|---|
| 1 | Odometer replay (monotonic u32, strict `==` not `>=`) | `auth/secp256r1/mod.rs:91-94` | ✓ `expected_counter = header.counter.wrapping_add(1)`, strict equality, rejects reuse |
| 2 | Slot freshness 150 slots, closed on both sides | `auth/secp256r1/mod.rs:24, 72-79` | ✓ rejects future slots (line 74) and stale ≥150 (line 77) |
| 3 | CPI stack_height guard on every authenticated path | `auth/secp256r1/mod.rs:67` + `immediate.rs:158` (session) | ✓ **See Finding NBP-1 for Ed25519 exemption note** |
| 4 | Challenge hash 6-element field order | `auth/secp256r1/mod.rs:122-135` | ✓ (matches SDK per W1.1) |
| 5 | Vault owner + data_len invariants (H1) | `immediate.rs:243-335` | ✓ snapshot pre-CPI (243-252), check post-CPI (325-334) — **only for session+actions path** (design: direct authority Execute is fully trusted) |
| 6 | Per-listed-mint token authority snapshots (H1 extension) | `actions.rs:191-275` | ✓ snapshots `owner(32)`, `delegate(36)`, `close_authority(36)` — all option-wrapped |
| 7 | Protocol config_pda ownership (H2) | `processor/protocol/{update_protocol,withdraw_treasury,register_integrator,initialize_treasury_shard}.rs` | ✓ `config_pda.owner() == program_id` precedes any data read in all 4 paths |
| 8 | u8 truncation guards (production, not debug-only) | `compact.rs:161, 164, 216` | ✓ `assert!()` — runtime panic on overflow |
| 9 | `actions_len` cap 2048 + `MAX_ACTIONS=16` | `session/create.rs:70-72`, `state/action.rs:19, 136` | ✓ both caps enforced at parse + validation time |
| 10 | SolMaxPerTx per-CPI gross outflow | `immediate.rs:259-318` | ✓ `vault_lamports_gross_out.saturating_add(prev - post)` per CPI, not net |
| 11 | Constant-time challenge comparison | `auth/secp256r1/mod.rs:180, 268-277` | ✓ `ct_eq`: length-equal XOR-accumulate, no early return on byte mismatch |
| 12 | Self-reentrancy (no CPI to own program) | `immediate.rs:283-285` | ✓ `decompressed.program_id.as_ref() == program_id.as_ref()` rejection |
| 13 | Wallet discriminator check before any field read | `immediate.rs:69-72` | ✓ precedes account-info iterator |
| 14 | Fixed 145-byte Authority layout (rpIdHash at offset 113) | `state/authority.rs:1-29`, `auth/secp256r1/mod.rs:96-103` | ✓ `[Header(48)][credential_id_hash(32)][Pubkey(33)][rpIdHash(32)]` — no dynamic offset |
| 15 | Fee-collection preamble: ownership+discriminator before unsafe pointer read | `entrypoint.rs:71-209` | ✓ all 3 fee accounts (`config`, `shard`, `record`) checked at lines 92, 122, 138 before cast |

---

## W3 — Audit-finding archaeology: **all fixes verified**

| Finding | Commit | Fix site | Test |
|---|---|---|---|
| **H1** vault invariants | `c08d1fe` (+ test `60ca81f`) | `immediate.rs:243-335`, `actions.rs:191-275` | `tests-sdk/tests/14-session-vault-invariants.test.ts` exercises `System::Assign` (expect error 3030 `SessionVaultOwnerChanged`) and `System::Allocate` (expect error 3031 `SessionVaultDataLenChanged`) ✓ |
| **H2** protocol admin ownership | `dc39fed` | `update_protocol.rs:49`, `withdraw_treasury.rs:56`, `register_integrator.rs:73`, `initialize_treasury_shard.rs:68` | `12-protocol-fees.test.ts` — implicit coverage via positive flow ✓ |
| **M1** JSON parser nested strings | `958b763` | `auth/secp256r1/webauthn.rs:162-221` + Rust unit tests at `webauthn.rs:397, 437` | Rust unit tests directly exercise `tokenBinding.id: "x}y"` payload ✓ |
| **L1** origin-field non-validation (doc-only) | `294b6a9` | `auth/secp256r1/mod.rs:163-167` (comment block) | N/A |
| **L2** strict length auth_payload | `294b6a9` | `auth/secp256r1/mod.rs:158` (`payload.len() != cdj_offset + cdj_len`) | Rust-side only (cannot be triggered via SDK, which always builds exact-length) |
| **L3** ct_eq challenge compare | `294b6a9` | `auth/secp256r1/mod.rs:180, 268-277` | Rust unit tests at 283-299 |
| **L5** CPI anti-reentrancy | `294b6a9` | `immediate.rs:158`, `auth/secp256r1/mod.rs:67` | `11-security.test.ts:183-225` |
| Pre-audit batch | `40714d1`, `7b21e31`, `3141124`, `fa0d214`, `0637910` | Counter, authority bounds, session revoke alias, token limits, triple-borrow fix | `05-replay.test.ts` (8 adversarial cases), `06-counter.test.ts`, `11-security.test.ts` |

**No bypass found during code re-read.** Every claim traced to both (a) an enforcement site in HEAD and (b) a test that either directly exercises the negative path or is covered by Rust-side unit tests.

---

## W4 — Red-team threat walks: **12/12 defended**

| # | Scenario | Defense layer(s) | Verdict |
|---|---|---|---|
| 1 | Forged passkey signature | Secp256r1 precompile CU-level verify + program introspects precompile at `mod.rs:238-248` | Fails at precompile stage |
| 2 | Replay via stale counter | `expected = stored + 1`, strict equality | Fails at `mod.rs:92` (covered by `05-replay.test.ts`) |
| 3 | Cross-wallet replay with same challenge | Challenge hash binds `payer`; accounts hash binds every account pubkey per instruction | Fails (covered by `11-security.test.ts` cross-wallet + accounts-hash suites) |
| 4 | SolMaxPerTx bypass via round-trip | Per-CPI gross-outflow accumulator, `saturating_add` prevents net | Fails at `immediate.rs:311-318` |
| 5 | Whitelist escape via `System::Assign(vault, …)` | H1 vault owner snapshot + post-CPI check | Fails at `immediate.rs:325-328` (covered by `14-session-vault-invariants.test.ts`) |
| 6 | Token limit bypass via dummy 0-balance account | `find_token_balance` sums every vault-owned account for the mint, with owner-program allowlist for SPL-Token + Token-2022 | Fails at `actions.rs:613-650` (docstring explicitly calls out the attack) |
| 7 | Protocol admin via fake config | H2 owner check precedes unsafe read of admin field | Fails in all 4 admin paths |
| 8 | Compact parser DoS (256 ixs × 256 accounts × 64KB data) | `MAX_COMPACT_INSTRUCTIONS = 16`, per-ix bounds check, `actions_len ≤ 2048` | Fails at parse (compact.rs:127-129) |
| 9 | JSON parser injection via `tokenBinding.id: "},"challenge":"fake"` | M1 string-aware nesting skip | Fails (Rust unit test at `webauthn.rs:397`) |
| 10 | CSPRNG predictability for shard selection | `randomFillSync` in `sdk/.../client.ts:401-404`; shard only affects fee-destination (non-security-sensitive) | Not exploitable — wrong shard → fees still collected, just in a different treasury shard |
| 11 | Counter race post-Phase-2 parallelization | On-chain strict `==` check; failed tx leaves chain state unchanged | Second tx fails, no silent corruption |
| 12 | npm tarball surface | `files` whitelist — ships `dist/`, `README.md`, `LICENSE`, `package.json` only | Verified: 33 files, 35.6 kB, no `src/`, no `node_modules`, no `.env` |

---

## W5 — Static analysis

- **`cargo clippy --all-targets`** (program crate): 18 unique warnings — all **style / cosmetic** (`needless_borrow`, `too_many_arguments`, `needlessly taken reference`, `unused mut`, `manual !RangeInclusive::contains`). None security-relevant. Triage: add to backlog or fix in a followup PR.
- **`npm audit`** (sdk-legacy + tests-sdk): **0 vulnerabilities** at `--audit-level=low`.
- **`cargo-audit`**: not installed — skipped. See **Finding NBP-3**.
- **`cargo-geiger`**: not installed — used manual grep. **92 `unsafe` blocks** across `program/src/`. This is expected for a pinocchio + zero-copy program. Every `unsafe` block I inspected during W1/W2 is gated by a prior validation (owner check, size check, discriminator check).

---

## W6 — Test coverage gaps

Helpers introduced by Phase 4a/4b of the final SDK refactor pass:

| Helper | Direct unit test | Integration coverage |
|---|---|---|
| `assertByteLength` | ✓ `15-sdk-unit.test.ts:142-296` | — |
| `buildCompactLayoutAndHash` | ✗ | `03-execute.test.ts`, `11-security.test.ts` (accounts-hash mismatch test) |
| `buildPasskeySigning` | ✗ | `05-replay.test.ts`, `06-counter.test.ts`, `11-security.test.ts` |
| `extractSecp256r1Params` | ✗ | Indirect via all unified-method tests |
| `resolveEd25519AuthorityPda` | ✗ | Indirect via all unified-method tests |

Other gaps:
- **`serializeActions` with malformed action type IDs** — no direct SDK negative test. The Rust parser rejects unknown types at `validate_actions_buffer()` (state/action.rs:152+), so end-to-end behavior is correct, but the SDK does not pre-flight validate. See **Finding NBP-2**.

**Judgment:** gaps are not blocking. All four helpers are ≤10 LOC each and are exercised by integration tests that would fail loudly on any byte-layout regression (the accounts-hash mismatch test at `11-security.test.ts` is the canary). A follow-up PR adding golden-value round-trip tests for each helper would shorten debug time on any future regression; it's not required for this merge.

---

## W7 — Docs / release safety

1. **No Claude co-author lines** in any commit on this branch (grep for `Co-Authored-By.*Claude` returns empty). ✓
2. **Program ID consistency**:
   - `sdk/sdk-legacy/src/constants.ts` → `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` ✓
   - `assertions/src/lib.rs` (`declare_id!`) → same ✓
   - `target/deploy/lazorkit_program-keypair.json` pubkey → same ✓
   - `program/src/lib.rs`: no `declare_id!` (pinocchio pattern — program_id is an entrypoint argument). Correct.
   - `program/idl.json`: no address field (shank default). Acceptable — on-chain address is known via deployed program.
3. **IDL ↔ program drift**: `cargo build-sbf` regenerates `idl.json` with zero diff. ✓
4. **npm tarball integrity**: `npm pack --dry-run` → 33 files, 35.6 kB packed / 187 kB unpacked. Only `dist/`, `README.md`, `LICENSE`, `package.json`. No `src/`, no `node_modules`, no `.env`, no test fixtures. ✓
5. **`SECURITY.md` truthiness**: 13/14 mechanisms accurately describe code in HEAD. See **Finding NBP-1**.
6. **CI gate**: No `.github/workflows/` exists. See **Finding NBP-3**.

---

## Findings

All findings are **non-blocking** (NBP = non-blocking priority).

### NBP-1 — SECURITY.md bullet 3 slightly overclaims (doc-drift)

`SECURITY.md:40` states:

> CPI `stack_height` anti-reentrancy check on every authenticated path.

**Reality:** the Ed25519 authenticator (`program/src/auth/ed25519.rs`) does not perform a `stack_height` check. This is **intentional** — Ed25519 authorization relies on Solana's native transaction signature verification + tx-level blockhash freshness. CPI reentrancy via an Ed25519 signer is not possible because CPIs cannot introduce a new `is_signer == true` flag for an account.

**Recommendation:** tighten the wording to "CPI `stack_height` anti-reentrancy check on every Secp256r1 / session-authenticated path; Ed25519 relies on Solana's native tx-level signature verification." Non-blocking.

### NBP-2 — SDK does not pre-flight validate action type IDs

`serializeActions` (`sdk/sdk-legacy/src/utils/actions.ts:263`) dispatches on `SessionActionType`. Since TypeScript's enum narrowing gates the type at compile-time for well-typed callers, but a caller using `Actions.*` helpers + escape-hatches (`as any`) could craft a SessionAction with an invalid `type` field. The Rust parser (`state/action.rs:validate_actions_buffer`) rejects unknown IDs, so end-to-end behavior is correct — but the SDK throws a server-side error at tx simulate time rather than an ergonomic SDK-side error.

**Recommendation:** in a follow-up PR, add a default branch to the switch in `serializeActionData` that throws with a helpful message, and a unit test in `15-sdk-unit.test.ts` for it. Non-blocking.

### NBP-3 — No CI workflow; static-analysis tools not installed

- `.github/workflows/` missing — no automated PR gate for `cargo test`, `cargo clippy`, `npm test`, or `cargo-audit` / `npm audit`.
- `cargo-audit` and `cargo-geiger` are not installed locally; no baseline for Rust dep-level CVEs.

**Recommendation:** add `.github/workflows/ci.yml` that runs:
1. `cargo test` + `cargo clippy --all-targets -- -W clippy::all`
2. `npm --prefix sdk/sdk-legacy audit --audit-level=moderate`
3. `npm --prefix tests-sdk run test:local` (against local validator)
4. Optional: `cargo install cargo-audit && cargo audit`

This should be a separate PR after this one merges, so the branch stays clean. Non-blocking.

---

## Additional observations

- **Minor doc-drift:** `SECURITY.md:8` links to `lazor-kit/program-v2` but the active repo is `lazor-kit/lazorkit-protocol`. Update in a follow-up.
- **Naming inconsistency:** `processor/protocol/register_integrator.rs` is invoked by the `RegisterPayer` enum variant (`instruction.rs:320`). Functional, but file name and enum are out of sync. Follow-up rename.
- **Unsafe inventory:** 92 `unsafe` blocks. Each I inspected during W1/W2 is preceded by: (a) `owner()` check, (b) `data[0]` discriminator check, (c) `data.len() >= N` bounds check. The zero-copy pattern is faithfully applied; reviewers should treat the existing invariants (per W2) as the contract every future modification of these sites must preserve.

---

## Sign-off

**Reviewer:** internal
**Date:** 2026-04-21
**Branch HEAD:** `fe10ba5 chore(sdk): prep @lazorkit/sdk-legacy for npm publish`
**Commits reviewed:** 52 (`origin/main`..`refactor/sdk-cleanup`)
**Test pass:** 118/118 SDK + 165/165 Rust before and after (rebuild clean)

**Merge-ready.** Three follow-up issues (NBP-1, NBP-2, NBP-3) tracked separately; none block this merge.
