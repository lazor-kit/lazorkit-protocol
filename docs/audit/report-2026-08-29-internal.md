# Internal audit report — 2026-08-29

A deep internal audit of the v2 delta, run before external audit. **Not a
substitute for external audit** — the auditor and the code author overlap, which
is a structural blind spot; this is the strongest internal pass we can do, and it
caught real, serious bugs the earlier reviews missed.

## Method

Two rounds. Round 1 (four reviewers, one per subsystem) preceded this and is in
[`internal-review.md`](internal-review.md). Round 2 (this report): five reviewers
with fresh context, each a systematic whole-program sweep under one lens —
(1) account validation / type confusion / PDA substitution, (2) secp256r1 /
WebAuthn / odometer, (3) arithmetic / CPI / unsafe-UB, (4) money conservation /
lifecycle, (5) MigrateWallet + fee layer. Every finding below was independently
verified against the code (and, where decidable, with a reproduction test)
before being accepted or rejected. Findings raised by more than one reviewer are
marked.

## Findings

### CRITICAL — anti-CPI guard missing on all Ed25519 management instructions  ·  FIXED
*(2 reviewers + manual verification)*

H-1 (the CPI signer-forwarding bypass) was fixed on `Execute` only. The guard
lived in `immediate.rs`/`deferred.rs` and the Secp256r1 authenticator, but **not**
in `Ed25519Authenticator`, so every Ed25519-authenticated management instruction —
`AddAuthority`, `RemoveAuthority`, `TransferOwnership`, `CreateSession`,
`RevokeSession`, `MigrateWallet` — could be re-entered via CPI with a victim's
forwarded signer, giving full takeover/drain of any Ed25519-authority wallet. This
was **live on v1 mainnet** (v1 has the full, unfixed H-1). **Fix:** the guard now
lives inside `Ed25519Authenticator::authenticate` (`auth/ed25519.rs`), covering
every path in one place. Regression test: `repro_h1_cpi_bypass::h1_d`.

### HIGH — wrong SPL Token-2022 program id disables Token-2022 spending limits  ·  FIXED
*(2 reviewers + manual base58 decode)*

`SPL_TOKEN_2022_PROGRAM_ID` in `execute/actions.rs` was wrong (diverged at byte 8
from the canonical `TokenzQd…`). The policy engine's ownership gate therefore
never recognised a real Token-2022 account, so every `TokenLimit` /
`TokenRecurringLimit` / `TokenMaxPerTx` and the SetAuthority/Approve freeze
silently no-op'd for Token-2022 assets — a bounded session/Delegate could drain
them. **Live on v1 mainnet** (pre-existing, introduced in `fa0d214`). **Fix:** the
SPL ids are now a single source of truth in `crate::utils`, pinned by
`utils::spl_id_tests` against the canonical base58, and `actions.rs`/`migrate.rs`
import them.

### MEDIUM — fee-layer bootstrap freeze  ·  DOCUMENTED
*(1 reviewer)*

If `enabled=1` and a fee `>0` while **no** treasury shard has been initialised,
every fee-eligible instruction reverts (`InvalidTreasuryShard`) — a freeze,
contradicting the C-1 invariant. It is bootstrap-only and admin-recoverable (make
a shard, or set fee/enabled to 0), a *post-setup* admin cannot weaponise it, and
the existing mainnet already has shards, so it cannot occur there. A code fix that
"skips on missing shard" would open fee evasion (a user passing an uninitialised
shard), so this is fixed by process: the deploy checklist and `initialize_protocol`
now state that shards must exist before fees are enabled.

### LOW — MigrateWallet `refund_dest` not bound into the signature  ·  FIXED
*(3 reviewers)*

The signed payload covered `destination ‖ v1_wallet ‖ num_tokens` but not
`refund_dest`, so a relayer could redirect the reclaimed rent (dust) to itself.
**Fix:** `refund_dest` is now part of the signed payload, matching the other
closers.

### LOW — `withdraw_treasury` did not re-derive the shard PDA  ·  FIXED
*(3 reviewers, not exploitable)*

Validated the shard by owner+discriminator but not its canonical address, unlike
`try_collect_fee`. Not exploitable (only the admin-gated init mints a shard), but
inconsistent. **Fix:** the address is now re-derived from the shard's own
`shard_id`.

### LOW — unchecked slot addition in `authorize.rs`  ·  FIXED
Not reachable (`expiry_offset ≤ 9000`, slot far from `u64::MAX`), fixed to
`checked_add` for consistency.

### INFO — accepted, documented
- **A zero-action session is unrestricted.** No actions ⇒ no policy engine ⇒ a
  vault-controlling key until expiry. By design (creation needs Owner/Admin), but
  a footgun; documented in Architecture, and the SDK should guard it.
- **`num_tokens` under-count strands tokens.** The signature stops a *relayer*
  from dropping tokens, but a client that under-enumerates its own vault-owned
  token accounts strands the rest on close. Documented: the client MUST enumerate
  all of them.
- **User Presence, not User Verification.** The passkey path requires UP, not UV
  (biometric/PIN), for synced-passkey compatibility. A deliberate trade-off.
- **`FeeRecord` u32 counters** revert a payer after ~4.3e9 fee-eligible txs.
  Fails safe, astronomically impractical.

## Rejected (verified NOT bugs)

- **"Silent failed CPI in MigrateWallet strands funds."** Raised by two reviewers,
  refuted three ways: an empirical wrong-mint test aborts the whole transaction,
  and pinocchio 0.9's checked *and* unchecked `invoke_signed` both discard the
  syscall status — the Solana runtime aborts on any failed CPI, so nothing is
  swallowed.
- **Unsafe aliasing of authority data with `accounts`.** Not reachable: the
  authenticators read only account metadata (or the instructions sysvar, gated by
  key), never re-borrowing the mutably-held authority/session account.

## Confirmed clean (load-bearing, by multiple reviewers)

Account validation and PDA re-derivation at every instruction (full coverage
table in the round-2 account-validation pass); the secp256r1 precompile
introspection (offsets and indices pinned, message and key bound to the on-chain
key); the WebAuthn JSON/base64 parsing; the odometer/replay and slot-freshness;
the H-3 signer-forwarding rule (identical in immediate/deferred); arithmetic
(checked/saturating throughout); CPI signing (only verified-PDA seeds); unsafe
soundness (length-checked casts, no reachable aliasing); money conservation and
the deferred/session/fee lifecycles (no double-spend, double-close, or
double-charge); multi-owner accounting (`owner_count` can't diverge or reach 0);
governance (init gate, two-step rotation, M-2/M-3 pinning, fee ceiling).

## Post-fix status

198 lib + 266 integration tests green; both SDKs build; the two live-on-mainnet
issues (CRITICAL anti-CPI, HIGH Token-2022) are fixed and regression-tested. The
external audit should still treat MigrateWallet, the fee layer, and the auth
primitives as primary — this pass reduces risk, it does not replace independent
review.
