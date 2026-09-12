# Internal review — what we already found

Disclosed on purpose. These are the areas we know are fragile and the issues we
already caught; treat them as starting points, not a clean bill of health. An
external auditor who knows where we struggled spends their time better.

## Method

Before requesting this audit, the v2 delta was reviewed by four independent
reviewers, each with a fresh context (they did not see the code being written),
one per subsystem, prompted adversarially. The prior vulnerabilities (C-1,
H-1..H-4) each have a reproduction test that was inverted from "proves the
exploit" to "proves rejection" as its fix landed
(`program/tests/repro_*.rs`).

## Results

| Subsystem | Reviewer verdict |
|---|---|
| Governance / C-1 (fee layer, admin rotation, M-2/M-3 pinning) | No CRITICAL/HIGH/MEDIUM. Skip-not-revert, fee ceiling, init gate, two-step rotation, address pinning all confirmed correct. |
| Wire format (H-3 signer forwarding, M-4 privilege binding) | No CRITICAL/HIGH/MEDIUM. Fee payer never forwarded (by-key), session forwards only its own key, flags bound into the hash, forward bit masked before lookup. |
| Rank / policy + multi-owner | No CRITICAL/HIGH. `owner_count` cannot reach 0; `PolicyLocation` resolves the 80==80 ambiguity by discriminator; escalation guard holds. **One MEDIUM** (below). |
| **MigrateWallet** (the newest code) | **1 HIGH + 2 MEDIUM.** |

## Issues found and fixed (all reproduced with a test first)

- **HIGH — MigrateWallet ignored authority rank.** Any authority whose key signed
  — a bounded Delegate, an Admin — could sweep and close the entire wallet,
  defeating the spending policy that limits a non-Owner. Fixed: `role == Owner`
  required. Regression test: `migrate_refuses_a_non_owner_authority`.
- **MEDIUM — MigrateWallet's passkey challenge bound only the destination.** A
  relayer could drop `num_tokens` to 0, sweep the SOL, and let the close strand
  the tokens; or replay a signature against another wallet the same key controls.
  Fixed: the challenge binds `destination ‖ v1_wallet ‖ num_tokens`. Tests:
  `passkey_migrate_relayer_cannot_drop_tokens`,
  `passkey_migrate_signature_is_wallet_bound`.
- **MEDIUM — the deferred path bypassed the policy engine.** `authorize.rs`
  admitted role 0/1 without checking `policy_len`, and `ExecuteDeferred` does not
  run the action engine — so a policy-bearing Admin could spend without limit via
  Authorize + ExecuteDeferred. Fixed: `authorize.rs` refuses a policy-bearing
  authority.
- **LOW** — `deferred.rs` gained the anti-CPI guard `immediate.rs` had; both SDK
  `computeAccountsHash` builders mask the forward bit off the program-id index;
  stale `entrypoint`/`error` comments describing an abandoned "strict reject"
  design (a trap for a maintainer) were corrected and two dead error codes
  retired.

## A claim that did NOT reproduce (so you don't chase it)

A reviewer argued that a silently-failed inner CPI in MigrateWallet
(`invoke_signed_unchecked` drops the syscall status) would leave a partial
migration and strand funds while reporting success. **Tested and false:** a failed
inner CPI (a wrong-mint token transfer) aborts the whole transaction — the vault
was untouched, the authority not closed, the tokens not moved. No change was made.
Worth confirming independently, but this is the reasoning we followed.

## Where we'd point you first

1. **MigrateWallet** — it had the only HIGH, and the relayer is fully adversarial
   there. Re-derive the trust argument from scratch: what does the *signature*
   actually cover, and what can a relayer still change underneath it?
2. **The fee layer** — never audited, runs on every fund-moving instruction.
3. **The policy engine across all paths** — we missed the deferred path once;
   confirm there is no third path that moves value without enforcing a policy.
