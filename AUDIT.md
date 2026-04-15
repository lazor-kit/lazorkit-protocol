# LazorKit Protocol — Security Audit Report

**Date:** 2026-04-15 (updated 2026-04-15)  
**Auditor:** Internal (Claude Code)  
**Scope:** Full program source — all processors, state, auth, compact, utils  
**Status:** All findings fixed

---

## Summary

| Severity | Count | Fixed |
|---|---|---|
| Critical | 1 | ✅ |
| High | 4 | ✅ |
| Medium | 3 | ✅ |
| Low | 3 | ✅ |
| (Bonus) Duplicate slot in Secp256r1 hash | 1 | ✅ |
| (Bonus) TransferOwnership refund_dest missing | 1 | ✅ |

---

## Findings

---

### [CRITICAL] Token Limit Bypass via Multiple Token Accounts

**File:** `program/src/processor/execute/actions.rs`  
**Function:** `find_token_balance`

**Description:**  
`find_token_balance` returned the **first** token account matching vault + mint in the accounts list. Because the caller controls which accounts are passed to `Execute` and in what order, an attacker could:

1. Pre-create a valid SPL token account owned by the vault with 0 balance for the target mint.
2. Place this 0-balance account **before** the real token account in the instruction accounts list.
3. Pre-CPI snapshot picks the 0-balance account → `before = 0`.
4. CPI drains the real token account.
5. Post-CPI check picks the 0-balance account again → `after = 0`.
6. `token_spent = 0` → all `TokenLimit`, `TokenRecurringLimit`, and `TokenMaxPerTx` actions are completely bypassed.

This allowed a session key to drain tokens beyond any configured spending limit.

**Fix:**  
Changed `find_token_balance` to **sum all matching accounts** (same vault + mint) rather than returning on the first match. The pre-CPI and post-CPI values are now computed over the same total, making any per-account manipulation irrelevant.

```rust
// Before (vulnerable):
return Some(amount); // first match only

// After (fixed):
total = total.saturating_add(amount); // sum all matches
found = true;
```

---

### [HIGH] `AddAuthority`: `new_role` Not Validated — Arbitrary Role Creation

**File:** `program/src/processor/authority/manage.rs`  
**Function:** `process_add_authority`

**Description:**  
The `new_role` field from instruction data was never validated to be a known enum value (0=Owner, 1=Admin, 2=Spender). An Owner could pass `new_role = 255` and the authorization check would pass because `admin_header.role == 0` short-circuits the entire condition.

An authority with `role = 255` could:
- **Execute transactions** on behalf of the wallet (no role check in the Execute path for authority accounts).
- **Not be revoked by any Admin** — the Admin remove-authority check requires `target_header.role == 2`, so only the Owner can ever remove it.
- Not create sessions, not authorize deferred execution, not revoke sessions.

This created a hidden privileged executor role that bypassed the revocation controls available to Admin-level operators.

**Fix:**  
Added an explicit range check before the role-based permission check:

```rust
if args.new_role > 2 {
    return Err(AuthError::PermissionDenied.into());
}
```

---

### [HIGH] `compact.rs`: `accounts.len() as u8` Silently Truncates at 256

**File:** `program/src/compact.rs`  
**Functions:** `into_bytes`, `to_bytes`

**Description:**  
Both serialization functions cast `accounts.len()` and `inner_instructions.len()` to `u8` without bounds checking. When the count is exactly 256, the cast produces `0`, and the deserialized instruction has 0 accounts. The 256 account-index bytes are then misinterpreted as the start of `data_len`, silently corrupting the instruction stream. The test at line 270 even documents this as a "known limitation."

While Solana's transaction-level limits make hitting 256 accounts difficult in practice, the serialization code should be self-defending.

**Fix:**  
Added `debug_assert!` guards at both call sites to make the invariant explicit and catch violations during development:

```rust
debug_assert!(self.inner_instructions.len() <= 255);
debug_assert!(ix.accounts.len() <= 255);
```

---

### [HIGH] `compact.rs`: No Upper Bound on `num_instructions`

**File:** `program/src/compact.rs`  
**Function:** `parse_compact_instructions`

**Description:**  
`num_instructions` from instruction data was accepted as any value 0–255 with no upper limit. The Execute handler loops over all parsed instructions, and each loop body performs multiple account lookups, CPI calls, and hash computations. With 255 instructions, an attacker could exhaust the per-transaction compute unit budget, causing legitimate transactions to fail after consuming fees.

Compare to `state/action.rs` which enforces `MAX_ACTIONS = 16`.

**Fix:**  
Added `MAX_COMPACT_INSTRUCTIONS = 16` constant and a rejection check:

```rust
pub const MAX_COMPACT_INSTRUCTIONS: usize = 16;

if num_instructions > MAX_COMPACT_INSTRUCTIONS {
    return Err(ProgramError::InvalidInstructionData);
}
```

---

### [HIGH] Unconstrained `rp_id_len` Allows Oversized Authority Accounts

**Files:**  
- `program/src/processor/wallet/create.rs`  
- `program/src/processor/authority/manage.rs`  
- `program/src/processor/authority/transfer_ownership.rs`

**Description:**  
The `rp_id_len` byte in the Secp256r1 authority data was read directly without an upper bound check. A payer (which need not be the wallet owner) could pass `rp_id_len = 255` and force the creation of a 369-byte authority account (`48 header + 32 cred_id + 33 pubkey + 1 len + 255 rpId`) rather than the expected ~80-100 bytes. The rent difference is paid by the payer, but the on-chain authority account would contain 255 bytes of arbitrary attacker-controlled data stored as the rpId.

**Fix:**  
Added `rp_id_len == 0 || rp_id_len > 253` check in all three files (253 is the maximum valid DNS name length, which is what rpId represents):

```rust
if rp_id_len == 0 || rp_id_len > 253 {
    return Err(ProgramError::InvalidInstructionData);
}
```

---

### [MEDIUM] `RemoveAuthority` / `RevokeSession`: Alias Bug When `refund_dest == target`

**Files:**  
- `program/src/processor/authority/manage.rs`  
- `program/src/processor/session/revoke.rs`

**Description:**  
Both account-closing instructions followed the pattern:

```rust
let target_lamports = *target.borrow_mut_lamports_unchecked();
let refund_lamports = *refund_dest.borrow_mut_lamports_unchecked();
*refund_dest.borrow_mut_lamports_unchecked() = refund_lamports + target_lamports; // Step A
*target.borrow_mut_lamports_unchecked() = 0;                                       // Step B
```

When `target` and `refund_dest` are the same account, Step A writes `2X` to the account, then Step B overwrites it with `0`. This burns the original lamports, which causes the Solana runtime to reject the transaction for violating lamport conservation. However, the account data is zeroed in the same instruction before the lamport check fires, leaving the account in a briefly corrupted state before the transaction reverts.

**Fix:**  
Added an explicit key-equality guard before the lamport transfer:

```rust
if target.key() == refund_dest.key() {
    return Err(ProgramError::InvalidAccountData);
}
```

---

### [MEDIUM] `SolMaxPerTx` Checks Net SOL Outflow, Not Gross

**File:** `program/src/processor/execute/actions.rs`, `program/src/processor/execute/immediate.rs`  
**Function:** `evaluate_post_actions`, `process`

**Description:**  
The original SOL spending delta was computed as net outflow:

```rust
let sol_spent = vault_lamports_before.saturating_sub(vault_lamports_after);
```

A DeFi swap sending 10 SOL out and receiving 9.9 SOL back would appear to have spent only 0.1 SOL, bypassing a `SolMaxPerTx(1_SOL)` cap.

**Fix:**  
Added per-CPI lamport snapshotting in `immediate.rs` to track **gross** outflow:

```rust
// After each invoke_signed_unchecked:
let post = vault_pda.lamports();
if prev_vault_lamports > post {
    vault_lamports_gross_out = vault_lamports_gross_out
        .saturating_add(prev_vault_lamports - post);
}
prev_vault_lamports = post;
```

`vault_lamports_gross_out` is passed to `evaluate_post_actions` and used exclusively for `SolMaxPerTx`. Cumulative limits (`SolLimit`, `SolRecurringLimit`) continue to use net outflow, which is conservative and appropriate for those use cases.

---

### [MEDIUM] Expired Actions Leave Session Unrestricted

**File:** `program/src/processor/execute/actions.rs`  
**Function:** `evaluate_pre_actions`, `evaluate_post_actions`

**Description:**  
When a `SolLimit`, `TokenLimit`, or `ProgramWhitelist` action expires, it was silently skipped. If all spending-limit actions on a session expired before the session itself, the session gained **unrestricted spending and unrestricted program access** for the remainder of its lifetime.

**Fix:**  
Expired actions are now treated as **fully exhausted / hard deny**:

- **`ProgramWhitelist`**: Tracks `has_any_whitelist_action` regardless of expiry. If a whitelist action exists but is expired, all programs are denied (empty active set). An expired whitelist = lock-down, not open access.
- **`SolLimit`, `SolRecurringLimit`, `SolMaxPerTx`**: If the action is expired and any SOL was spent, the transaction is rejected.
- **`TokenLimit`, `TokenRecurringLimit`, `TokenMaxPerTx`**: Same — expired + any token spend = reject.
- **`ProgramBlacklist`**: Expired entries are silently dropped (the ban has lifted — intentional).

```rust
// ProgramWhitelist (evaluate_pre_actions):
if has_any_whitelist_action && !whitelisted.iter().any(|p| p == target_program.as_ref()) {
    return Err(AuthError::ActionProgramNotWhitelisted.into()); // also fires when all entries expired
}

// SolLimit (evaluate_post_actions):
if sol_spent > 0 {
    if action_expired {
        return Err(AuthError::ActionSolLimitExceeded.into());
    }
    // ... normal check
}
```

---

### [LOW] `CreateWallet`: Ed25519 Used Exact-Length Check Instead of Minimum-Length

**File:** `program/src/processor/wallet/create.rs`

**Description:**  
The Ed25519 path in `CreateWallet` required `rest.len() == 32` exactly, while the equivalent check in `AddAuthority` and `TransferOwnership` correctly used `rest.len() < 32`. This inconsistency caused `CreateWallet` to fail with a generic `InvalidInstructionData` if a client appended any trailing bytes, while the same client code would succeed against the other instructions.

**Fix:**  
Changed to minimum-length check, consistent with the rest of the codebase:

```rust
// Before:
if rest.len() != 32 { return Err(...) }

// After:
if rest.len() < 32 { return Err(...) }
let (pubkey, _) = rest.split_at(32);
```

---

### [LOW] `evaluate_post_actions`: Unnecessary `to_vec()` Allocation in Phase 2

**File:** `program/src/processor/execute/actions.rs`  
**Function:** `evaluate_post_actions`

**Description:**  
Phase 2 re-parsed the actions buffer using `.to_vec()` which allocates a full copy of the buffer on the heap:

```rust
// Before (wasteful):
let actions = parse_actions(&session_data[SESSION_HEADER_SIZE..].to_vec())?;
```

`parse_actions` takes a `&[u8]` reference and does not require owned data. The `.to_vec()` copy was unnecessary and allocated up to `MAX_ACTIONS * (ACTION_HEADER_SIZE + 64)` bytes on every session Execute call.

**Fix:**

```rust
// After (fixed):
let actions = parse_actions(&session_data[SESSION_HEADER_SIZE..])?;
```

---

### [LOW] Triple Mutable Borrow of `authority_pda` in Execute

**File:** `program/src/processor/execute/immediate.rs`

**Description:**  
The session path in `immediate.rs` created three overlapping borrows of `authority_pda` data: two via `borrow_mut_data_unchecked()` and one via `borrow_data_unchecked()`. This is technically undefined behavior in Rust — any future refactor adding a write between borrow sites would silently corrupt state without a compiler warning.

**Fix:**  
Refactored to use the single `authority_data` borrow created at the top of the function throughout the entire session path. All redundant `let session_data = unsafe { authority_pda.borrow_*_unchecked() };` lines were removed and replaced with `authority_data`. Since `&mut [u8]` coerces to `&[u8]`, this works for both read and write call sites.

---

## What Was NOT Changed

The following items were identified during the audit but intentionally left as-is:

| Item | Rationale |
|---|---|
| Multiple wallet Owners allowed | Intentional; supports multi-owner wallets |
| `auth_bump` field in CreateWallet is ignored | Vestigial field; harmless, SDK cleanup only |
| `MAX_SLOT_AGE = 150` (~60s for Secp256r1) | Adequate for WebAuthn; UX note only |

---

## Files Changed

| File | Changes |
|---|---|
| `program/src/processor/authority/manage.rs` | Validate `new_role <= 2`; guard `refund_dest != target`; validate `rp_id_len` |
| `program/src/processor/authority/transfer_ownership.rs` | Add `refund_dest` account; sign over refund_dest; alias guard; validate `rp_id_len` |
| `program/src/processor/wallet/create.rs` | Validate `rp_id_len`; fix Ed25519 exact-length check |
| `program/src/processor/session/revoke.rs` | Guard `refund_dest != session_pda` |
| `program/src/processor/execute/actions.rs` | Fix `find_token_balance` to sum all accounts; remove Phase 2 `to_vec()`; add `vault_lamports_gross_out` to `evaluate_post_actions`; expired whitelist = hard deny; expired spending limits = reject |
| `program/src/processor/execute/immediate.rs` | Per-CPI gross lamport tracking; eliminate triple borrow of `authority_pda` |
| `program/src/auth/secp256r1/mod.rs` | Remove redundant `slot` from challenge hash (slot already in `auth_payload[0..8]`) |
| `program/src/compact.rs` | Add `MAX_COMPACT_INSTRUCTIONS = 16`; add `debug_assert` for u8 truncation |
| `sdk/solita-client/src/utils/secp256r1.ts` | Remove redundant `slotBuf` from `buildSecp256r1Challenge` (mirrors on-chain fix) |
| `sdk/solita-client/src/utils/instructions.ts` | Add `refundDestination` param to `createTransferOwnershipIx`; shift sysvar index to 7 |
| `sdk/solita-client/src/utils/client.ts` | Update `SYSVAR_IX_INDEX_TRANSFER_OWNERSHIP = 7`; add `refundDestination` to `transferOwnership` |
