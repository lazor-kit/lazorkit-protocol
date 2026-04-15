//! Session action evaluation for the Execute instruction.
//!
//! Provides pre-CPI and post-CPI checks for session-based execution.
//! Pre-CPI: program whitelist/blacklist enforcement.
//! Post-CPI: spending limit enforcement with balance diffing.
//!
//! Security model (learned from Swig wallet):
//! - Saturating arithmetic throughout to prevent overflow/underflow
//! - Balance increases (vault gains) are ignored, only outflows count
//! - Recurring limit windows align to slot boundaries
//! - Recurring limits validate single-tx doesn't exceed full window limit
//! - State mutations only happen after all checks pass
//! - Zero spending transactions pass through without triggering limits

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::{
    compact::CompactInstruction,
    error::AuthError,
    state::{
        action::{parse_actions, read_u64, write_u64, ActionType, ActionView},
        session::{has_actions, SESSION_HEADER_SIZE},
    },
};

// ─── Token Account Layout (SPL Token) ────────────────────────────────
// mint:   bytes 0..32
// owner:  bytes 32..64
// amount: bytes 64..72

const TOKEN_MINT_OFFSET: usize = 0;
const TOKEN_OWNER_OFFSET: usize = 32;
const TOKEN_AMOUNT_OFFSET: usize = 64;
const TOKEN_ACCOUNT_MIN_SIZE: usize = 165;

/// A snapshot of a token account balance for a specific mint.
pub struct TokenSnapshot {
    pub mint: [u8; 32],
    pub amount: u64,
}

/// Evaluate pre-CPI actions (program whitelist/blacklist).
///
/// Call this BEFORE executing compact instructions.
/// Returns early with Ok(()) if no actions exist.
pub fn evaluate_pre_actions(
    session_data: &[u8],
    compact_instructions: &[CompactInstruction],
    accounts: &[AccountInfo],
    current_slot: u64,
) -> Result<(), ProgramError> {
    if !has_actions(session_data) {
        return Ok(());
    }

    let actions_buf = &session_data[SESSION_HEADER_SIZE..];
    let actions = parse_actions(actions_buf)?;

    // Collect whitelist/blacklist program IDs.
    // Expired whitelist actions are intentionally NOT added to `whitelisted`, but they still set
    // `has_any_whitelist_action = true`. This means if a whitelist existed but has now expired,
    // NO program is permitted — treating an expired whitelist as a hard deny rather than open
    // access. An expired blacklist entry, however, is silently dropped (the ban has lifted).
    let mut whitelisted: Vec<[u8; 32]> = Vec::new();
    let mut blacklisted: Vec<[u8; 32]> = Vec::new();
    let mut has_any_whitelist_action = false;

    for action in &actions {
        match action.action_type {
            ActionType::ProgramWhitelist => {
                has_any_whitelist_action = true;
                if !is_expired(action, current_slot) {
                    let mut prog_id = [0u8; 32];
                    prog_id.copy_from_slice(
                        &actions_buf[action.data_offset..action.data_offset + 32],
                    );
                    whitelisted.push(prog_id);
                }
            }
            ActionType::ProgramBlacklist => {
                if !is_expired(action, current_slot) {
                    let mut prog_id = [0u8; 32];
                    prog_id.copy_from_slice(
                        &actions_buf[action.data_offset..action.data_offset + 32],
                    );
                    blacklisted.push(prog_id);
                }
            }
            _ => {}
        }
    }

    // Enforce program restrictions on each instruction
    for ix in compact_instructions {
        let prog_idx = ix.program_id_index as usize;
        if prog_idx >= accounts.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let target_program = accounts[prog_idx].key();

        // Whitelist: if any whitelist action EVER existed (even expired), program must be in the
        // active set. An expired whitelist = deny all programs.
        if has_any_whitelist_action && !whitelisted.iter().any(|p| p == target_program.as_ref()) {
            return Err(AuthError::ActionProgramNotWhitelisted.into());
        }

        // Blacklist: program must NOT be in the active set (expired entries already dropped above).
        if blacklisted.iter().any(|p| p == target_program.as_ref()) {
            return Err(AuthError::ActionProgramBlacklisted.into());
        }
    }

    Ok(())
}

/// Snapshot token balances for mints referenced in token actions.
pub fn snapshot_token_balances(
    session_data: &[u8],
    accounts: &[AccountInfo],
    vault_key: &Pubkey,
) -> Result<Vec<TokenSnapshot>, ProgramError> {
    if !has_actions(session_data) {
        return Ok(Vec::new());
    }

    let actions_buf = &session_data[SESSION_HEADER_SIZE..];
    let actions = parse_actions(actions_buf)?;

    let mut mints: Vec<[u8; 32]> = Vec::new();
    for action in &actions {
        match action.action_type {
            ActionType::TokenLimit
            | ActionType::TokenRecurringLimit
            | ActionType::TokenMaxPerTx => {
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&actions_buf[action.data_offset..action.data_offset + 32]);
                if !mints.iter().any(|m| m == &mint) {
                    mints.push(mint);
                }
            }
            _ => {}
        }
    }

    if mints.is_empty() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for mint in &mints {
        if let Some(amount) = find_token_balance(accounts, vault_key, mint) {
            snapshots.push(TokenSnapshot {
                mint: *mint,
                amount,
            });
        }
    }

    Ok(snapshots)
}

/// Evaluate post-CPI actions (spending limits).
///
/// `vault_lamports_gross_out` is the sum of all per-CPI outflows from the vault, used for
/// `SolMaxPerTx` (which must block even DeFi round-trips that appear net-zero).
/// `vault_lamports_before`/`after` net diff is used for the cumulative limits (SolLimit,
/// SolRecurringLimit), where net accounting is conservative and appropriate.
///
/// Security: This function first computes all spending deltas and validates
/// ALL limits before writing any state. This ensures no partial state mutation
/// if a later check fails.
pub fn evaluate_post_actions(
    session_data: &mut [u8],
    accounts: &[AccountInfo],
    vault_key: &Pubkey,
    vault_lamports_before: u64,
    vault_lamports_after: u64,
    vault_lamports_gross_out: u64,
    token_snapshots_before: &[TokenSnapshot],
    current_slot: u64,
) -> Result<(), ProgramError> {
    if !has_actions(session_data) {
        return Ok(());
    }

    // Only count outflows. If vault gained lamports, sol_spent = 0.
    // This matches Swig's pattern: balance increases are tracked but not counted against limits.
    let sol_spent = vault_lamports_before.saturating_sub(vault_lamports_after);

    // If nothing was spent, skip all checks (no state mutation needed for SOL).
    // Token checks still need to run.

    let actions_buf_readonly = &session_data[SESSION_HEADER_SIZE..];
    let actions = parse_actions(actions_buf_readonly)?;

    // ── Phase 1: Validate all SOL limits (read-only check) ──────────
    // Expired spending-limit actions are treated as fully exhausted / "0 remaining":
    // if any SOL was spent and a limit action has expired, the tx is rejected.
    // This prevents a session with expired limits from becoming unrestricted.
    for action in &actions {
        let action_expired = is_expired(action, current_slot);
        let abs_data_offset = SESSION_HEADER_SIZE + action.data_offset;

        match action.action_type {
            ActionType::SolMaxPerTx => {
                // Use gross outflow so DeFi round-trips that return most lamports cannot bypass
                // a per-tx cap (the net diff would be near-zero but gross could be large).
                if vault_lamports_gross_out > 0 {
                    if action_expired {
                        return Err(AuthError::ActionSolMaxPerTxExceeded.into());
                    }
                    let max = read_u64(&session_data[abs_data_offset..], 0);
                    if vault_lamports_gross_out > max {
                        return Err(AuthError::ActionSolMaxPerTxExceeded.into());
                    }
                }
            }
            ActionType::SolLimit => {
                if sol_spent > 0 {
                    if action_expired {
                        return Err(AuthError::ActionSolLimitExceeded.into());
                    }
                    let remaining = read_u64(&session_data[abs_data_offset..], 0);
                    if sol_spent > remaining {
                        return Err(AuthError::ActionSolLimitExceeded.into());
                    }
                }
            }
            ActionType::SolRecurringLimit => {
                if sol_spent > 0 {
                    if action_expired {
                        return Err(AuthError::ActionSolRecurringLimitExceeded.into());
                    }
                    let limit = read_u64(&session_data[abs_data_offset..], 0);
                    let spent = read_u64(&session_data[abs_data_offset..], 8);
                    let window = read_u64(&session_data[abs_data_offset..], 16);
                    let last_reset = read_u64(&session_data[abs_data_offset..], 24);

                    let effective_spent = if current_slot.saturating_sub(last_reset) > window {
                        // Window expired — reset. But single tx can't exceed full limit.
                        if sol_spent > limit {
                            return Err(AuthError::ActionSolRecurringLimitExceeded.into());
                        }
                        0u64
                    } else {
                        spent
                    };

                    // Use saturating_add to prevent overflow
                    if effective_spent.saturating_add(sol_spent) > limit {
                        return Err(AuthError::ActionSolRecurringLimitExceeded.into());
                    }
                }
            }
            _ => {}
        }
    }

    // ── Phase 1b: Validate all token limits (read-only check) ───────
    // Same policy as SOL limits: expired = treat as fully exhausted.
    for action in &actions {
        let action_expired = is_expired(action, current_slot);
        let abs_data_offset = SESSION_HEADER_SIZE + action.data_offset;

        match action.action_type {
            ActionType::TokenMaxPerTx | ActionType::TokenLimit | ActionType::TokenRecurringLimit => {
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&session_data[abs_data_offset..abs_data_offset + 32]);

                let before_amount = token_snapshots_before
                    .iter()
                    .find(|s| s.mint == mint)
                    .map(|s| s.amount)
                    .unwrap_or(0);

                let after_amount = find_token_balance(accounts, vault_key, &mint).unwrap_or(0);

                // Only count outflows
                let token_spent = before_amount.saturating_sub(after_amount);

                if token_spent > 0 {
                    if action_expired {
                        // Treat expired token limit as fully exhausted — deny any spend.
                        return match action.action_type {
                            ActionType::TokenMaxPerTx => Err(AuthError::ActionTokenMaxPerTxExceeded.into()),
                            ActionType::TokenLimit => Err(AuthError::ActionTokenLimitExceeded.into()),
                            _ => Err(AuthError::ActionTokenRecurringLimitExceeded.into()),
                        };
                    }
                    match action.action_type {
                        ActionType::TokenMaxPerTx => {
                            let max = read_u64(&session_data[abs_data_offset..], 32);
                            if token_spent > max {
                                return Err(AuthError::ActionTokenMaxPerTxExceeded.into());
                            }
                        }
                        ActionType::TokenLimit => {
                            let remaining = read_u64(&session_data[abs_data_offset..], 32);
                            if token_spent > remaining {
                                return Err(AuthError::ActionTokenLimitExceeded.into());
                            }
                        }
                        ActionType::TokenRecurringLimit => {
                            let limit = read_u64(&session_data[abs_data_offset..], 32);
                            let spent = read_u64(&session_data[abs_data_offset..], 40);
                            let window = read_u64(&session_data[abs_data_offset..], 48);
                            let last_reset = read_u64(&session_data[abs_data_offset..], 56);

                            let effective_spent =
                                if current_slot.saturating_sub(last_reset) > window {
                                    if token_spent > limit {
                                        return Err(
                                            AuthError::ActionTokenRecurringLimitExceeded.into()
                                        );
                                    }
                                    0u64
                                } else {
                                    spent
                                };

                            if effective_spent.saturating_add(token_spent) > limit {
                                return Err(AuthError::ActionTokenRecurringLimitExceeded.into());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // ── Phase 2: All checks passed. Now write state mutations. ──────
    // Re-parse using a slice reference — no allocation needed, same bytes, same offsets.
    let actions = parse_actions(&session_data[SESSION_HEADER_SIZE..])?;

    for action in &actions {
        if is_expired(action, current_slot) {
            continue;
        }

        let abs_data_offset = SESSION_HEADER_SIZE + action.data_offset;

        match action.action_type {
            ActionType::SolLimit => {
                if sol_spent > 0 {
                    let remaining = read_u64(&session_data[abs_data_offset..], 0);
                    write_u64(
                        &mut session_data[abs_data_offset..],
                        0,
                        remaining.saturating_sub(sol_spent),
                    );
                }
            }
            ActionType::SolRecurringLimit => {
                if sol_spent > 0 {
                    let _limit = read_u64(&session_data[abs_data_offset..], 0);
                    let spent = read_u64(&session_data[abs_data_offset..], 8);
                    let window = read_u64(&session_data[abs_data_offset..], 16);
                    let last_reset = read_u64(&session_data[abs_data_offset..], 24);

                    let (new_spent, new_last_reset) =
                        if current_slot.saturating_sub(last_reset) > window {
                            let aligned = (current_slot / window) * window;
                            (sol_spent, aligned)
                        } else {
                            (spent.saturating_add(sol_spent), last_reset)
                        };

                    write_u64(&mut session_data[abs_data_offset..], 8, new_spent);
                    write_u64(&mut session_data[abs_data_offset..], 24, new_last_reset);
                }
            }
            ActionType::TokenLimit => {
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&session_data[abs_data_offset..abs_data_offset + 32]);
                let before = token_snapshots_before
                    .iter()
                    .find(|s| s.mint == mint)
                    .map(|s| s.amount)
                    .unwrap_or(0);
                let after = find_token_balance(accounts, vault_key, &mint).unwrap_or(0);
                let token_spent = before.saturating_sub(after);

                if token_spent > 0 {
                    let remaining = read_u64(&session_data[abs_data_offset..], 32);
                    write_u64(
                        &mut session_data[abs_data_offset..],
                        32,
                        remaining.saturating_sub(token_spent),
                    );
                }
            }
            ActionType::TokenRecurringLimit => {
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&session_data[abs_data_offset..abs_data_offset + 32]);
                let before = token_snapshots_before
                    .iter()
                    .find(|s| s.mint == mint)
                    .map(|s| s.amount)
                    .unwrap_or(0);
                let after = find_token_balance(accounts, vault_key, &mint).unwrap_or(0);
                let token_spent = before.saturating_sub(after);

                if token_spent > 0 {
                    let spent = read_u64(&session_data[abs_data_offset..], 40);
                    let window = read_u64(&session_data[abs_data_offset..], 48);
                    let last_reset = read_u64(&session_data[abs_data_offset..], 56);

                    let (new_spent, new_last_reset) =
                        if current_slot.saturating_sub(last_reset) > window {
                            let aligned = (current_slot / window) * window;
                            (token_spent, aligned)
                        } else {
                            (spent.saturating_add(token_spent), last_reset)
                        };

                    write_u64(&mut session_data[abs_data_offset..], 40, new_spent);
                    write_u64(&mut session_data[abs_data_offset..], 56, new_last_reset);
                }
            }
            _ => {} // SolMaxPerTx, TokenMaxPerTx, whitelist/blacklist have no mutable state
        }
    }

    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────

/// Check if an action has expired.
#[inline]
fn is_expired(action: &ActionView, current_slot: u64) -> bool {
    action.expires_at != 0 && current_slot > action.expires_at
}

/// SPL Token program ID
const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133,
    237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// SPL Token-2022 program ID
const SPL_TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 170, 164, 12, 4, 223, 116, 174, 240, 70, 137, 163, 89,
    77, 149, 128, 12, 61, 73, 196, 253, 210, 164, 82, 159,
];

/// Find the total token balance across ALL token accounts for a given mint owned by the vault.
///
/// Security: Sums every matching account rather than returning the first match.
/// Returning only the first match allowed an attacker to place a 0-balance dummy
/// token account (owned by vault, same mint) before the real account in the
/// accounts list, causing both the pre-CPI snapshot and post-CPI check to read
/// the dummy account (balance always 0) and bypass all token spending limits.
///
/// Verifies each account is owned by SPL Token or Token-2022 to prevent fake
/// accounts with fabricated mint/owner fields.
fn find_token_balance(
    accounts: &[AccountInfo],
    vault_key: &Pubkey,
    mint: &[u8; 32],
) -> Option<u64> {
    let mut total: u64 = 0;
    let mut found = false;

    for acc in accounts {
        // CRITICAL: Verify account is owned by SPL Token or Token-2022 program.
        let owner = acc.owner();
        if owner.as_ref() != &SPL_TOKEN_PROGRAM_ID && owner.as_ref() != &SPL_TOKEN_2022_PROGRAM_ID
        {
            continue;
        }

        let data = unsafe { acc.borrow_data_unchecked() };
        if data.len() < TOKEN_ACCOUNT_MIN_SIZE {
            continue;
        }
        if &data[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32] != mint {
            continue;
        }
        if &data[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32] != vault_key.as_ref() {
            continue;
        }
        let amount = u64::from_le_bytes(
            match data[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            },
        );
        total = total.saturating_add(amount);
        found = true;
    }

    if found { Some(total) } else { None }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::action::ACTION_HEADER_SIZE;

    fn build_action(action_type: u8, expires_at: u64, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(action_type);
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&expires_at.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn build_session_data(actions: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; SESSION_HEADER_SIZE];
        data[0] = 3; // discriminator
        data.extend_from_slice(actions);
        data
    }

    fn build_sol_recurring(limit: u64, spent: u64, window: u64, last_reset: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&limit.to_le_bytes());
        data.extend_from_slice(&spent.to_le_bytes());
        data.extend_from_slice(&window.to_le_bytes());
        data.extend_from_slice(&last_reset.to_le_bytes());
        data
    }

    // ─── Basic functionality ──────────────────────────────────────

    #[test]
    fn test_no_actions_passthrough() {
        let mut session_data = vec![0u8; SESSION_HEADER_SIZE];
        session_data[0] = 3;
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            10_000_000, 0, &[], 100,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_spending_no_state_change() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);
        let original = session_data.clone();

        // vault gained lamports (before < after) → sol_spent = 0
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 2_000_000, // vault gained 1M
            &[], 100,
        );
        assert!(result.is_ok());
        // State unchanged — remaining should still be 1M
        assert_eq!(session_data, original);
    }

    #[test]
    fn test_vault_balance_increase_ignored() {
        // SolMaxPerTx of 500k, but vault GAINS lamports
        let actions = build_action(3, 0, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 5_000_000, // gained 4M
            &[], 100,
        );
        assert!(result.is_ok()); // No violation, gains are ignored
    }

    // ─── SolLimit ─────────────────────────────────────────────────

    #[test]
    fn test_sol_limit_exact_remaining() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Spend exactly the remaining amount — should succeed
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_000_000, // spent exactly 1M
            &[], 100,
        );
        assert!(result.is_ok());

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        let remaining = read_u64(&session_data[abs_offset..], 0);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_sol_limit_depletes_across_txs() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Tx 1: spend 600k
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_400_000, &[], 100,
        );
        assert!(result.is_ok());

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 400_000);

        // Tx 2: spend 400k (exact remaining) — OK
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_400_000, 1_000_000, &[], 101,
        );
        assert!(result.is_ok());
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 0);

        // Tx 3: spend 1 lamport — should fail (0 remaining)
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 999_999, &[], 102,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_limit_single_overspend() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Try to spend 1M + 1 — should fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 999_999, // spent 1_000_001
            &[], 100,
        );
        assert!(result.is_err());

        // State unchanged after failed check
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 1_000_000);
    }

    // ─── SolMaxPerTx ──────────────────────────────────────────────

    #[test]
    fn test_sol_max_per_tx_exact_limit() {
        let actions = build_action(3, 0, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Spend exactly the max — OK
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_500_000, &[], 100,
        );
        assert!(result.is_ok());

        // Exceed by 1 — fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_499_999, &[], 101,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_max_per_tx_repeatable() {
        // MaxPerTx does NOT accumulate — each tx is independent
        let actions = build_action(3, 0, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        for slot in 100..110 {
            let result = evaluate_post_actions(
                &mut session_data, &[], &Pubkey::default(),
                2_000_000, 1_500_000, // 500k each time
                &[], slot,
            );
            assert!(result.is_ok());
        }
    }

    // ─── SolRecurringLimit ────────────────────────────────────────

    #[test]
    fn test_sol_recurring_limit_basic() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend 600k at slot 50
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_400_000, &[], 50,
        );
        assert!(result.is_ok());

        // Spend 500k more at slot 60 — total 1.1M > 1M limit
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_400_000, 900_000, &[], 60,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_recurring_limit_window_reset() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend 900k at slot 50
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_100_000, &[], 50,
        ).unwrap();

        // At slot 150 (after window), 500k should work again
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_100_000, 600_000, &[], 150,
        );
        assert!(result.is_ok());

        // Verify last_reset was aligned to window boundary
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        let last_reset = read_u64(&session_data[abs_offset..], 24);
        assert_eq!(last_reset, 100); // (150 / 100) * 100 = 100
    }

    #[test]
    fn test_sol_recurring_single_tx_exceeds_full_limit_after_reset() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // At slot 150 (fresh window), try to spend more than the full limit
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 3_500_000, // 1.5M > 1M limit
            &[], 150,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_recurring_exact_limit_in_window() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend exactly the limit
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_000_000, &[], 50,
        );
        assert!(result.is_ok());

        // Spend 1 more in same window — fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 999_999, &[], 60,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_recurring_overflow_protection() {
        // spent is near u64::MAX, adding more would overflow
        let data = build_sol_recurring(u64::MAX, u64::MAX - 100, 1000, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend 200 — would overflow spent + sol_spent without saturating_add
        // But limit is u64::MAX so it should be within limit
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 999_800, // spent 200
            &[], 50,
        );
        // saturating_add(u64::MAX - 100, 200) = u64::MAX, which == limit, so OK
        assert!(result.is_ok());
    }

    // ─── Combined actions ─────────────────────────────────────────

    #[test]
    fn test_combined_sol_limit_and_max_per_tx() {
        let mut actions_buf = Vec::new();
        // SolLimit: 2M lifetime
        actions_buf.extend_from_slice(&build_action(1, 0, &2_000_000u64.to_le_bytes()));
        // SolMaxPerTx: 500k per tx
        actions_buf.extend_from_slice(&build_action(3, 0, &500_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);

        // 400k — under both limits
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 4_600_000, &[], 100,
        );
        assert!(result.is_ok());

        // 600k — under lifetime (1.6M left) but over per-tx (500k)
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            4_600_000, 4_000_000, &[], 101,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_combined_recurring_and_max_per_tx() {
        let mut actions_buf = Vec::new();
        // SolRecurringLimit: 1M per 100 slots
        actions_buf.extend_from_slice(&build_action(2, 0, &build_sol_recurring(1_000_000, 0, 100, 0)));
        // SolMaxPerTx: 300k per tx
        actions_buf.extend_from_slice(&build_action(3, 0, &300_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);

        // 200k — OK
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 4_800_000, &[], 50,
        ).unwrap();

        // 200k more — OK (400k total in window, under 1M; 200k under 300k per-tx)
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            4_800_000, 4_600_000, &[], 60,
        ).unwrap();

        // 350k — fails per-tx (350k > 300k) even though recurring has room
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            4_600_000, 4_250_000, &[], 70,
        );
        assert!(result.is_err());
    }

    // ─── Action expiry ────────────────────────────────────────────

    #[test]
    fn test_expired_action_skipped() {
        let actions = build_action(3, 50, &500_000u64.to_le_bytes()); // Expires at slot 50
        let mut session_data = build_session_data(&actions);

        // At slot 100, action expired — 600k spend should pass
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_400_000, &[], 100,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_active_at_expiry_slot() {
        // Action expires at slot 50. At exactly slot 50 it should still be active.
        // Only expired when current_slot > expires_at.
        let actions = build_action(3, 50, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // At slot 50 — still active, 600k > 500k → fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_400_000, &[], 50,
        );
        assert!(result.is_err());

        // At slot 51 — expired, 600k → pass
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_400_000, &[], 51,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_mixed_expired_and_active_actions() {
        let mut actions_buf = Vec::new();
        // SolMaxPerTx: 500k, expires at slot 50
        actions_buf.extend_from_slice(&build_action(3, 50, &500_000u64.to_le_bytes()));
        // SolLimit: 2M, never expires
        actions_buf.extend_from_slice(&build_action(1, 0, &2_000_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);

        // At slot 100: MaxPerTx expired, but SolLimit still active
        // 3M spend → exceeds SolLimit of 2M → fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 2_000_000, &[], 100,
        );
        assert!(result.is_err());

        // 1M spend → under SolLimit → OK (MaxPerTx expired, doesn't block)
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 4_000_000, &[], 100,
        );
        assert!(result.is_ok());
    }

    // ─── State mutation safety ────────────────────────────────────

    #[test]
    fn test_failed_check_no_state_mutation() {
        let mut actions_buf = Vec::new();
        // SolLimit: 2M
        actions_buf.extend_from_slice(&build_action(1, 0, &2_000_000u64.to_le_bytes()));
        // SolMaxPerTx: 100k (will fail)
        actions_buf.extend_from_slice(&build_action(3, 0, &100_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);
        let original = session_data.clone();

        // 500k spend — passes SolLimit but fails SolMaxPerTx
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            5_000_000, 4_500_000, &[], 100,
        );
        assert!(result.is_err());

        // Because we validate ALL checks before writing, state is unchanged
        assert_eq!(session_data, original);
    }

    #[test]
    fn test_recurring_state_persists_correctly() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;

        // Spend 300k at slot 50
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            2_000_000, 1_700_000, &[], 50,
        ).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 300_000); // spent
        assert_eq!(read_u64(&session_data[abs_offset..], 24), 0); // last_reset (first window)

        // Spend 200k at slot 60
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_700_000, 1_500_000, &[], 60,
        ).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 500_000); // cumulative

        // Window reset at slot 200
        evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_500_000, 1_300_000, &[], 200,
        ).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 200_000); // reset + new spend
        assert_eq!(read_u64(&session_data[abs_offset..], 24), 200); // aligned: (200/100)*100
    }

    // ─── Edge: zero limit ─────────────────────────────────────────

    #[test]
    fn test_zero_sol_limit_blocks_all_spending() {
        let actions = build_action(1, 0, &0u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Even 1 lamport should fail
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 999_999, &[], 100,
        );
        assert!(result.is_err());

        // But zero spending is OK
        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 1_000_000, &[], 100,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_max_per_tx_blocks_all_spending() {
        let actions = build_action(3, 0, &0u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 999_999, &[], 100,
        );
        assert!(result.is_err());

        let result = evaluate_post_actions(
            &mut session_data, &[], &Pubkey::default(),
            1_000_000, 1_000_000, &[], 100,
        );
        assert!(result.is_ok());
    }
}
