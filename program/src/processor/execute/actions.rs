//! Policy evaluation for the Execute instruction.
//!
//! Provides pre-CPI and post-CPI checks for an Execute whose signer carries a
//! policy: a session with actions, or a Delegate authority.
//! Pre-CPI: program whitelist/blacklist enforcement.
//! Post-CPI: spending limit enforcement with balance diffing, and the rule
//! that an asset the policy does not name may not leave. The vault's net SOL,
//! and its net balance of each mint over the token accounts it owned before
//! the CPIs, may fall only where an action names that asset (D13).
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
    compact::CompactInstructionRef,
    error::AuthError,
    state::{
        action::{parse_actions, read_u64, write_u64, ActionType, ActionView},
        policy::PolicyLocation,
    },
};

// ─── Token Account Layout (SPL Token and Token-2022) ─────────────────
// mint 0..32 · owner 32..64 · amount 64..72 · delegate 72..108 (COption, 4-byte tag)
// state 108 · is_native 109..121 (COption<u64>) · delegated_amount 121..129
// close_authority 129..165 (COption). Token-2022, when longer: account type at 165
// (2 = Account), TLV extensions from 166. A multisig is 355 bytes and Token-2022
// never sizes an account to 355.

const TOKEN_MINT_OFFSET: usize = 0;
const TOKEN_OWNER_OFFSET: usize = 32;
const TOKEN_AMOUNT_OFFSET: usize = 64;
const TOKEN_DELEGATE_OFFSET: usize = 72;
const TOKEN_STATE_OFFSET: usize = 108;
const TOKEN_IS_NATIVE_OFFSET: usize = 109;
const TOKEN_DELEGATED_AMOUNT_OFFSET: usize = 121;
const TOKEN_CLOSE_AUTHORITY_OFFSET: usize = 129;
const TOKEN_ACCOUNT_LEN: usize = 165;
const TOKEN_ACCOUNT_TYPE_OFFSET: usize = 165;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TOKEN_MULTISIG_LEN: usize = 355;
const COPTION_TAG_LEN: usize = 4;

/// One vault-owned token account as it stood before the CPI loop.
pub struct VaultTokenSnapshot {
    /// Position in Execute's account list; re-read by index, not searched for.
    pub index: usize,
    pub data_len: usize,
    pub lamports: u64,
    /// Bytes 0..165: every field of the base layout.
    pub base: [u8; TOKEN_ACCOUNT_LEN],
}

/// A mint's balance over the snapshotted accounts, before and after the loop.
pub struct MintFlow {
    pub mint: [u8; 32],
    pub before: u64,
    pub after: u64,
}

impl MintFlow {
    /// What left the snapshotted accounts, net of what came back into them.
    pub fn outflow(&self) -> u64 {
        self.before.saturating_sub(self.after)
    }
}

/// Evaluate pre-CPI actions (program whitelist/blacklist).
///
/// Call this BEFORE executing compact instructions.
/// Returns early with Ok(()) if no actions exist.
pub fn evaluate_pre_actions(
    session_data: &[u8],
    loc: PolicyLocation,
    compact_instructions: &[CompactInstructionRef<'_>],
    accounts: &[AccountInfo],
    current_slot: u64,
) -> Result<(), ProgramError> {
    if !loc.is_present(session_data) {
        return Ok(());
    }

    let actions_buf = loc.slice(session_data);
    let actions = parse_actions(actions_buf)?;

    // Expired whitelist actions are intentionally NOT accepted by
    // `names_program`, but they still set `has_any_whitelist_action = true`.
    // This means if a whitelist existed but has now expired, NO program is
    // permitted — treating an expired whitelist as a hard deny rather than open
    // access. An expired blacklist entry, however, is silently dropped (the ban
    // has lifted). Read from the parsed views rather than collected into Vecs:
    // the heap is a bump allocator that never frees.
    let has_any_whitelist_action = actions
        .iter()
        .any(|a| a.action_type == ActionType::ProgramWhitelist);

    // Enforce program restrictions on each instruction
    for ix in compact_instructions {
        let prog_idx = ix.program_id_index as usize;
        if prog_idx >= accounts.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let target_program = accounts[prog_idx].key();

        // Whitelist: if any whitelist action EVER existed (even expired), program must be in the
        // active set. An expired whitelist = deny all programs.
        if has_any_whitelist_action
            && !names_program(
                &actions,
                actions_buf,
                ActionType::ProgramWhitelist,
                target_program,
                current_slot,
            )
        {
            return Err(AuthError::ActionProgramNotWhitelisted.into());
        }

        // Blacklist: program must NOT be in the active set (expired entries do not count).
        if names_program(
            &actions,
            actions_buf,
            ActionType::ProgramBlacklist,
            target_program,
            current_slot,
        ) {
            return Err(AuthError::ActionProgramBlacklisted.into());
        }
    }

    Ok(())
}

/// Whether an unexpired action of `action_type` names `program`.
fn names_program(
    actions: &[ActionView],
    actions_buf: &[u8],
    action_type: ActionType,
    program: &Pubkey,
    current_slot: u64,
) -> bool {
    actions.iter().any(|a| {
        a.action_type == action_type
            && !is_expired(a, current_slot)
            && actions_buf[a.data_offset..a.data_offset + 32] == program[..]
    })
}

/// Copy every writable, vault-owned token account in `accounts`, once per key.
///
/// Called before the CPI loop when the signer carries a policy. After the loop,
/// [`verify_vault_token_accounts`] holds each copy to everything but its
/// balance, and [`mint_flows`] measures each mint's balance over exactly these
/// accounts. Together they keep a policy-bound signer from doing either of two
/// things the lamport and balance limits cannot see:
///
/// - Reassigning control of a vault token account without moving a token:
///   `SetAuthority`, `Approve`, `Revoke`, `CloseAccount`, `FreezeAccount`,
///   `WithdrawExcessLamports`, `Reallocate`. The copy is deliberately
///   mint-agnostic: a policy that never mentions a mint is not a policy that
///   consented to hand that mint's account away (H-4).
/// - Moving value out under cover of a new account. "Before" and "after" are
///   measured over the same accounts, so a transfer into a token account that
///   becomes vault-owned during the Execute is spent, not kept, and that
///   account may carry no delegate or close authority when the loop ends.
///
/// Read-only accounts are skipped: the runtime refuses any change to an
/// account the transaction does not lock writable, and a CPI cannot raise
/// writability. A duplicate shares its first entry's data, so it is copied
/// once and counted once.
pub fn snapshot_vault_token_accounts(
    accounts: &[AccountInfo],
    vault_key: &Pubkey,
) -> Vec<VaultTokenSnapshot> {
    // Positions to copy, found in one walk: each writable vault-owned token
    // account at its first position in the list. A repeat is looked for only
    // among the positions already found, not among every account before it.
    // The runtime passes an instruction at most 255 accounts, and
    // `MAX_TX_ACCOUNTS` covers them (see `entrypoint.rs`), so a position fits
    // a byte and the list fits the stack.
    let mut found = [0u8; pinocchio::MAX_TX_ACCOUNTS];
    let mut count = 0;
    for (index, acc) in accounts.iter().enumerate() {
        if !is_snapshot_candidate(acc, vault_key)
            || found[..count]
                .iter()
                .any(|&j| accounts[j as usize].key() == acc.key())
        {
            continue;
        }
        found[count] = index as u8;
        count += 1;
    }

    // Allocated once at its final size: the heap is a 32 KiB bump allocator
    // that never frees, and a Vec that grows leaves every smaller buffer
    // behind. Sized by unique accounts, so passing one account many times
    // costs one copy.
    let mut out = Vec::with_capacity(count);
    for &index in &found[..count] {
        let index = index as usize;
        let acc = &accounts[index];
        let data = unsafe { acc.borrow_data_unchecked() };
        let mut base = [0u8; TOKEN_ACCOUNT_LEN];
        base.copy_from_slice(&data[..TOKEN_ACCOUNT_LEN]);
        out.push(VaultTokenSnapshot {
            index,
            data_len: data.len(),
            lamports: acc.lamports(),
            base,
        });
    }
    out
}

// A position in Execute's account list is stored as a byte above.
const _: () = assert!(pinocchio::MAX_TX_ACCOUNTS <= u8::MAX as usize + 1);

/// Check every snapshotted account after the CPI loop, and every token account
/// that became vault-owned during it. Any failure is
/// `SessionTokenAuthorityChanged` (3032).
///
/// A snapshotted account must still be a token account of the same length with
/// lamports in it, and every base field but `amount` must be as it was, except
/// that `delegated_amount` may fall. Its lamports may fall only by what a native
/// (wSOL) account's `amount` fell by.
///
/// A token account that is vault-owned now but was not snapshotted must carry
/// no delegate and no close authority. Its balance is not credited to the
/// vault (see [`mint_flows`]); this keeps it from being drained later, for
/// instance through deposits made into a vault ATA created in this Execute.
pub fn verify_vault_token_accounts(
    snapshots: &[VaultTokenSnapshot],
    accounts: &[AccountInfo],
    vault_key: &Pubkey,
) -> Result<(), ProgramError> {
    for snap in snapshots {
        let acc = &accounts[snap.index];
        let data = unsafe { acc.borrow_data_unchecked() };
        if acc.lamports() == 0
            || data.len() != snap.data_len
            || !is_token_account(acc.owner(), data)
            || !base_unchanged_except_balance(&snap.base, data)
            || !lamports_kept(snap.lamports, &snap.base, acc.lamports(), data)
        {
            return Err(AuthError::SessionTokenAuthorityChanged.into());
        }
    }

    for (index, acc) in accounts.iter().enumerate() {
        if !is_snapshot_candidate(acc, vault_key) {
            continue;
        }
        // Snapshotted here (the snapshot is in index order), or a repeat of an
        // account listed earlier, which is either snapshotted or checked at
        // its first position.
        if snapshots.binary_search_by_key(&index, |s| s.index).is_ok()
            || repeats_earlier(accounts, index)
        {
            continue;
        }
        let data = unsafe { acc.borrow_data_unchecked() };
        if data[TOKEN_DELEGATE_OFFSET..TOKEN_DELEGATE_OFFSET + COPTION_TAG_LEN]
            != [0u8; COPTION_TAG_LEN]
            || data[TOKEN_CLOSE_AUTHORITY_OFFSET..TOKEN_CLOSE_AUTHORITY_OFFSET + COPTION_TAG_LEN]
                != [0u8; COPTION_TAG_LEN]
        {
            return Err(AuthError::SessionTokenAuthorityChanged.into());
        }
    }

    Ok(())
}

/// Each mint's balance over the snapshotted accounts, before and after the CPI
/// loop. Call only after [`verify_vault_token_accounts`] has passed, which
/// guarantees every snapshotted account still holds the same mint.
///
/// Measured over the snapshot alone: a token account that became vault-owned
/// during the Execute adds nothing to "after", so moving tokens into one is
/// spending them.
pub fn mint_flows(snapshots: &[VaultTokenSnapshot], accounts: &[AccountInfo]) -> Vec<MintFlow> {
    let mut flows = Vec::with_capacity(snapshots.len());
    for snap in snapshots {
        let data = unsafe { accounts[snap.index].borrow_data_unchecked() };
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&snap.base[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32]);
        add_flow(
            &mut flows,
            mint,
            read_u64(&snap.base, TOKEN_AMOUNT_OFFSET),
            read_u64(data, TOKEN_AMOUNT_OFFSET),
        );
    }
    flows
}

/// Evaluate post-CPI actions (spending limits, and the assets the policy does
/// not name).
///
/// `vault_lamports_gross_out` is the sum of all per-CPI outflows from the vault, used for
/// `SolMaxPerTx` (which must block even DeFi round-trips that appear net-zero).
/// `vault_lamports_before`/`after` net diff is used for the cumulative limits (SolLimit,
/// SolRecurringLimit), where net accounting is conservative and appropriate.
/// `mint_flows` holds each mint's net balance over the vault token accounts
/// snapshotted before the loop.
///
/// Security: This function first computes all spending deltas and validates
/// ALL limits before writing any state. This ensures no partial state mutation
/// if a later check fails.
pub fn evaluate_post_actions(
    session_data: &mut [u8],
    loc: PolicyLocation,
    vault_lamports_before: u64,
    vault_lamports_after: u64,
    vault_lamports_gross_out: u64,
    mint_flows: &[MintFlow],
    current_slot: u64,
) -> Result<(), ProgramError> {
    if !loc.is_present(session_data) {
        return Ok(());
    }

    // Only count outflows. If vault gained lamports, sol_spent = 0.
    // This matches Swig's pattern: balance increases are tracked but not counted against limits.
    let sol_spent = vault_lamports_before.saturating_sub(vault_lamports_after);

    // If nothing was spent, skip all checks (no state mutation needed for SOL).
    // Token checks still need to run.

    // Parsed once: `ActionView` holds offsets into the buffer, not borrows of
    // it, so Phase 2 below writes through `session_data` with these same views.
    let actions = parse_actions(loc.slice(session_data))?;

    // ── Phase 1: Validate all SOL limits (read-only check) ──────────
    // Expired spending-limit actions are treated as fully exhausted / "0 remaining":
    // if any SOL was spent and a limit action has expired, the tx is rejected.
    // This prevents a session with expired limits from becoming unrestricted.
    for action in &actions {
        let action_expired = is_expired(action, current_slot);
        let abs_data_offset = loc.abs(action.data_offset);

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
            },
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
            },
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
            },
            _ => {},
        }
    }

    // ── Phase 1b: Validate all token limits (read-only check) ───────
    // Same policy as SOL limits: expired = treat as fully exhausted.
    for action in &actions {
        let action_expired = is_expired(action, current_slot);
        let abs_data_offset = loc.abs(action.data_offset);

        match action.action_type {
            ActionType::TokenMaxPerTx
            | ActionType::TokenLimit
            | ActionType::TokenRecurringLimit => {
                // Only count outflows, net per mint over the snapshotted accounts.
                let token_spent = mint_outflow(
                    mint_flows,
                    &session_data[abs_data_offset..abs_data_offset + 32],
                );

                if token_spent > 0 {
                    if action_expired {
                        // Treat expired token limit as fully exhausted — deny any spend.
                        return match action.action_type {
                            ActionType::TokenMaxPerTx => {
                                Err(AuthError::ActionTokenMaxPerTxExceeded.into())
                            },
                            ActionType::TokenLimit => {
                                Err(AuthError::ActionTokenLimitExceeded.into())
                            },
                            _ => Err(AuthError::ActionTokenRecurringLimitExceeded.into()),
                        };
                    }
                    match action.action_type {
                        ActionType::TokenMaxPerTx => {
                            let max = read_u64(&session_data[abs_data_offset..], 32);
                            if token_spent > max {
                                return Err(AuthError::ActionTokenMaxPerTxExceeded.into());
                            }
                        },
                        ActionType::TokenLimit => {
                            let remaining = read_u64(&session_data[abs_data_offset..], 32);
                            if token_spent > remaining {
                                return Err(AuthError::ActionTokenLimitExceeded.into());
                            }
                        },
                        ActionType::TokenRecurringLimit => {
                            let limit = read_u64(&session_data[abs_data_offset..], 32);
                            let spent = read_u64(&session_data[abs_data_offset..], 40);
                            let window = read_u64(&session_data[abs_data_offset..], 48);
                            let last_reset = read_u64(&session_data[abs_data_offset..], 56);

                            let effective_spent = if current_slot.saturating_sub(last_reset)
                                > window
                            {
                                if token_spent > limit {
                                    return Err(AuthError::ActionTokenRecurringLimitExceeded.into());
                                }
                                0u64
                            } else {
                                spent
                            };

                            if effective_spent.saturating_add(token_spent) > limit {
                                return Err(AuthError::ActionTokenRecurringLimitExceeded.into());
                            }
                        },
                        _ => {},
                    }
                }
            },
            _ => {},
        }
    }

    // ── Phase 1c: Assets the policy does not name (read-only check) ──
    // A policy lists what may leave; an asset it does not name may not. Any
    // `Sol*` action names SOL, and a `Token*` action names its mint — expired
    // or not, since an expired limit is already an exhausted one above. Net,
    // like the limits: an Execute that puts back what it took passes.
    // Rent the vault pays for a new account is SOL leaving the vault.
    let names_sol = actions.iter().any(|a| {
        matches!(
            a.action_type,
            ActionType::SolLimit | ActionType::SolRecurringLimit | ActionType::SolMaxPerTx
        )
    });
    if !names_sol && sol_spent > 0 {
        return Err(AuthError::ActionUnlistedSolOutflow.into());
    }
    for flow in mint_flows {
        if flow.outflow() > 0 && !names_mint(&actions, session_data, loc, &flow.mint) {
            return Err(AuthError::ActionUnlistedTokenOutflow.into());
        }
    }

    // ── Phase 2: All checks passed. Now write state mutations. ──────
    for action in &actions {
        if is_expired(action, current_slot) {
            continue;
        }

        let abs_data_offset = loc.abs(action.data_offset);

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
            },
            ActionType::SolRecurringLimit => {
                if sol_spent > 0 {
                    let _limit = read_u64(&session_data[abs_data_offset..], 0);
                    let spent = read_u64(&session_data[abs_data_offset..], 8);
                    let window = read_u64(&session_data[abs_data_offset..], 16);
                    let last_reset = read_u64(&session_data[abs_data_offset..], 24);

                    // The window restarts at the spend that opened it, not at a
                    // grid boundary. Snapping `last_reset` back to
                    // `(current_slot / window) * window` made the window expire
                    // early by however far into it the spend fell: a spend at
                    // `kW + W - 1` reset and pinned `last_reset = kW`, so a
                    // spend two slots later at `kW + W + 1` satisfied
                    // `W + 1 > W` and reset again — two full allowances inside
                    // a second, against a cap the granter wrote as one per
                    // window. Recording the spend's own slot makes the
                    // worst-case rate equal the nominal cap.
                    let (new_spent, new_last_reset) =
                        if current_slot.saturating_sub(last_reset) > window {
                            (sol_spent, current_slot)
                        } else {
                            (spent.saturating_add(sol_spent), last_reset)
                        };

                    write_u64(&mut session_data[abs_data_offset..], 8, new_spent);
                    write_u64(&mut session_data[abs_data_offset..], 24, new_last_reset);
                }
            },
            ActionType::TokenLimit => {
                let token_spent = mint_outflow(
                    mint_flows,
                    &session_data[abs_data_offset..abs_data_offset + 32],
                );

                if token_spent > 0 {
                    let remaining = read_u64(&session_data[abs_data_offset..], 32);
                    write_u64(
                        &mut session_data[abs_data_offset..],
                        32,
                        remaining.saturating_sub(token_spent),
                    );
                }
            },
            ActionType::TokenRecurringLimit => {
                let token_spent = mint_outflow(
                    mint_flows,
                    &session_data[abs_data_offset..abs_data_offset + 32],
                );

                if token_spent > 0 {
                    let spent = read_u64(&session_data[abs_data_offset..], 40);
                    let window = read_u64(&session_data[abs_data_offset..], 48);
                    let last_reset = read_u64(&session_data[abs_data_offset..], 56);

                    // Same fix as SolRecurringLimit above: restart the window at
                    // the spend that opened it, not at a grid boundary, so a
                    // spend landing late in a window cannot immediately open a
                    // second one.
                    let (new_spent, new_last_reset) =
                        if current_slot.saturating_sub(last_reset) > window {
                            (token_spent, current_slot)
                        } else {
                            (spent.saturating_add(token_spent), last_reset)
                        };

                    write_u64(&mut session_data[abs_data_offset..], 40, new_spent);
                    write_u64(&mut session_data[abs_data_offset..], 56, new_last_reset);
                }
            },
            _ => {}, // SolMaxPerTx, TokenMaxPerTx, whitelist/blacklist have no mutable state
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

// SPL program ids live in `crate::utils` (single source of truth, pinned by
// a test) — the Token-2022 constant was previously wrong here.
use crate::utils::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};

/// Whether any `Token*` action, expired or not, names `mint`.
fn names_mint(
    actions: &[ActionView],
    session_data: &[u8],
    loc: PolicyLocation,
    mint: &[u8; 32],
) -> bool {
    actions.iter().any(|a| {
        matches!(
            a.action_type,
            ActionType::TokenLimit | ActionType::TokenRecurringLimit | ActionType::TokenMaxPerTx
        ) && session_data[loc.abs(a.data_offset)..loc.abs(a.data_offset) + 32] == mint[..]
    })
}

/// The net outflow of `mint` over the snapshotted accounts; zero for a mint
/// the vault held no snapshotted account of.
fn mint_outflow(mint_flows: &[MintFlow], mint: &[u8]) -> u64 {
    mint_flows
        .iter()
        .find(|f| f.mint[..] == *mint)
        .map(MintFlow::outflow)
        .unwrap_or(0)
}

/// Fold one account's before/after balance into its mint's entry.
fn add_flow(flows: &mut Vec<MintFlow>, mint: [u8; 32], before: u64, after: u64) {
    match flows.iter_mut().find(|f| f.mint == mint) {
        Some(flow) => {
            flow.before = flow.before.saturating_add(before);
            flow.after = flow.after.saturating_add(after);
        },
        None => flows.push(MintFlow {
            mint,
            before,
            after,
        }),
    }
}

/// A writable, initialized token account whose owner field is the vault.
fn is_snapshot_candidate(acc: &AccountInfo, vault_key: &Pubkey) -> bool {
    if !acc.is_writable() {
        return false;
    }
    let data = unsafe { acc.borrow_data_unchecked() };
    is_token_account(acc.owner(), data)
        && data[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32] == vault_key[..]
}

/// Whether `accounts[i]` repeats an account listed earlier.
fn repeats_earlier(accounts: &[AccountInfo], i: usize) -> bool {
    let key = accounts[i].key();
    accounts[..i].iter().any(|a| a.key() == key)
}

/// Whether `data`, owned by `program`, is an initialized token account: not a
/// mint, not a multisig, not an account nobody has initialized.
///
/// An earlier reader accepted any token-program-owned account of 165 bytes or
/// more whose bytes 32..64 matched the vault. A 355-byte multisig's signer
/// keys are whatever its creator chose, and a Token-2022 mint with extensions
/// is longer than 165 bytes too, so neither length nor owner field was enough.
fn is_token_account(program: &Pubkey, data: &[u8]) -> bool {
    // Length and state first: one load each, and they rule out most accounts
    // in an Execute before any 32-byte comparison runs.
    if data.len() < TOKEN_ACCOUNT_LEN || !matches!(data[TOKEN_STATE_OFFSET], 1 | 2) {
        return false;
    }
    if data.len() == TOKEN_ACCOUNT_LEN {
        program == &SPL_TOKEN_PROGRAM_ID || program == &SPL_TOKEN_2022_PROGRAM_ID
    } else {
        program == &SPL_TOKEN_2022_PROGRAM_ID
            && data.len() != TOKEN_MULTISIG_LEN
            && data[TOKEN_ACCOUNT_TYPE_OFFSET] == TOKEN_2022_ACCOUNT_TYPE_ACCOUNT
    }
}

/// Every base field but `amount` is as it was, except that `delegated_amount`
/// may have fallen (an existing delegate spent some of its allowance, or the
/// owner lowered it).
///
/// Frozen: mint and owner (0..64); delegate, state and is_native (72..121);
/// close_authority (129..165). A raised `delegated_amount` is a re-`Approve`
/// of the same delegate for more, which leaves the delegate field untouched.
fn base_unchanged_except_balance(before: &[u8; TOKEN_ACCOUNT_LEN], after: &[u8]) -> bool {
    if after.len() < TOKEN_ACCOUNT_LEN {
        return false;
    }
    after[..TOKEN_AMOUNT_OFFSET] == before[..TOKEN_AMOUNT_OFFSET]
        && after[TOKEN_DELEGATE_OFFSET..TOKEN_DELEGATED_AMOUNT_OFFSET]
            == before[TOKEN_DELEGATE_OFFSET..TOKEN_DELEGATED_AMOUNT_OFFSET]
        && after[TOKEN_CLOSE_AUTHORITY_OFFSET..TOKEN_ACCOUNT_LEN]
            == before[TOKEN_CLOSE_AUTHORITY_OFFSET..TOKEN_ACCOUNT_LEN]
        && read_u64(after, TOKEN_DELEGATED_AMOUNT_OFFSET)
            <= read_u64(before, TOKEN_DELEGATED_AMOUNT_OFFSET)
}

/// A token account's lamports fell only with a matching fall in a native
/// (wSOL) account's `amount`. A non-native account's lamports are its rent and
/// any excess, and neither may leave: `WithdrawExcessLamports` would otherwise
/// move vault SOL that no SOL action sees.
fn lamports_kept(
    before_lamports: u64,
    before: &[u8; TOKEN_ACCOUNT_LEN],
    after_lamports: u64,
    after: &[u8],
) -> bool {
    let drop = before_lamports.saturating_sub(after_lamports);
    if drop == 0 {
        return true;
    }
    let is_native = before[TOKEN_IS_NATIVE_OFFSET..TOKEN_IS_NATIVE_OFFSET + COPTION_TAG_LEN]
        != [0u8; COPTION_TAG_LEN];
    is_native
        && drop
            <= read_u64(before, TOKEN_AMOUNT_OFFSET)
                .saturating_sub(read_u64(after, TOKEN_AMOUNT_OFFSET))
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::action::ACTION_HEADER_SIZE;
    use crate::state::session::SESSION_HEADER_SIZE;

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
        data[0] = crate::state::AccountDiscriminator::Session as u8;
        data.extend_from_slice(actions);
        data
    }

    /// Test helper: calls evaluate_post_actions with gross_out = before - after (single CPI).
    fn eval_post(
        session_data: &mut [u8],
        before: u64,
        after: u64,
        mint_flows: &[MintFlow],
        slot: u64,
    ) -> Result<(), ProgramError> {
        let gross = before.saturating_sub(after);
        let loc = PolicyLocation::of(session_data).expect("session data resolves");
        evaluate_post_actions(session_data, loc, before, after, gross, mint_flows, slot)
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
        session_data[0] = crate::state::AccountDiscriminator::Session as u8;
        let result = eval_post(&mut session_data, 10_000_000, 0, &[], 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_spending_no_state_change() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);
        let original = session_data.clone();

        // vault gained lamports (before < after) → sol_spent = 0
        let result = eval_post(
            &mut session_data,
            1_000_000,
            2_000_000, // vault gained 1M
            &[],
            100,
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

        let result = eval_post(
            &mut session_data,
            1_000_000,
            5_000_000, // gained 4M
            &[],
            100,
        );
        assert!(result.is_ok()); // No violation, gains are ignored
    }

    // ─── SolLimit ─────────────────────────────────────────────────

    #[test]
    fn test_sol_limit_exact_remaining() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Spend exactly the remaining amount — should succeed
        let result = eval_post(
            &mut session_data,
            2_000_000,
            1_000_000, // spent exactly 1M
            &[],
            100,
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
        let result = eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 100);
        assert!(result.is_ok());

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 400_000);

        // Tx 2: spend 400k (exact remaining) — OK
        let result = eval_post(&mut session_data, 1_400_000, 1_000_000, &[], 101);
        assert!(result.is_ok());
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 0);

        // Tx 3: spend 1 lamport — should fail (0 remaining)
        let result = eval_post(&mut session_data, 1_000_000, 999_999, &[], 102);
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_limit_single_overspend() {
        let actions = build_action(1, 0, &1_000_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Try to spend 1M + 1 — should fail
        let result = eval_post(
            &mut session_data,
            2_000_000,
            999_999, // spent 1_000_001
            &[],
            100,
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
        let result = eval_post(&mut session_data, 2_000_000, 1_500_000, &[], 100);
        assert!(result.is_ok());

        // Exceed by 1 — fail
        let result = eval_post(&mut session_data, 2_000_000, 1_499_999, &[], 101);
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_max_per_tx_repeatable() {
        // MaxPerTx does NOT accumulate — each tx is independent
        let actions = build_action(3, 0, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        for slot in 100..110 {
            let result = eval_post(
                &mut session_data,
                2_000_000,
                1_500_000, // 500k each time
                &[],
                slot,
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
        let result = eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 50);
        assert!(result.is_ok());

        // Spend 500k more at slot 60 — total 1.1M > 1M limit
        let result = eval_post(&mut session_data, 1_400_000, 900_000, &[], 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_recurring_limit_window_reset() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend 900k at slot 50
        eval_post(&mut session_data, 2_000_000, 1_100_000, &[], 50).unwrap();

        // At slot 150 (after window), 500k should work again
        let result = eval_post(&mut session_data, 1_100_000, 600_000, &[], 150);
        assert!(result.is_ok());

        // The new window starts at the spend that opened it, not at the grid
        // boundary below it. Snapping back to 100 here would leave the window
        // half spent already, so the next spend at 201 would reset a second
        // time — two full allowances inside one nominal window.
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        let last_reset = read_u64(&session_data[abs_offset..], 24);
        assert_eq!(last_reset, 150);
    }

    /// The window may not restart twice in quick succession. With a grid-aligned
    /// reset, a spend landing at the end of a window pinned `last_reset` to the
    /// window's start, so a spend two slots later cleared `> window` again and
    /// the cap was worth double what the granter wrote.
    #[test]
    fn test_sol_recurring_limit_cannot_double_reset_across_a_boundary() {
        // limit 1 SOL per 100-slot window.
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend the full allowance late in the first window (slot 199).
        eval_post(&mut session_data, 5_000_000, 4_000_000, &[], 199)
            .expect("first window's allowance");

        // Two slots later the old code reset again (199 -> aligned 100, and
        // 201 - 100 = 101 > 100). It must not: only 2 slots of a 100-slot
        // window have elapsed.
        let result = eval_post(&mut session_data, 4_000_000, 3_000_000, &[], 201);
        assert!(
            result.is_err(),
            "a second full allowance 2 slots later must be refused"
        );

        // A spend past the real window boundary is allowed again.
        eval_post(&mut session_data, 4_000_000, 3_000_000, &[], 300)
            .expect("the window genuinely elapsed");
    }

    #[test]
    fn test_sol_recurring_single_tx_exceeds_full_limit_after_reset() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // At slot 150 (fresh window), try to spend more than the full limit
        let result = eval_post(
            &mut session_data,
            5_000_000,
            3_500_000, // 1.5M > 1M limit
            &[],
            150,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sol_recurring_exact_limit_in_window() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let actions = build_action(2, 0, &data);
        let mut session_data = build_session_data(&actions);

        // Spend exactly the limit
        let result = eval_post(&mut session_data, 2_000_000, 1_000_000, &[], 50);
        assert!(result.is_ok());

        // Spend 1 more in same window — fail
        let result = eval_post(&mut session_data, 1_000_000, 999_999, &[], 60);
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
        let result = eval_post(
            &mut session_data,
            1_000_000,
            999_800, // spent 200
            &[],
            50,
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
        let result = eval_post(&mut session_data, 5_000_000, 4_600_000, &[], 100);
        assert!(result.is_ok());

        // 600k — under lifetime (1.6M left) but over per-tx (500k)
        let result = eval_post(&mut session_data, 4_600_000, 4_000_000, &[], 101);
        assert!(result.is_err());
    }

    #[test]
    fn test_combined_recurring_and_max_per_tx() {
        let mut actions_buf = Vec::new();
        // SolRecurringLimit: 1M per 100 slots
        actions_buf.extend_from_slice(&build_action(
            2,
            0,
            &build_sol_recurring(1_000_000, 0, 100, 0),
        ));
        // SolMaxPerTx: 300k per tx
        actions_buf.extend_from_slice(&build_action(3, 0, &300_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);

        // 200k — OK
        eval_post(&mut session_data, 5_000_000, 4_800_000, &[], 50).unwrap();

        // 200k more — OK (400k total in window, under 1M; 200k under 300k per-tx)
        eval_post(&mut session_data, 4_800_000, 4_600_000, &[], 60).unwrap();

        // 350k — fails per-tx (350k > 300k) even though recurring has room
        let result = eval_post(&mut session_data, 4_600_000, 4_250_000, &[], 70);
        assert!(result.is_err());
    }

    // ─── Action expiry ────────────────────────────────────────────

    #[test]
    fn test_expired_action_blocks_spending() {
        // Expired spending limits are treated as fully exhausted (not skipped).
        let actions = build_action(3, 50, &500_000u64.to_le_bytes()); // Expires at slot 50
        let mut session_data = build_session_data(&actions);

        // At slot 100, action expired — any spend should FAIL
        let result = eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 100);
        assert!(result.is_err());

        // Zero spending is still OK even with expired action
        let result = eval_post(&mut session_data, 2_000_000, 2_000_000, &[], 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_action_active_at_expiry_slot() {
        // Action expires at slot 50. At exactly slot 50 it should still be active.
        // Only expired when current_slot > expires_at.
        let actions = build_action(3, 50, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // At slot 50 — still active, 600k > 500k → fail
        let result = eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 50);
        assert!(result.is_err());

        // At slot 51 — expired, any spend → also fail (expired = exhausted)
        let result = eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 51);
        assert!(result.is_err());
    }

    #[test]
    fn test_mixed_expired_and_active_actions() {
        let mut actions_buf = Vec::new();
        // SolMaxPerTx: 500k, expires at slot 50
        actions_buf.extend_from_slice(&build_action(3, 50, &500_000u64.to_le_bytes()));
        // SolLimit: 2M, never expires
        actions_buf.extend_from_slice(&build_action(1, 0, &2_000_000u64.to_le_bytes()));

        let mut session_data = build_session_data(&actions_buf);

        // At slot 100: MaxPerTx expired → any spend blocked by expired MaxPerTx
        let result = eval_post(&mut session_data, 5_000_000, 2_000_000, &[], 100);
        assert!(result.is_err());

        // Even 1 lamport fails because expired MaxPerTx blocks all spending
        let result = eval_post(&mut session_data, 5_000_000, 4_999_999, &[], 100);
        assert!(result.is_err());

        // Zero spend is OK
        let result = eval_post(&mut session_data, 5_000_000, 5_000_000, &[], 100);
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
        let result = eval_post(&mut session_data, 5_000_000, 4_500_000, &[], 100);
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
        eval_post(&mut session_data, 2_000_000, 1_700_000, &[], 50).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 300_000); // spent
        assert_eq!(read_u64(&session_data[abs_offset..], 24), 0); // last_reset (first window)

        // Spend 200k at slot 60
        eval_post(&mut session_data, 1_700_000, 1_500_000, &[], 60).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 500_000); // cumulative

        // Window reset at slot 200
        eval_post(&mut session_data, 1_500_000, 1_300_000, &[], 200).unwrap();

        assert_eq!(read_u64(&session_data[abs_offset..], 8), 200_000); // reset + new spend
        assert_eq!(read_u64(&session_data[abs_offset..], 24), 200); // aligned: (200/100)*100
    }

    // ─── Edge: zero limit ─────────────────────────────────────────

    #[test]
    fn test_zero_sol_limit_blocks_all_spending() {
        let actions = build_action(1, 0, &0u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Even 1 lamport should fail
        let result = eval_post(&mut session_data, 1_000_000, 999_999, &[], 100);
        assert!(result.is_err());

        // But zero spending is OK
        let result = eval_post(&mut session_data, 1_000_000, 1_000_000, &[], 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_max_per_tx_blocks_all_spending() {
        let actions = build_action(3, 0, &0u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        let result = eval_post(&mut session_data, 1_000_000, 999_999, &[], 100);
        assert!(result.is_err());

        let result = eval_post(&mut session_data, 1_000_000, 1_000_000, &[], 100);
        assert!(result.is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // Token spending limit tests
    // ══════════════════════════════════════════════════════════════════
    //
    // Token tests pass a `MintFlow` with `after: 0`, meaning "all tokens
    // drained": `before` is the amount that left the snapshotted accounts.

    fn build_token_limit(mint: &[u8; 32], remaining: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(mint); // [0..32]
        data.extend_from_slice(&remaining.to_le_bytes()); // [32..40]
        data
    }

    fn build_token_max_per_tx(mint: &[u8; 32], max: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(mint);
        data.extend_from_slice(&max.to_le_bytes());
        data
    }

    fn build_token_recurring(
        mint: &[u8; 32],
        limit: u64,
        spent: u64,
        window: u64,
        last_reset: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(mint); // [0..32]
        data.extend_from_slice(&limit.to_le_bytes()); // [32..40]
        data.extend_from_slice(&spent.to_le_bytes()); // [40..48]
        data.extend_from_slice(&window.to_le_bytes()); // [48..56]
        data.extend_from_slice(&last_reset.to_le_bytes()); // [56..64]
        data
    }

    // ── TokenLimit ───────────────────────────────────────────────────

    #[test]
    fn test_token_limit_within_budget() {
        let mint = [0xAA; 32];
        let actions = build_action(4, 0, &build_token_limit(&mint, 1_000_000));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 500_000,
            after: 0,
        }];

        // accounts=[] → after=0, token_spent=500_000, within 1M limit
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_ok());

        // Verify remaining was decremented
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        let remaining = read_u64(&session_data[abs_offset..], 32);
        assert_eq!(remaining, 500_000);
    }

    #[test]
    fn test_token_limit_exceeds_budget() {
        let mint = [0xBB; 32];
        let actions = build_action(4, 0, &build_token_limit(&mint, 100_000));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 200_000,
            after: 0,
        }];

        // token_spent=200k > remaining=100k → fail
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_limit_exact_budget() {
        let mint = [0xCC; 32];
        let actions = build_action(4, 0, &build_token_limit(&mint, 500_000));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 500_000,
            after: 0,
        }];

        // token_spent = exactly remaining → OK
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_ok());

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 32), 0);
    }

    #[test]
    fn test_token_limit_depletes_across_txs() {
        let mint = [0xDD; 32];
        let actions = build_action(4, 0, &build_token_limit(&mint, 1_000_000));
        let mut session_data = build_session_data(&actions);

        // Tx 1: drain 600k
        let s1 = vec![MintFlow {
            mint,
            before: 600_000,
            after: 0,
        }];
        eval_post(&mut session_data, 0, 0, &s1, 100).unwrap();

        // remaining = 400k
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 32), 400_000);

        // Tx 2: drain 400k → exact
        let s2 = vec![MintFlow {
            mint,
            before: 400_000,
            after: 0,
        }];
        eval_post(&mut session_data, 0, 0, &s2, 101).unwrap();
        assert_eq!(read_u64(&session_data[abs_offset..], 32), 0);

        // Tx 3: drain 1 → fail
        let s3 = vec![MintFlow {
            mint,
            before: 1,
            after: 0,
        }];
        let result = eval_post(&mut session_data, 0, 0, &s3, 102);
        assert!(result.is_err());
    }

    // ── TokenMaxPerTx ───────────────────────────────────────────────

    #[test]
    fn test_token_max_per_tx_within_limit() {
        let mint = [0xEE; 32];
        let actions = build_action(6, 0, &build_token_max_per_tx(&mint, 500_000));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 300_000,
            after: 0,
        }];

        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_max_per_tx_exceeds() {
        let mint = [0xFF; 32];
        let actions = build_action(6, 0, &build_token_max_per_tx(&mint, 500_000));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 600_000,
            after: 0,
        }];

        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_max_per_tx_repeatable() {
        // MaxPerTx has no cumulative state — repeated spends within limit all pass
        let mint = [0x11; 32];
        let actions = build_action(6, 0, &build_token_max_per_tx(&mint, 500_000));
        let mut session_data = build_session_data(&actions);

        for slot in 100..105 {
            let snapshots = vec![MintFlow {
                mint,
                before: 500_000,
                after: 0,
            }];
            let result = eval_post(&mut session_data, 0, 0, &snapshots, slot);
            assert!(result.is_ok());
        }
    }

    // ── TokenRecurringLimit ─────────────────────────────────────────

    #[test]
    fn test_token_recurring_basic() {
        let mint = [0x22; 32];
        let actions = build_action(5, 0, &build_token_recurring(&mint, 1_000_000, 0, 100, 0));
        let mut session_data = build_session_data(&actions);

        // Spend 600k at slot 50 — OK
        let s1 = vec![MintFlow {
            mint,
            before: 600_000,
            after: 0,
        }];
        eval_post(&mut session_data, 0, 0, &s1, 50).unwrap();

        // Spend 500k more at slot 60 → total 1.1M > 1M limit → fail
        let s2 = vec![MintFlow {
            mint,
            before: 500_000,
            after: 0,
        }];
        let result = eval_post(&mut session_data, 0, 0, &s2, 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_recurring_window_reset() {
        let mint = [0x33; 32];
        let actions = build_action(5, 0, &build_token_recurring(&mint, 1_000_000, 0, 100, 0));
        let mut session_data = build_session_data(&actions);

        // Spend 900k at slot 50
        let s1 = vec![MintFlow {
            mint,
            before: 900_000,
            after: 0,
        }];
        eval_post(&mut session_data, 0, 0, &s1, 50).unwrap();

        // At slot 150 (after window), spending resets → 500k OK
        let s2 = vec![MintFlow {
            mint,
            before: 500_000,
            after: 0,
        }];
        let result = eval_post(&mut session_data, 0, 0, &s2, 150);
        assert!(result.is_ok());
    }

    // ── Expired token limits ─────────────────────────────────────────

    #[test]
    fn test_expired_token_limit_blocks_spending() {
        let mint = [0x44; 32];
        let actions = build_action(4, 50, &build_token_limit(&mint, 1_000_000)); // expires at slot 50
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 100,
            after: 0,
        }];

        // At slot 100 (expired), any token spend → fail
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token_max_per_tx_blocks_spending() {
        let mint = [0x55; 32];
        let actions = build_action(6, 50, &build_token_max_per_tx(&mint, 1_000_000)); // expires at 50
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 1,
            after: 0,
        }];

        // Expired → even 1 token blocked
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token_recurring_blocks_spending() {
        let mint = [0x66; 32];
        let actions = build_action(5, 50, &build_token_recurring(&mint, 1_000_000, 0, 100, 0));
        let mut session_data = build_session_data(&actions);
        let snapshots = vec![MintFlow {
            mint,
            before: 1,
            after: 0,
        }];

        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    // ── Multiple mint limits ────────────────────────────────────────

    #[test]
    fn test_multiple_mints_independent() {
        let mint_a = [0xAA; 32];
        let mint_b = [0xBB; 32];
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint_a, 100_000)));
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint_b, 500_000)));
        let mut session_data = build_session_data(&actions_buf);

        // Drain mint_a within its limit, drain mint_b within its limit
        let snapshots = vec![
            MintFlow {
                mint: mint_a,
                before: 50_000,
                after: 0,
            },
            MintFlow {
                mint: mint_b,
                before: 400_000,
                after: 0,
            },
        ];
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_mints_one_exceeds() {
        let mint_a = [0xAA; 32];
        let mint_b = [0xBB; 32];
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint_a, 100_000)));
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint_b, 500_000)));
        let mut session_data = build_session_data(&actions_buf);

        // mint_a: 50k OK, mint_b: 600k > 500k → fail
        let snapshots = vec![
            MintFlow {
                mint: mint_a,
                before: 50_000,
                after: 0,
            },
            MintFlow {
                mint: mint_b,
                before: 600_000,
                after: 0,
            },
        ];
        let result = eval_post(&mut session_data, 0, 0, &snapshots, 100);
        assert!(result.is_err());
    }

    // ── Combined SOL + Token limits ─────────────────────────────────

    #[test]
    fn test_combined_sol_and_token_limits() {
        let mint = [0xCC; 32];
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(1, 0, &1_000_000u64.to_le_bytes())); // SolLimit: 1M
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint, 500_000))); // TokenLimit: 500k
        let mut session_data = build_session_data(&actions_buf);

        let snapshots = vec![MintFlow {
            mint,
            before: 300_000,
            after: 0,
        }];

        // SOL: 200k spent (under 1M), Token: 300k spent (under 500k) → OK
        let result = eval_post(&mut session_data, 1_000_000, 800_000, &snapshots, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_combined_sol_ok_token_exceeds() {
        let mint = [0xDD; 32];
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(1, 0, &10_000_000u64.to_le_bytes())); // SolLimit: 10M
        actions_buf.extend_from_slice(&build_action(4, 0, &build_token_limit(&mint, 100_000))); // TokenLimit: 100k
        let mut session_data = build_session_data(&actions_buf);

        let snapshots = vec![MintFlow {
            mint,
            before: 200_000,
            after: 0,
        }];

        // SOL: 500k spent (under 10M), Token: 200k > 100k → fail
        let result = eval_post(&mut session_data, 5_000_000, 4_500_000, &snapshots, 100);
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // Gross outflow tests (SolMaxPerTx uses gross, not net)
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_sol_max_per_tx_gross_vs_net() {
        // SolMaxPerTx = 1 SOL. A DeFi swap sends 10 SOL out and receives 9.5 back.
        // Net = 0.5 SOL (would pass if using net), Gross = 10 SOL (must fail).
        let actions = build_action(3, 0, &1_000_000_000u64.to_le_bytes()); // 1 SOL max
        let mut session_data = build_session_data(&actions);

        // before=20 SOL, after=19.5 SOL → net = 0.5 SOL
        // But gross = 10 SOL (passed explicitly)
        let loc = PolicyLocation::of(&session_data).expect("session data resolves");
        let result = evaluate_post_actions(
            &mut session_data,
            loc,
            20_000_000_000,
            19_500_000_000,
            10_000_000_000, // gross = 10 SOL
            &[],
            100,
        );
        assert!(result.is_err()); // 10 SOL gross > 1 SOL max → fail
    }

    #[test]
    fn test_sol_max_per_tx_gross_within_limit() {
        let actions = build_action(3, 0, &5_000_000_000u64.to_le_bytes()); // 5 SOL max
        let mut session_data = build_session_data(&actions);

        // Gross = 3 SOL, net = 1 SOL
        let loc = PolicyLocation::of(&session_data).expect("session data resolves");
        let result = evaluate_post_actions(
            &mut session_data,
            loc,
            20_000_000_000,
            19_000_000_000,
            3_000_000_000, // gross = 3 SOL
            &[],
            100,
        );
        assert!(result.is_ok()); // 3 SOL gross < 5 SOL max → OK
    }

    #[test]
    fn test_sol_limit_uses_net_not_gross() {
        // SolLimit (cumulative) should use net, not gross.
        // A round-trip that returns most lamports shouldn't deplete the budget.
        let actions = build_action(1, 0, &2_000_000_000u64.to_le_bytes()); // 2 SOL limit
        let mut session_data = build_session_data(&actions);

        // net = 0.5 SOL, gross = 10 SOL
        let loc = PolicyLocation::of(&session_data).expect("session data resolves");
        let result = evaluate_post_actions(
            &mut session_data,
            loc,
            20_000_000_000,
            19_500_000_000,
            10_000_000_000,
            &[],
            100,
        );
        assert!(result.is_ok()); // SolLimit uses net: 0.5 SOL < 2 SOL → OK

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        let remaining = read_u64(&session_data[abs_offset..], 0);
        assert_eq!(remaining, 1_500_000_000); // 2 SOL - 0.5 SOL net
    }

    // ══════════════════════════════════════════════════════════════════
    // Attacker pattern tests
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_attacker_all_limits_expired_session_locked() {
        // Attacker scenario: create a session with a short-lived SolLimit.
        // After expiry, the session should be locked — not unrestricted.
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(1, 50, &1_000_000u64.to_le_bytes())); // SolLimit, expires at 50
        actions_buf.extend_from_slice(&build_action(3, 50, &500_000u64.to_le_bytes())); // SolMaxPerTx, expires at 50
        let mut session_data = build_session_data(&actions_buf);

        // At slot 100 (both expired), even 1 lamport spend is blocked
        let result = eval_post(&mut session_data, 1_000_000, 999_999, &[], 100);
        assert!(result.is_err());

        // Zero spend still OK
        let result = eval_post(&mut session_data, 1_000_000, 1_000_000, &[], 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attacker_expired_token_and_sol_limits() {
        // All limits expired — both SOL and token spending blocked
        let mint = [0xFF; 32];
        let mut actions_buf = Vec::new();
        actions_buf.extend_from_slice(&build_action(1, 50, &1_000_000u64.to_le_bytes()));
        actions_buf.extend_from_slice(&build_action(4, 50, &build_token_limit(&mint, 500_000)));
        let mut session_data = build_session_data(&actions_buf);

        // SOL spend → blocked
        let result = eval_post(&mut session_data, 1_000_000, 999_000, &[], 100);
        assert!(result.is_err());

        // Token spend → blocked
        let snapshots = vec![MintFlow {
            mint,
            before: 100,
            after: 0,
        }];
        let result = eval_post(
            &mut session_data,
            1_000_000,
            1_000_000, // no SOL change
            &snapshots,
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_attacker_u64_max_overflow() {
        // Attacker tries u64::MAX as remaining — should not cause overflow
        let actions = build_action(1, 0, &u64::MAX.to_le_bytes());
        let mut session_data = build_session_data(&actions);

        // Spend u64::MAX → should succeed (exact match)
        let result = eval_post(&mut session_data, u64::MAX, 0, &[], 100);
        assert!(result.is_ok());

        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 0), 0);
    }

    #[test]
    fn test_no_token_snapshot_means_no_change() {
        // If a token mint has a limit but no snapshotted account, token_spent = 0
        let mint = [0xAA; 32];
        let actions = build_action(4, 0, &build_token_limit(&mint, 1_000_000));
        let mut session_data = build_session_data(&actions);

        // No flows → before=0, after=0 → spent=0 → OK
        let result = eval_post(&mut session_data, 0, 0, &[], 100);
        assert!(result.is_ok());
    }

    // ══════════════════════════════════════════════════════════════════
    // Assets the policy does not name (D13)
    // ══════════════════════════════════════════════════════════════════

    fn custom_code(result: Result<(), ProgramError>) -> Option<u32> {
        match result {
            Err(ProgramError::Custom(code)) => Some(code),
            _ => None,
        }
    }

    const ERR_UNLISTED_SOL: u32 = AuthError::ActionUnlistedSolOutflow as u32;
    const ERR_UNLISTED_TOKEN: u32 = AuthError::ActionUnlistedTokenOutflow as u32;
    const ERR_TOKEN_LIMIT: u32 = AuthError::ActionTokenLimitExceeded as u32;

    fn whitelist_only() -> Vec<u8> {
        build_action(10, 0, &[0x77; 32])
    }

    fn flow(mint: [u8; 32], before: u64, after: u64) -> MintFlow {
        MintFlow {
            mint,
            before,
            after,
        }
    }

    #[test]
    fn unlisted_sol_outflow_rejected() {
        let mut session_data = build_session_data(&whitelist_only());
        let original = session_data.clone();
        let result = eval_post(&mut session_data, 2_000_000, 1_999_999, &[], 100);
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_SOL));
        assert_eq!(session_data, original);
    }

    #[test]
    fn unlisted_sol_inflow_ok() {
        let mut session_data = build_session_data(&whitelist_only());
        assert!(eval_post(&mut session_data, 1_000_000, 3_000_000, &[], 100).is_ok());
        assert!(eval_post(&mut session_data, 1_000_000, 1_000_000, &[], 100).is_ok());
    }

    /// A per-transaction cap alone names SOL: it was written to bound SOL, so
    /// the unlisted rule does not stack on top of it.
    #[test]
    fn sol_max_per_tx_alone_names_sol() {
        let actions = build_action(3, 0, &500_000u64.to_le_bytes());
        let mut session_data = build_session_data(&actions);
        assert!(eval_post(&mut session_data, 2_000_000, 1_500_000, &[], 100).is_ok());
        assert_eq!(
            custom_code(eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 100)),
            Some(AuthError::ActionSolMaxPerTxExceeded as u32)
        );
    }

    #[test]
    fn sol_recurring_alone_names_sol() {
        let data = build_sol_recurring(1_000_000, 0, 100, 0);
        let mut session_data = build_session_data(&build_action(2, 0, &data));
        assert!(eval_post(&mut session_data, 2_000_000, 1_400_000, &[], 50).is_ok());
    }

    #[test]
    fn unlisted_mint_outflow_rejected() {
        let listed = [0xAA; 32];
        let unlisted = [0xBB; 32];
        let mut actions = whitelist_only();
        actions.extend_from_slice(&build_action(4, 0, &build_token_limit(&listed, 1_000)));
        let mut session_data = build_session_data(&actions);
        let result = eval_post(&mut session_data, 0, 0, &[flow(unlisted, 10, 9)], 100);
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_TOKEN));
    }

    #[test]
    fn unlisted_mint_inflow_ok() {
        let mut session_data = build_session_data(&whitelist_only());
        let flows = [flow([0xBB; 32], 10, 500)];
        assert!(eval_post(&mut session_data, 0, 0, &flows, 100).is_ok());
    }

    /// Net per mint: moving an unlisted mint between two vault accounts, or
    /// sending some out and getting as much back, leaves the balance where it
    /// was.
    #[test]
    fn unlisted_mint_net_zero_ok() {
        let mut session_data = build_session_data(&whitelist_only());
        let flows = [flow([0xBB; 32], 700, 700)];
        assert!(eval_post(&mut session_data, 0, 0, &flows, 100).is_ok());
    }

    /// An expired limit still names its mint; it is an exhausted limit, not an
    /// absent one, so the error is the limit's.
    #[test]
    fn expired_token_action_still_names_mint() {
        let mint = [0x44; 32];
        let actions = build_action(4, 50, &build_token_limit(&mint, 1_000_000));
        let mut session_data = build_session_data(&actions);
        let result = eval_post(&mut session_data, 0, 0, &[flow(mint, 100, 0)], 100);
        assert_eq!(custom_code(result), Some(ERR_TOKEN_LIMIT));
    }

    #[test]
    fn listed_and_unlisted_outflow_reports_listed_first_when_over_limit() {
        let listed = [0xAA; 32];
        let unlisted = [0xBB; 32];
        let actions = build_action(4, 0, &build_token_limit(&listed, 10));
        let mut session_data = build_session_data(&actions);
        let flows = [flow(unlisted, 5, 0), flow(listed, 11, 0)];
        assert_eq!(
            custom_code(eval_post(&mut session_data, 0, 0, &flows, 100)),
            Some(ERR_TOKEN_LIMIT)
        );

        // Within the listed limit, the unlisted outflow is what fails.
        let flows = [flow(listed, 10, 0), flow(unlisted, 5, 0)];
        assert_eq!(
            custom_code(eval_post(&mut session_data, 0, 0, &flows, 100)),
            Some(ERR_UNLISTED_TOKEN)
        );
    }

    /// The unlisted checks run before Phase 2, so a listed spend that would
    /// otherwise be charged is not written when an unlisted asset left too.
    #[test]
    fn no_state_written_when_unlisted_check_fails() {
        let listed = [0xAA; 32];
        let mut actions = build_action(4, 0, &build_token_limit(&listed, 1_000));
        actions.extend_from_slice(&whitelist_only());
        let mut session_data = build_session_data(&actions);
        let original = session_data.clone();

        // Listed spend within its limit, plus SOL with no SOL action.
        let result = eval_post(
            &mut session_data,
            5_000,
            4_000,
            &[flow(listed, 100, 0)],
            100,
        );
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_SOL));
        assert_eq!(session_data, original);

        // Listed spend within its limit, plus an unlisted mint.
        let flows = [flow(listed, 100, 0), flow([0xBB; 32], 1, 0)];
        let result = eval_post(&mut session_data, 0, 0, &flows, 100);
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_TOKEN));
        assert_eq!(session_data, original);

        // The listed spend alone is charged.
        eval_post(&mut session_data, 0, 0, &[flow(listed, 100, 0)], 100).unwrap();
        let abs_offset = SESSION_HEADER_SIZE + ACTION_HEADER_SIZE;
        assert_eq!(read_u64(&session_data[abs_offset..], 32), 900);
    }

    /// wSOL is a mint; a SOL action does not name it, and a token action on
    /// wSOL does not name SOL.
    #[test]
    fn sol_and_wsol_are_separate_assets() {
        let wsol = [0x06; 32];
        let mut session_data = build_session_data(&build_action(1, 0, &u64::MAX.to_le_bytes()));
        let result = eval_post(&mut session_data, 0, 0, &[flow(wsol, 10, 0)], 100);
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_TOKEN));

        let mut session_data =
            build_session_data(&build_action(4, 0, &build_token_limit(&wsol, u64::MAX)));
        let result = eval_post(&mut session_data, 10, 0, &[], 100);
        assert_eq!(custom_code(result), Some(ERR_UNLISTED_SOL));
    }

    #[test]
    fn add_flow_folds_per_mint_without_cross_mint_netting() {
        let mut flows = Vec::new();
        add_flow(&mut flows, [1; 32], 100, 40);
        add_flow(&mut flows, [2; 32], 0, 500);
        add_flow(&mut flows, [1; 32], 0, 60);
        add_flow(&mut flows, [1; 32], u64::MAX, 0);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].before, u64::MAX);
        assert_eq!(flows[0].after, 100);
        assert_eq!(flows[1].outflow(), 0);
    }

    // ── Token account classification and the per-field freeze ─────────

    fn token_account_bytes(len: usize, state: u8) -> Vec<u8> {
        let mut data = vec![0u8; len];
        data[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32].copy_from_slice(&[0x11; 32]);
        data[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32].copy_from_slice(&[0x22; 32]);
        data[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8].copy_from_slice(&1_000u64.to_le_bytes());
        data[TOKEN_STATE_OFFSET] = state;
        data
    }

    #[test]
    fn classifier_accepts_only_initialized_token_accounts() {
        let legacy = &SPL_TOKEN_PROGRAM_ID;
        let t22 = &SPL_TOKEN_2022_PROGRAM_ID;

        assert!(is_token_account(legacy, &token_account_bytes(165, 1)));
        assert!(
            is_token_account(legacy, &token_account_bytes(165, 2)),
            "frozen"
        );
        assert!(
            !is_token_account(legacy, &token_account_bytes(165, 0)),
            "uninitialized"
        );
        assert!(
            !is_token_account(legacy, &token_account_bytes(170, 1)),
            "legacy is 165 only"
        );
        assert!(
            !is_token_account(legacy, &token_account_bytes(355, 1)),
            "multisig"
        );
        assert!(!is_token_account(legacy, &[0u8; 82]), "mint");

        assert!(is_token_account(t22, &token_account_bytes(165, 1)));
        let mut ext = token_account_bytes(170, 1);
        ext[TOKEN_ACCOUNT_TYPE_OFFSET] = TOKEN_2022_ACCOUNT_TYPE_ACCOUNT;
        assert!(
            is_token_account(t22, &ext),
            "Token-2022 account with an extension"
        );
        let mut mint = token_account_bytes(278, 1);
        mint[TOKEN_ACCOUNT_TYPE_OFFSET] = 1;
        assert!(
            !is_token_account(t22, &mint),
            "Token-2022 mint with extensions"
        );
        let mut multisig = token_account_bytes(355, 1);
        multisig[TOKEN_ACCOUNT_TYPE_OFFSET] = TOKEN_2022_ACCOUNT_TYPE_ACCOUNT;
        assert!(!is_token_account(t22, &multisig), "355 bytes is a multisig");

        assert!(
            !is_token_account(&[9u8; 32], &token_account_bytes(165, 1)),
            "other program"
        );
    }

    fn base_of(data: &[u8]) -> [u8; TOKEN_ACCOUNT_LEN] {
        let mut base = [0u8; TOKEN_ACCOUNT_LEN];
        base.copy_from_slice(&data[..TOKEN_ACCOUNT_LEN]);
        base
    }

    #[test]
    fn base_unchanged_except_balance_freezes_every_field_but_amount() {
        let mut before = token_account_bytes(165, 1);
        before[TOKEN_DELEGATED_AMOUNT_OFFSET..TOKEN_DELEGATED_AMOUNT_OFFSET + 8]
            .copy_from_slice(&10u64.to_le_bytes());
        let base = base_of(&before);

        assert!(base_unchanged_except_balance(&base, &before));

        let mut amount = before.clone();
        amount[TOKEN_AMOUNT_OFFSET] = 0;
        assert!(
            base_unchanged_except_balance(&base, &amount),
            "amount is free"
        );

        // (offset, field) — one byte flipped in each frozen field.
        for (offset, field) in [
            (TOKEN_MINT_OFFSET, "mint"),
            (TOKEN_OWNER_OFFSET + 31, "owner"),
            (TOKEN_DELEGATE_OFFSET, "delegate tag"),
            (TOKEN_DELEGATE_OFFSET + 4, "delegate key"),
            (TOKEN_STATE_OFFSET, "state"),
            (TOKEN_IS_NATIVE_OFFSET, "is_native tag"),
            (TOKEN_IS_NATIVE_OFFSET + 4, "is_native reserve"),
            (TOKEN_CLOSE_AUTHORITY_OFFSET, "close_authority tag"),
            (TOKEN_CLOSE_AUTHORITY_OFFSET + 35, "close_authority key"),
        ] {
            let mut after = before.clone();
            after[offset] ^= 0xFF;
            assert!(!base_unchanged_except_balance(&base, &after), "{field}");
        }

        let mut up = before.clone();
        up[TOKEN_DELEGATED_AMOUNT_OFFSET..TOKEN_DELEGATED_AMOUNT_OFFSET + 8]
            .copy_from_slice(&11u64.to_le_bytes());
        assert!(
            !base_unchanged_except_balance(&base, &up),
            "delegated_amount up"
        );

        let mut down = before.clone();
        down[TOKEN_DELEGATED_AMOUNT_OFFSET..TOKEN_DELEGATED_AMOUNT_OFFSET + 8]
            .copy_from_slice(&9u64.to_le_bytes());
        assert!(
            base_unchanged_except_balance(&base, &down),
            "delegated_amount down"
        );

        assert!(
            !base_unchanged_except_balance(&base, &before[..164]),
            "truncated"
        );
    }

    #[test]
    fn lamports_kept_allows_only_a_native_unwrap() {
        let plain = token_account_bytes(165, 1);
        let base = base_of(&plain);
        assert!(lamports_kept(2_000, &base, 2_000, &plain));
        assert!(
            lamports_kept(2_000, &base, 9_000, &plain),
            "a lamport inflow"
        );
        assert!(
            !lamports_kept(2_000, &base, 1_999, &plain),
            "non-native drop"
        );

        let mut native = token_account_bytes(165, 1);
        native[TOKEN_IS_NATIVE_OFFSET..TOKEN_IS_NATIVE_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let base = base_of(&native);
        let mut after = native.clone();
        after[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8].copy_from_slice(&600u64.to_le_bytes());
        assert!(
            lamports_kept(5_000, &base, 4_600, &after),
            "drop equals amount drop"
        );
        assert!(
            lamports_kept(5_000, &base, 4_700, &after),
            "drop below amount drop"
        );
        assert!(
            !lamports_kept(5_000, &base, 4_599, &after),
            "drop beyond amount drop"
        );
        assert!(
            !lamports_kept(5_000, &base, 4_999, &native),
            "excess lamports, amount unchanged"
        );
    }

    // ── evaluate_pre_actions tests ───────────────────────────────────
    // These test whitelist/blacklist logic directly.
    // We create minimal CompactInstructions that reference account indexes.

    #[test]
    fn test_pre_actions_no_actions_passthrough() {
        let mut session_data = vec![0u8; SESSION_HEADER_SIZE];
        session_data[0] = crate::state::AccountDiscriminator::Session as u8;

        let loc = PolicyLocation::of(&session_data).expect("session data resolves");
        let result = evaluate_pre_actions(&session_data, loc, &[], &[], 100);
        assert!(result.is_ok());
    }

    // ── Session creation: actions_len cap ────────────────────────────
    // (tested in session/create.rs but we verify the constant here)

    #[test]
    fn test_max_actions_constant_is_16() {
        assert_eq!(crate::state::action::MAX_ACTIONS, 16);
    }
}
