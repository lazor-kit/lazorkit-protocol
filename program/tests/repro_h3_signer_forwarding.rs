//! H-3 — `Execute` forwarded every outer signer into its inner CPIs, so a
//! tightly restricted session could spend the paymaster's own funds.
//!
//! The reproduction moved 2 SOL out of the fee payer's wallet using a session
//! whose entire authority was a 0.001 SOL `SolLimit`. Nothing was bypassed: the
//! action limits watch the *vault*, the paymaster is a different account, and
//! `try_collect_fee` requires the payer to sign, so its signature was always
//! there to conscript.
//!
//! Forwarding is now opt-in, requested by the high bit of an account's index
//! byte inside the compact instruction, and bounded by two rules the bit cannot
//! override:
//!
//!   - the fee payer is never forwarded, compared by key so passing it twice
//!     cannot launder it
//!   - a session may only forward its own session key
//!
//! The second rule matters because the bit is *not* consent in the session
//! branch. For a Secp256r1 authority the compact bytes sit inside the signed
//! payload, so setting the bit is something the passkey holder signs. A session
//! key signs no payload — it is the adversary in this finding — and would simply
//! set the bit itself.
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

/// High bit of an account index byte: forward this account's signer flag.
const FORWARD_SIGNER: u8 = 0x80;

/// The allowance the wallet owner believes they are handing out.
const SESSION_ALLOWANCE: u64 = 1_000_000;

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
            // Writable so it can also be used as a transfer source.
            AccountMeta::new(session.pubkey(), true),
        ],
        context,
    )
}

/// `Execute` data whose single inner instruction is
/// `System::Transfer(accounts[from] -> accounts[5])`.
///
/// `from` is the raw index byte, so a caller can set [`FORWARD_SIGNER`] on it.
fn transfer_from(from: u8, lamports: u64) -> Vec<u8> {
    let mut data = vec![4u8]; // Execute
    data.extend_from_slice(&encode_compact(&[(
        4, // program_id_index -> system program
        vec![from, 5],
        system_transfer_data(lamports),
    )]));
    data
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}

/// A session locked down as tightly as the action model allows: System Program
/// only, and a 0.001 SOL lifetime allowance.
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

    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from(3, 500_000), // index 3 = vault
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("spending inside the allowance must work");
    assert_eq!(lamports_of(&context, &destination), 500_000);

    advance(&mut context.svm);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from(3, 100_000_000),
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
// H-3b — the hole
// ─────────────────────────────────────────────────────────────────────────

/// Kept as the record of what the hole actually did, and runnable against a
/// pre-fix binary with `--ignored`.
#[test]
#[ignore = "reproduces pre-fix behaviour; forwarding is opt-in and never covers the payer"]
fn h3_b_restricted_session_drains_the_paymaster() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, attacker),
        data: transfer_from(0, 2_000_000_000), // index 0 = payer / paymaster
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("pre-fix: Execute forwarded the paymaster's signature");
    assert_eq!(lamports_of(&context, &attacker), 2_000_000_000);
}

// ─────────────────────────────────────────────────────────────────────────
// H-3c — the fee payer is never forwarded, flagged or not
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h3_c_the_paymaster_is_never_conscripted() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let attacker = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let payer_before = lamports_of(&context, &payer.pubkey());
    let actions_before = session_actions(&context.svm, session_pda);

    // Both spellings of the attack. Index 0 is the fee payer, so a bare
    // `FORWARD_SIGNER` *is* index 0 with the bit set.
    for (label, from) in [("flag set", FORWARD_SIGNER), ("flag clear", 0u8)] {
        advance(&mut context.svm);
        let ix = Instruction {
            program_id: context.program_id,
            accounts: session_execute_accounts(&context, &wallet, session_pda, &session, attacker),
            data: transfer_from(from, 2_000_000_000),
        };
        let result = try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]);
        assert!(
            result.is_err(),
            "H-3c ({label}): the fee payer must never be forwarded into an inner CPI"
        );
    }

    assert_eq!(
        lamports_of(&context, &attacker),
        0,
        "H-3c: nothing reached the attacker"
    );
    assert!(
        payer_before - lamports_of(&context, &payer.pubkey()) < 1_000_000,
        "H-3c: the relayer kept its balance, minus transaction fees"
    );
    assert_eq!(
        session_actions(&context.svm, session_pda),
        actions_before,
        "H-3c: and no policy state moved, because nothing was spent"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-3d — forwarding still works where it is asked for and permitted
// ─────────────────────────────────────────────────────────────────────────

/// A session may conscript its own signature — the one it already holds. This
/// is what keeps legitimate multi-signer inner instructions possible after
/// closing the hole.
#[test]
fn h3_d_a_session_may_forward_its_own_key_when_flagged() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    // Fund the session key so it can be a transfer source.
    context
        .svm
        .airdrop(&session.pubkey(), 100_000_000)
        .expect("fund session key");

    let destination = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // Index 6 is the session key. Without the flag the CPI has no signature for
    // it and the System Program refuses.
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from(6, 1_000_000),
    };
    assert!(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]).is_err(),
        "H-3d: forwarding is opt-in — an unflagged signer is not forwarded"
    );
    assert_eq!(lamports_of(&context, &destination), 0);

    // With the flag it is forwarded, and the transfer lands.
    advance(&mut context.svm);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from(6 | FORWARD_SIGNER, 1_000_000),
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("H-3d: a session may forward its own key");
    assert_eq!(lamports_of(&context, &destination), 1_000_000);
}

/// The vault signs without any flag — it is the wallet's identity, and the
/// program signs for it with seeds rather than forwarding anything.
#[test]
fn h3_d_the_vault_signs_unconditionally() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = restricted_session(&mut context, &wallet);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);

    let destination = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // Index 3 is the vault, no flag set.
    let ix = Instruction {
        program_id: context.program_id,
        accounts: session_execute_accounts(&context, &wallet, session_pda, &session, destination),
        data: transfer_from(3, 500_000),
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &session])
        .expect("H-3d: the vault needs no flag");
    assert_eq!(lamports_of(&context, &destination), 500_000);
}
