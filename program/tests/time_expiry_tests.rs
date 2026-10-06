//! Session expiry and policy time are Unix seconds, not slots.
//!
//! `CreateSession`'s `expires_at`, every action's `expires_at`, and a recurring
//! limit's `window` and `last_reset` are read against `Clock::unix_timestamp`.
//! Slots stay where they bound how a transaction lands: the passkey
//! signature's age and the deferred-execution window (`Authorize`'s
//! `expiry_offset`).
//!
//! Each test moves one clock and not the other, so it shows which one decides.
//! Every suite starts at `TEST_UNIX_TIME` (2026-10-04), where a slot passed in
//! place of a time is decades in the past — which is also what accounts written
//! by a slot-based build look like now, and they fail closed (`legacy_*`).
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test time_expiry_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::InvalidSessionDuration`
const ERR_INVALID_SESSION_DURATION: u32 = 3008;
/// `AuthError::SessionExpired`
const ERR_SESSION_EXPIRED: u32 = 3009;
/// `AuthError::DeferredAuthorizationExpired`
const ERR_DEFERRED_EXPIRED: u32 = 3014;
/// `AuthError::ActionSolLimitExceeded`
const ERR_SOL_LIMIT: u32 = 3024;
/// `AuthError::ActionSolRecurringLimitExceeded`
const ERR_SOL_RECURRING: u32 = 3025;

const DAY: u64 = 24 * 60 * 60;
const MAX_SESSION_SECONDS: u64 = 30 * DAY;
/// Devnet's slot on 2026-10-04.
const DEVNET_SLOT: u64 = 507_081_509;

fn set_slot(context: &mut TestContext, slot: u64) {
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = slot;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);
}

/// An action with its own expiry: `[type][data_len u16][expires_at u64][data]`.
fn action_expiring(action_type: u8, data: &[u8], expires_at: u64) -> Vec<u8> {
    let mut out = vec![action_type];
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&expires_at.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// `CreateSession` at a chosen `expires_at`, authorized by the Ed25519 Owner.
#[allow(clippy::result_large_err)]
fn create_session_at(
    context: &mut TestContext,
    wallet: &WalletFixture,
    expires_at: u64,
    actions: &[u8],
) -> Result<(Keypair, Pubkey), litesvm::types::FailedTransactionMetadata> {
    let session = Keypair::new();
    let session_pda = session_pda_for(context.program_id, wallet, &session);
    let mut data = vec![5u8]; // CreateSession
    data.extend_from_slice(session.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());
    data.extend_from_slice(&(actions.len() as u16).to_le_bytes());
    data.extend_from_slice(actions);
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
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])?;
    Ok((session, session_pda))
}

/// A session Execute of one SOL transfer out of the vault.
#[allow(clippy::result_large_err)]
fn session_transfer(
    context: &mut TestContext,
    wallet: &WalletFixture,
    session: &Keypair,
    session_pda: Pubkey,
    lamports: u64,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    advance(&mut context.svm);
    let recipient = Pubkey::new_unique();
    let ix = Instruction {
        program_id: context.program_id,
        accounts: execute_accounts(
            context,
            wallet,
            session_pda,
            vec![
                AccountMeta::new_readonly(session.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(recipient, false),
            ],
        ),
        data: execute_data(&[(5, vec![3, 6], system_transfer_data(lamports))]),
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, session])
}

fn landed(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    what: &str,
) {
    if let Err(failed) = result {
        panic!("{what}: {:?}\n{}", failed.err, failed.meta.pretty_logs());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// CreateSession
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn create_session_takes_an_expiry_up_to_thirty_days_ahead() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let now = unix_now(&context.svm);

    for (expires_at, what) in [(now, "now"), (now - 1, "a second ago")] {
        assert_custom_error(
            create_session_at(&mut context, &wallet, expires_at, &[]),
            ERR_INVALID_SESSION_DURATION,
            what,
        );
    }
    assert_custom_error(
        create_session_at(&mut context, &wallet, now + MAX_SESSION_SECONDS + 1, &[]),
        ERR_INVALID_SESSION_DURATION,
        "thirty days and a second",
    );
    create_session_at(&mut context, &wallet, now + 1, &[]).expect("a second ahead");
    create_session_at(&mut context, &wallet, now + MAX_SESSION_SECONDS, &[])
        .expect("thirty days ahead");
}

/// What a client from before time-based expiry sends: the current slot plus a
/// duration in slots. Refused at creation, not stored as a session that is
/// expired from the start.
#[test]
fn create_session_refuses_a_slot_for_an_expiry() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    set_slot(&mut context, DEVNET_SLOT);
    assert_custom_error(
        create_session_at(&mut context, &wallet, DEVNET_SLOT + 50_000, &[]),
        ERR_INVALID_SESSION_DURATION,
        "slot + 50,000",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Session expiry in Execute
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_session_lives_through_its_expiry_second_whatever_the_slot() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let expires_at = unix_now(&context.svm) + DAY;
    let (session, pda) = create_session_at(&mut context, &wallet, expires_at, &[]).unwrap();

    // Ten million slots on — weeks of them, at any cluster's pace — and no
    // time: still live.
    set_slot(&mut context, DEVNET_SLOT + 10_000_000);
    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        "slots moved, time did not",
    );

    set_unix_time(&mut context.svm, expires_at);
    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        "the expiry second",
    );

    set_unix_time(&mut context.svm, expires_at + 1);
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        ERR_SESSION_EXPIRED,
        "a second past",
    );
}

/// A v2 session written before time-based expiry holds a slot in
/// `expires_at`. Read as a time that is 1986, so the session is refused —
/// even though the slot has not reached it yet.
#[test]
fn legacy_a_slot_valued_session_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let expires_at = unix_now(&context.svm) + DAY;
    let (session, pda) = create_session_at(&mut context, &wallet, expires_at, &[]).unwrap();

    let slot_expiry = DEVNET_SLOT + 6_480_000; // the longest the old rule allowed
    let mut account = context.svm.get_account(&pda).unwrap();
    account.data[72..80].copy_from_slice(&slot_expiry.to_le_bytes());
    context.svm.set_account(pda, account).unwrap();
    set_slot(&mut context, DEVNET_SLOT);

    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        ERR_SESSION_EXPIRED,
        "slot-valued expiry",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Action expiry and recurring windows
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn an_action_expires_by_time_not_by_slot() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let now = unix_now(&context.svm);
    let limit = action_expiring(1, &10_000_000u64.to_le_bytes(), now + 3_600); // SolLimit
    let (session, pda) = create_session_at(&mut context, &wallet, now + DAY, &limit).unwrap();

    set_slot(&mut context, DEVNET_SLOT + 10_000_000);
    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        "slots moved, time did not",
    );

    set_unix_time(&mut context.svm, now + 3_600);
    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        "the action's expiry second",
    );

    // An expired limit is an exhausted one.
    set_unix_time(&mut context.svm, now + 3_601);
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        ERR_SOL_LIMIT,
        "a second past the action's expiry",
    );
}

#[test]
fn a_recurring_window_is_measured_in_seconds() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let now = unix_now(&context.svm);
    // 1,000,000 lamports per hour.
    let policy = action_sol_recurring_limit(1_000_000, 3_600);
    let (session, pda) = create_session_at(&mut context, &wallet, now + DAY, &policy).unwrap();

    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000_000),
        "the hour's allowance",
    );
    assert_eq!(
        session_action_u64(&context.svm, pda, 0, 24),
        now,
        "last_reset is the time"
    );

    // However many slots pass, the hour has not.
    set_slot(&mut context, DEVNET_SLOT + 10_000_000);
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1),
        ERR_SOL_RECURRING,
        "slots moved, time did not",
    );
    set_unix_time(&mut context.svm, now + 3_600);
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1),
        ERR_SOL_RECURRING,
        "exactly an hour on: still the same window",
    );

    set_unix_time(&mut context.svm, now + 3_601);
    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000_000),
        "a new hour",
    );
}

/// A policy written by a slot-based build: a SOL limit expiring at a slot not
/// yet reached. Read as a time it expired long ago, and an expired limit is an
/// exhausted one: refused, never unlimited.
#[test]
fn legacy_a_slot_valued_action_expiry_has_expired() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    set_slot(&mut context, DEVNET_SLOT);
    let limit = action_expiring(1, &10_000_000u64.to_le_bytes(), DEVNET_SLOT + 216_000);
    // CreateSession does not check an action's expiry, so this is also what a
    // slot-based client can still store; either way the limit is expired.
    let expires_at = unix_now(&context.svm) + DAY;
    let (session, pda) = create_session_at(&mut context, &wallet, expires_at, &limit).unwrap();
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1_000),
        ERR_SOL_LIMIT,
        "slot-valued action expiry",
    );
}

/// A recurring limit written by a slot-based build carries a slot in
/// `last_reset`. Read as a time it is long past, so the first spend after the
/// upgrade opens a fresh window: one allowance early, once. From then on the
/// window is in seconds — and its stored length, written as slots, is read as
/// seconds, which on any cluster is a longer window than the slots were.
#[test]
fn legacy_a_slot_valued_last_reset_opens_one_fresh_window() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let now = unix_now(&context.svm);
    let policy = action_sol_recurring_limit(1_000_000, 216_000);
    let (session, pda) = create_session_at(&mut context, &wallet, now + DAY, &policy).unwrap();

    // As a slot-based build left it: the allowance spent at a recent slot.
    let mut account = context.svm.get_account(&pda).unwrap();
    let data = 80 + 11; // policy start + action header
    account.data[data + 8..data + 16].copy_from_slice(&1_000_000u64.to_le_bytes());
    account.data[data + 24..data + 32].copy_from_slice(&DEVNET_SLOT.to_le_bytes());
    context.svm.set_account(pda, account).unwrap();
    set_slot(&mut context, DEVNET_SLOT + 1);

    landed(
        session_transfer(&mut context, &wallet, &session, pda, 1_000_000),
        "the slot-valued window counts as elapsed",
    );
    assert_eq!(session_action_u64(&context.svm, pda, 0, 24), now);
    assert_custom_error(
        session_transfer(&mut context, &wallet, &session, pda, 1),
        ERR_SOL_RECURRING,
        "and the new window holds",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// What stays in slots
// ─────────────────────────────────────────────────────────────────────────

/// The deferred-execution window is `Authorize`'s `expiry_offset`, signed as a
/// slot count, and ExecuteDeferred compares the slot. Time moving does not
/// expire it; the slot passing does.
#[test]
fn the_deferred_window_stays_in_slots() {
    const EXPIRY_OFFSET: u16 = 100;
    let mut context = setup_test();
    let pk = Passkey::new();
    let w = create_passkey_wallet(&mut context, &pk);
    context.svm.airdrop(&w.vault, 1_000_000_000).unwrap();
    let payer = context.payer.insecure_clone();

    // tx2's accounts: payer · wallet · vault · DeferredExec · refund (payer) ·
    // system program · recipient.
    let recipient = Pubkey::new_unique();
    let compact = encode_compact(&[(5, vec![2, 6], system_transfer_data(1_000))]);
    let flags = |signer: bool, writable: bool| (signer as u8) | ((writable as u8) << 1);
    let mut preimage = Vec::new();
    for (key, f) in [
        (solana_sdk::system_program::id(), flags(false, false)),
        (w.vault, flags(false, true)),
        (recipient, flags(false, true)),
    ] {
        preimage.extend_from_slice(key.as_ref());
        preimage.push(f);
    }
    let accounts_hash: [u8; 32] = Sha256::digest(&preimage).into();
    let instructions_hash: [u8; 32] = Sha256::digest(&compact).into();
    let mut signed_payload = instructions_hash.to_vec();
    signed_payload.extend_from_slice(&accounts_hash);
    signed_payload.extend_from_slice(&EXPIRY_OFFSET.to_le_bytes());

    let deferred_for = |context: &TestContext, counter: u32| {
        Pubkey::find_program_address(
            &[
                lazorkit_program::seeds::DEFERRED,
                w.wallet.as_ref(),
                w.authority.as_ref(),
                &counter.to_le_bytes(),
            ],
            &context.program_id,
        )
        .0
    };
    let authorize = |context: &mut TestContext| -> (Pubkey, u64) {
        let counter = authority_counter(&context.svm, w.authority) + 1;
        let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
        let prefix = secp256r1_prefix(slot, counter, 6);
        let challenge = secp256r1_challenge(
            6,
            &prefix,
            &signed_payload,
            &payer.pubkey(),
            &w.wallet,
            counter,
            &context.program_id,
        );
        let (precompile, auth_payload) =
            passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge);
        let deferred = deferred_for(context, counter);
        let mut data = vec![6u8];
        data.extend_from_slice(&signed_payload);
        data.extend_from_slice(&auth_payload);
        let ix = Instruction {
            program_id: context.program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(w.wallet, false),
                AccountMeta::new(w.authority, false),
                AccountMeta::new(deferred, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            ],
            data,
        };
        advance(&mut context.svm);
        try_send(&mut context.svm, &payer, &[precompile, ix], &[&payer]).expect("Authorize");
        (deferred, slot + EXPIRY_OFFSET as u64)
    };
    let execute = |context: &mut TestContext, deferred: Pubkey| {
        advance(&mut context.svm);
        let mut data = vec![7u8];
        data.extend_from_slice(&compact);
        let ix = Instruction {
            program_id: context.program_id,
            accounts: with_protocol_fee_accounts(
                vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(w.wallet, false),
                    AccountMeta::new(w.vault, false),
                    AccountMeta::new(deferred, false),
                    AccountMeta::new(payer.pubkey(), false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                    AccountMeta::new(recipient, false),
                ],
                context,
            ),
            data,
        };
        try_send(&mut context.svm, &payer, &[ix], &[&payer])
    };

    // A day passes and no slot does: the authorization is still live.
    let (deferred, expires_at_slot) = authorize(&mut context);
    let later = unix_now(&context.svm) + DAY;
    set_unix_time(&mut context.svm, later);
    landed(execute(&mut context, deferred), "a day on, same slot");

    // The slot passes the window and no time does: expired.
    let (deferred, expires_at_slot_2) = authorize(&mut context);
    assert_eq!(expires_at_slot_2, expires_at_slot);
    set_slot(&mut context, expires_at_slot_2 + 1);
    assert_custom_error(
        execute(&mut context, deferred),
        ERR_DEFERRED_EXPIRED,
        "slot past the window",
    );
}
