//! Rent goes back to the account that paid it.
//!
//! From layout revision 2 an authority and a session record the account that
//! paid their rent (`state::rent_payer`), and every instruction that closes one
//! refunds to that account and refuses any other destination with 3039
//! `RefundDestinationMismatch`, whoever signs the close and whoever pays its
//! fee. Here the payer is a sponsor (the suite's context payer) and the wallet's
//! Owner is someone else, as on a relayed flow.
//!
//! Each close path is pinned three ways: the recorded payer is refunded in
//! full; any other destination is refused and the account survives; and an
//! account written before revision 2, which records no payer, still closes
//! where the signer says. A revision-1 policy is still read where revision 1
//! put it.
//!
//! ExecuteDeferred and ReclaimDeferred refunded only to the DeferredExec's
//! stored payer before this change, and now say so with the same 3039; the
//! last two tests pin both.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test rent_refund_tests

mod common;

use common::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

const ERR_REFUND_DESTINATION_MISMATCH: u32 = 3039;
const ERR_SOL_LIMIT: u32 = 3024;
const ERR_UNAUTHORIZED_RECLAIM: u32 = 3017;

const DISC_REMOVE_AUTHORITY: u8 = 2;
const DISC_TRANSFER_OWNERSHIP: u8 = 3;
const DISC_REVOKE_SESSION: u8 = 9;
const DISC_CLOSE_EXPIRED_SESSION: u8 = 18;

fn lamports(context: &TestContext, key: &Pubkey) -> u64 {
    context.svm.get_balance(key).unwrap_or(0)
}

/// The wallet's Owner, funded so it can pay for a transaction itself.
fn funded_owner(context: &mut TestContext, wallet: &WalletFixture) -> Keypair {
    let owner = wallet.owner.insecure_clone();
    context.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
    owner
}

/// Rewrite a revision-2 authority or session as revision 1 left it: no rent
/// payer, the policy straight after the fixed part.
fn make_revision_1(context: &mut TestContext, key: Pubkey) {
    let mut account = context.svm.get_account(&key).unwrap();
    let start = policy_offset(&account.data);
    let payer_at = start - 32;
    account.data.drain(payer_at..start);
    match account.data[0] {
        0x23 => account.data[2] = 1,
        0x22 => account.data[4] = 1,
        other => panic!("not an authority or a session: {other:#x}"),
    }
    context.svm.set_account(key, account).unwrap();
    advance(&mut context.svm);
}

fn revoke_ix(
    context: &TestContext,
    wallet: &WalletFixture,
    tx_payer: Pubkey,
    session_pda: Pubkey,
    refund: Pubkey,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(tx_payer, true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new(refund, false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data: vec![DISC_REVOKE_SESSION],
    }
}

fn remove_ix(
    context: &TestContext,
    wallet: &WalletFixture,
    tx_payer: Pubkey,
    target: Pubkey,
    refund: Pubkey,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(tx_payer, true),
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(target, false),
            AccountMeta::new(refund, false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data: vec![DISC_REMOVE_AUTHORITY],
    }
}

/// TransferOwnership from the wallet's Ed25519 Owner to `new_owner`.
fn transfer_ix(
    context: &TestContext,
    wallet: &WalletFixture,
    tx_payer: Pubkey,
    new_owner: &Keypair,
    refund: Pubkey,
) -> (Instruction, Pubkey) {
    let new_pda = authority_pda_for(context.program_id, wallet.wallet_pda, &new_owner.pubkey());
    let mut data = vec![DISC_TRANSFER_OWNERSHIP, 0];
    data.extend_from_slice(new_owner.pubkey().as_ref());
    (
        Instruction {
            program_id: context.program_id,
            accounts: vec![
                AccountMeta::new(tx_payer, true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(wallet.owner_auth_pda, false),
                AccountMeta::new(new_pda, false),
                AccountMeta::new(refund, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(wallet.owner.pubkey(), true),
            ],
            data,
        },
        new_pda,
    )
}

fn close_expired_ix(
    context: &TestContext,
    caller: Pubkey,
    session: Pubkey,
    refund: Pubkey,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(caller, true),
            AccountMeta::new(session, false),
            AccountMeta::new(refund, false),
        ],
        data: vec![DISC_CLOSE_EXPIRED_SESSION],
    }
}

// ─── Creation records the payer ──────────────────────────────────────────

#[test]
fn every_rent_funded_account_records_its_payer() {
    let mut context = setup_test();
    let sponsor = context.payer.pubkey();
    let wallet = create_ed25519_wallet(&mut context, 0);
    assert_eq!(
        recorded_rent_payer(&context.svm, wallet.owner_auth_pda),
        sponsor
    );

    let admin = Keypair::new();
    let admin_pda = owner_adds_ed25519(&mut context, &wallet, &admin, RANK_ADMIN, &[]).unwrap();
    assert_eq!(recorded_rent_payer(&context.svm, admin_pda), sponsor);

    let delegate = Keypair::new();
    let policy = action_sol_limit(1_000_000);
    let delegate_pda =
        owner_adds_ed25519(&mut context, &wallet, &delegate, RANK_DELEGATE, &policy).unwrap();
    assert_eq!(recorded_rent_payer(&context.svm, delegate_pda), sponsor);
    assert_eq!(session_actions(&context.svm, delegate_pda), policy);

    let session = create_session_with_actions(&mut context, &wallet, &policy);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);
    assert_eq!(recorded_rent_payer(&context.svm, session_pda), sponsor);
    assert_eq!(session_actions(&context.svm, session_pda), policy);

    // Sizes: the fixed part, 32 bytes of payer, the policy.
    let len = |k: &Pubkey| context.svm.get_account(k).unwrap().data.len();
    assert_eq!(len(&wallet.owner_auth_pda), 80 + 32);
    assert_eq!(len(&admin_pda), 80 + 32);
    assert_eq!(len(&delegate_pda), 80 + 32 + policy.len());
    assert_eq!(len(&session_pda), 80 + 32 + policy.len());
}

#[test]
fn a_passkey_owner_records_its_payer_after_its_key_material() {
    let mut context = setup_test();
    let pk = Passkey::new();
    let w = create_passkey_wallet(&mut context, &pk);
    let data = context.svm.get_account(&w.authority).unwrap().data;
    assert_eq!(data.len(), 145 + 32);
    assert_eq!(&data[145..177], context.payer.pubkey().as_ref());
}

// ─── RevokeSession ───────────────────────────────────────────────────────

#[test]
fn revoke_session_refunds_the_sponsor_and_refuses_anyone_else() {
    let mut context = setup_test();
    let sponsor = context.payer.pubkey();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let session = create_session_with_actions(&mut context, &wallet, &[]);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);
    let rent = lamports(&context, &session_pda);

    // The Owner pays for the revoke itself and names itself: refused.
    let owner = funded_owner(&mut context, &wallet);
    let ix = revoke_ix(
        &context,
        &wallet,
        owner.pubkey(),
        session_pda,
        owner.pubkey(),
    );
    assert_custom_error(
        try_send(&mut context.svm, &owner, &[ix], &[&owner]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "RevokeSession into the Owner",
    );
    // A third account: refused too.
    advance(&mut context.svm);
    let ix = revoke_ix(
        &context,
        &wallet,
        owner.pubkey(),
        session_pda,
        Pubkey::new_unique(),
    );
    assert_custom_error(
        try_send(&mut context.svm, &owner, &[ix], &[&owner]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "RevokeSession into a third account",
    );
    assert_eq!(
        lamports(&context, &session_pda),
        rent,
        "the session survives"
    );

    // Into the sponsor, still paid for and signed by the Owner: lands.
    advance(&mut context.svm);
    let before = lamports(&context, &sponsor);
    let ix = revoke_ix(&context, &wallet, owner.pubkey(), session_pda, sponsor);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("revoke into the sponsor");
    assert_eq!(lamports(&context, &session_pda), 0);
    assert_eq!(lamports(&context, &sponsor), before + rent);
}

#[test]
fn a_revision_1_session_revokes_into_the_signers_choice() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let session = create_session_with_actions(&mut context, &wallet, &[]);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);
    make_revision_1(&mut context, session_pda);
    let rent = lamports(&context, &session_pda);

    let owner = funded_owner(&mut context, &wallet);
    let elsewhere = Pubkey::new_unique();
    let ix = revoke_ix(&context, &wallet, owner.pubkey(), session_pda, elsewhere);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("legacy revoke");
    assert_eq!(lamports(&context, &elsewhere), rent);
}

// ─── CloseExpiredSession ─────────────────────────────────────────────────

#[test]
fn an_expired_session_closes_into_its_sponsor_whoever_calls() {
    let mut context = setup_test();
    let sponsor = context.payer.pubkey();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let session = create_session_with_actions(&mut context, &wallet, &[]);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);
    let rent = lamports(&context, &session_pda);
    // Past create_session_with_actions' expiry.
    let now = unix_now(&context.svm);
    set_unix_time(&mut context.svm, now + 100_001);

    // The Owner, closing its own expired session, may not take the rent.
    let owner = funded_owner(&mut context, &wallet);
    let ix = close_expired_ix(&context, owner.pubkey(), session_pda, owner.pubkey());
    assert_custom_error(
        try_send(&mut context.svm, &owner, &[ix], &[&owner]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "CloseExpiredSession into the Owner",
    );

    advance(&mut context.svm);
    let before = lamports(&context, &sponsor);
    let ix = close_expired_ix(&context, owner.pubkey(), session_pda, sponsor);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("close into the sponsor");
    assert_eq!(lamports(&context, &sponsor), before + rent);
}

// ─── RemoveAuthority ─────────────────────────────────────────────────────

#[test]
fn remove_authority_refunds_the_sponsor_and_refuses_anyone_else() {
    let mut context = setup_test();
    let sponsor = context.payer.pubkey();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let delegate = Keypair::new();
    let target = owner_adds_ed25519(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &action_sol_limit(1_000),
    )
    .unwrap();
    let rent = lamports(&context, &target);

    let owner = funded_owner(&mut context, &wallet);
    for (refund, what) in [
        (owner.pubkey(), "into the Owner"),
        (delegate.pubkey(), "into the removed key"),
        (wallet.vault_pda, "into the vault"),
    ] {
        advance(&mut context.svm);
        let ix = remove_ix(&context, &wallet, owner.pubkey(), target, refund);
        assert_custom_error(
            try_send(&mut context.svm, &owner, &[ix], &[&owner]),
            ERR_REFUND_DESTINATION_MISMATCH,
            what,
        );
    }
    assert_eq!(lamports(&context, &target), rent, "the authority survives");

    advance(&mut context.svm);
    let before = lamports(&context, &sponsor);
    let ix = remove_ix(&context, &wallet, owner.pubkey(), target, sponsor);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("remove into the sponsor");
    assert_eq!(lamports(&context, &target), 0);
    assert_eq!(lamports(&context, &sponsor), before + rent);
}

#[test]
fn a_revision_1_authority_removes_into_the_signers_choice() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let admin = Keypair::new();
    let target = owner_adds_ed25519(&mut context, &wallet, &admin, RANK_ADMIN, &[]).unwrap();
    make_revision_1(&mut context, target);
    assert_eq!(context.svm.get_account(&target).unwrap().data.len(), 80);
    let rent = lamports(&context, &target);

    let owner = funded_owner(&mut context, &wallet);
    let elsewhere = Pubkey::new_unique();
    let ix = remove_ix(&context, &wallet, owner.pubkey(), target, elsewhere);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("legacy remove");
    assert_eq!(lamports(&context, &elsewhere), rent);
}

// ─── TransferOwnership ───────────────────────────────────────────────────

#[test]
fn transfer_ownership_refunds_the_old_owners_sponsor() {
    let mut context = setup_test();
    let sponsor = context.payer.pubkey();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let rent = lamports(&context, &wallet.owner_auth_pda);
    let owner = funded_owner(&mut context, &wallet);
    let next = Keypair::new();

    // The Owner pays for the new Owner and names itself for the old one's rent.
    let (ix, _) = transfer_ix(&context, &wallet, owner.pubkey(), &next, owner.pubkey());
    assert_custom_error(
        try_send(&mut context.svm, &owner, &[ix], &[&owner]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "TransferOwnership into the Owner",
    );
    assert_eq!(lamports(&context, &wallet.owner_auth_pda), rent);

    advance(&mut context.svm);
    let before = lamports(&context, &sponsor);
    let (ix, new_pda) = transfer_ix(&context, &wallet, owner.pubkey(), &next, sponsor);
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("transfer, refund to sponsor");
    assert_eq!(lamports(&context, &wallet.owner_auth_pda), 0);
    assert_eq!(lamports(&context, &sponsor), before + rent);
    // Whoever paid for the new Owner is the one its rent goes back to.
    assert_eq!(recorded_rent_payer(&context.svm, new_pda), owner.pubkey());
}

#[test]
fn a_revision_1_owner_transfers_into_the_signers_choice() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    make_revision_1(&mut context, wallet.owner_auth_pda);
    let rent = lamports(&context, &wallet.owner_auth_pda);
    let owner = funded_owner(&mut context, &wallet);
    let elsewhere = Pubkey::new_unique();
    let (ix, _) = transfer_ix(
        &context,
        &wallet,
        owner.pubkey(),
        &Keypair::new(),
        elsewhere,
    );
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("legacy transfer");
    assert_eq!(lamports(&context, &elsewhere), rent);
}

// ─── Revision-1 policies still bind ──────────────────────────────────────

/// A revision-1 Delegate's policy sits right after its key material. Read from
/// revision 2's offset it would be 32 bytes of nothing; it must still bind.
#[test]
fn a_revision_1_delegates_policy_still_binds() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let delegate = Keypair::new();
    let pda = owner_adds_ed25519(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &action_sol_limit(1_000_000),
    )
    .unwrap();
    make_revision_1(&mut context, pda);
    assert_eq!(
        policy_offset(&context.svm.get_account(&pda).unwrap().data),
        80
    );

    let payer = context.payer.insecure_clone();
    let over = execute_as(
        &context,
        &wallet,
        pda,
        &delegate,
        Pubkey::new_unique(),
        1_000_001,
    );
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[over], &[&payer, &delegate]),
        ERR_SOL_LIMIT,
        "over a revision-1 Delegate's limit",
    );
    advance(&mut context.svm);
    let within = execute_as(
        &context,
        &wallet,
        pda,
        &delegate,
        Pubkey::new_unique(),
        400_000,
    );
    try_send(&mut context.svm, &payer, &[within], &[&payer, &delegate]).expect("within");
    assert_eq!(session_action_u64(&context.svm, pda, 0, 0), 600_000);
}

#[test]
fn a_revision_1_sessions_actions_still_bind() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let session = create_session_with_actions(&mut context, &wallet, &action_sol_limit(1_000_000));
    let pda = session_pda_for(context.program_id, &wallet, &session);
    make_revision_1(&mut context, pda);

    let payer = context.payer.insecure_clone();
    let over = execute_as(
        &context,
        &wallet,
        pda,
        &session,
        Pubkey::new_unique(),
        1_000_001,
    );
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[over], &[&payer, &session]),
        ERR_SOL_LIMIT,
        "over a revision-1 session's limit",
    );
    advance(&mut context.svm);
    let within = execute_as(
        &context,
        &wallet,
        pda,
        &session,
        Pubkey::new_unique(),
        400_000,
    );
    try_send(&mut context.svm, &payer, &[within], &[&payer, &session]).expect("within");
    assert_eq!(session_action_u64(&context.svm, pda, 0, 0), 600_000);
}

/// A session at a layout revision this binary does not know is refused by
/// Execute, not run as if it carried no actions.
#[test]
fn execute_refuses_a_session_of_an_unknown_revision() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let session = create_session_with_actions(&mut context, &wallet, &action_sol_limit(1));
    let pda = session_pda_for(context.program_id, &wallet, &session);
    let mut account = context.svm.get_account(&pda).unwrap();
    account.data[2] = 3;
    context.svm.set_account(pda, account).unwrap();

    let payer = context.payer.insecure_clone();
    let ix = execute_as(
        &context,
        &wallet,
        pda,
        &session,
        Pubkey::new_unique(),
        500_000,
    );
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]),
        4013,
        "a session at revision 3",
    );
}

// ─── DeferredExec: already bound to its stored payer ─────────────────────

/// A DeferredExec written straight into the bank: `payer` recorded, expired
/// at slot 1.
fn plant_deferred(context: &mut TestContext, wallet: Pubkey, payer: Pubkey) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 176];
    data[0] = 0x24;
    data[1] = 1;
    data[2] = 255;
    data[72..104].copy_from_slice(wallet.as_ref());
    data[104..136].copy_from_slice(Pubkey::new_unique().as_ref());
    data[136..168].copy_from_slice(payer.as_ref());
    data[168..176].copy_from_slice(&1u64.to_le_bytes());
    context
        .svm
        .set_account(
            key,
            Account {
                lamports: 2_116_800,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    key
}

#[test]
fn reclaim_deferred_refunds_only_its_stored_payer() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let sponsor = context.payer.insecure_clone();
    let deferred = plant_deferred(&mut context, wallet.wallet_pda, sponsor.pubkey());
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = 10;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);

    let program_id = context.program_id;
    let reclaim = |refund: Pubkey| Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(sponsor.pubkey(), true),
            AccountMeta::new(deferred, false),
            AccountMeta::new(refund, false),
        ],
        data: vec![8],
    };
    let ix = reclaim(Pubkey::new_unique());
    assert_custom_error(
        try_send(&mut context.svm, &sponsor, &[ix], &[&sponsor]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "ReclaimDeferred into another account",
    );
    // Someone else signing for it: refused before the destination is looked at.
    let other = Keypair::new();
    context.svm.airdrop(&other.pubkey(), 1_000_000_000).unwrap();
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(other.pubkey(), true),
            AccountMeta::new(deferred, false),
            AccountMeta::new(sponsor.pubkey(), false),
        ],
        data: vec![8],
    };
    assert_custom_error(
        try_send(&mut context.svm, &other, &[ix], &[&other]),
        ERR_UNAUTHORIZED_RECLAIM,
        "ReclaimDeferred signed by another account",
    );
    advance(&mut context.svm);
    let ix = reclaim(sponsor.pubkey());
    try_send(&mut context.svm, &sponsor, &[ix], &[&sponsor]).expect("reclaim into its payer");
    assert_eq!(lamports(&context, &deferred), 0);
}

#[test]
fn execute_deferred_refunds_only_its_stored_payer() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let sponsor = context.payer.pubkey();
    let deferred = plant_deferred(&mut context, wallet.wallet_pda, sponsor);
    // Live: the refund check comes before the expiry and the hashes.
    let mut account = context.svm.get_account(&deferred).unwrap();
    account.data[168..176].copy_from_slice(&u64::MAX.to_le_bytes());
    context.svm.set_account(deferred, account).unwrap();

    let payer = context.payer.insecure_clone();
    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(wallet.vault_pda, false),
                AccountMeta::new(deferred, false),
                AccountMeta::new(Pubkey::new_unique(), false),
            ],
            &context,
        ),
        data: vec![7, 0],
    };
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "ExecuteDeferred into another account",
    );
}

// ─── Closing never depends on the payer ──────────────────────────────────

/// CreateSession paid for by `payer` (not the suite's payer), authorized by the
/// wallet's Owner. Returns the session PDA.
fn session_paid_by(context: &mut TestContext, wallet: &WalletFixture, payer: &Keypair) -> Pubkey {
    let session = Keypair::new();
    let pda = session_pda_for(context.program_id, wallet, &session);
    let expires_at = unix_now(&context.svm) + 100_000;
    let mut data = vec![5u8];
    data.extend_from_slice(session.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };
    try_send(&mut context.svm, payer, &[ix], &[payer, &wallet.owner]).expect("CreateSession");
    pda
}

/// Turn `key` into an executable account, as deploying a program at its
/// address would (any ELF will do; this one is at hand).
fn make_executable(context: &mut TestContext, key: Pubkey) {
    context
        .svm
        .add_program_from_file(key, sbf_artifact_path())
        .expect("load a program at the payer's address");
    assert!(context.svm.get_account(&key).unwrap().executable);
    advance(&mut context.svm);
}

/// A key that paid for a session cannot keep the Owner from revoking it by
/// becoming an account the runtime may refuse to credit: the session closes
/// and its rent stays in the dead account.
#[test]
fn a_payer_that_became_executable_cannot_block_a_revoke() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let insider = Keypair::new();
    context
        .svm
        .airdrop(&insider.pubkey(), 1_000_000_000)
        .unwrap();
    let pda = session_paid_by(&mut context, &wallet, &insider);
    assert_eq!(recorded_rent_payer(&context.svm, pda), insider.pubkey());
    let rent = lamports(&context, &pda);
    make_executable(&mut context, insider.pubkey());

    let owner = funded_owner(&mut context, &wallet);
    // Still only the recorded payer may be named.
    let ix = revoke_ix(&context, &wallet, owner.pubkey(), pda, owner.pubkey());
    assert_custom_error(
        try_send(&mut context.svm, &owner, &[ix], &[&owner]),
        ERR_REFUND_DESTINATION_MISMATCH,
        "RevokeSession into the Owner",
    );
    advance(&mut context.svm);
    let mut ix = revoke_ix(&context, &wallet, owner.pubkey(), pda, insider.pubkey());
    // Read-only: a transaction may not even load an executable account writable.
    ix.accounts[4].is_writable = false;
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("the revoke lands");
    let after = context.svm.get_account(&pda).unwrap();
    assert!(after.data.iter().all(|&b| b == 0), "the session is dead");
    assert_eq!(after.lamports, rent, "its rent stayed where it was");
}

#[test]
fn a_payer_that_became_executable_cannot_block_a_removal() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let insider = Keypair::new();
    context
        .svm
        .airdrop(&insider.pubkey(), 1_000_000_000)
        .unwrap();
    // The insider pays for a Delegate the Owner adds.
    let delegate = Keypair::new();
    let target = authority_pda_for(context.program_id, wallet.wallet_pda, &delegate.pubkey());
    let policy = action_sol_limit(1_000_000);
    let mut data = vec![1u8, 0, RANK_DELEGATE, 0, 0, 0, 0, 0, 0];
    data.extend_from_slice(delegate.pubkey().as_ref());
    data.extend_from_slice(&(policy.len() as u16).to_le_bytes());
    data.extend_from_slice(&policy);
    let add = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(insider.pubkey(), true),
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(target, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };
    try_send(
        &mut context.svm,
        &insider,
        &[add],
        &[&insider, &wallet.owner],
    )
    .expect("AddAuthority");
    let rent = lamports(&context, &target);
    make_executable(&mut context, insider.pubkey());

    let owner = funded_owner(&mut context, &wallet);
    let mut ix = remove_ix(&context, &wallet, owner.pubkey(), target, insider.pubkey());
    ix.accounts[4].is_writable = false;
    try_send(&mut context.svm, &owner, &[ix], &[&owner]).expect("the removal lands");
    let after = context.svm.get_account(&target).unwrap();
    assert!(after.data.iter().all(|&b| b == 0), "the Delegate is dead");
    assert_eq!(after.lamports, rent);
    // And it can no longer spend.
    let payer = context.payer.insecure_clone();
    let spend = execute_as(
        &context,
        &wallet,
        target,
        &delegate,
        Pubkey::new_unique(),
        1,
    );
    assert!(try_send(&mut context.svm, &payer, &[spend], &[&payer, &delegate]).is_err());
}

/// Only an ordinary system account may be recorded as a rent payer. A PDA
/// someone pre-funded skips the System transfer, so without this a
/// program-owned or executable signer could be recorded.
#[test]
fn a_payer_that_is_not_a_system_account_is_refused_at_creation() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let odd = Keypair::new();
    context
        .svm
        .set_account(
            odd.pubkey(),
            Account {
                lamports: 1_000_000_000,
                data: vec![],
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    // Pre-fund the session PDA, so no System transfer from `odd` is needed.
    let session = Keypair::new();
    let pda = session_pda_for(context.program_id, &wallet, &session);
    context.svm.airdrop(&pda, 10_000_000).unwrap();
    let expires_at = unix_now(&context.svm) + 100_000;
    let mut data = vec![5u8];
    data.extend_from_slice(session.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(odd.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };
    let payer = context.payer.insecure_clone();
    let result = try_send(
        &mut context.svm,
        &payer,
        &[ix],
        &[&payer, &odd, &wallet.owner],
    );
    match result {
        Err(failed) => assert_eq!(
            failed.err,
            solana_sdk::transaction::TransactionError::InstructionError(
                0,
                solana_sdk::instruction::InstructionError::IllegalOwner
            ),
            "{}",
            failed.meta.pretty_logs()
        ),
        Ok(_) => panic!("a program-owned payer was recorded"),
    }
}

#[test]
fn a_payer_that_became_executable_cannot_block_closing_an_expired_session() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let insider = Keypair::new();
    context
        .svm
        .airdrop(&insider.pubkey(), 1_000_000_000)
        .unwrap();
    let pda = session_paid_by(&mut context, &wallet, &insider);
    let rent = lamports(&context, &pda);
    make_executable(&mut context, insider.pubkey());
    let now = unix_now(&context.svm);
    set_unix_time(&mut context.svm, now + 100_001);

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    for writable in [true, false] {
        let mut ix = close_expired_ix(&context, stranger.pubkey(), pda, insider.pubkey());
        ix.accounts[2].is_writable = writable;
        if try_send(&mut context.svm, &stranger, &[ix], &[&stranger]).is_ok() {
            break;
        }
        assert!(writable, "the read-only form must land");
        advance(&mut context.svm);
    }
    let after = context.svm.get_account(&pda).unwrap();
    assert!(after.data.iter().all(|&b| b == 0));
    assert_eq!(after.lamports, rent);
}
