//! Multiple Owners on one wallet.
//!
//! The product case is a person with several devices. Each device holds its own
//! passkey, and a passkey cannot be copied between them, so "one wallet, several
//! devices" means "one wallet, several authorities". Making them all Owners is
//! what lets a surviving device revoke a lost one without any recovery protocol,
//! any guardian set, or any timelock — the wallet's own keys are the recovery.
//!
//! The rule that makes this safe rather than merely convenient is that the last
//! Owner cannot be removed. A wallet with no Owner is not frozen — its Admins
//! and Delegates keep spending — but nothing can ever be added or revoked again,
//! so the lost device stays valid forever. `WalletAccount::owner_count` exists
//! for exactly that check.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test multi_owner_tests

mod common;

use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

/// `AuthError::PermissionDenied`
const ERR_PERMISSION_DENIED: u32 = 3002;

// ─────────────────────────────────────────────────────────────────────────
// Adding
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_new_wallet_has_exactly_one_owner() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
    assert_eq!(
        authority_role(&context.svm, wallet.owner_auth_pda),
        RANK_OWNER
    );
}

#[test]
fn an_owner_may_add_another_owner() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let second = Keypair::new();
    let second_pda = owner_adds_ed25519(&mut context, &wallet, &second, RANK_OWNER, &[])
        .expect("an Owner may add an Owner");

    assert_eq!(authority_role(&context.svm, second_pda), RANK_OWNER);
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 2);
}

/// The count tracks Owners, not authorities.
#[test]
fn adding_a_non_owner_leaves_the_count_alone() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let admin = Keypair::new();
    owner_adds_ed25519(&mut context, &wallet, &admin, RANK_ADMIN, &[]).expect("Owner adds Admin");
    advance(&mut context.svm);

    let delegate = Keypair::new();
    owner_adds_ed25519(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &action_sol_limit(1_000_000),
    )
    .expect("Owner adds Delegate");

    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
}

#[test]
fn an_admin_may_not_add_an_owner() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let admin = Keypair::new();
    let admin_pda = owner_adds_ed25519(&mut context, &wallet, &admin, RANK_ADMIN, &[])
        .expect("Owner adds Admin");
    advance(&mut context.svm);

    let usurper = Keypair::new();
    assert_custom_error(
        add_ed25519_authority(
            &mut context,
            &wallet,
            admin_pda,
            &admin,
            &usurper,
            RANK_OWNER,
            &[],
        ),
        ERR_PERMISSION_DENIED,
        "an Admin cannot promote anyone to Owner",
    );
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Removing
// ─────────────────────────────────────────────────────────────────────────

/// The lost-device case, end to end.
#[test]
fn a_surviving_owner_may_remove_a_lost_one() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let phone = Keypair::new();
    let phone_pda = owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[])
        .expect("second device joins as Owner");
    advance(&mut context.svm);
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 2);

    // The laptop is lost. The phone revokes it.
    remove_authority(
        &mut context,
        &wallet,
        phone_pda,
        &phone,
        wallet.owner_auth_pda,
    )
    .expect("an Owner may remove another Owner");

    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
    assert!(
        context.svm.get_account(&wallet.owner_auth_pda).is_none()
            || context
                .svm
                .get_account(&wallet.owner_auth_pda)
                .unwrap()
                .data
                .iter()
                .all(|b| *b == 0),
        "the removed authority is gone"
    );
}

/// The rule `owner_count` exists for.
#[test]
fn the_last_owner_cannot_be_removed() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    // A second Owner, so the first has someone able to remove it at all — and
    // then remove the second, leaving one.
    let phone = Keypair::new();
    let phone_pda =
        owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[]).expect("second Owner");
    advance(&mut context.svm);

    let owner_pda = wallet.owner_auth_pda;
    let owner_key = wallet.owner.insecure_clone();
    remove_authority(&mut context, &wallet, owner_pda, &owner_key, phone_pda)
        .expect("down to one Owner");
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
    advance(&mut context.svm);

    // Now nobody can remove the survivor. Self-removal is refused on its own
    // rule, so the count check needs a second Owner-ranked actor to be the one
    // that fires — which is exactly what no longer exists. Both spellings:
    let admin = Keypair::new();
    let admin_pda = owner_adds_ed25519(&mut context, &wallet, &admin, RANK_ADMIN, &[])
        .expect("Owner adds Admin");
    advance(&mut context.svm);

    assert_custom_error(
        remove_authority(&mut context, &wallet, admin_pda, &admin, owner_pda),
        ERR_PERMISSION_DENIED,
        "an Admin may not remove an Owner",
    );
    advance(&mut context.svm);

    assert_custom_error(
        remove_authority(&mut context, &wallet, owner_pda, &owner_key, owner_pda),
        ERR_PERMISSION_DENIED,
        "and an Owner may not remove itself",
    );

    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 1);
    assert_eq!(authority_role(&context.svm, owner_pda), RANK_OWNER);
}

/// A batch of removals in one transaction cannot empty the wallet.
///
/// Note what actually holds the line here. Removing an Owner requires an Owner,
/// and an Owner cannot remove itself, so the remover always survives its own
/// batch — the count can be driven to one, never to zero, whatever the ordering.
/// `owner_count` is the belt to that braces: it is what would still refuse if
/// self-removal were ever relaxed, or if an Admin were ever given the power.
#[test]
fn a_batch_of_removals_cannot_empty_the_wallet() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let phone = Keypair::new();
    let tablet = Keypair::new();
    let phone_pda =
        owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[]).expect("second Owner");
    advance(&mut context.svm);
    let tablet_pda =
        owner_adds_ed25519(&mut context, &wallet, &tablet, RANK_OWNER, &[]).expect("third Owner");
    advance(&mut context.svm);
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 3);

    let owner_pda = wallet.owner_auth_pda;
    let owner_key = wallet.owner.insecure_clone();

    // Three removals in one transaction, ordered to strip every Owner: the
    // laptop removes both other devices, then itself.
    let ixs = [
        remove_authority_ix(&context, &wallet, owner_pda, &owner_key, phone_pda),
        remove_authority_ix(&context, &wallet, owner_pda, &owner_key, tablet_pda),
        remove_authority_ix(&context, &wallet, owner_pda, &owner_key, owner_pda),
    ];
    let payer = context.payer.insecure_clone();
    assert_custom_error(
        try_send(&mut context.svm, &payer, &ixs, &[&payer, &owner_key]),
        ERR_PERMISSION_DENIED,
        "the last removal must be refused",
    );

    // The whole transaction rolled back, so all three Owners are still there.
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 3);
    for pda in [owner_pda, phone_pda, tablet_pda] {
        assert_eq!(authority_role(&context.svm, pda), RANK_OWNER);
    }
}

/// The count one instruction writes is visible to the next in the same
/// transaction.
///
/// This is what stops the guard being defeated by staleness: the count lives in
/// account data rather than in a local, so a batch that read a snapshot from the
/// top of the transaction would let every instruction in it see the same
/// pre-batch value.
#[test]
fn the_owner_count_is_current_within_a_transaction() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let phone = Keypair::new();
    let tablet = Keypair::new();
    let phone_pda =
        owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[]).expect("second Owner");
    advance(&mut context.svm);
    let tablet_pda =
        owner_adds_ed25519(&mut context, &wallet, &tablet, RANK_OWNER, &[]).expect("third Owner");
    advance(&mut context.svm);

    let owner_pda = wallet.owner_auth_pda;
    let owner_key = wallet.owner.insecure_clone();

    // Two removals in one transaction. The second is legal only if it sees the
    // 3 -> 2 the first one wrote; against a stale 3 it would also be legal, so
    // the count assertion afterwards is what distinguishes them.
    let ixs = [
        remove_authority_ix(&context, &wallet, owner_pda, &owner_key, phone_pda),
        remove_authority_ix(&context, &wallet, owner_pda, &owner_key, tablet_pda),
    ];
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &ixs, &[&payer, &owner_key])
        .expect("two removals down to one Owner are legal");

    assert_eq!(
        wallet_owner_count(&context.svm, wallet.wallet_pda),
        1,
        "each removal decremented — a stale read would have left this at 2"
    );

    // And the survivor is genuinely the last one, so a further removal is out.
    advance(&mut context.svm);
    assert_custom_error(
        remove_authority(&mut context, &wallet, owner_pda, &owner_key, owner_pda),
        ERR_PERMISSION_DENIED,
        "nothing is left that can remove the last Owner",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Both Owners are real Owners
// ─────────────────────────────────────────────────────────────────────────

/// An added Owner is not a lesser Owner: it manages everything the original
/// does. Without this the feature would be a label rather than a capability.
#[test]
fn an_added_owner_has_the_full_owner_powers() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 10_000_000);

    let phone = Keypair::new();
    let phone_pda =
        owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[]).expect("second Owner");
    advance(&mut context.svm);

    // It can add an Admin…
    let admin = Keypair::new();
    let admin_pda = add_ed25519_authority(
        &mut context,
        &wallet,
        phone_pda,
        &phone,
        &admin,
        RANK_ADMIN,
        &[],
    )
    .expect("added Owner adds an Admin");
    advance(&mut context.svm);

    // …a Delegate…
    let delegate = Keypair::new();
    add_ed25519_authority(
        &mut context,
        &wallet,
        phone_pda,
        &phone,
        &delegate,
        RANK_DELEGATE,
        &action_sol_limit(1_000_000),
    )
    .expect("added Owner adds a Delegate");
    advance(&mut context.svm);

    // …and a third Owner.
    let tablet = Keypair::new();
    add_ed25519_authority(
        &mut context,
        &wallet,
        phone_pda,
        &phone,
        &tablet,
        RANK_OWNER,
        &[],
    )
    .expect("added Owner adds an Owner");
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 3);
    advance(&mut context.svm);

    // And it can revoke.
    remove_authority(&mut context, &wallet, phone_pda, &phone, admin_pda)
        .expect("added Owner removes an Admin");
    assert_eq!(wallet_owner_count(&context.svm, wallet.wallet_pda), 3);
}

/// An Owner spends the vault without a policy — rank is not a spending limit,
/// and adding Owners must not have quietly changed that.
#[test]
fn an_added_owner_can_spend_the_vault() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let phone = Keypair::new();
    owner_adds_ed25519(&mut context, &wallet, &phone, RANK_OWNER, &[]).expect("second Owner");
    advance(&mut context.svm);

    let phone_wallet = WalletFixture {
        user_seed: wallet.user_seed,
        owner: phone.insecure_clone(),
        wallet_pda: wallet.wallet_pda,
        vault_pda: wallet.vault_pda,
        owner_auth_pda: authority_pda_for(context.program_id, wallet.wallet_pda, &phone.pubkey()),
    };

    let recipient = Pubkey::new_unique();
    let ix = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &phone_wallet, recipient),
        data: vault_transfer_execute_data(1_000_000),
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &phone])
        .expect("an Owner spends without a policy");

    assert_eq!(
        context
            .svm
            .get_account(&recipient)
            .map(|a| a.lamports)
            .unwrap_or(0),
        1_000_000
    );
}
