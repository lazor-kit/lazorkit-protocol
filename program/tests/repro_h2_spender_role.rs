//! H-2 — `Execute` never read the authority's `role`, so a "Spender" had
//! exactly the same power over the vault as an Owner.
//!
//! The reproduction showed a Spender emptying a vault in two instructions while
//! still being correctly blocked from `AddAuthority` and `CreateSession`. That
//! asymmetry was the finding: `role` gated five management instructions and
//! nothing else, because a spending limit for an authority did not exist. It
//! only existed for sessions, as an action buffer.
//!
//! So the fix is not an `if` in Execute. It is splitting the one field that was
//! doing two jobs:
//!
//!   - **rank** — Owner / Admin / Delegate — governs management only
//!   - **policy** — an action buffer — governs spending, and any authority may
//!     carry one
//!
//! A Delegate must now carry a policy (3033), which makes the tier's name true:
//! it manages nothing and spends only what its policy allows. The same engine
//! that has always bounded sessions bounds it, through the same code path.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test repro_h2_spender_role

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::PermissionDenied`
const ERR_PERMISSION_DENIED: u32 = 3002;
/// `AuthError::ActionSolLimitExceeded`
const ERR_SOL_LIMIT_EXCEEDED: u32 = 3024;
/// `AuthError::DelegateRequiresPolicy`
const ERR_DELEGATE_REQUIRES_POLICY: u32 = 3033;
/// `AuthError::PolicyBearingAuthorityCannotDelegate`
const ERR_POLICY_BEARING_CANNOT_DELEGATE: u32 = 3034;

const RANK_ADMIN: u8 = 1;
const RANK_DELEGATE: u8 = 2;

/// Add an Ed25519 authority, optionally carrying a policy.
///
/// Large `Err` variant is litesvm's `FailedTransactionMetadata` — see the note
/// on `common::try_send`.
#[allow(clippy::result_large_err)]
fn add_ed25519_authority(
    context: &mut TestContext,
    wallet: &WalletFixture,
    authorizer_pda: Pubkey,
    authorizer_key: &Keypair,
    new_key: &Keypair,
    rank: u8,
    policy: &[u8],
) -> Result<Pubkey, litesvm::types::FailedTransactionMetadata> {
    let (new_auth_pda, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.wallet_pda.as_ref(),
            new_key.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    let mut data = vec![1u8]; // AddAuthority
    data.push(0); // authority_type = Ed25519
    data.push(rank);
    data.extend_from_slice(&[0u8; 6]); // padding
    data.extend_from_slice(new_key.pubkey().as_ref());
    // `[policy_len u16][policy]` sits between the key material and the auth
    // payload — the same shape CreateSession uses for its actions, and inside
    // the signed region for the same reason.
    data.extend_from_slice(&(policy.len() as u16).to_le_bytes());
    data.extend_from_slice(policy);

    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            // Writable: AddAuthority maintains the wallet's owner_count.
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(authorizer_pda, false),
            AccountMeta::new(new_auth_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(authorizer_key.pubkey(), true),
        ],
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, authorizer_key])?;
    Ok(new_auth_pda)
}

/// Convenience: add an authority authorized by the wallet's Owner.
#[allow(clippy::result_large_err)]
fn owner_adds(
    context: &mut TestContext,
    wallet: &WalletFixture,
    new_key: &Keypair,
    rank: u8,
    policy: &[u8],
) -> Result<Pubkey, litesvm::types::FailedTransactionMetadata> {
    let owner_pda = wallet.owner_auth_pda;
    let owner_key = wallet.owner.insecure_clone();
    add_ed25519_authority(
        context, wallet, owner_pda, &owner_key, new_key, rank, policy,
    )
}

/// `Execute` authorized by an arbitrary authority PDA + its Ed25519 signer.
fn execute_as(
    context: &TestContext,
    wallet: &WalletFixture,
    authority_pda: Pubkey,
    signer: &Keypair,
    recipient: Pubkey,
    lamports: u64,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(authority_pda, false),
                AccountMeta::new(wallet.vault_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(recipient, false),
                AccountMeta::new_readonly(signer.pubkey(), true),
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

/// A policy allowing SOL spending up to `limit`, through the System Program.
fn spend_limit_policy(limit: u64) -> Vec<u8> {
    let mut policy = action_sol_limit(limit);
    policy.extend_from_slice(&action_program_whitelist(solana_sdk::system_program::id()));
    policy
}

// ─────────────────────────────────────────────────────────────────────────
// H-2a — CONTROL: rank still gates the management instructions
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h2_a_control_delegate_is_blocked_from_privileged_instructions() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let delegate = Keypair::new();
    let delegate_auth = owner_adds(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &spend_limit_policy(1_000_000),
    )
    .expect("Owner may add a Delegate that carries a policy");

    let payer = context.payer.insecure_clone();

    // A Delegate cannot add authorities — blocked on rank, before the
    // policy-bearing rule is even reached.
    {
        let victim = Keypair::new();
        let result = add_ed25519_authority(
            &mut context,
            &wallet,
            delegate_auth,
            &delegate,
            &victim,
            RANK_DELEGATE,
            &spend_limit_policy(1_000_000),
        );
        assert_custom_error(
            result.map(|_| unreachable!()),
            ERR_PERMISSION_DENIED,
            "H-2a: a Delegate must not be able to add authorities",
        );
    }

    // A Delegate cannot create sessions.
    {
        advance(&mut context.svm);
        let session = Keypair::new();
        let (session_pda, _) = Pubkey::find_program_address(
            &[
                lazorkit_program::seeds::SESSION,
                wallet.wallet_pda.as_ref(),
                session.pubkey().as_ref(),
            ],
            &context.program_id,
        );
        let clock: solana_sdk::clock::Clock = context.svm.get_sysvar();

        let mut data = vec![5u8];
        data.extend_from_slice(session.pubkey().as_ref());
        data.extend_from_slice(&(clock.slot + 100_000).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        let ix = Instruction {
            program_id: context.program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(delegate_auth, false),
                AccountMeta::new(session_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(delegate.pubkey(), true),
            ],
            data,
        };

        assert_custom_error(
            try_send(&mut context.svm, &payer, &[ix], &[&payer, &delegate]),
            ERR_PERMISSION_DENIED,
            "H-2a: a Delegate must not be able to create sessions",
        );
    }
}

/// The escalation rule exists for a bounded **Admin**, not for a Delegate — a
/// Delegate is already stopped by rank. Without it, an Admin capped at 0.001 SOL
/// could mint a Delegate capped at 100, and the cap on the Admin would mean
/// nothing.
#[test]
fn h2_a_a_bounded_admin_cannot_mint_authorities() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    // An Admin that is itself bounded. Rank alone would let it add a Delegate.
    let admin = Keypair::new();
    let admin_auth = owner_adds(
        &mut context,
        &wallet,
        &admin,
        RANK_ADMIN,
        &spend_limit_policy(1_000_000),
    )
    .expect("an Admin may carry a policy");

    advance(&mut context.svm);
    let victim = Keypair::new();
    let result = add_ed25519_authority(
        &mut context,
        &wallet,
        admin_auth,
        &admin,
        &victim,
        RANK_DELEGATE,
        &spend_limit_policy(100_000_000_000),
    );
    assert_custom_error(
        result.map(|_| unreachable!()),
        ERR_POLICY_BEARING_CANNOT_DELEGATE,
        "H-2a: a bounded Admin must not be able to grant a larger allowance",
    );

    // An unbounded Admin still may — the rule is about the granter carrying a
    // policy, not about rank.
    advance(&mut context.svm);
    let plain_admin = Keypair::new();
    let plain_admin_auth = owner_adds(&mut context, &wallet, &plain_admin, RANK_ADMIN, &[])
        .expect("add unbounded Admin");
    advance(&mut context.svm);
    let ok = Keypair::new();
    add_ed25519_authority(
        &mut context,
        &wallet,
        plain_admin_auth,
        &plain_admin,
        &ok,
        RANK_DELEGATE,
        &spend_limit_policy(1_000_000),
    )
    .expect("H-2a: an unbounded Admin may still mint a Delegate");
}

// ─────────────────────────────────────────────────────────────────────────
// H-2b — the hole: Execute ignored rank entirely
// ─────────────────────────────────────────────────────────────────────────

/// Kept as the record of what the hole actually did, and runnable against a
/// pre-fix binary with `--ignored`. It cannot pass now: a Delegate without a
/// policy no longer exists to be created.
#[test]
#[ignore = "reproduces pre-fix behaviour; a policy-less Delegate is now rejected at creation"]
fn h2_b_spender_can_drain_the_whole_vault() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let spender = Keypair::new();
    let spender_auth = owner_adds(&mut context, &wallet, &spender, RANK_DELEGATE, &[])
        .expect("pre-fix: an unbounded Spender could be created");

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();
    let ix = execute_as(
        &context,
        &wallet,
        spender_auth,
        &spender,
        recipient,
        400_000_000,
    );
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &spender])
        .expect("pre-fix: Execute accepted a Spender with no limit at all");
}

// ─────────────────────────────────────────────────────────────────────────
// H-2c — a Delegate is bounded exactly as an equivalent session is
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h2_c_a_policy_less_delegate_cannot_be_created() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let spender = Keypair::new();
    let result = owner_adds(&mut context, &wallet, &spender, RANK_DELEGATE, &[]);
    assert_custom_error(
        result.map(|_| unreachable!()),
        ERR_DELEGATE_REQUIRES_POLICY,
        "H-2c: the unbounded Spender of the reproduction can no longer be minted",
    );

    // Admin is unaffected — it is a management tier, and an unbounded Admin is
    // a deliberate choice rather than a misleading name.
    advance(&mut context.svm);
    let admin = Keypair::new();
    owner_adds(&mut context, &wallet, &admin, RANK_ADMIN, &[])
        .expect("H-2c: an Admin without a policy is still legal");
}

#[test]
fn h2_c_a_delegate_is_bounded_by_its_policy() {
    let mut context = setup_test();
    let vault_funding = 500_000_000;
    let wallet = create_ed25519_wallet(&mut context, vault_funding);

    let allowance = 1_000_000u64;
    let delegate = Keypair::new();
    let delegate_auth = owner_adds(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &spend_limit_policy(allowance),
    )
    .expect("add Delegate");

    // The policy is stored on the authority, after its key material.
    let stored = context
        .svm
        .get_account(&delegate_auth)
        .expect("delegate authority exists")
        .data;
    assert_eq!(stored[2], RANK_DELEGATE, "stored with rank Delegate");
    let policy_len = u16::from_le_bytes(stored[12..14].try_into().unwrap()) as usize;
    assert!(policy_len > 0, "policy_len recorded in the header");
    assert_eq!(
        stored.len(),
        80 + policy_len,
        "an Ed25519 authority is 80 bytes plus its policy"
    );

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // Inside the allowance: permitted.
    let ix = execute_as(
        &context,
        &wallet,
        delegate_auth,
        &delegate,
        recipient,
        500_000,
    );
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &delegate])
        .expect("H-2c: spending inside the allowance must work");
    assert_eq!(lamports_of(&context, &recipient), 500_000);

    // Beyond it: refused, with the same error a session would raise. This is the
    // property the whole change exists to establish — the drain in the
    // reproduction is now bounded by the number the wallet owner chose.
    advance(&mut context.svm);
    let ix = execute_as(
        &context,
        &wallet,
        delegate_auth,
        &delegate,
        recipient,
        400_000_000,
    );
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &delegate]),
        ERR_SOL_LIMIT_EXCEEDED,
        "H-2c: a Delegate cannot spend past its policy",
    );

    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_funding - 500_000,
        "H-2c: only the permitted amount ever left the vault"
    );
}

/// The limit is cumulative across transactions, not per transaction — the same
/// semantics `SolLimit` has always had for sessions, now reached through the
/// authority path.
#[test]
fn h2_c_a_delegate_policy_depletes_across_transactions() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let delegate = Keypair::new();
    let delegate_auth = owner_adds(
        &mut context,
        &wallet,
        &delegate,
        RANK_DELEGATE,
        &spend_limit_policy(1_000_000),
    )
    .expect("add Delegate");

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    for _ in 0..2 {
        advance(&mut context.svm);
        let ix = execute_as(
            &context,
            &wallet,
            delegate_auth,
            &delegate,
            recipient,
            500_000,
        );
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &delegate])
            .expect("two withdrawals exactly exhaust the allowance");
    }
    assert_eq!(lamports_of(&context, &recipient), 1_000_000);

    // The third exceeds what is left, not what a single transaction may spend.
    advance(&mut context.svm);
    let ix = execute_as(&context, &wallet, delegate_auth, &delegate, recipient, 1);
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &delegate]),
        ERR_SOL_LIMIT_EXCEEDED,
        "H-2c: the allowance is cumulative and now spent",
    );
}

/// Owner and Admin keep unbounded Execute — the fix bounds the tier that was
/// misnamed, it does not demote the tiers above it.
#[test]
fn h2_c_owner_and_admin_still_execute_without_a_policy() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let admin = Keypair::new();
    let admin_auth = owner_adds(&mut context, &wallet, &admin, RANK_ADMIN, &[]).expect("add Admin");

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    advance(&mut context.svm);
    let ix = execute_as(
        &context,
        &wallet,
        admin_auth,
        &admin,
        recipient,
        100_000_000,
    );
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &admin])
        .expect("H-2c: an Admin executes without a policy");

    advance(&mut context.svm);
    let ix = execute_as(
        &context,
        &wallet,
        wallet.owner_auth_pda,
        &wallet.owner,
        recipient,
        100_000_000,
    );
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
        .expect("H-2c: so does the Owner");

    assert_eq!(lamports_of(&context, &recipient), 200_000_000);
}
