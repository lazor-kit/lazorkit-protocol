//! `MigrateWallet` — moving a v1 wallet's SOL and SPL tokens onto v2.
//!
//! The situation this exists for is live on mainnet: the vanity program id holds
//! a v1 deployment with real users, v2 is an in-place upgrade whose `lk2:` seeds
//! make every v1 PDA unreachable through the normal paths, and a user's funds
//! can only be moved by that user's own key. `MigrateWallet` is the one path
//! that bridges the two, authorized by the v1 authority.
//!
//! These tests fabricate v1-shaped accounts directly — old seeds, old
//! discriminators, the v1 authority layout — because that is exactly what an
//! upgraded binary finds on chain. A companion validator script
//! (`scripts/rehearse-migrate.sh`) proves the same thing through a real in-place
//! `solana program deploy --upgrade`, which is the mainnet mechanism; this file
//! proves the instruction logic.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test migrate_v1_tests

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

const DISC_MIGRATE: u8 = 17;

// v1 constants — bare seeds, old discriminators. Mirrors `legacy` in the program.
const V1_WALLET_SEED: &[u8] = b"wallet";
const V1_VAULT_SEED: &[u8] = b"vault";
const V1_AUTHORITY_SEED: &[u8] = b"authority";
const V1_DISC_WALLET: u8 = 1;
const V1_DISC_AUTHORITY: u8 = 2;

struct V1Wallet {
    owner: Keypair,
    wallet: Pubkey,
    vault: Pubkey,
    authority: Pubkey,
}

/// Fabricate a v1 wallet controlled by an Ed25519 owner, funded with `lamports`.
fn fabricate_v1_ed25519_wallet(context: &mut TestContext, lamports: u64) -> V1Wallet {
    let program_id = context.program_id;
    let user_seed = rand::random::<[u8; 32]>();
    let owner = Keypair::new();

    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&[V1_WALLET_SEED, &user_seed], &program_id);
    let (vault, _) = Pubkey::find_program_address(&[V1_VAULT_SEED, wallet.as_ref()], &program_id);
    let (authority, auth_bump) = Pubkey::find_program_address(
        &[V1_AUTHORITY_SEED, wallet.as_ref(), owner.pubkey().as_ref()],
        &program_id,
    );

    // v1 WalletAccount — 8 bytes: disc(1) bump(1) version(1) pad(5).
    let mut wdata = vec![0u8; 8];
    wdata[0] = V1_DISC_WALLET;
    wdata[1] = wallet_bump;
    wdata[2] = 1; // version
    set_program_account(context, wallet, wdata);

    // v1 AuthorityAccountHeader (48) + Ed25519 pubkey (32) = 80 bytes.
    // disc(1) type(1) role(1) bump(1) version(1) pad(3) counter(4) pad(4) wallet(32)
    let mut adata = vec![0u8; 80];
    adata[0] = V1_DISC_AUTHORITY;
    adata[1] = 0; // Ed25519
    adata[2] = 0; // Owner
    adata[3] = auth_bump;
    adata[4] = 1; // version
                  // counter stays 0, padding stays 0
    adata[16..48].copy_from_slice(wallet.as_ref());
    adata[48..80].copy_from_slice(owner.pubkey().as_ref());
    set_program_account(context, authority, adata);

    // v1 vault — system-owned, no data, funded.
    context
        .svm
        .set_account(
            vault,
            solana_sdk::account::Account {
                lamports,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set v1 vault");

    V1Wallet {
        owner,
        wallet,
        vault,
        authority,
    }
}

/// Write a program-owned account with the given data, rent-exempt for its size.
fn set_program_account(context: &mut TestContext, key: Pubkey, data: Vec<u8>) {
    let lamports = 1_000_000 + (data.len() as u64) * 7_000;
    context
        .svm
        .set_account(
            key,
            solana_sdk::account::Account {
                lamports,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set program account");
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}

fn token_amount(context: &TestContext, ata: Pubkey) -> u64 {
    let d = context.svm.get_account(&ata).expect("token account").data;
    u64::from_le_bytes(d[64..72].try_into().unwrap())
}

/// The fixed 10-account prefix every MigrateWallet shares.
fn migrate_prefix(
    context: &TestContext,
    v1: &V1Wallet,
    destination: Pubkey,
    refund_dest: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new(v1.wallet, false),
        AccountMeta::new(v1.authority, false),
        AccountMeta::new(v1.vault, false),
        AccountMeta::new(destination, false),
        AccountMeta::new(refund_dest, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(spl_token_id(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        AccountMeta::new_readonly(v1.owner.pubkey(), true),
    ]
}

// ─────────────────────────────────────────────────────────────────────────
// SOL only
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn migrates_vault_sol_and_closes_the_v1_pdas() {
    let mut context = setup_test();
    let vault_funds = 2_000_000_000u64;
    let v1 = fabricate_v1_ed25519_wallet(&mut context, vault_funds);

    let destination = Pubkey::new_unique(); // stands in for the v2 vault
    let refund_dest = Pubkey::new_unique();

    let wallet_rent = lamports_of(&context, &v1.wallet);
    let auth_rent = lamports_of(&context, &v1.authority);

    let ix = Instruction {
        program_id: context.program_id,
        accounts: migrate_prefix(&context, &v1, destination, refund_dest),
        data: vec![DISC_MIGRATE, 0], // num_tokens = 0
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &v1.owner])
        .expect("migrate SOL must succeed");

    // SOL landed at the destination.
    assert_eq!(lamports_of(&context, &destination), vault_funds);
    assert_eq!(lamports_of(&context, &v1.vault), 0);

    // v1 PDAs closed, their rent refunded to the named destination.
    assert_eq!(lamports_of(&context, &v1.wallet), 0);
    assert_eq!(lamports_of(&context, &v1.authority), 0);
    assert_eq!(lamports_of(&context, &refund_dest), wallet_rent + auth_rent);
}

// ─────────────────────────────────────────────────────────────────────────
// SOL + SPL token (the USDC case)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn migrates_vault_sol_and_an_spl_token() {
    let mut context = setup_test();
    let vault_funds = 1_500_000_000u64;
    let v1 = fabricate_v1_ed25519_wallet(&mut context, vault_funds);

    // A mint standing in for USDC, and the v1 vault's token account holding it.
    let mint = Pubkey::new_unique();
    create_mint(&mut context.svm, mint, Pubkey::new_unique(), 1_000_000_000);
    let source_ata = Pubkey::new_unique();
    let token_amount_held = 250_000_000u64; // 250 "USDC"
    create_token_account(
        &mut context.svm,
        source_ata,
        mint,
        v1.vault,
        token_amount_held,
    );

    // The v2-side destination and its token account (owner = destination).
    let destination = Pubkey::new_unique();
    let dest_ata = Pubkey::new_unique();
    create_token_account(&mut context.svm, dest_ata, mint, destination, 0);
    let refund_dest = Pubkey::new_unique();

    let source_ata_rent = lamports_of(&context, &source_ata);

    let mut accounts = migrate_prefix(&context, &v1, destination, refund_dest);
    accounts.push(AccountMeta::new(source_ata, false));
    accounts.push(AccountMeta::new(dest_ata, false));

    let ix = Instruction {
        program_id: context.program_id,
        accounts,
        data: vec![DISC_MIGRATE, 1], // num_tokens = 1
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &v1.owner])
        .expect("migrate SOL + token must succeed");

    // Token moved in full to the destination's account.
    assert_eq!(token_amount(&context, dest_ata), token_amount_held);
    // Source token account emptied and closed, its rent refunded.
    assert!(
        context
            .svm
            .get_account(&source_ata)
            .map(|a| a.lamports)
            .unwrap_or(0)
            == 0,
        "source ATA should be closed"
    );
    // SOL swept too.
    assert_eq!(lamports_of(&context, &destination), vault_funds);
    // Refund got the source ATA rent plus the two PDA rents.
    assert!(lamports_of(&context, &refund_dest) >= source_ata_rent);
}

// ─────────────────────────────────────────────────────────────────────────
// Authorization
// ─────────────────────────────────────────────────────────────────────────

/// Without the owner's signature there is no migration — this is the property
/// that makes MigrateWallet a convenience and not a backdoor.
#[test]
fn migrate_without_the_owner_signature_is_refused() {
    let mut context = setup_test();
    let v1 = fabricate_v1_ed25519_wallet(&mut context, 1_000_000_000);

    let destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();

    // The owner is listed but NOT a signer.
    let mut accounts = migrate_prefix(&context, &v1, destination, refund_dest);
    accounts[9] = AccountMeta::new_readonly(v1.owner.pubkey(), false);

    let ix = Instruction {
        program_id: context.program_id,
        accounts,
        data: vec![DISC_MIGRATE, 0],
    };
    let payer = context.payer.insecure_clone();
    let result = try_send(&mut context.svm, &payer, &[ix], &[&payer]);
    assert!(result.is_err(), "migration without the owner key must fail");
    // Nothing moved.
    assert_eq!(lamports_of(&context, &destination), 0);
    assert_eq!(lamports_of(&context, &v1.vault), 1_000_000_000);
}

/// A different key cannot migrate someone else's wallet, even signing.
#[test]
fn migrate_with_the_wrong_key_is_refused() {
    let mut context = setup_test();
    let v1 = fabricate_v1_ed25519_wallet(&mut context, 1_000_000_000);

    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&attacker.pubkey(), 100_000_000)
        .unwrap();

    let destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();

    let mut accounts = migrate_prefix(&context, &v1, destination, refund_dest);
    accounts[9] = AccountMeta::new_readonly(attacker.pubkey(), true);

    let ix = Instruction {
        program_id: context.program_id,
        accounts,
        data: vec![DISC_MIGRATE, 0],
    };
    let payer = context.payer.insecure_clone();
    let result = try_send(&mut context.svm, &payer, &[ix], &[&payer, &attacker]);
    assert!(result.is_err(), "a stranger cannot migrate the wallet");
    assert_eq!(lamports_of(&context, &v1.vault), 1_000_000_000);
}

/// A v2-discriminator authority is not a v1 account and must be rejected — the
/// migrate path is only for the old world.
#[test]
fn migrate_refuses_a_non_v1_wallet() {
    let mut context = setup_test();
    let v1 = fabricate_v1_ed25519_wallet(&mut context, 1_000_000_000);

    // Corrupt the wallet discriminator to the v2 value.
    let mut wdata = context.svm.get_account(&v1.wallet).unwrap().data;
    wdata[0] = 0x21; // AccountDiscriminator::Wallet (v2)
    set_program_account(&mut context, v1.wallet, wdata);

    let destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();
    let ix = Instruction {
        program_id: context.program_id,
        accounts: migrate_prefix(&context, &v1, destination, refund_dest),
        data: vec![DISC_MIGRATE, 0],
    };
    let payer = context.payer.insecure_clone();
    assert!(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &v1.owner]).is_err(),
        "a v2-shaped wallet must not be migratable through the v1 path"
    );
}
