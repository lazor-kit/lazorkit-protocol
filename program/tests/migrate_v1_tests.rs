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
    accounts.push(AccountMeta::new_readonly(spl_token_id(), false));

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
    accounts[8] = AccountMeta::new_readonly(v1.owner.pubkey(), false);

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
    accounts[8] = AccountMeta::new_readonly(attacker.pubkey(), true);

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

// ─────────────────────────────────────────────────────────────────────────
// Secp256r1 (passkey) — the path 85% of mainnet uses
// ─────────────────────────────────────────────────────────────────────────

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};
use sha2::Digest;

struct V1Passkey {
    signing_key: SigningKey,
    rp_id: String,
    wallet: Pubkey,
    vault: Pubkey,
    authority: Pubkey,
}

/// Fabricate a v1 wallet controlled by a Secp256r1 passkey, funded with SOL.
fn fabricate_v1_passkey_wallet(context: &mut TestContext, lamports: u64) -> V1Passkey {
    let program_id = context.program_id;
    let user_seed = rand::random::<[u8; 32]>();
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let pubkey_compressed = VerifyingKey::from(&signing_key)
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let credential_id_hash = rand::random::<[u8; 32]>();
    let rp_id = "lazorkit.mainnet".to_string();
    let rp_id_hash: [u8; 32] = sha2::Sha256::digest(rp_id.as_bytes()).into();

    let (wallet, wallet_bump) =
        Pubkey::find_program_address(&[V1_WALLET_SEED, &user_seed], &program_id);
    let (vault, _) = Pubkey::find_program_address(&[V1_VAULT_SEED, wallet.as_ref()], &program_id);
    let (authority, auth_bump) = Pubkey::find_program_address(
        &[V1_AUTHORITY_SEED, wallet.as_ref(), &credential_id_hash],
        &program_id,
    );

    let mut wdata = vec![0u8; 8];
    wdata[0] = V1_DISC_WALLET;
    wdata[1] = wallet_bump;
    wdata[2] = 1;
    set_program_account(context, wallet, wdata);

    // v1 secp authority: header(48) ‖ credential_hash(32) ‖ pubkey(33) ‖ rpIdHash(32) = 145.
    let mut adata = vec![0u8; 145];
    adata[0] = V1_DISC_AUTHORITY;
    adata[1] = 1; // Secp256r1
    adata[2] = 0; // Owner
    adata[3] = auth_bump;
    adata[4] = 1; // version
    adata[16..48].copy_from_slice(wallet.as_ref());
    adata[48..80].copy_from_slice(&credential_id_hash);
    adata[80..113].copy_from_slice(&pubkey_compressed);
    adata[113..145].copy_from_slice(&rp_id_hash);
    set_program_account(context, authority, adata);

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

    V1Passkey {
        signing_key,
        rp_id,
        wallet,
        vault,
        authority,
    }
}

fn base64url_no_pad(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        out.push(A[((b >> 18) & 0x3f) as usize] as char);
        out.push(A[((b >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((b >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(b & 0x3f) as usize] as char);
        }
    }
    out
}

/// The Secp256r1 precompile instruction, in the exact fixed-offset layout the
/// program's introspection requires (signature@16, pubkey@80, message@114, all
/// indices self-referential 0xFFFF). The generic SDK builder lays the fields out
/// differently, so this mirrors `buildSecp256r1PrecompileIx` in sdk-legacy.
fn build_secp256r1_precompile_ix(
    pubkey33: &[u8; 33],
    sig64: &[u8; 64],
    message: &[u8],
) -> Instruction {
    const HEADER: usize = 16;
    let sig_off = HEADER;
    let pk_off = sig_off + 64;
    let msg_off = pk_off + 33 + 1; // 1 byte alignment padding
    let mut data = vec![0u8; msg_off + message.len()];
    data[0] = 1; // num signatures
    data[1] = 0; // padding
    data[2..4].copy_from_slice(&(sig_off as u16).to_le_bytes());
    data[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[6..8].copy_from_slice(&(pk_off as u16).to_le_bytes());
    data[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[10..12].copy_from_slice(&(msg_off as u16).to_le_bytes());
    data[12..14].copy_from_slice(&(message.len() as u16).to_le_bytes());
    data[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[sig_off..sig_off + 64].copy_from_slice(sig64);
    data[pk_off..pk_off + 33].copy_from_slice(pubkey33);
    data[msg_off..msg_off + message.len()].copy_from_slice(message);
    Instruction {
        program_id: "Secp256r1SigVerify1111111111111111111111111"
            .parse()
            .unwrap(),
        accounts: vec![],
        data,
    }
}

/// Build the `[precompile, migrate]` instruction pair a passkey signs.
///
/// `signed_destination` is what the passkey commits to; `sysvar_ix_index` is
/// where the instructions sysvar sits in the migrate account list (8).
fn build_passkey_migrate(
    context: &TestContext,
    pk: &V1Passkey,
    signed_destination: Pubkey,
    migrate_accounts: Vec<AccountMeta>,
    num_tokens: u8,
) -> [Instruction; 2] {
    let program_id = context.program_id;
    let payer = context.payer.pubkey();
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let counter: u32 = 1; // stored 0 + 1
    let sysvar_ix_index: u8 = 7;

    // auth_payload prefix (14 bytes): slot(8) counter(4) sysvarIdx(1) flags(1)
    let mut prefix = Vec::with_capacity(14);
    prefix.extend_from_slice(&slot.to_le_bytes());
    prefix.extend_from_slice(&counter.to_le_bytes());
    prefix.push(sysvar_ix_index);
    prefix.push(0);

    // signed_payload = destination ‖ v1_wallet ‖ num_tokens ‖ refund_dest ‖
    //                  source_ata[0..num_tokens] — the program's order. refund_dest
    //                  is accounts[5]; the token triples start at accounts[9], so
    //                  each source ATA is accounts[9 + i*3].
    let refund_dest = migrate_accounts[5].pubkey;
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(signed_destination.as_ref());
    signed_payload.extend_from_slice(pk.wallet.as_ref());
    signed_payload.push(num_tokens);
    signed_payload.extend_from_slice(refund_dest.as_ref());
    for i in 0..num_tokens as usize {
        signed_payload.extend_from_slice(migrate_accounts[9 + i * 3].pubkey.as_ref());
    }

    // challenge_hash = SHA256(disc ‖ prefix14 ‖ signed_payload ‖ payer ‖ counter ‖ program_id)
    let mut h = sha2::Sha256::new();
    h.update([17u8]);
    h.update(&prefix);
    h.update(&signed_payload);
    h.update(payer.as_ref());
    h.update(counter.to_le_bytes());
    h.update(program_id.as_ref());
    let challenge_hash: [u8; 32] = h.finalize().into();

    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
        base64url_no_pad(&challenge_hash),
        pk.rp_id
    );
    let cdj_hash: [u8; 32] = sha2::Sha256::digest(client_data_json.as_bytes()).into();

    let rp_id_hash: [u8; 32] = sha2::Sha256::digest(pk.rp_id.as_bytes()).into();
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0x01); // user present
    authenticator_data.extend_from_slice(&1u32.to_be_bytes()); // webauthn counter

    let mut message = authenticator_data.clone();
    message.extend_from_slice(&cdj_hash);

    // The Secp256r1 precompile requires a low-S signature; p256 does not
    // normalize by default.
    let sig: Signature = pk.signing_key.sign(&message);
    let sig = sig.normalize_s().unwrap_or(sig);
    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    let pubkey_compressed: [u8; 33] = VerifyingKey::from(&pk.signing_key)
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let precompile_ix = build_secp256r1_precompile_ix(&pubkey_compressed, &sig_bytes, &message);

    // Full auth_payload: prefix14 ‖ authDataLen(2) ‖ authData ‖ cdjLen(2) ‖ cdj
    let mut auth_payload = prefix;
    auth_payload.extend_from_slice(&(authenticator_data.len() as u16).to_le_bytes());
    auth_payload.extend_from_slice(&authenticator_data);
    auth_payload.extend_from_slice(&(client_data_json.len() as u16).to_le_bytes());
    auth_payload.extend_from_slice(client_data_json.as_bytes());

    let mut data = vec![DISC_MIGRATE, num_tokens];
    data.extend_from_slice(&auth_payload);

    let migrate_ix = Instruction {
        program_id,
        accounts: migrate_accounts,
        data,
    };
    [precompile_ix, migrate_ix]
}

/// Passkey account prefix — index 9 (Ed25519 signer slot) is unused, filled with
/// the payer as a non-signer placeholder.
fn passkey_prefix(
    context: &TestContext,
    pk: &V1Passkey,
    destination: Pubkey,
    refund_dest: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new(pk.wallet, false),
        AccountMeta::new(pk.authority, false),
        AccountMeta::new(pk.vault, false),
        AccountMeta::new(destination, false),
        AccountMeta::new(refund_dest, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        AccountMeta::new_readonly(context.payer.pubkey(), false),
    ]
}

#[test]
fn passkey_migrates_vault_sol_and_token() {
    let mut context = setup_test();
    let vault_funds = 1_200_000_000u64;
    let pk = fabricate_v1_passkey_wallet(&mut context, vault_funds);

    let mint = Pubkey::new_unique();
    create_mint(&mut context.svm, mint, Pubkey::new_unique(), 1_000_000_000);
    let source_ata = Pubkey::new_unique();
    let held = 74_000_000u64; // 74 "USDC"
    create_token_account(&mut context.svm, source_ata, mint, pk.vault, held);

    let destination = Pubkey::new_unique();
    let dest_ata = Pubkey::new_unique();
    create_token_account(&mut context.svm, dest_ata, mint, destination, 0);
    let refund_dest = Pubkey::new_unique();

    let mut accounts = passkey_prefix(&context, &pk, destination, refund_dest);
    accounts.push(AccountMeta::new(source_ata, false));
    accounts.push(AccountMeta::new(dest_ata, false));
    accounts.push(AccountMeta::new_readonly(spl_token_id(), false));

    let ixs = build_passkey_migrate(&context, &pk, destination, accounts, 1);
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &ixs, &[&payer]).expect("passkey migrate must succeed");

    assert_eq!(token_amount(&context, dest_ata), held);
    assert_eq!(lamports_of(&context, &destination), vault_funds);
    assert_eq!(lamports_of(&context, &pk.vault), 0);
    assert_eq!(lamports_of(&context, &pk.wallet), 0);
    assert_eq!(lamports_of(&context, &pk.authority), 0);
}

/// The passkey signs approval for one destination. A relayer that swaps in a
/// different destination breaks the challenge, so the sweep cannot be
/// redirected — this is the anti-redirect binding, on the path that matters.
#[test]
fn passkey_migrate_cannot_be_redirected() {
    let mut context = setup_test();
    let pk = fabricate_v1_passkey_wallet(&mut context, 1_000_000_000);

    let signed_destination = Pubkey::new_unique();
    let attacker_destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();

    // Sign for `signed_destination`, but build the account list with the
    // attacker's destination at index 4.
    let accounts = passkey_prefix(&context, &pk, attacker_destination, refund_dest);
    let ixs = build_passkey_migrate(&context, &pk, signed_destination, accounts, 0);

    let payer = context.payer.insecure_clone();
    let result = try_send(&mut context.svm, &payer, &ixs, &[&payer]);
    let err = format!("{:?}", result.as_ref().err().unwrap());
    assert!(
        err.contains("Custom(3005)"),
        "expected InvalidMessageHash (3005) from the destination binding, got: {err}"
    );
    assert_eq!(lamports_of(&context, &pk.vault), 1_000_000_000);
    assert_eq!(lamports_of(&context, &attacker_destination), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Regression tests for the independent-review findings
// ─────────────────────────────────────────────────────────────────────────

/// HIGH: only an Owner may migrate. A bounded Delegate (or an Admin) whose key
/// signs must NOT be able to drain and close the whole wallet — that would
/// defeat the spending policy that is the only thing limiting a non-Owner.
#[test]
fn migrate_refuses_a_non_owner_authority() {
    for rank in [1u8 /* Admin */, 2u8 /* Delegate */] {
        let mut context = setup_test();
        let v1 = fabricate_v1_ed25519_wallet(&mut context, 1_000_000_000);
        let mut adata = context.svm.get_account(&v1.authority).unwrap().data;
        adata[2] = rank;
        set_program_account(&mut context, v1.authority, adata);

        let destination = Pubkey::new_unique();
        let refund_dest = Pubkey::new_unique();
        let ix = solana_sdk::instruction::Instruction {
            program_id: context.program_id,
            accounts: migrate_prefix(&context, &v1, destination, refund_dest),
            data: vec![DISC_MIGRATE, 0],
        };
        let payer = context.payer.insecure_clone();
        assert_custom_error(
            try_send(&mut context.svm, &payer, &[ix], &[&payer, &v1.owner]),
            3002,
            &format!("rank {rank} must not be able to migrate"),
        );
        assert_eq!(
            lamports_of(&context, &v1.vault),
            1_000_000_000,
            "vault untouched when a non-Owner tries to migrate"
        );
    }
}

/// MEDIUM: a passkey signs how many token accounts it is migrating. A relayer
/// that drops `num_tokens` to 0 — to sweep the SOL and let the close strand the
/// tokens — breaks the challenge.
#[test]
fn passkey_migrate_relayer_cannot_drop_tokens() {
    let mut context = setup_test();
    let pk = fabricate_v1_passkey_wallet(&mut context, 1_000_000_000);

    let mint = Pubkey::new_unique();
    create_mint(&mut context.svm, mint, Pubkey::new_unique(), 1_000_000_000);
    let source_ata = Pubkey::new_unique();
    create_token_account(&mut context.svm, source_ata, mint, pk.vault, 50_000_000);
    let destination = Pubkey::new_unique();
    let dest_ata = Pubkey::new_unique();
    create_token_account(&mut context.svm, dest_ata, mint, destination, 0);
    let refund_dest = Pubkey::new_unique();

    // The owner signs a migration of 1 token.
    let mut accounts = passkey_prefix(&context, &pk, destination, refund_dest);
    accounts.push(AccountMeta::new(source_ata, false));
    accounts.push(AccountMeta::new(dest_ata, false));
    accounts.push(AccountMeta::new_readonly(spl_token_id(), false));
    let ixs = build_passkey_migrate(&context, &pk, destination, accounts, 1);

    // The relayer strips the token pair and rewrites num_tokens to 0, keeping the
    // passkey-signed precompile (which committed to num_tokens = 1).
    let precompile = ixs[0].clone();
    let mut tampered = ixs[1].clone();
    tampered.data[1] = 0; // num_tokens 1 -> 0
    tampered.accounts.truncate(9); // drop the token triple

    let payer = context.payer.insecure_clone();
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[precompile, tampered], &[&payer]),
        3005,
        "dropping num_tokens after signing must break the challenge",
    );
    assert_eq!(
        token_amount(&context, source_ata),
        50_000_000,
        "tokens stay put; nothing stranded"
    );
    assert_eq!(
        lamports_of(&context, &pk.vault),
        1_000_000_000,
        "SOL untouched"
    );
}

/// HIGH: the signature binds WHICH token accounts move, not just how many. A
/// relayer cannot keep `num_tokens` and swap the approved source ATA for dust it
/// created, which would migrate the dust and strand the real token on close.
#[test]
fn passkey_migrate_relayer_cannot_swap_token_set() {
    let mut context = setup_test();
    let pk = fabricate_v1_passkey_wallet(&mut context, 1_000_000_000);

    // The token the owner actually approved.
    let mint_a = Pubkey::new_unique();
    create_mint(
        &mut context.svm,
        mint_a,
        Pubkey::new_unique(),
        1_000_000_000,
    );
    let source_a = Pubkey::new_unique();
    create_token_account(&mut context.svm, source_a, mint_a, pk.vault, 74_000_000);
    let destination = Pubkey::new_unique();
    let dest_a = Pubkey::new_unique();
    create_token_account(&mut context.svm, dest_a, mint_a, destination, 0);
    let refund_dest = Pubkey::new_unique();

    // Dust the relayer manufactured: a second vault-owned token account it would
    // migrate instead, leaving `source_a` behind to be stranded on close.
    let mint_b = Pubkey::new_unique();
    create_mint(
        &mut context.svm,
        mint_b,
        Pubkey::new_unique(),
        1_000_000_000,
    );
    let source_b = Pubkey::new_unique();
    create_token_account(&mut context.svm, source_b, mint_b, pk.vault, 1);
    let dest_b = Pubkey::new_unique();
    create_token_account(&mut context.svm, dest_b, mint_b, destination, 0);

    // Owner signs a migration of source_a (num_tokens = 1).
    let mut accounts = passkey_prefix(&context, &pk, destination, refund_dest);
    accounts.push(AccountMeta::new(source_a, false));
    accounts.push(AccountMeta::new(dest_a, false));
    accounts.push(AccountMeta::new_readonly(spl_token_id(), false));
    let ixs = build_passkey_migrate(&context, &pk, destination, accounts, 1);

    // Relayer swaps in the dust triple, keeping num_tokens = 1 and the passkey
    // precompile that committed to source_a.
    let precompile = ixs[0].clone();
    let mut tampered = ixs[1].clone();
    tampered.accounts[9] = AccountMeta::new(source_b, false);
    tampered.accounts[10] = AccountMeta::new(dest_b, false);

    let payer = context.payer.insecure_clone();
    assert_custom_error(
        try_send(&mut context.svm, &payer, &[precompile, tampered], &[&payer]),
        3005,
        "swapping the source ATA after signing must break the challenge",
    );
    assert_eq!(
        token_amount(&context, source_a),
        74_000_000,
        "the approved token stays put; nothing stranded"
    );
    assert_eq!(
        lamports_of(&context, &pk.vault),
        1_000_000_000,
        "SOL untouched"
    );
}

/// LOW: the signature binds the wallet being migrated, so a passkey assertion
/// for one wallet cannot be replayed against another wallet the same key
/// controls.
#[test]
fn passkey_migrate_signature_is_wallet_bound() {
    let mut context = setup_test();
    let pk_a = fabricate_v1_passkey_wallet(&mut context, 1_000_000_000);

    // A second wallet controlled by the SAME passkey (same signing key + rpId,
    // fresh credential/user seed → a distinct authority PDA storing the same key).
    let program_id = context.program_id;
    let user_seed_b = rand::random::<[u8; 32]>();
    let pubkey_compressed = VerifyingKey::from(&pk_a.signing_key)
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let credential_b = rand::random::<[u8; 32]>();
    let rp_id_hash: [u8; 32] = sha2::Sha256::digest(pk_a.rp_id.as_bytes()).into();
    let (wallet_b, wb_bump) =
        Pubkey::find_program_address(&[V1_WALLET_SEED, &user_seed_b], &program_id);
    let (vault_b, _) =
        Pubkey::find_program_address(&[V1_VAULT_SEED, wallet_b.as_ref()], &program_id);
    let (auth_b, ab_bump) = Pubkey::find_program_address(
        &[V1_AUTHORITY_SEED, wallet_b.as_ref(), &credential_b],
        &program_id,
    );
    let mut wdata = vec![0u8; 8];
    wdata[0] = 1;
    wdata[1] = wb_bump;
    wdata[2] = 1;
    set_program_account(&mut context, wallet_b, wdata);
    let mut adata = vec![0u8; 145];
    adata[0] = 2;
    adata[1] = 1;
    adata[2] = 0;
    adata[3] = ab_bump;
    adata[4] = 1;
    wallet_b
        .to_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, b)| adata[16 + i] = *b);
    adata[48..80].copy_from_slice(&credential_b);
    adata[80..113].copy_from_slice(&pubkey_compressed);
    adata[113..145].copy_from_slice(&rp_id_hash);
    set_program_account(&mut context, auth_b, adata);
    context
        .svm
        .set_account(
            vault_b,
            solana_sdk::account::Account {
                lamports: 1_000_000_000,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let pk_b = V1Passkey {
        signing_key: pk_a.signing_key.clone(),
        rp_id: pk_a.rp_id.clone(),
        wallet: wallet_b,
        vault: vault_b,
        authority: auth_b,
    };

    // Sign a migration of wallet A to `destination`…
    let destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();
    let accounts_a = passkey_prefix(&context, &pk_a, destination, refund_dest);
    let ixs_a = build_passkey_migrate(&context, &pk_a, destination, accounts_a, 0);

    // …then replay that precompile against wallet B (same destination, same key).
    let precompile = ixs_a[0].clone();
    let migrate_b = solana_sdk::instruction::Instruction {
        program_id,
        accounts: passkey_prefix(&context, &pk_b, destination, refund_dest),
        data: ixs_a[1].data.clone(),
    };
    let payer = context.payer.insecure_clone();
    assert_custom_error(
        try_send(
            &mut context.svm,
            &payer,
            &[precompile, migrate_b],
            &[&payer],
        ),
        3005,
        "a signature for wallet A must not migrate wallet B",
    );
    assert_eq!(
        lamports_of(&context, &vault_b),
        1_000_000_000,
        "wallet B untouched"
    );
}

/// The reason token accounts carry their own program: a vault holding BOTH SPL
/// Token and Token-2022 assets migrates in one call. A single fixed
/// token-program account could not express this.
#[test]
fn migrates_mixed_spl_and_token_2022_in_one_call() {
    use solana_sdk::account::Account;
    let token_2022 = Pubkey::try_from("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();

    // Fabricate a token account owned by an arbitrary token program.
    let set_token = |context: &mut TestContext,
                     addr: Pubkey,
                     mint: Pubkey,
                     owner: Pubkey,
                     amount: u64,
                     program: Pubkey| {
        let mut data = vec![0u8; 165];
        data[0..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(owner.as_ref());
        data[64..72].copy_from_slice(&amount.to_le_bytes());
        data[108] = 1; // initialized
        context
            .svm
            .set_account(
                addr,
                Account {
                    lamports: 2_039_280,
                    data,
                    owner: program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    };
    let set_mint = |context: &mut TestContext, mint: Pubkey, program: Pubkey| {
        let mut data = vec![0u8; 82];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[44] = 6;
        data[45] = 1;
        context
            .svm
            .set_account(
                mint,
                Account {
                    lamports: 1_461_600,
                    data,
                    owner: program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    };

    let mut context = setup_test();
    let v1 = fabricate_v1_ed25519_wallet(&mut context, 1_000_000_000);
    let destination = Pubkey::new_unique();
    let refund_dest = Pubkey::new_unique();

    // Classic SPL token.
    let mint_a = Pubkey::new_unique();
    create_mint(
        &mut context.svm,
        mint_a,
        Pubkey::new_unique(),
        1_000_000_000,
    );
    let src_a = Pubkey::new_unique();
    let dst_a = Pubkey::new_unique();
    create_token_account(&mut context.svm, src_a, mint_a, v1.vault, 40_000_000);
    create_token_account(&mut context.svm, dst_a, mint_a, destination, 0);

    // Token-2022.
    let mint_b = Pubkey::new_unique();
    set_mint(&mut context, mint_b, token_2022);
    let src_b = Pubkey::new_unique();
    let dst_b = Pubkey::new_unique();
    set_token(
        &mut context,
        src_b,
        mint_b,
        v1.vault,
        33_000_000,
        token_2022,
    );
    set_token(&mut context, dst_b, mint_b, destination, 0, token_2022);

    let mut accounts = migrate_prefix(&context, &v1, destination, refund_dest);
    // triple A (classic), triple B (token-2022)
    accounts.push(AccountMeta::new(src_a, false));
    accounts.push(AccountMeta::new(dst_a, false));
    accounts.push(AccountMeta::new_readonly(spl_token_id(), false));
    accounts.push(AccountMeta::new(src_b, false));
    accounts.push(AccountMeta::new(dst_b, false));
    accounts.push(AccountMeta::new_readonly(token_2022, false));

    let ix = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts,
        data: vec![DISC_MIGRATE, 2],
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &v1.owner])
        .expect("mixed SPL + Token-2022 migration must succeed");

    assert_eq!(token_amount(&context, dst_a), 40_000_000, "SPL token moved");
    assert_eq!(
        token_amount(&context, dst_b),
        33_000_000,
        "Token-2022 moved"
    );
    assert_eq!(
        lamports_of(&context, &destination),
        1_000_000_000,
        "SOL swept"
    );
    assert_eq!(lamports_of(&context, &v1.authority), 0, "authority closed");
}
