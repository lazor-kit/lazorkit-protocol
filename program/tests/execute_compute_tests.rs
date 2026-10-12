//! What Execute and ExecuteDeferred cost, measured.
//!
//! Every figure is the compute units of the whole transaction (litesvm), one
//! inner System transfer of 0.001 SOL out of the vault, with the fee suffix and
//! the protocol fee the local suites configure (`setup_test`: 2,000 lamports per
//! Execute). A `find_program_address` costs 1,500 CU for every bump it tries,
//! so a single wallet's figure depends on where its bumps happen to fall: each
//! path here is measured over [`SAMPLES`] fixed wallets and payers, the same on
//! every run, and reported as mean, min and max.
//!
//! The ceilings pin each mean at its measurement plus about 5%, and the spread
//! across samples below one bump's 1,500 CU, so a change that puts a bump
//! search back on the hot path fails here.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test execute_compute_tests -- --nocapture

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::{keypair::keypair_from_seed, Signer},
};

const SAMPLES: u8 = 24;
const TRANSFER: u64 = 1_000_000;
const VAULT_LAMPORTS: u64 = 1_000_000_000;

const DISC_EXECUTE: u8 = 4;
const DISC_AUTHORIZE: u8 = 6;
const DISC_EXECUTE_DEFERRED: u8 = 7;
/// payer, wallet, authority, vault, sysvar instructions.
const EXECUTE_SYSVAR_IX_INDEX: u8 = 4;
/// payer, wallet, authority, DeferredExec, system program, rent, sysvar.
const AUTHORIZE_SYSVAR_IX_INDEX: u8 = 6;
const EXPIRY_OFFSET: u16 = 100;

struct Stats {
    mean: u64,
    min: u64,
    max: u64,
}

fn stats(samples: &[u64]) -> Stats {
    Stats {
        mean: samples.iter().sum::<u64>() / samples.len() as u64,
        min: *samples.iter().min().unwrap(),
        max: *samples.iter().max().unwrap(),
    }
}

fn seeded(tag: u8, i: u8) -> Keypair {
    keypair_from_seed(&[tag ^ i.wrapping_mul(31); 32]).unwrap()
}

/// A context whose payer (and so FeeRecord) is fixed for sample `i`.
fn context_for(i: u8) -> TestContext {
    let mut context = setup_test();
    let payer = seeded(0x51, i);
    context
        .svm
        .airdrop(&payer.pubkey(), 10_000_000_000)
        .unwrap();
    context.payer = payer;
    context
}

/// Pays once with the context payer so its FeeRecord exists: what every
/// sample measures is the steady state, not a payer's first transaction.
fn ed25519_wallet(context: &mut TestContext, i: u8) -> WalletFixture {
    create_ed25519_wallet_with(context, VAULT_LAMPORTS, [0x30 ^ i; 32], seeded(0x0E, i))
}

#[allow(clippy::result_large_err)]
fn cu(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    what: &str,
) -> u64 {
    match result {
        Ok(meta) => meta.compute_units_consumed,
        Err(failed) => panic!("{what}: {:?}\n{}", failed.err, failed.meta.pretty_logs()),
    }
}

fn ed25519_owner_execute(i: u8, fees_enabled: bool) -> u64 {
    let mut context = context_for(i);
    if !fees_enabled {
        let admin = init_authority();
        let ix = update_protocol_ix(context.program_id, admin.pubkey(), 0, 0, 0, admin.pubkey());
        try_send(&mut context.svm, &admin, &[ix], &[&admin]).expect("disable fees");
    }
    let wallet = ed25519_wallet(&mut context, i);
    let ix = execute_as(
        &context,
        &wallet,
        wallet.owner_auth_pda,
        &wallet.owner,
        Pubkey::new_unique(),
        TRANSFER,
    );
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    cu(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]),
        "Ed25519 Execute",
    )
}

fn session_execute(i: u8) -> u64 {
    let mut context = context_for(i);
    let wallet = ed25519_wallet(&mut context, i);
    let session = create_session_with_actions(&mut context, &wallet, &[]);
    let session_pda = session_pda_for(context.program_id, &wallet, &session);
    let ix = execute_as(
        &context,
        &wallet,
        session_pda,
        &session,
        Pubkey::new_unique(),
        TRANSFER,
    );
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    cu(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &session]),
        "session Execute",
    )
}

fn passkey(i: u8) -> Passkey {
    Passkey {
        signing_key: p256::ecdsa::SigningKey::from_bytes(&[0x70 ^ i; 32].into()).unwrap(),
        credential_id_hash: [0xC0 ^ i; 32],
        rp_id: "lazorkit.test",
    }
}

/// `CreateWallet` for `pk` at a fixed user seed.
fn passkey_wallet(context: &mut TestContext, pk: &Passkey, i: u8) -> PasskeyWallet {
    let program_id = context.program_id;
    let user_seed = [0xA0 ^ i; 32];
    let (wallet, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::WALLET, &user_seed], &program_id);
    let (vault, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::VAULT, wallet.as_ref()],
        &program_id,
    );
    let (authority, auth_bump) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.as_ref(),
            &pk.credential_id_hash,
        ],
        &program_id,
    );
    let mut data = vec![0u8];
    data.extend_from_slice(&user_seed);
    data.push(1);
    data.push(auth_bump);
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(&pk.credential_id_hash);
    data.extend_from_slice(
        p256::ecdsa::VerifyingKey::from(&pk.signing_key)
            .to_encoded_point(true)
            .as_bytes(),
    );
    data.push(pk.rp_id.len() as u8);
    data.extend_from_slice(pk.rp_id.as_bytes());
    let ix = Instruction {
        program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new(wallet, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(authority, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            ],
            context,
        ),
        data,
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer]).expect("CreateWallet (passkey)");
    context.svm.airdrop(&vault, VAULT_LAMPORTS).unwrap();
    PasskeyWallet {
        wallet,
        vault,
        authority,
    }
}

/// `flags = is_signer | is_writable << 1`, as `compact::account_flags`.
fn flags(is_signer: bool, is_writable: bool) -> u8 {
    (is_signer as u8) | ((is_writable as u8) << 1)
}

/// The accounts hash of one System transfer, vault → `to`.
fn transfer_accounts_hash(vault: &Pubkey, to: &Pubkey, to_signs: bool) -> [u8; 32] {
    let mut preimage = Vec::new();
    for (key, f) in [
        (solana_sdk::system_program::id(), flags(false, false)),
        (*vault, flags(false, true)),
        (*to, flags(to_signs, true)),
    ] {
        preimage.extend_from_slice(key.as_ref());
        preimage.push(f);
    }
    Sha256::digest(&preimage).into()
}

fn passkey_sign(
    context: &TestContext,
    pk: &Passkey,
    w: &PasskeyWallet,
    discriminator: u8,
    sysvar_ix_index: u8,
    signed_payload: &[u8],
) -> (Instruction, Vec<u8>, u32) {
    let counter = authority_counter(&context.svm, w.authority) + 1;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, sysvar_ix_index);
    let challenge = secp256r1_challenge(
        discriminator,
        &prefix,
        signed_payload,
        &context.payer.pubkey(),
        &w.wallet,
        counter,
        &context.program_id,
    );
    let (precompile, auth_payload) =
        passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge);
    (precompile, auth_payload, counter)
}

fn passkey_execute(i: u8) -> u64 {
    let mut context = context_for(i);
    let pk = passkey(i);
    let w = passkey_wallet(&mut context, &pk, i);
    let recipient = Pubkey::new_unique();

    // payer · wallet · authority · vault · sysvar ix · system · recipient
    let compact = encode_compact(&[(5, vec![3, 6], system_transfer_data(TRANSFER))]);
    let mut signed_payload = compact.clone();
    signed_payload.extend_from_slice(&transfer_accounts_hash(&w.vault, &recipient, false));
    let (precompile, auth_payload, _) = passkey_sign(
        &context,
        &pk,
        &w,
        DISC_EXECUTE,
        EXECUTE_SYSVAR_IX_INDEX,
        &signed_payload,
    );
    let mut data = vec![DISC_EXECUTE];
    data.extend_from_slice(&compact);
    data.extend_from_slice(&auth_payload);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(w.wallet, false),
                AccountMeta::new(w.authority, false),
                AccountMeta::new(w.vault, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(recipient, false),
            ],
            &context,
        ),
        data,
    };
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    cu(
        try_send(&mut context.svm, &payer, &[precompile, ix], &[&payer]),
        "passkey Execute",
    )
}

/// Authorize, then ExecuteDeferred; measures tx2.
fn execute_deferred(i: u8) -> u64 {
    let mut context = context_for(i);
    let pk = passkey(i);
    let w = passkey_wallet(&mut context, &pk, i);
    let recipient = Pubkey::new_unique();

    // tx2: payer · wallet · vault · DeferredExec · refund · system · recipient
    let compact = encode_compact(&[(5, vec![2, 6], system_transfer_data(TRANSFER))]);
    let instructions_hash: [u8; 32] = Sha256::digest(&compact).into();
    let mut signed_payload = Vec::with_capacity(66);
    signed_payload.extend_from_slice(&instructions_hash);
    signed_payload.extend_from_slice(&transfer_accounts_hash(&w.vault, &recipient, false));
    signed_payload.extend_from_slice(&EXPIRY_OFFSET.to_le_bytes());
    let (precompile, auth_payload, counter) = passkey_sign(
        &context,
        &pk,
        &w,
        DISC_AUTHORIZE,
        AUTHORIZE_SYSVAR_IX_INDEX,
        &signed_payload,
    );
    let deferred = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::DEFERRED,
            w.wallet.as_ref(),
            w.authority.as_ref(),
            &counter.to_le_bytes(),
        ],
        &context.program_id,
    )
    .0;
    let mut data = vec![DISC_AUTHORIZE];
    data.extend_from_slice(&signed_payload);
    data.extend_from_slice(&auth_payload);
    let payer = context.payer.insecure_clone();
    let authorize = Instruction {
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
    cu(
        try_send(
            &mut context.svm,
            &payer,
            &[precompile, authorize],
            &[&payer],
        ),
        "Authorize",
    );

    let mut data = vec![DISC_EXECUTE_DEFERRED];
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
            &context,
        ),
        data,
    };
    advance(&mut context.svm);
    cu(
        try_send(&mut context.svm, &payer, &[ix], &[&payer]),
        "ExecuteDeferred",
    )
}

fn measure(f: impl Fn(u8) -> u64) -> Stats {
    let samples: Vec<u64> = (0..SAMPLES).map(f).collect();
    stats(&samples)
}

#[test]
fn execute_compute_units() {
    // (path, measurement, ceiling): the ceiling is the mean measured with
    // stored bumps plus about 5%. The develop build before them (`f2779b66…`)
    // measured, as mean (min–max) over the same samples: 17,809 (14,997–
    // 26,997), 8,929 (7,429–16,429), 18,243 (15,431–27,431), 24,106 (20,606–
    // 32,606) and 18,848 (15,348–27,348).
    let rows = [
        (
            "Execute, Ed25519 Owner, fee charged",
            measure(|i| ed25519_owner_execute(i, true)),
            5_570,
        ),
        (
            "Execute, Ed25519 Owner, fees disabled",
            measure(|i| ed25519_owner_execute(i, false)),
            3_500,
        ),
        (
            "Execute, session (no actions)",
            measure(session_execute),
            6_050,
        ),
        ("Execute, passkey Owner", measure(passkey_execute), 11_460),
        (
            "ExecuteDeferred (passkey Owner)",
            measure(execute_deferred),
            5_900,
        ),
    ];
    println!("| Path | mean | min | max |");
    println!("|---|---|---|---|");
    for (name, s, _) in &rows {
        println!("| {name} | {} | {} | {} |", s.mean, s.min, s.max);
    }
    for (name, s, ceiling) in &rows {
        assert!(
            s.mean <= *ceiling,
            "{name}: mean {} CU, ceiling {ceiling}",
            s.mean
        );
        // No sample may pay for a bump search: the spread a search causes
        // (1,500 CU a bump) is gone.
        assert!(
            s.max - s.min < 1_500,
            "{name}: {}–{} CU across samples",
            s.min,
            s.max
        );
    }
}
