//! The passkey challenges of CreateSession, RevokeSession and RemoveAuthority,
//! pinned as vectors the SDK's typed approval requests are tested against.
//!
//! `@lazorkit/sdk-legacy/approval` computes these challenges itself, from a
//! typed request, so a portal can show what a passkey approves and sign it.
//! `tests-sdk/tests/20-approval-unit.test.ts` (run in CI without a validator)
//! checks `approvalChallenge` against the hex values below. Here the same
//! payload builders and prefix sign one instruction of each kind that lands
//! on the program, so a change to the program's recipe fails this suite, and a
//! change to the SDK's fails that one.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test typed_approval_vectors_tests

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

const DISC_REMOVE_AUTHORITY: u8 = 2;
const DISC_CREATE_SESSION: u8 = 5;
const DISC_REVOKE_SESSION: u8 = 9;

/// Where each instruction lists the Instructions sysvar (the auth payload names it).
const SYSVAR_IX_INDEX_REMOVE_AUTHORITY: u8 = 5;
const SYSVAR_IX_INDEX_CREATE_SESSION: u8 = 6;
const SYSVAR_IX_INDEX_REVOKE_SESSION: u8 = 5;

/// The 14-byte prefix as the SDKs write it: slot, counter, sysvar index, and
/// 0x80 in the reserved byte (the program hashes whatever is there).
fn sdk_prefix(slot: u64, counter: u32, sysvar_ix_index: u8) -> Vec<u8> {
    let mut prefix = secp256r1_prefix(slot, counter, sysvar_ix_index);
    prefix[13] = 0x80;
    prefix
}

/// CreateSession's signed payload: the instruction's own args, then the payer.
fn create_session_payload(
    session_key: &Pubkey,
    expires_at: u64,
    actions: &[u8],
    payer: &Pubkey,
) -> Vec<u8> {
    let mut p = create_session_args(session_key, expires_at, actions);
    p.extend_from_slice(payer.as_ref());
    p
}

/// CreateSession's args: `session_key(32) || expires_at u64 || actions_len u16 || actions`.
fn create_session_args(session_key: &Pubkey, expires_at: u64, actions: &[u8]) -> Vec<u8> {
    let mut a = session_key.to_bytes().to_vec();
    a.extend_from_slice(&expires_at.to_le_bytes());
    a.extend_from_slice(&(actions.len() as u16).to_le_bytes());
    a.extend_from_slice(actions);
    a
}

/// RevokeSession's and RemoveAuthority's signed payload: the account, then the refund.
fn account_refund_payload(account: &Pubkey, refund: &Pubkey) -> Vec<u8> {
    let mut p = account.to_bytes().to_vec();
    p.extend_from_slice(refund.as_ref());
    p
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── The vectors ─────────────────────────────────────────────────────────

const VECTOR_SLOT: u64 = 234_567_890;
const VECTOR_COUNTER: u32 = 42;
const VECTOR_EXPIRES_AT: u64 = 1_791_072_000;

fn devnet_v2() -> Pubkey {
    "57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv"
        .parse()
        .unwrap()
}

fn filled(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

/// SolMaxPerTx 2,000,000 and TokenLimit 5,000,000 of mint `0x55…`.
fn vector_actions() -> Vec<u8> {
    let mut a = action_sol_max_per_tx(2_000_000);
    a.extend_from_slice(&action_token_limit(filled(0x55), 5_000_000));
    a
}

/// Inputs: program = devnet v2, wallet = `0x11…`, payer = `0x22…`, slot
/// 234,567,890, counter 42. CreateSession: session key `0x33…`, expires at
/// 1,791,072,000, the actions above. RevokeSession: session `0x44…`, refund
/// `0x22…`. RemoveAuthority: target `0x77…`, refund `0x22…`.
#[test]
fn typed_request_challenges_match_the_sdk_vectors() {
    let program_id = devnet_v2();
    let wallet = filled(0x11);
    let payer = filled(0x22);

    assert_eq!(
        hex(&vector_actions()),
        concat!(
            // SolMaxPerTx: type, data length, no expiry, max.
            "0308000000000000000000",
            "80841e0000000000",
            // TokenLimit: type, data length, no expiry, mint, remaining.
            "0428000000000000000000",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "404b4c0000000000",
        ),
        "the actions buffer the vector carries"
    );

    let create = secp256r1_challenge(
        DISC_CREATE_SESSION,
        &sdk_prefix(VECTOR_SLOT, VECTOR_COUNTER, SYSVAR_IX_INDEX_CREATE_SESSION),
        &create_session_payload(&filled(0x33), VECTOR_EXPIRES_AT, &vector_actions(), &payer),
        &payer,
        &wallet,
        VECTOR_COUNTER,
        &program_id,
    );
    let revoke = secp256r1_challenge(
        DISC_REVOKE_SESSION,
        &sdk_prefix(VECTOR_SLOT, VECTOR_COUNTER, SYSVAR_IX_INDEX_REVOKE_SESSION),
        &account_refund_payload(&filled(0x44), &payer),
        &payer,
        &wallet,
        VECTOR_COUNTER,
        &program_id,
    );
    let remove = secp256r1_challenge(
        DISC_REMOVE_AUTHORITY,
        &sdk_prefix(
            VECTOR_SLOT,
            VECTOR_COUNTER,
            SYSVAR_IX_INDEX_REMOVE_AUTHORITY,
        ),
        &account_refund_payload(&filled(0x77), &payer),
        &payer,
        &wallet,
        VECTOR_COUNTER,
        &program_id,
    );

    assert_eq!(
        hex(&create),
        "d1841cf56f964039a42a5a2569f3a030991cdd8d3d5b8f29387e97ca34f8333a",
        "createSession"
    );
    assert_eq!(
        hex(&revoke),
        "83051a9cb28655e7ae605e66556d085a9b32d9d9986807ef16ffc174aada6beb",
        "revokeSession"
    );
    assert_eq!(
        hex(&remove),
        "7768f9770b74d4ec77eaf3178fa2cdc712b330f66e02472cf360b36c4d912df9",
        "removeAuthority"
    );
}

// ─── The same builders, on the program ───────────────────────────────────

/// Sign `signed_payload` for `disc` with the passkey at the current slot and
/// the next counter, as the vectors do. Returns the precompile instruction
/// and the auth payload.
fn sign(
    context: &TestContext,
    pk: &Passkey,
    wallet: &Pubkey,
    authority: &Pubkey,
    disc: u8,
    sysvar_ix_index: u8,
    signed_payload: &[u8],
) -> (Instruction, Vec<u8>) {
    let counter = authority_counter(&context.svm, *authority) + 1;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = sdk_prefix(slot, counter, sysvar_ix_index);
    let challenge = secp256r1_challenge(
        disc,
        &prefix,
        signed_payload,
        &context.payer.pubkey(),
        wallet,
        counter,
        &context.program_id,
    );
    passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge)
}

#[test]
fn the_vector_builders_sign_what_the_program_accepts() {
    let mut context = setup_test();
    let w = create_ed25519_wallet(&mut context, 1_000_000_000);
    let payer = context.payer.insecure_clone();
    let sysvar_ix = solana_sdk::sysvar::instructions::id();

    // A passkey Owner beside the Ed25519 one, added by the Ed25519 Owner.
    let pk = Passkey::new();
    let (authority, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            w.wallet_pda.as_ref(),
            &pk.credential_id_hash,
        ],
        &context.program_id,
    );
    let mut data = vec![1u8]; // AddAuthority
    data.push(1); // Secp256r1
    data.push(RANK_OWNER);
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(&pk.credential_id_hash);
    data.extend_from_slice(
        p256::ecdsa::VerifyingKey::from(&pk.signing_key)
            .to_encoded_point(true)
            .as_bytes(),
    );
    data.push(pk.rp_id.len() as u8);
    data.extend_from_slice(pk.rp_id.as_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // no policy
    let add = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(w.wallet_pda, false),
            AccountMeta::new(w.owner_auth_pda, false),
            AccountMeta::new(authority, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(w.owner.pubkey(), true),
        ],
        data,
    };
    try_send(&mut context.svm, &payer, &[add], &[&payer, &w.owner]).expect("AddAuthority");
    assert_eq!(authority_role(&context.svm, authority), RANK_OWNER);

    // CreateSession, with the vector's actions.
    let session_key = Keypair::new().pubkey();
    let session = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            w.wallet_pda.as_ref(),
            session_key.as_ref(),
        ],
        &context.program_id,
    )
    .0;
    let expires_at = unix_now(&context.svm) + 3_600;
    let actions = vector_actions();
    let (precompile, auth_payload) = sign(
        &context,
        &pk,
        &w.wallet_pda,
        &authority,
        DISC_CREATE_SESSION,
        SYSVAR_IX_INDEX_CREATE_SESSION,
        &create_session_payload(&session_key, expires_at, &actions, &payer.pubkey()),
    );
    let mut data = vec![DISC_CREATE_SESSION];
    data.extend_from_slice(&create_session_args(&session_key, expires_at, &actions));
    data.extend_from_slice(&auth_payload);
    let create = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(w.wallet_pda, false),
            AccountMeta::new(authority, false),
            AccountMeta::new(session, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(sysvar_ix, false),
        ],
        data,
    };
    advance(&mut context.svm);
    try_send(&mut context.svm, &payer, &[precompile, create], &[&payer]).expect("CreateSession");
    assert_eq!(session_actions(&context.svm, session), actions);
    assert_eq!(authority_counter(&context.svm, authority), 1);

    // RevokeSession, the deposit back to the payer.
    let (precompile, auth_payload) = sign(
        &context,
        &pk,
        &w.wallet_pda,
        &authority,
        DISC_REVOKE_SESSION,
        SYSVAR_IX_INDEX_REVOKE_SESSION,
        &account_refund_payload(&session, &payer.pubkey()),
    );
    let mut data = vec![DISC_REVOKE_SESSION];
    data.extend_from_slice(&auth_payload);
    let revoke = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(w.wallet_pda, false),
            AccountMeta::new(authority, false),
            AccountMeta::new(session, false),
            AccountMeta::new(payer.pubkey(), false),
            AccountMeta::new_readonly(sysvar_ix, false),
        ],
        data,
    };
    advance(&mut context.svm);
    try_send(&mut context.svm, &payer, &[precompile, revoke], &[&payer]).expect("RevokeSession");
    assert!(context
        .svm
        .get_account(&session)
        .is_none_or(|a| a.lamports == 0));

    // RemoveAuthority: the passkey Owner removes the Ed25519 Owner.
    let (precompile, auth_payload) = sign(
        &context,
        &pk,
        &w.wallet_pda,
        &authority,
        DISC_REMOVE_AUTHORITY,
        SYSVAR_IX_INDEX_REMOVE_AUTHORITY,
        &account_refund_payload(&w.owner_auth_pda, &payer.pubkey()),
    );
    let mut data = vec![DISC_REMOVE_AUTHORITY];
    data.extend_from_slice(&auth_payload);
    let remove = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(w.wallet_pda, false),
            AccountMeta::new(authority, false),
            AccountMeta::new(w.owner_auth_pda, false),
            AccountMeta::new(payer.pubkey(), false),
            AccountMeta::new_readonly(sysvar_ix, false),
        ],
        data,
    };
    advance(&mut context.svm);
    try_send(&mut context.svm, &payer, &[precompile, remove], &[&payer]).expect("RemoveAuthority");
    assert!(context
        .svm
        .get_account(&w.owner_auth_pda)
        .is_none_or(|a| a.lamports == 0));
    assert_eq!(authority_counter(&context.svm, authority), 3);
}
