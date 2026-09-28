//! A passkey signature approves one wallet, not every wallet the key controls.
//!
//! One passkey can be an authority on several wallets. The authority PDA is
//! derived from the wallet and the credential, so the same credential id and
//! the same P-256 key sit on wallet A and wallet B at two addresses, each with
//! its own counter starting at zero.
//!
//! The Secp256r1 challenge used to be
//! `SHA256(disc || auth_payload[..14] || signed_payload || payer || counter || program_id)`,
//! and for several instructions none of that tells A from B. CreateSession's
//! and AddAuthority's signed payloads carry only the new key material; the
//! payer is a relayer's paymaster, the same for every wallet it serves. So an
//! assertion the owner made for A verified on B whenever B's counter matched,
//! for as long as the slot was fresh — a session key or an Admin approved for
//! A could be installed on B by whoever saw the transaction. (Execute was
//! already bound, through the accounts hash in its signed payload.)
//!
//! The challenge now folds in the authenticating authority's own `wallet`
//! field, after the payer. Every caller has checked that field against the
//! wallet account, so it is the wallet the instruction acts on.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test wallet_binding_tests

mod common;

use common::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::InvalidMessageHash` — the clientDataJSON challenge is not the
/// one the program recomputed.
const ERR_INVALID_MESSAGE_HASH: u32 = 3005;

const DISC_ADD_AUTHORITY: u8 = 1;
const DISC_CREATE_SESSION: u8 = 5;

/// Where the instructions sysvar sits in both account lists below: after
/// payer, wallet, authority, target PDA, system program and rent.
const SYSVAR_IX_INDEX: u8 = 6;

/// Sign `signed_payload` with `pk`, with the challenge bound to `signed_for`.
///
/// Returns the precompile instruction and the auth payload that follows the
/// instruction's own data. The counter is the authority's next one, which is
/// 1 on both wallets here — the coincidence a cross-wallet replay needs.
fn sign(
    context: &TestContext,
    pk: &Passkey,
    signed_for: &PasskeyWallet,
    discriminator: u8,
    signed_payload: &[u8],
) -> (Instruction, Vec<u8>) {
    let counter = authority_counter(&context.svm, signed_for.authority) + 1;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, SYSVAR_IX_INDEX);
    let challenge = secp256r1_challenge(
        discriminator,
        &prefix,
        signed_payload,
        &context.payer.pubkey(),
        &signed_for.wallet,
        counter,
        &context.program_id,
    );
    passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge)
}

/// Send as the relayer would: the payer is the transaction's only signer. The
/// passkey's approval travels inside the instructions, not as a signature.
#[allow(clippy::result_large_err)]
fn send(
    context: &mut TestContext,
    ixs: &[Instruction],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, ixs, &[&payer])
}

// ─── CreateSession ───────────────────────────────────────────────────────

/// `CreateSession` data after the discriminator, up to where the auth payload
/// begins: `[session_key 32][expires_at u64][actions_len u16 = 0]`. The program
/// signs over exactly these bytes followed by the payer.
fn create_session_args(context: &TestContext, session_key: &Pubkey) -> Vec<u8> {
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let mut args = Vec::with_capacity(42);
    args.extend_from_slice(session_key.as_ref());
    args.extend_from_slice(&(slot + 100_000).to_le_bytes());
    args.extend_from_slice(&0u16.to_le_bytes());
    args
}

fn session_pda(context: &TestContext, wallet: &Pubkey, session_key: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            wallet.as_ref(),
            session_key.as_ref(),
        ],
        &context.program_id,
    )
    .0
}

/// The `CreateSession` instruction for `target`. The data is whatever was
/// signed; only the accounts say which wallet it lands on.
fn create_session_ix(
    context: &TestContext,
    target: &PasskeyWallet,
    session_key: &Pubkey,
    args: &[u8],
    auth_payload: &[u8],
) -> Instruction {
    let mut data = vec![DISC_CREATE_SESSION];
    data.extend_from_slice(args);
    data.extend_from_slice(auth_payload);
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(target.wallet, false),
            AccountMeta::new(target.authority, false),
            AccountMeta::new(session_pda(context, &target.wallet, session_key), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        data,
    }
}

fn signed_session_payload(context: &TestContext, args: &[u8]) -> Vec<u8> {
    let mut payload = args.to_vec();
    payload.extend_from_slice(context.payer.pubkey().as_ref());
    payload
}

/// The owner approves a session key on A; the relayer lands it there, then
/// replays the same assertion against B, where the same passkey is Owner and
/// the counter lines up. B must refuse it — and must still accept a session
/// its owner actually signed for B, or the refusal proves nothing.
#[test]
fn create_session_signed_for_a_is_refused_on_b() {
    let mut context = setup_test();
    let pk = Passkey::new();
    let a = create_passkey_wallet(&mut context, &pk);
    let b = create_passkey_wallet(&mut context, &pk);

    let session_key = Keypair::new().pubkey();
    let args = create_session_args(&context, &session_key);
    let (precompile, auth_payload) = sign(
        &context,
        &pk,
        &a,
        DISC_CREATE_SESSION,
        &signed_session_payload(&context, &args),
    );

    // On A, as signed.
    let on_a = [
        precompile.clone(),
        create_session_ix(&context, &a, &session_key, &args, &auth_payload),
    ];
    send(&mut context, &on_a).expect("CreateSession on the wallet it was signed for");
    assert_eq!(authority_counter(&context.svm, a.authority), 1);
    assert!(context
        .svm
        .get_account(&session_pda(&context, &a.wallet, &session_key))
        .is_some());

    // Replayed on B: same precompile, same data, B's accounts.
    assert_eq!(
        authority_counter(&context.svm, b.authority),
        0,
        "B's next counter is the one A's assertion carries"
    );
    let replay_on_b = [
        precompile,
        create_session_ix(&context, &b, &session_key, &args, &auth_payload),
    ];
    assert_custom_error(
        send(&mut context, &replay_on_b),
        ERR_INVALID_MESSAGE_HASH,
        "a CreateSession assertion for wallet A must not verify on wallet B",
    );
    assert!(
        context
            .svm
            .get_account(&session_pda(&context, &b.wallet, &session_key))
            .is_none(),
        "no session on B"
    );
    assert_eq!(authority_counter(&context.svm, b.authority), 0);

    // Control: signed for B, the same session lands on B.
    let (precompile_b, auth_payload_b) = sign(
        &context,
        &pk,
        &b,
        DISC_CREATE_SESSION,
        &signed_session_payload(&context, &args),
    );
    let signed_for_b = [
        precompile_b,
        create_session_ix(&context, &b, &session_key, &args, &auth_payload_b),
    ];
    send(&mut context, &signed_for_b).expect("CreateSession signed for B");
    assert_eq!(authority_counter(&context.svm, b.authority), 1);
}

/// A client still hashing the old layout — no wallet between payer and
/// counter — is refused even on the wallet it meant. That break is the point:
/// a program that also accepted the old hash would still accept a cross-wallet
/// replay of it.
#[test]
fn a_challenge_without_the_wallet_is_refused() {
    use sha2::Digest;

    let mut context = setup_test();
    let pk = Passkey::new();
    let a = create_passkey_wallet(&mut context, &pk);

    let session_key = Keypair::new().pubkey();
    let args = create_session_args(&context, &session_key);
    let counter = 1u32;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, SYSVAR_IX_INDEX);

    let mut h = sha2::Sha256::new();
    h.update([DISC_CREATE_SESSION]);
    h.update(&prefix);
    h.update(signed_session_payload(&context, &args));
    h.update(context.payer.pubkey().as_ref());
    h.update(counter.to_le_bytes());
    h.update(context.program_id.as_ref());
    let old_challenge: [u8; 32] = h.finalize().into();
    let (precompile, auth_payload) =
        passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &old_challenge);

    let on_a = [
        precompile,
        create_session_ix(&context, &a, &session_key, &args, &auth_payload),
    ];
    assert_custom_error(
        send(&mut context, &on_a),
        ERR_INVALID_MESSAGE_HASH,
        "the pre-binding challenge layout must not verify",
    );
    assert_eq!(authority_counter(&context.svm, a.authority), 0);
}

// ─── AddAuthority ────────────────────────────────────────────────────────

/// `AddAuthority` data after the discriminator, up to where the auth payload
/// begins: an Ed25519 Admin with no policy,
/// `[type 0][rank][padding 6][pubkey 32][policy_len u16 = 0]`.
fn add_admin_args(new_key: &Pubkey) -> Vec<u8> {
    let mut args = Vec::with_capacity(42);
    args.push(0); // Ed25519
    args.push(RANK_ADMIN);
    args.extend_from_slice(&[0u8; 6]);
    args.extend_from_slice(new_key.as_ref());
    args.extend_from_slice(&0u16.to_le_bytes());
    args
}

fn add_authority_ix(
    context: &TestContext,
    target: &PasskeyWallet,
    new_key: &Pubkey,
    args: &[u8],
    auth_payload: &[u8],
) -> Instruction {
    let mut data = vec![DISC_ADD_AUTHORITY];
    data.extend_from_slice(args);
    data.extend_from_slice(auth_payload);
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new(target.wallet, false),
            AccountMeta::new(target.authority, false),
            AccountMeta::new(
                authority_pda_for(context.program_id, target.wallet, new_key),
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        data,
    }
}

/// The owner makes a key an Admin on A. Replayed on B, that key would become an
/// Admin of a wallet whose owner never approved it — the more damaging of the
/// two, since an Admin can mint sessions and add Delegates.
#[test]
fn add_authority_signed_for_a_is_refused_on_b() {
    let mut context = setup_test();
    let pk = Passkey::new();
    let a = create_passkey_wallet(&mut context, &pk);
    let b = create_passkey_wallet(&mut context, &pk);

    let new_admin = Keypair::new().pubkey();
    let args = add_admin_args(&new_admin);
    let mut signed_payload = args.clone();
    signed_payload.extend_from_slice(context.payer.pubkey().as_ref());
    let (precompile, auth_payload) = sign(&context, &pk, &a, DISC_ADD_AUTHORITY, &signed_payload);

    let on_a = [
        precompile.clone(),
        add_authority_ix(&context, &a, &new_admin, &args, &auth_payload),
    ];
    send(&mut context, &on_a).expect("AddAuthority on the wallet it was signed for");
    let admin_on_a = authority_pda_for(context.program_id, a.wallet, &new_admin);
    assert_eq!(authority_role(&context.svm, admin_on_a), RANK_ADMIN);

    let replay_on_b = [
        precompile,
        add_authority_ix(&context, &b, &new_admin, &args, &auth_payload),
    ];
    assert_custom_error(
        send(&mut context, &replay_on_b),
        ERR_INVALID_MESSAGE_HASH,
        "an AddAuthority assertion for wallet A must not verify on wallet B",
    );
    let admin_on_b = authority_pda_for(context.program_id, b.wallet, &new_admin);
    assert!(
        context.svm.get_account(&admin_on_b).is_none(),
        "the key must not become an authority on B"
    );
    assert_eq!(authority_counter(&context.svm, b.authority), 0);

    // Control: signed for B, the same key is added to B.
    let (precompile_b, auth_payload_b) =
        sign(&context, &pk, &b, DISC_ADD_AUTHORITY, &signed_payload);
    let signed_for_b = [
        precompile_b,
        add_authority_ix(&context, &b, &new_admin, &args, &auth_payload_b),
    ];
    send(&mut context, &signed_for_b).expect("AddAuthority signed for B");
    assert_eq!(authority_role(&context.svm, admin_on_b), RANK_ADMIN);
}

// ─── The layout both SDKs build ──────────────────────────────────────────

/// The fixed vector sdk-legacy (`tests-sdk/tests/15-sdk-unit.test.ts`) and
/// sdk-kit (`tests/secp256r1.test.ts`) pin. `secp256r1_challenge` is the helper
/// every passkey test above signs with, so the suites passing against the
/// program and this vector matching tie the program's hash, the helper and both
/// SDKs to the same bytes.
#[test]
fn the_challenge_matches_the_sdk_vector() {
    // Slot 234_567_890, counter 42, sysvar index 1, and the 0x80 the SDKs
    // write in the reserved byte (the program hashes whatever is there).
    let mut prefix = secp256r1_prefix(234_567_890, 42, 1);
    prefix[13] = 0x80;
    assert_eq!(
        hex(&prefix),
        "d238fb0d000000002a0000000180",
        "prefix = slot_le8 || counter_le4 || sysvar_ix_index || reserved"
    );

    let payer: Pubkey = "11111111111111111111111111111112".parse().unwrap();
    let wallet = Pubkey::new_from_array([0x57; 32]);
    let program_id: Pubkey = "4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS"
        .parse()
        .unwrap();
    let challenge = secp256r1_challenge(
        4,
        &prefix,
        &[0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34],
        &payer,
        &wallet,
        42,
        &program_id,
    );
    assert_eq!(
        hex(&challenge),
        "31f26fb840bdfae901ec007fb8c8be9d12b2e521ec382fbbffddc66f92efd9ae"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
