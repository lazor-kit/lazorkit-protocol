//! `CloseExpiredSession` — the permissionless half of a session's life.
//!
//! Before expiry only the wallet's Owner or Admin may end a session. After it,
//! the account authorises nothing (`execute` refuses past `expires_at`) and the
//! only key that could free the rent belongs to a user with no reason to return
//! — so anyone may close it and keep the rent.
//!
//! What these tests pin: a stranger can do it, only after expiry, on a v1
//! session as well as a v2 one, and the rent lands where the caller said.
mod common;

use common::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};

const DISC_CLOSE_EXPIRED_SESSION: u8 = 18;
const DISC_CREATE_SESSION: u8 = 5;
/// v1's Session tag. v2 uses 0x23; the instruction takes either.
const V1_DISC_SESSION: u8 = 3;
const ERR_SESSION_NOT_EXPIRED: u32 = 3036;

fn close_ix(program_id: Pubkey, session: Pubkey, caller: Pubkey, refund: Pubkey) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(caller, true),
            AccountMeta::new(session, false),
            AccountMeta::new(refund, false),
        ],
        data: vec![DISC_CLOSE_EXPIRED_SESSION],
    }
}

fn send(
    context: &mut TestContext,
    ix: Instruction,
    signer: &Keypair,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let blockhash = context.svm.latest_blockhash();
    let message =
        v0::Message::try_compile(&signer.pubkey(), &[ix], &[], blockhash).expect("compile");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[signer]).expect("sign");
    context.svm.send_transaction(tx).map(|_| ())
}

fn warp_past(context: &mut TestContext, slot: u64) {
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = slot + 1;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);
}

/// Create a real v2 session on a real wallet, and return it with its expiry.
fn create_v2_session(context: &mut TestContext) -> (Pubkey, u64) {
    let wallet = create_ed25519_wallet(context, 10_000_000);
    let session_keypair = Keypair::new();
    let expires_at = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot + 100;

    let (session_pda, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            wallet.wallet_pda.as_ref(),
            session_keypair.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    let mut data = vec![DISC_CREATE_SESSION];
    data.extend_from_slice(session_keypair.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());

    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };

    let blockhash = context.svm.latest_blockhash();
    let message = v0::Message::try_compile(&context.payer.pubkey(), &[ix], &[], blockhash).unwrap();
    let tx = VersionedTransaction::try_new(
        VersionedMessage::V0(message),
        &[&context.payer, &wallet.owner],
    )
    .unwrap();
    context.svm.send_transaction(tx).expect("create session");

    (session_pda, expires_at)
}

/// A v1 session, written byte by byte the way the retired binary left it:
/// disc | bump | version | pad(5) | wallet(32) | session_key(32) | expires_at(8).
fn set_v1_session(context: &mut TestContext, expires_at: u64) -> (Pubkey, u64) {
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 80];
    data[0] = V1_DISC_SESSION;
    data[1] = 255;
    data[2] = 1;
    data[8..40].copy_from_slice(Pubkey::new_unique().as_ref());
    data[40..72].copy_from_slice(Pubkey::new_unique().as_ref());
    data[72..80].copy_from_slice(&expires_at.to_le_bytes());

    let lamports = 1_600_000;
    context
        .svm
        .set_account(
            key,
            Account {
                lamports,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("set v1 session");
    (key, lamports)
}

#[test]
fn a_stranger_closes_an_expired_session_and_keeps_the_rent() {
    let mut context = setup_test();
    let program_id = context.program_id;
    let (session_pda, expires_at) = create_v2_session(&mut context);
    let rent = context.svm.get_account(&session_pda).unwrap().lamports;

    // Nobody who has ever touched this wallet.
    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let before = context
        .svm
        .get_account(&stranger.pubkey())
        .unwrap()
        .lamports;

    warp_past(&mut context, expires_at);
    send(
        &mut context,
        close_ix(
            program_id,
            session_pda,
            stranger.pubkey(),
            stranger.pubkey(),
        ),
        &stranger,
    )
    .expect("a stranger may close an expired session");

    assert!(
        context
            .svm
            .get_account(&session_pda)
            .is_none_or(|a| a.lamports == 0),
        "the session account should be drained",
    );
    let after = context
        .svm
        .get_account(&stranger.pubkey())
        .unwrap()
        .lamports;
    assert!(
        after > before,
        "the caller keeps the rent: {before} -> {after} (session held {rent})",
    );
}

#[test]
fn a_live_session_is_refused() {
    let mut context = setup_test();
    let program_id = context.program_id;
    let (session_pda, _) = create_v2_session(&mut context);

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();

    let result = send(
        &mut context,
        close_ix(
            program_id,
            session_pda,
            stranger.pubkey(),
            stranger.pubkey(),
        ),
        &stranger,
    );
    assert_custom_error(result, ERR_SESSION_NOT_EXPIRED, "closing a live session");
    assert!(
        context.svm.get_account(&session_pda).unwrap().lamports > 0,
        "a live session must survive the attempt",
    );
}

#[test]
fn the_final_slot_still_belongs_to_the_session() {
    let mut context = setup_test();
    let program_id = context.program_id;
    let (session_pda, expires_at) = create_v2_session(&mut context);

    // Exactly at expires_at, `execute` still accepts the session — it refuses
    // only when the slot is strictly past. Closing has to agree, or a keeper
    // can end a session one slot early.
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = expires_at;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let result = send(
        &mut context,
        close_ix(
            program_id,
            session_pda,
            stranger.pubkey(),
            stranger.pubkey(),
        ),
        &stranger,
    );
    assert_custom_error(
        result,
        ERR_SESSION_NOT_EXPIRED,
        "closing exactly at expires_at",
    );
}

#[test]
fn a_v1_session_is_closable_too() {
    let mut context = setup_test();
    let program_id = context.program_id;
    // The case this instruction exists for: sessions left behind by the
    // upgrade, which no v1 instruction can reach any more.
    let now = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let (session, rent) = set_v1_session(&mut context, now + 10);
    warp_past(&mut context, now + 10);

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let before = context
        .svm
        .get_account(&stranger.pubkey())
        .unwrap()
        .lamports;

    send(
        &mut context,
        close_ix(program_id, session, stranger.pubkey(), stranger.pubkey()),
        &stranger,
    )
    .expect("a v1 session should close");

    assert!(context
        .svm
        .get_account(&session)
        .is_none_or(|a| a.lamports == 0));
    let after = context
        .svm
        .get_account(&stranger.pubkey())
        .unwrap()
        .lamports;
    assert!(
        after > before,
        "rent moved: {before} -> {after} (held {rent})"
    );
}

#[test]
fn a_v1_session_that_has_not_expired_is_refused() {
    let mut context = setup_test();
    let program_id = context.program_id;
    let now = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let (session, _) = set_v1_session(&mut context, now + 10_000);

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let result = send(
        &mut context,
        close_ix(program_id, session, stranger.pubkey(), stranger.pubkey()),
        &stranger,
    );
    assert_custom_error(result, ERR_SESSION_NOT_EXPIRED, "closing a live v1 session");
}

#[test]
fn an_account_that_is_not_a_session_is_refused() {
    let mut context = setup_test();
    let program_id = context.program_id;
    // A program-owned account with someone else's discriminator. Ownership
    // alone must not be enough, or every account this program holds becomes
    // closable by anyone the moment it looks expired.
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 120];
    data[0] = 0x22; // Authority
    context
        .svm
        .set_account(
            key,
            Account {
                lamports: 2_000_000,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    let result = send(
        &mut context,
        close_ix(program_id, key, stranger.pubkey(), stranger.pubkey()),
        &stranger,
    );
    assert!(
        result.is_err(),
        "an Authority account must not close as a session"
    );
    assert_eq!(context.svm.get_account(&key).unwrap().lamports, 2_000_000);
}
