//! The sunset binary — what a retired v1 deployment runs after v2 has moved to
//! its own program id.
//!
//! It serves exactly three instructions, each of which only ever takes value
//! *out* of a v1 account: `ReclaimDeferred` (8), `MigrateWallet` (17) and
//! `CloseExpiredSession` (18). Everything else — creating wallets, Execute, the
//! fee layer, protocol administration — is refused with `RetiredDeployment`
//! (4018) before any processor runs.
//!
//! Only compiled for the sunset features. Run with:
//!
//!   ( cd program && cargo build-sbf --features rehearsal-v1 )
//!   cargo test --features rehearsal-v1 -p lazorkit-program --test sunset_tests
#![cfg(any(
    feature = "mainnet-v1",
    feature = "devnet-v1",
    feature = "rehearsal-v1"
))]

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

const ERR_RETIRED_DEPLOYMENT: u32 = 4018;
const ERR_SESSION_NOT_EXPIRED: u32 = 3036;

const V1_DISC_WALLET: u8 = 1;
const V1_DISC_AUTHORITY: u8 = 2;
const V1_DISC_SESSION: u8 = 3;
const V1_DISC_DEFERRED: u8 = 4;

#[allow(clippy::result_large_err)]
fn send(
    context: &mut TestContext,
    ixs: &[Instruction],
    signers: &[&Keypair],
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let blockhash = context.svm.latest_blockhash();
    let message =
        v0::Message::try_compile(&signers[0].pubkey(), ixs, &[], blockhash).expect("compile");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), signers).expect("sign");
    context.svm.send_transaction(tx).map(|_| ())
}

fn set_program_account(context: &mut TestContext, key: Pubkey, data: Vec<u8>, lamports: u64) {
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
        .expect("set program account");
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}

fn slot(context: &TestContext) -> u64 {
    context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
}

fn warp_to(context: &mut TestContext, target: u64) {
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = target;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);
}

fn funded(context: &mut TestContext) -> Keypair {
    let k = Keypair::new();
    context.svm.airdrop(&k.pubkey(), 1_000_000_000).unwrap();
    k
}

// ── everything but the three ways out is refused ────────────────────────

#[test]
fn every_other_instruction_is_refused_as_retired() {
    let mut context = setup_uninitialized();
    let payer = context.payer.insecure_clone();
    let program_id = context.program_id;

    // Every discriminator the full binary knows, minus the three that stay.
    // The data after the tag does not matter: the gate runs before any parsing,
    // which is exactly what this proves.
    for disc in [0u8, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16] {
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(payer.pubkey(), true)],
            data: vec![disc, 0, 0, 0, 0],
        };
        let result = send(&mut context, &[ix], &[&payer]);
        assert_custom_error(
            result,
            ERR_RETIRED_DEPLOYMENT,
            &format!("instruction {disc}"),
        );
        advance(&mut context.svm);
    }
}

// ── MigrateWallet: out, to a destination at another program ─────────────

#[test]
fn migrate_moves_a_v1_wallet_to_a_vault_the_owner_names_anywhere() {
    let mut context = setup_uninitialized();
    let program_id = context.program_id;
    let owner = Keypair::new();
    let user_seed = rand::random::<[u8; 32]>();

    let (wallet, wallet_bump) = Pubkey::find_program_address(&[b"wallet", &user_seed], &program_id);
    let (vault, _) = Pubkey::find_program_address(&[b"vault", wallet.as_ref()], &program_id);
    let (authority, auth_bump) = Pubkey::find_program_address(
        &[b"authority", wallet.as_ref(), owner.pubkey().as_ref()],
        &program_id,
    );

    let mut wdata = vec![0u8; 8];
    wdata[0] = V1_DISC_WALLET;
    wdata[1] = wallet_bump;
    wdata[2] = 1;
    set_program_account(&mut context, wallet, wdata, 1_000_000);

    let mut adata = vec![0u8; 80];
    adata[0] = V1_DISC_AUTHORITY;
    adata[1] = 0; // Ed25519
    adata[2] = 0; // Owner
    adata[3] = auth_bump;
    adata[4] = 1;
    adata[16..48].copy_from_slice(wallet.as_ref());
    adata[48..80].copy_from_slice(owner.pubkey().as_ref());
    set_program_account(&mut context, authority, adata, 1_600_000);

    let funds = 750_000_000u64;
    context
        .svm
        .set_account(
            vault,
            Account {
                lamports: funds,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    // The destination stands for the owner's v2 vault — at a different program
    // id entirely, which this binary knows nothing about. MigrateWallet binds
    // the destination into the owner's signed intent and never asks whose it is.
    let destination = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(wallet, false),
            AccountMeta::new(authority, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(destination, false),
            AccountMeta::new(payer.pubkey(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            AccountMeta::new_readonly(owner.pubkey(), true),
        ],
        data: vec![17, 0],
    };
    send(&mut context, &[ix], &[&payer, &owner]).expect("migrate on the sunset binary");

    assert_eq!(
        lamports_of(&context, &destination),
        funds,
        "every lamport arrives"
    );
    assert_eq!(lamports_of(&context, &vault), 0, "the v1 vault is empty");
    assert_eq!(lamports_of(&context, &wallet), 0, "the v1 wallet is closed");
    assert_eq!(
        lamports_of(&context, &authority),
        0,
        "the v1 authority is closed"
    );
}

// ── CloseExpiredSession: anyone, once it is dead ────────────────────────

fn v1_session(context: &mut TestContext, expires_at: u64) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 80];
    data[0] = V1_DISC_SESSION;
    data[8..40].copy_from_slice(Pubkey::new_unique().as_ref());
    data[40..72].copy_from_slice(Pubkey::new_unique().as_ref());
    data[72..80].copy_from_slice(&expires_at.to_le_bytes());
    set_program_account(context, key, data, 1_500_000);
    key
}

#[test]
fn an_expired_v1_session_closes_for_anyone() {
    let mut context = setup_uninitialized();
    let program_id = context.program_id;
    let now = slot(&context);
    let session = v1_session(&mut context, now + 10);
    let stranger = funded(&mut context);

    let close = |s| Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(stranger.pubkey(), true),
            AccountMeta::new(s, false),
            AccountMeta::new(stranger.pubkey(), false),
        ],
        data: vec![18],
    };

    let early = send(&mut context, &[close(session)], &[&stranger]);
    assert_custom_error(early, ERR_SESSION_NOT_EXPIRED, "closing a live session");

    warp_to(&mut context, now + 11);
    let before = lamports_of(&context, &stranger.pubkey());
    send(&mut context, &[close(session)], &[&stranger]).expect("close after expiry");
    assert_eq!(lamports_of(&context, &session), 0);
    assert!(
        lamports_of(&context, &stranger.pubkey()) > before,
        "the closer keeps the rent"
    );
}

// ── ReclaimDeferred: the original payer, after expiry ───────────────────

fn v1_deferred(context: &mut TestContext, payer: Pubkey, expires_at: u64) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 176];
    data[0] = V1_DISC_DEFERRED;
    data[136..168].copy_from_slice(payer.as_ref());
    data[168..176].copy_from_slice(&expires_at.to_le_bytes());
    set_program_account(context, key, data, 2_115_840);
    key
}

#[test]
fn an_expired_v1_deferred_account_returns_to_its_payer_only() {
    let mut context = setup_uninitialized();
    let program_id = context.program_id;
    let now = slot(&context);
    let sponsor = funded(&mut context);
    let deferred = v1_deferred(&mut context, sponsor.pubkey(), now + 10);

    let reclaim = |signer: Pubkey| Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(deferred, false),
            AccountMeta::new(signer, false),
        ],
        data: vec![8],
    };

    warp_to(&mut context, now + 11);

    // Not permissionless: someone else's authorization is not a stranger's rent.
    let stranger = funded(&mut context);
    let theft = send(&mut context, &[reclaim(stranger.pubkey())], &[&stranger]);
    assert!(theft.is_err(), "only the payer that funded it may reclaim");
    assert_eq!(lamports_of(&context, &deferred), 2_115_840);

    let before = lamports_of(&context, &sponsor.pubkey());
    send(&mut context, &[reclaim(sponsor.pubkey())], &[&sponsor]).expect("payer reclaims");
    assert_eq!(lamports_of(&context, &deferred), 0);
    assert!(lamports_of(&context, &sponsor.pubkey()) > before);
}
