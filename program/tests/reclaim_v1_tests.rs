//! `ReclaimDeferred` accepts a v1 DeferredExec account as well as a v2 one.
//!
//! The upgrade leaves v1 authorizations behind, and their rent belongs to the
//! payer that funded them — on every sponsored authorization, the paymaster.
//! Before this, that rent had to be recovered before the upgrade or never; now
//! the same instruction, gated on the same payer signature, recovers it after.
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

const V1_DISC_DEFERRED: u8 = 4;
const ERR_NOT_EXPIRED: u32 = 3018;

fn v1_deferred(context: &mut TestContext, payer: Pubkey, expires_at: u64) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; 176];
    data[0] = V1_DISC_DEFERRED;
    data[136..168].copy_from_slice(payer.as_ref());
    data[168..176].copy_from_slice(&expires_at.to_le_bytes());
    context
        .svm
        .set_account(
            key,
            Account {
                lamports: 2_115_840,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    key
}

fn reclaim(program_id: Pubkey, signer: Pubkey, deferred: Pubkey) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(deferred, false),
            AccountMeta::new(signer, false),
        ],
        data: vec![8],
    }
}

#[allow(clippy::result_large_err)]
fn send(
    context: &mut TestContext,
    ix: Instruction,
    signer: &Keypair,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let blockhash = context.svm.latest_blockhash();
    let message = v0::Message::try_compile(&signer.pubkey(), &[ix], &[], blockhash).unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[signer]).unwrap();
    context.svm.send_transaction(tx).map(|_| ())
}

#[test]
fn a_v1_authorization_returns_its_rent_to_its_payer() {
    let mut context = setup_test();
    let program_id = context.program_id;
    let sponsor = Keypair::new();
    context
        .svm
        .airdrop(&sponsor.pubkey(), 1_000_000_000)
        .unwrap();
    let now = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let deferred = v1_deferred(&mut context, sponsor.pubkey(), now + 5);

    // Before expiry: refused, exactly as for a v2 authorization.
    let early = send(
        &mut context,
        reclaim(program_id, sponsor.pubkey(), deferred),
        &sponsor,
    );
    assert_custom_error(early, ERR_NOT_EXPIRED, "reclaiming a live v1 authorization");

    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = now + 6;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);

    // Someone else: refused. This is the payer's money, not a keeper's reward.
    let stranger = Keypair::new();
    context
        .svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .unwrap();
    assert!(send(
        &mut context,
        reclaim(program_id, stranger.pubkey(), deferred),
        &stranger
    )
    .is_err());

    let before = context.svm.get_account(&sponsor.pubkey()).unwrap().lamports;
    send(
        &mut context,
        reclaim(program_id, sponsor.pubkey(), deferred),
        &sponsor,
    )
    .expect("the payer reclaims a v1 authorization");
    assert!(context
        .svm
        .get_account(&deferred)
        .is_none_or(|a| a.lamports == 0));
    assert!(context.svm.get_account(&sponsor.pubkey()).unwrap().lamports > before);
}

#[test]
fn the_rent_goes_to_the_payer_and_nowhere_else() {
    // The payer is usually a paymaster that signs whatever LazorKit transaction
    // it is handed. If the destination were free, anyone could hand it a
    // reclaim that routes the rent to themselves.
    let mut context = setup_test();
    let program_id = context.program_id;
    let sponsor = Keypair::new();
    context
        .svm
        .airdrop(&sponsor.pubkey(), 1_000_000_000)
        .unwrap();
    let now = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let deferred = v1_deferred(&mut context, sponsor.pubkey(), now + 1);
    let mut clock = context.svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.slot = now + 2;
    context.svm.set_sysvar(&clock);
    advance(&mut context.svm);

    let thief = Pubkey::new_unique();
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(sponsor.pubkey(), true),
            AccountMeta::new(deferred, false),
            AccountMeta::new(thief, false),
        ],
        data: vec![8],
    };
    assert!(
        send(&mut context, ix, &sponsor).is_err(),
        "a foreign refund destination is refused"
    );
    assert_eq!(
        context.svm.get_account(&deferred).unwrap().lamports,
        2_115_840
    );
}
