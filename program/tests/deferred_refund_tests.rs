//! ExecuteDeferred whose inner instructions pay the refund destination.
//!
//! The refund destination is the payer that funded the Authorize — on a
//! sponsored flow the paymaster, which is also the account an inner transfer
//! most often names ("pay the relayer back"). ExecuteDeferred used to move the
//! DeferredExec rent into it with direct lamport writes *before* the CPI loop.
//! The runtime syncs a caller's lamport writes into a CPI only for the accounts
//! that CPI is handed, so the refund's credit crossed the boundary while the
//! DeferredExec debit did not, and the push failed with UnbalancedInstruction
//! before the inner program ran. Both tests here failed that way.
//!
//! They go through Authorize with a real passkey assertion rather than planting
//! a DeferredExec, so they also pin the accounts-hash flags a client has to
//! sign for this layout: the refund destination at index 4 reports the
//! privileges of its key across the whole message — signer and writable when it
//! is also the fee payer, writable only when someone else pays for tx2.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test deferred_refund_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

const DISC_AUTHORIZE: u8 = 6;
const DISC_EXECUTE_DEFERRED: u8 = 7;

/// Where the instructions sysvar sits in Authorize: after payer, wallet,
/// authority, DeferredExec, system program and rent.
const AUTHORIZE_SYSVAR_IX_INDEX: u8 = 6;

/// Slots the authorization stays live.
const EXPIRY_OFFSET: u16 = 100;

const TRANSFER: u64 = 1_000_000;

/// ExecuteDeferred's fixed accounts, which the compact instruction indexes:
/// 0 payer · 1 wallet · 2 vault · 3 DeferredExec · 4 refund · 5 system.
const IDX_VAULT: u8 = 2;
const IDX_REFUND: u8 = 4;
const IDX_SYSTEM: u8 = 5;

/// `flags = is_signer | is_writable << 1`, as `compact::account_flags`.
fn flags(is_signer: bool, is_writable: bool) -> u8 {
    (is_signer as u8) | ((is_writable as u8) << 1)
}

/// One system transfer, vault → refund destination.
fn repay_refund_destination() -> Vec<u8> {
    encode_compact(&[(
        IDX_SYSTEM,
        vec![IDX_VAULT, IDX_REFUND],
        system_transfer_data(TRANSFER),
    )])
}

/// The accounts hash for [`repay_refund_destination`], in the program's walk
/// order (program id, then each account), with the flags the runtime will
/// report for each key in tx2.
fn accounts_hash(vault: &Pubkey, refund: &Pubkey, refund_signs_tx2: bool) -> [u8; 32] {
    let mut preimage = Vec::new();
    for (key, f) in [
        (solana_sdk::system_program::id(), flags(false, false)),
        (*vault, flags(false, true)),
        (*refund, flags(refund_signs_tx2, true)),
    ] {
        preimage.extend_from_slice(key.as_ref());
        preimage.push(f);
    }
    Sha256::digest(&preimage).into()
}

fn deferred_pda(context: &TestContext, w: &PasskeyWallet, counter: u32) -> Pubkey {
    Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::DEFERRED,
            w.wallet.as_ref(),
            w.authority.as_ref(),
            &counter.to_le_bytes(),
        ],
        &context.program_id,
    )
    .0
}

/// Tx1: the passkey authorizes `compact` against `accounts_hash`, paid by
/// `tx1_payer`, who becomes the refund destination. Returns the DeferredExec.
fn authorize(
    context: &mut TestContext,
    pk: &Passkey,
    w: &PasskeyWallet,
    tx1_payer: &Keypair,
    compact: &[u8],
    accounts_hash: [u8; 32],
) -> Pubkey {
    let instructions_hash: [u8; 32] = Sha256::digest(compact).into();
    let mut signed_payload = Vec::with_capacity(66);
    signed_payload.extend_from_slice(&instructions_hash);
    signed_payload.extend_from_slice(&accounts_hash);
    signed_payload.extend_from_slice(&EXPIRY_OFFSET.to_le_bytes());

    let counter = authority_counter(&context.svm, w.authority) + 1;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, AUTHORIZE_SYSVAR_IX_INDEX);
    let challenge = secp256r1_challenge(
        DISC_AUTHORIZE,
        &prefix,
        &signed_payload,
        &tx1_payer.pubkey(),
        &w.wallet,
        counter,
        &context.program_id,
    );
    let (precompile, auth_payload) =
        passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge);

    let deferred = deferred_pda(context, w, counter);
    let mut data = vec![DISC_AUTHORIZE];
    data.extend_from_slice(&signed_payload);
    data.extend_from_slice(&auth_payload);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(tx1_payer.pubkey(), true),
            AccountMeta::new_readonly(w.wallet, false),
            AccountMeta::new(w.authority, false),
            AccountMeta::new(deferred, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        data,
    };
    if let Err(failed) = try_send(&mut context.svm, tx1_payer, &[precompile, ix], &[tx1_payer]) {
        panic!(
            "Authorize failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        );
    }
    deferred
}

/// Tx2, paid by the context payer (who owns the fee suffix's FeeRecord).
#[allow(clippy::result_large_err)]
fn execute_deferred(
    context: &mut TestContext,
    w: &PasskeyWallet,
    deferred: Pubkey,
    refund: Pubkey,
    compact: &[u8],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let payer = context.payer.insecure_clone();
    let mut data = vec![DISC_EXECUTE_DEFERRED];
    data.extend_from_slice(compact);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(w.wallet, false),
                AccountMeta::new(w.vault, false),
                AccountMeta::new(deferred, false),
                AccountMeta::new(refund, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            context,
        ),
        data,
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer])
}

fn balance(context: &TestContext, key: &Pubkey) -> u64 {
    context.svm.get_balance(key).unwrap_or(0)
}

fn treasury_shard(context: &TestContext) -> Pubkey {
    protocol_fee_account_metas(context)[2].pubkey
}

/// The sponsored default: one relayer pays both transactions and is repaid
/// from the vault by the deferred instructions themselves.
#[test]
fn an_inner_transfer_to_the_refund_destination_executes() {
    let mut context = setup_test();
    let pk = Passkey::new();
    let w = create_passkey_wallet(&mut context, &pk);
    context.svm.airdrop(&w.vault, 1_000_000_000).unwrap();
    let relayer = context.payer.insecure_clone();

    let compact = repay_refund_destination();
    // The refund destination is the fee payer of tx2, so it reports signer +
    // writable at index 4 even though the instruction lists it as writable only.
    let hash = accounts_hash(&w.vault, &relayer.pubkey(), true);
    let deferred = authorize(&mut context, &pk, &w, &relayer, &compact, hash);
    let rent = balance(&context, &deferred);
    assert!(rent > 0, "Authorize funded the DeferredExec");

    let vault_before = balance(&context, &w.vault);
    let relayer_before = balance(&context, &relayer.pubkey());
    let shard_before = balance(&context, &treasury_shard(&context));

    if let Err(failed) = execute_deferred(&mut context, &w, deferred, relayer.pubkey(), &compact) {
        panic!(
            "ExecuteDeferred failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        );
    }

    assert_eq!(
        vault_before - balance(&context, &w.vault),
        TRANSFER,
        "the inner transfer ran exactly once"
    );
    assert!(
        context
            .svm
            .get_account(&deferred)
            .is_none_or(|a| a.lamports == 0),
        "the authorization is consumed"
    );
    // The relayer paid the signature fee and the protocol fee, and got back
    // both the transfer and the rent: neither credit overwrote the other.
    let protocol_fee = balance(&context, &treasury_shard(&context)) - shard_before;
    assert_eq!(
        balance(&context, &relayer.pubkey()) + protocol_fee + 5_000,
        relayer_before + TRANSFER + rent,
    );
}

/// Someone other than the Authorize payer sends tx2. The refund destination is
/// then not a signer of tx2 and reports writable only — and the program must
/// still land the inner credit and the rent on it.
#[test]
fn another_payer_executes_and_the_refund_destination_is_repaid() {
    let mut context = setup_test();
    let pk = Passkey::new();
    let w = create_passkey_wallet(&mut context, &pk);
    context.svm.airdrop(&w.vault, 1_000_000_000).unwrap();
    let first_relayer = Keypair::new();
    context
        .svm
        .airdrop(&first_relayer.pubkey(), 1_000_000_000)
        .unwrap();

    let compact = repay_refund_destination();
    let hash = accounts_hash(&w.vault, &first_relayer.pubkey(), false);
    let deferred = authorize(&mut context, &pk, &w, &first_relayer, &compact, hash);
    let rent = balance(&context, &deferred);

    let vault_before = balance(&context, &w.vault);
    let refund_before = balance(&context, &first_relayer.pubkey());

    if let Err(failed) =
        execute_deferred(&mut context, &w, deferred, first_relayer.pubkey(), &compact)
    {
        panic!(
            "ExecuteDeferred failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        );
    }

    assert_eq!(vault_before - balance(&context, &w.vault), TRANSFER);
    assert_eq!(
        balance(&context, &first_relayer.pubkey()) - refund_before,
        TRANSFER + rent,
        "the refund destination gets the transfer and the rent, and pays nothing"
    );
    assert!(context
        .svm
        .get_account(&deferred)
        .is_none_or(|a| a.lamports == 0));
}
