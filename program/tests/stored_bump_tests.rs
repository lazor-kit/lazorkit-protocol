//! Execute's PDA checks after the bump searches came out of the hot path.
//!
//! `Execute` and `ExecuteDeferred` used to run up to four `find_program_address`
//! searches each (the protocol config, the treasury shard, the payer's fee
//! record, the vault), 1,500 CU for every bump tried. Each address is now
//! checked with one hash of its seeds and the bump the program stored when it
//! created the account (`utils::is_program_address`): the config, shard and
//! fee record store their own; a wallet stores its vault's in what was a
//! padding byte. A wallet from before holds 0 there and is searched for as
//! before.
//!
//! These tests try the substitutions the checks exist to stop: another
//! wallet's vault, a vault bump that is not the wallet's, another payer's fee
//! record, look-alike config and shard accounts. Every one must fail as the
//! search did, and the legacy path must still work.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test stored_bump_tests

mod common;

use common::*;
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::TransactionError,
};

const ERR_PROTOCOL_NOT_INITIALIZED: u32 = 4009;
const ERR_INVALID_TREASURY_SHARD: u32 = 4010;
const ERR_INVALID_FEE_RECORD: u32 = 4011;

#[allow(clippy::result_large_err)]
fn assert_invalid_seeds(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    what: &str,
) {
    match result {
        Err(failed) => assert_eq!(
            failed.err,
            TransactionError::InstructionError(0, InstructionError::InvalidSeeds),
            "{what}\n{}",
            failed.meta.pretty_logs()
        ),
        Ok(_) => panic!("{what}: expected InvalidSeeds, the transaction landed"),
    }
}

fn set_data(context: &mut TestContext, key: Pubkey, f: impl FnOnce(&mut Vec<u8>)) {
    let mut account = context.svm.get_account(&key).unwrap();
    f(&mut account.data);
    context.svm.set_account(key, account).unwrap();
    advance(&mut context.svm);
}

fn owner_execute(context: &TestContext, wallet: &WalletFixture) -> Instruction {
    execute_as(
        context,
        wallet,
        wallet.owner_auth_pda,
        &wallet.owner,
        Pubkey::new_unique(),
        1_000_000,
    )
}

#[allow(clippy::result_large_err)]
fn send_owner(
    context: &mut TestContext,
    wallet: &WalletFixture,
    ix: Instruction,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
}

// ─── The vault ───────────────────────────────────────────────────────────

#[test]
fn a_wallet_records_its_vault_bump() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);
    let data = context.svm.get_account(&wallet.wallet_pda).unwrap().data;
    let (_, bump) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::VAULT, wallet.wallet_pda.as_ref()],
        &context.program_id,
    );
    assert_eq!(data[2], 1, "still layout revision 1: the byte was padding");
    assert_eq!(data[3], bump, "the vault's canonical bump");
}

#[test]
fn another_wallets_vault_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let other = create_ed25519_wallet(&mut context, 1_000_000_000);
    let mut ix = owner_execute(&context, &wallet);
    ix.accounts[3].pubkey = other.vault_pda;
    assert_invalid_seeds(
        send_owner(&mut context, &wallet, ix),
        "another wallet's vault",
    );
}

/// The program never rewrites the byte, so this is corruption simulated in
/// the bank: a stored bump that is not the canonical one for this wallet's
/// vault must not let any address through, the real vault included.
#[test]
fn a_vault_bump_that_is_not_the_wallets_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let other = create_ed25519_wallet(&mut context, 1_000_000_000);
    let other_bump = context.svm.get_account(&other.wallet_pda).unwrap().data[3];
    for bump in [1u8, 2, 254, 255, other_bump] {
        let real = context.svm.get_account(&wallet.wallet_pda).unwrap().data[3];
        if bump == real {
            continue;
        }
        set_data(&mut context, wallet.wallet_pda, |d| d[3] = bump);
        let ix = owner_execute(&context, &wallet);
        assert_invalid_seeds(
            send_owner(&mut context, &wallet, ix),
            &format!("stored bump {bump} for the real vault"),
        );
        let mut ix = owner_execute(&context, &wallet);
        ix.accounts[3].pubkey = other.vault_pda;
        assert_invalid_seeds(
            send_owner(&mut context, &wallet, ix),
            &format!("stored bump {bump} for another vault"),
        );
        set_data(&mut context, wallet.wallet_pda, |d| d[3] = real);
    }
    let ix = owner_execute(&context, &wallet);
    send_owner(&mut context, &wallet, ix).expect("the restored bump executes");
}

/// A wallet created before the vault bump was recorded holds 0 there: Execute
/// searches for the bump, as it always did.
#[test]
fn a_wallet_that_records_no_vault_bump_still_executes() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    set_data(&mut context, wallet.wallet_pda, |d| d[3] = 0);
    let recipient = Pubkey::new_unique();
    let mut ix = owner_execute(&context, &wallet);
    ix.accounts[5].pubkey = recipient;
    send_owner(&mut context, &wallet, ix).expect("a wallet without a recorded bump executes");
    assert_eq!(context.svm.get_balance(&recipient), Some(1_000_000));

    let other = create_ed25519_wallet(&mut context, 1_000_000_000);
    let mut ix = owner_execute(&context, &wallet);
    ix.accounts[3].pubkey = other.vault_pda;
    assert_invalid_seeds(
        send_owner(&mut context, &wallet, ix),
        "a wallet without a recorded bump, with another wallet's vault",
    );
}

// ─── The fee suffix ──────────────────────────────────────────────────────

/// The fee suffix sits at the end: config, fee record, shard, system program.
fn suffix_index(ix: &Instruction, back: usize) -> usize {
    ix.accounts.len() - back
}

#[test]
fn another_payers_fee_record_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    // A second payer with a record of its own.
    let second = Keypair::new();
    context
        .svm
        .airdrop(&second.pubkey(), 10_000_000_000)
        .unwrap();
    let first = context.payer.insecure_clone();
    context.payer = second.insecure_clone();
    let _ = create_ed25519_wallet(&mut context, 0);
    let second_record = protocol_fee_account_metas(&context)[1].pubkey;
    context.payer = first;

    let mut ix = owner_execute(&context, &wallet);
    let i = suffix_index(&ix, 3);
    ix.accounts[i].pubkey = second_record;
    assert_custom_error(
        send_owner(&mut context, &wallet, ix),
        ERR_INVALID_FEE_RECORD,
        "another payer's fee record",
    );
}

#[test]
fn a_fee_record_with_a_bump_that_is_not_its_own_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let record = protocol_fee_account_metas(&context)[1].pubkey;
    let real = context.svm.get_account(&record).unwrap().data[1];
    set_data(&mut context, record, |d| d[1] = real.wrapping_sub(1));
    let ix = owner_execute(&context, &wallet);
    assert_custom_error(
        send_owner(&mut context, &wallet, ix),
        ERR_INVALID_FEE_RECORD,
        "a fee record whose stored bump is not its own",
    );
}

#[test]
fn a_look_alike_config_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let config = protocol_fee_account_metas(&context)[0].pubkey;
    let real = context.svm.get_account(&config).unwrap();

    // A byte-for-byte copy of the config, owned by the program, at another
    // address: its stored bump does not derive that address.
    let copy = Pubkey::new_unique();
    context.svm.set_account(copy, real.clone()).unwrap();
    // And a system-owned account, which reads as "not initialised".
    let empty = Pubkey::new_unique();
    context
        .svm
        .set_account(
            empty,
            Account {
                lamports: 1_000_000,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    for (key, what) in [(copy, "a copy of the config"), (empty, "a system account")] {
        advance(&mut context.svm);
        let mut ix = owner_execute(&context, &wallet);
        let i = suffix_index(&ix, 4);
        ix.accounts[i].pubkey = key;
        assert_custom_error(
            send_owner(&mut context, &wallet, ix),
            ERR_PROTOCOL_NOT_INITIALIZED,
            what,
        );
    }

    // The real config with its stored bump altered.
    set_data(&mut context, config, |d| d[2] = d[2].wrapping_sub(1));
    let ix = owner_execute(&context, &wallet);
    assert_custom_error(
        send_owner(&mut context, &wallet, ix),
        ERR_PROTOCOL_NOT_INITIALIZED,
        "the config with a bump that is not its own",
    );
}

#[test]
fn a_look_alike_shard_is_refused() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let shard = protocol_fee_account_metas(&context)[2].pubkey;
    let copy = Pubkey::new_unique();
    let real = context.svm.get_account(&shard).unwrap();
    context.svm.set_account(copy, real).unwrap();
    let mut ix = owner_execute(&context, &wallet);
    let i = suffix_index(&ix, 2);
    ix.accounts[i].pubkey = copy;
    assert_custom_error(
        send_owner(&mut context, &wallet, ix),
        ERR_INVALID_TREASURY_SHARD,
        "a copy of shard 0 elsewhere",
    );

    // Shard 0 claiming to be shard 1.
    set_data(&mut context, shard, |d| d[2] = 1);
    let ix = owner_execute(&context, &wallet);
    assert_custom_error(
        send_owner(&mut context, &wallet, ix),
        ERR_INVALID_TREASURY_SHARD,
        "shard 0 with shard 1's id",
    );
}
