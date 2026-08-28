//! M-2 — the binary refuses to run at an address other than its own.
//!
//! The cluster id has always been compiled in (`assertions::ID`, selected by the
//! `mainnet`/`devnet` feature), and every PDA this program derives uses that id.
//! Nothing checked that the running instance actually *is* that id.
//!
//! A copy deployed elsewhere cannot reach real accounts — its derivations land
//! in a disjoint address space. What it can do is mint look-alike wallets,
//! authorities and sessions at addresses that look correct to anything resolving
//! them against the wrong program id: a mis-configured SDK, an explorer, an
//! indexer, a second deployment left over from a test. The cheap fix, now that
//! the deploy is under our control, is to refuse at the entrypoint.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test program_id_binding_tests

mod common;

use common::*;
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `ProtocolError::WrongProgramAddress`
const ERR_WRONG_PROGRAM_ADDRESS: u32 = 4017;

/// The same binary the real tests load, deployed at an address that is not the
/// one compiled into it.
fn svm_with_impostor() -> (LiteSVM, Pubkey, Keypair) {
    let mut svm = LiteSVM::new();
    let impostor = Pubkey::new_unique();
    svm.add_program_from_file(impostor, sbf_artifact_path())
        .expect("load program at the wrong address");

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("fund payer");

    (svm, impostor, payer)
}

/// Every instruction is refused, including the ones that take no accounts worth
/// validating — the check is at the entrypoint, ahead of dispatch, so there is
/// no discriminator that slips past it.
#[test]
fn every_instruction_is_refused_at_the_wrong_address() {
    // 0 CreateWallet · 1 AddAuthority · 2 RemoveAuthority · 3 TransferOwnership
    // 4 Execute · 5 CreateSession · 6 Authorize · 7 ExecuteDeferred
    // 8 RevokeSession · 9 ReclaimDeferred · 10..=16 protocol
    for discriminator in 0u8..=16 {
        let (mut svm, impostor, payer) = svm_with_impostor();

        let ix = Instruction {
            program_id: impostor,
            // Deliberately plausible but irrelevant: the entrypoint rejects
            // before any account is read, so the list cannot matter.
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            data: vec![discriminator],
        };

        let result = try_send(&mut svm, &payer, &[ix], &[&payer]);
        assert_custom_error(
            result,
            ERR_WRONG_PROGRAM_ADDRESS,
            &format!("discriminator {discriminator} at a foreign address"),
        );
    }
}

/// An empty instruction data buffer is refused for the address, not for being
/// empty — the ordering matters, because the address check is the one that must
/// not be reachable around.
#[test]
fn the_address_is_checked_before_the_instruction_data() {
    let (mut svm, impostor, payer) = svm_with_impostor();

    let ix = Instruction {
        program_id: impostor,
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![],
    };

    assert_custom_error(
        try_send(&mut svm, &payer, &[ix], &[&payer]),
        ERR_WRONG_PROGRAM_ADDRESS,
        "empty data at a foreign address is an address error, not a data error",
    );
}

/// Control: at its own address the same binary gets past the entrypoint and
/// fails on the merits instead. Without this the test above would also pass
/// against a program that rejected everything.
#[test]
fn the_real_address_gets_past_the_entrypoint() {
    let mut context = setup_test();

    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![AccountMeta::new(context.payer.pubkey(), true)],
        data: vec![],
    };
    let payer = context.payer.insecure_clone();
    let err = try_send(&mut context.svm, &payer, &[ix], &[&payer])
        .expect_err("empty instruction data is still invalid");

    let logs = err.meta.pretty_logs();
    assert!(
        !logs.contains(&format!("0x{ERR_WRONG_PROGRAM_ADDRESS:x}")),
        "at its own address the failure must not be the address check:\n{logs}"
    );
}
