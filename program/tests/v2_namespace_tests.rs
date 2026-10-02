//! The two mechanisms that let v2 ship without migration code, asserted rather
//! than assumed.
//!
//! v2 keeps the program address, so PDA addresses are a pure function of the
//! seeds and v1's accounts sit inside the address space v2 would otherwise use.
//! Two independent guards keep them apart:
//!
//!   1. **Seed namespace** — every seed carries the `lk2:` prefix, so a v2 PDA
//!      never lands on a v1 address. This matters most for the singletons:
//!      v1's `["protocol_config"]` still exists on chain, and if v2 derived the
//!      same address it could never initialise — `check_zero_data` requires
//!      `data_len() == 0`, which an existing 88-byte account cannot satisfy, and
//!      no instruction exists to repair that.
//!
//!   2. **Discriminator renumbering** — v2 discriminators carry the protocol
//!      version in the high nibble (`0x2N`), so a v1 account handed to a v2
//!      instruction fails on byte 0 rather than being reinterpreted.
//!
//! Belt and braces on purpose: either alone would do, and the second is what
//! catches a v1 account passed in deliberately rather than found by derivation.
//!
//! The version byte is also now read. In v1 it was written at ten sites and
//! never checked, so it carried no information; here a wrong layout revision is
//! rejected with a distinct code an operator can act on.

mod common;

use common::*;
use lazorkit_program::state::{AccountDiscriminator, CURRENT_ACCOUNT_VERSION, PROTOCOL_VERSION};
use solana_sdk::{account::Account, instruction::Instruction, pubkey::Pubkey};

/// `ProtocolError::AccountVersionMismatch`
const ERR_ACCOUNT_VERSION_MISMATCH: u32 = 4013;

// ─────────────────────────────────────────────────────────────────────────
// Seed namespace
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn v2_seeds_derive_addresses_disjoint_from_v1() {
    let program_id = Pubkey::new_unique();
    let user_seed = rand::random::<[u8; 32]>();

    // Every pair below is the same account type under v1 seeds and v2 seeds.
    let v1_wallet = Pubkey::find_program_address(&[b"wallet", &user_seed], &program_id).0;
    let v2_wallet =
        Pubkey::find_program_address(&[lazorkit_program::seeds::WALLET, &user_seed], &program_id).0;
    assert_ne!(v1_wallet, v2_wallet, "wallet PDA collides with v1");

    let v1_vault = Pubkey::find_program_address(&[b"vault", v1_wallet.as_ref()], &program_id).0;
    let v2_vault = Pubkey::find_program_address(
        &[lazorkit_program::seeds::VAULT, v2_wallet.as_ref()],
        &program_id,
    )
    .0;
    assert_ne!(v1_vault, v2_vault, "vault PDA collides with v1");

    // The singletons are the ones that actually matter: they have no random
    // material, so under v1 seeds they would land on the same address every
    // time and be permanently unrecoverable.
    let v1_config = Pubkey::find_program_address(&[b"protocol_config"], &program_id).0;
    let v2_config =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id).0;
    assert_ne!(v1_config, v2_config, "ProtocolConfig PDA collides with v1");

    let v1_shard = Pubkey::find_program_address(&[b"treasury_shard", &[0u8]], &program_id).0;
    let v2_shard = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &[0u8]],
        &program_id,
    )
    .0;
    assert_ne!(v1_shard, v2_shard, "TreasuryShard PDA collides with v1");
}

// ─────────────────────────────────────────────────────────────────────────
// Discriminator renumbering
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn discriminators_carry_the_protocol_version() {
    for (name, disc) in [
        ("Wallet", AccountDiscriminator::Wallet),
        ("Authority", AccountDiscriminator::Authority),
        ("Session", AccountDiscriminator::Session),
        ("DeferredExec", AccountDiscriminator::DeferredExec),
        ("ProtocolConfig", AccountDiscriminator::ProtocolConfig),
        ("FeeRecord", AccountDiscriminator::FeeRecord),
        ("TreasuryShard", AccountDiscriminator::TreasuryShard),
    ] {
        let byte = disc as u8;
        assert_eq!(
            byte >> 4,
            PROTOCOL_VERSION,
            "{name} discriminator {byte:#04x} does not encode the protocol version"
        );
        assert!(
            !(1..=7).contains(&byte),
            "{name} discriminator {byte:#04x} still overlaps the v1 range"
        );
    }
}

/// A wallet account written with v1's bytes must not be usable, even when it is
/// handed to the instruction directly rather than found by derivation.
#[test]
fn a_v1_shaped_wallet_account_is_rejected() {
    let mut context = setup_test();
    let payer = context.payer.insecure_clone();

    // A real v2 wallet, so the comparison isolates the account bytes.
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);

    // v1 layout: discriminator 1, bump, version 1, five padding bytes.
    let mut v1_bytes = vec![0u8; 8];
    v1_bytes[0] = 1; // v1 AccountDiscriminator::Wallet
    v1_bytes[1] = 255;
    v1_bytes[2] = 1;

    context
        .svm
        .set_account(
            wallet.wallet_pda,
            Account {
                lamports: 1_000_000,
                data: v1_bytes,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("overwrite wallet with v1 bytes");

    let recipient = Pubkey::new_unique();
    let ix = Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(1_000_000),
    };

    let result = try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]);
    assert!(
        result.is_err(),
        "a v1-discriminator wallet was accepted by a v2 instruction"
    );
    assert_eq!(
        lamports_of(&context, &recipient),
        0,
        "nothing moved on the rejected path"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Version byte
// ─────────────────────────────────────────────────────────────────────────

/// The point of reading the version byte at all: an account this binary did not
/// write is refused with a code that says so, rather than being parsed as if it
/// had the current layout.
#[test]
fn a_future_layout_version_is_rejected_with_its_own_error() {
    let mut context = setup_test();
    let payer = context.payer.insecure_clone();
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);

    let mut data = context
        .svm
        .get_account(&wallet.wallet_pda)
        .expect("wallet exists")
        .data;
    assert_eq!(
        data[0],
        AccountDiscriminator::Wallet as u8,
        "precondition: wallet carries the v2 discriminator"
    );
    assert_eq!(
        data[2], CURRENT_ACCOUNT_VERSION,
        "precondition: wallet is at the current layout revision"
    );

    // Same discriminator, layout revision this binary does not implement.
    data[2] = CURRENT_ACCOUNT_VERSION + 1;

    context
        .svm
        .set_account(
            wallet.wallet_pda,
            Account {
                lamports: 1_000_000,
                data,
                owner: context.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("bump wallet layout version");

    let recipient = Pubkey::new_unique();
    let ix = Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(1_000_000),
    };

    assert_custom_error(
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]),
        ERR_ACCOUNT_VERSION_MISMATCH,
        "a future layout revision must be refused with AccountVersionMismatch",
    );
}

/// Guard against a half-finished renumbering: every account this binary creates
/// must carry both the v2 discriminator and the current layout revision.
#[test]
fn accounts_are_created_at_the_current_version() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 0);

    for (name, key, disc, version_offset) in [
        (
            "wallet",
            wallet.wallet_pda,
            AccountDiscriminator::Wallet as u8,
            Some(2usize),
        ),
        (
            "authority",
            wallet.owner_auth_pda,
            AccountDiscriminator::Authority as u8,
            Some(4),
        ),
    ] {
        let data = context
            .svm
            .get_account(&key)
            .unwrap_or_else(|| panic!("{name} account missing"))
            .data;
        assert_eq!(data[0], disc, "{name} has the wrong discriminator");
        if let Some(offset) = version_offset {
            assert_eq!(
                data[offset], CURRENT_ACCOUNT_VERSION,
                "{name} was created at the wrong layout revision"
            );
        }
    }

    // Protocol accounts come from setup_test()'s initialisation.
    let (config_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::PROTOCOL_CONFIG],
        &context.program_id,
    );
    let config = context
        .svm
        .get_account(&config_pda)
        .expect("ProtocolConfig missing")
        .data;
    assert_eq!(config[0], AccountDiscriminator::ProtocolConfig as u8);
    assert_eq!(config[1], CURRENT_ACCOUNT_VERSION);
}

fn lamports_of(context: &TestContext, key: &Pubkey) -> u64 {
    context
        .svm
        .get_account(key)
        .map(|a| a.lamports)
        .unwrap_or(0)
}
