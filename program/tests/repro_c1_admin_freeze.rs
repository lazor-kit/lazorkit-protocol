//! C-1 — the protocol admin was claimed by whoever called first, could never be
//! rotated, and held a switch that froze every user's funds. Three defects that
//! only mattered because they compounded.
//!
//! What the reproduction showed, before the fix:
//!
//!   - `initialize_protocol` had no authorization gate of any kind, so the first
//!     caller after any deploy became admin permanently
//!   - `update_protocol` could write fees, the enabled flag and the treasury,
//!     but not `admin` — so "permanently" was literal
//!   - `try_collect_fee` reverted on `enabled == 0` or a zero fee, and
//!     discriminators 4 and 7 are the only paths that CPI with the vault PDA as
//!     signer, so one byte stranded 89,000,000 lamports with no instruction able
//!     to recover them
//!
//! Each test below now asserts the fix, and — more usefully — asserts the
//! property that made the defect matter rather than just the symptom. The
//! freeze case is the one to read: it checks that a disabled protocol still
//! lets users move their own money, and merely stops charging for it.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test repro_c1_admin_freeze

mod common;

use common::*;
use lazorkit_program::state::protocol_config::MAX_PROTOCOL_FEE_LAMPORTS;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

const ERR_PROTOCOL_ALREADY_INITIALIZED: u32 = 4001;
const ERR_INVALID_PROTOCOL_ADMIN: u32 = 4002;
const ERR_FEE_EXCEEDS_MAXIMUM: u32 = 4014;
const ERR_UNAUTHORIZED_INITIALIZER: u32 = 4015;
const ERR_NO_PENDING_ADMIN: u32 = 4016;

// ─────────────────────────────────────────────────────────────────────────
// C-1a — initialization is gated on a key compiled into the binary
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_a_only_the_init_authority_can_initialize() {
    let mut context = setup_uninitialized();

    // A stranger: not the deployer, holds no program-derived account, has never
    // touched LazorKit. Under v1 this transaction made them admin forever.
    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");

    let steal = initialize_protocol_ix(
        context.program_id,
        attacker.pubkey(),
        attacker.pubkey(), // admin — attacker names themselves
        attacker.pubkey(), // treasury
        5_000,
        2_000,
        1,
    );
    assert_custom_error(
        try_send(&mut context.svm, &attacker, &[steal], &[&attacker]),
        ERR_UNAUTHORIZED_INITIALIZER,
        "C-1a: a stranger must not be able to claim the admin slot",
    );

    // Nothing was written, so the real authority can still initialize.
    let authority = init_authority();
    context
        .svm
        .airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("airdrop");

    let legit = initialize_protocol_ix(
        context.program_id,
        authority.pubkey(),
        authority.pubkey(),
        authority.pubkey(),
        5_000,
        2_000,
        1,
    );
    try_send(&mut context.svm, &authority, &[legit], &[&authority])
        .expect("C-1a: the init authority must be able to initialize");

    assert_eq!(
        config_admin(&context.svm, context.program_id),
        authority.pubkey()
    );

    // Still one-shot: the gate is in addition to, not instead of, idempotency.
    advance(&mut context.svm);
    let again = initialize_protocol_ix(
        context.program_id,
        authority.pubkey(),
        authority.pubkey(),
        authority.pubkey(),
        5_000,
        2_000,
        1,
    );
    assert_custom_error(
        try_send(&mut context.svm, &authority, &[again], &[&authority]),
        ERR_PROTOCOL_ALREADY_INITIALIZED,
        "C-1a: initialization stays one-shot",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1b — the admin key rotates, in two steps
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_b_admin_rotates_in_two_steps() {
    let mut context = setup_test(); // admin == the init authority
    let admin = init_authority();
    let successor = Keypair::new();
    context
        .svm
        .airdrop(&successor.pubkey(), 1_000_000_000)
        .expect("airdrop");

    let payer = context.payer.insecure_clone();

    // Proposing does not transfer anything on its own.
    try_send(
        &mut context.svm,
        &payer,
        &[propose_admin_ix(
            context.program_id,
            admin.pubkey(),
            successor.pubkey(),
        )],
        &[&payer, &admin],
    )
    .expect("current admin may propose");
    assert_eq!(
        config_admin(&context.svm, context.program_id),
        admin.pubkey(),
        "C-1b: a proposal alone must not move the admin"
    );

    // Only the proposed key can accept. This is the half that stops a rotation
    // to a mistyped address from ending governance.
    advance(&mut context.svm);
    let impostor = Keypair::new();
    context
        .svm
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("airdrop");
    assert_custom_error(
        try_send(
            &mut context.svm,
            &impostor,
            &[accept_admin_ix(context.program_id, impostor.pubkey())],
            &[&impostor],
        ),
        ERR_NO_PENDING_ADMIN,
        "C-1b: only the proposed key may accept",
    );

    advance(&mut context.svm);
    try_send(
        &mut context.svm,
        &successor,
        &[accept_admin_ix(context.program_id, successor.pubkey())],
        &[&successor],
    )
    .expect("the proposed admin may accept");

    assert_eq!(
        config_admin(&context.svm, context.program_id),
        successor.pubkey(),
        "C-1b: rotation completed"
    );

    // The old admin is now powerless, and the new one is not.
    advance(&mut context.svm);
    assert_custom_error(
        try_send(
            &mut context.svm,
            &payer,
            &[update_protocol_ix(
                context.program_id,
                admin.pubkey(),
                5_000,
                2_000,
                1,
                admin.pubkey(),
            )],
            &[&payer, &admin],
        ),
        ERR_INVALID_PROTOCOL_ADMIN,
        "C-1b: the superseded admin loses its powers",
    );

    advance(&mut context.svm);
    try_send(
        &mut context.svm,
        &successor,
        &[update_protocol_ix(
            context.program_id,
            successor.pubkey(),
            5_000,
            2_000,
            1,
            successor.pubkey(),
        )],
        &[&successor],
    )
    .expect("C-1b: the new admin has them");
}

#[test]
fn c1_b_a_pending_rotation_can_be_cancelled() {
    let mut context = setup_test();
    let admin = init_authority();
    let successor = Keypair::new();
    context
        .svm
        .airdrop(&successor.pubkey(), 1_000_000_000)
        .expect("airdrop");
    let payer = context.payer.insecure_clone();

    try_send(
        &mut context.svm,
        &payer,
        &[propose_admin_ix(
            context.program_id,
            admin.pubkey(),
            successor.pubkey(),
        )],
        &[&payer, &admin],
    )
    .expect("propose");

    // Proposing the zero key withdraws the offer.
    advance(&mut context.svm);
    try_send(
        &mut context.svm,
        &payer,
        &[propose_admin_ix(
            context.program_id,
            admin.pubkey(),
            Pubkey::default(),
        )],
        &[&payer, &admin],
    )
    .expect("cancel");

    advance(&mut context.svm);
    assert_custom_error(
        try_send(
            &mut context.svm,
            &successor,
            &[accept_admin_ix(context.program_id, successor.pubkey())],
            &[&successor],
        ),
        ERR_NO_PENDING_ADMIN,
        "C-1b: a cancelled proposal cannot be accepted",
    );
    assert_eq!(
        config_admin(&context.svm, context.program_id),
        admin.pubkey()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1c — a disabled protocol stops charging, not stops working
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_c_disabling_the_protocol_no_longer_freezes_user_funds() {
    let mut context = setup_test();
    let admin = init_authority();
    let payer = context.payer.insecure_clone();

    let wallet = create_ed25519_wallet(&mut context, 100_000_000);
    let recipient = Pubkey::new_unique();

    // Baseline: enabled, so the withdrawal works and the shard is paid.
    let shard_before = shard_balance(&context.svm, context.program_id);
    let ix = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(10_000_000),
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner]).expect("baseline Execute");
    let shard_after_enabled = shard_balance(&context.svm, context.program_id);
    assert!(
        shard_after_enabled > shard_before,
        "precondition: an enabled protocol collects a fee"
    );

    // The admin flips the byte that used to strand everybody.
    advance(&mut context.svm);
    try_send(
        &mut context.svm,
        &payer,
        &[update_protocol_ix(
            context.program_id,
            admin.pubkey(),
            5_000,
            2_000,
            0, // enabled = 0
            admin.pubkey(),
        )],
        &[&payer, &admin],
    )
    .expect("disable");

    // The user can still move their own money. This is the whole fix.
    advance(&mut context.svm);
    let ix = solana_sdk::instruction::Instruction {
        program_id: context.program_id,
        accounts: ed25519_execute_accounts(&context, &wallet, recipient),
        data: vault_transfer_execute_data(10_000_000),
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
        .expect("C-1c: a disabled protocol must not prevent a user from moving their own funds");

    assert_eq!(
        context
            .svm
            .get_account(&recipient)
            .map(|a| a.lamports)
            .unwrap_or(0),
        20_000_000,
        "C-1c: both withdrawals landed"
    );
    assert_eq!(
        shard_balance(&context.svm, context.program_id),
        shard_after_enabled,
        "C-1c: and the protocol collected nothing while disabled — revenue is what \
         a disabled protocol gives up, not custody"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1d — an unbounded fee was the same freeze wearing a fee's clothes
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_d_fees_are_capped_at_write_time() {
    let mut context = setup_test();
    let admin = init_authority();
    let payer = context.payer.insecure_clone();

    for (label, creation, execution) in [
        ("creation fee", MAX_PROTOCOL_FEE_LAMPORTS + 1, 2_000),
        ("execution fee", 5_000, MAX_PROTOCOL_FEE_LAMPORTS + 1),
        ("both", u64::MAX, u64::MAX),
    ] {
        advance(&mut context.svm);
        assert_custom_error(
            try_send(
                &mut context.svm,
                &payer,
                &[update_protocol_ix(
                    context.program_id,
                    admin.pubkey(),
                    creation,
                    execution,
                    1,
                    admin.pubkey(),
                )],
                &[&payer, &admin],
            ),
            ERR_FEE_EXCEEDS_MAXIMUM,
            &format!("C-1d: {label} above the ceiling must be refused"),
        );
    }

    // At the ceiling exactly is still allowed — the cap bounds abuse, it does
    // not dictate pricing.
    advance(&mut context.svm);
    try_send(
        &mut context.svm,
        &payer,
        &[update_protocol_ix(
            context.program_id,
            admin.pubkey(),
            MAX_PROTOCOL_FEE_LAMPORTS,
            MAX_PROTOCOL_FEE_LAMPORTS,
            1,
            admin.pubkey(),
        )],
        &[&payer, &admin],
    )
    .expect("C-1d: the ceiling itself is a legal fee");
}

#[test]
fn c1_d_initialization_is_capped_too() {
    let mut context = setup_uninitialized();
    let authority = init_authority();
    context
        .svm
        .airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("airdrop");

    assert_custom_error(
        try_send(
            &mut context.svm,
            &authority,
            &[initialize_protocol_ix(
                context.program_id,
                authority.pubkey(),
                authority.pubkey(),
                authority.pubkey(),
                u64::MAX,
                2_000,
                1,
            )],
            &[&authority],
        ),
        ERR_FEE_EXCEEDS_MAXIMUM,
        "C-1d: the cap applies at initialization, not only at update",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// C-1e — the chain that made all three matter together
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn c1_e_the_stranger_never_gets_started() {
    let mut context = setup_uninitialized();

    let attacker = Keypair::new();
    context
        .svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");

    // Step one of the old chain — winning the init race — no longer exists.
    assert_custom_error(
        try_send(
            &mut context.svm,
            &attacker,
            &[initialize_protocol_ix(
                context.program_id,
                attacker.pubkey(),
                attacker.pubkey(),
                attacker.pubkey(),
                5_000,
                2_000,
                1,
            )],
            &[&attacker],
        ),
        ERR_UNAUTHORIZED_INITIALIZER,
        "C-1e: the chain starts with an init race that can no longer be won",
    );

    // And even granting the attacker the admin slot outright, the switch it
    // used to control no longer strands anybody — see c1_c. What remains is
    // the ability to overcharge up to the ceiling, which is a revenue problem,
    // not a custody one.
    assert!(
        context
            .svm
            .get_account(
                &Pubkey::find_program_address(
                    &[lazorkit_program::seeds::PROTOCOL_CONFIG],
                    &context.program_id
                )
                .0
            )
            .is_none_or(|a| a.data.is_empty()),
        "C-1e: nothing was written by the rejected attempt"
    );
}
