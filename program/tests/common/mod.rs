// Each integration test binary pulls in this whole module, so helpers used by
// only some of them would otherwise warn.
#![allow(dead_code)]

use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::VersionedTransaction,
};

pub struct TestContext {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub program_id: Pubkey,
}

// ─────────────────────────────────────────────────────────────────────────
// Additions for the C-1 / H-1 reproduction tests.
//
// Everything below is additive — `setup_test()` and the existing helpers are
// unchanged, so the pre-existing suite behaves exactly as before.
// ─────────────────────────────────────────────────────────────────────────

/// Byte offsets into `ProtocolConfig` (see `state/protocol_config.rs`).
pub mod config_offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const ENABLED: usize = 3;
    pub const ADMIN: usize = 8;
    pub const TREASURY: usize = 40;
    pub const CREATION_FEE: usize = 72;
    pub const EXECUTION_FEE: usize = 80;
}

/// The keypair `initialize_protocol` now requires.
///
/// `ProtocolConfig` is the root of the fee system and has no earlier on-chain
/// account to anchor trust to, so the anchor is a pubkey compiled into the
/// binary (`state::protocol_config::PROTOCOL_INIT_AUTHORITY`). The devnet value
/// is this committed test key — devnet carries no value, and a shared secret
/// would make the local suites unrunnable.
pub fn init_authority() -> Keypair {
    const PATH: &str = "../keys/devnet-init-authority.json";
    solana_sdk::signer::keypair::read_keypair_file(PATH)
        .unwrap_or_else(|e| panic!("cannot read {PATH}: {e}. It is committed; is the tree clean?"))
}

/// Load the program and fund a payer, but do **not** run `initialize_protocol`.
///
/// This is the state every fresh deployment is in for the window between
/// `solana program deploy` landing and the team's init transaction confirming.
pub fn setup_uninitialized() -> TestContext {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();
    start_the_clock(&mut svm);
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("Failed to airdrop");
    let program_id = load_program(&mut svm);

    TestContext {
        svm,
        payer,
        program_id,
    }
}

/// Build an `InitializeProtocol` (discriminator 10) instruction.
///
/// `payer` funds the rent; `admin` and `treasury` are whatever the caller
/// puts in the instruction data — the program does not check that they relate
/// to the signer, the deployer, or anything else.
pub fn initialize_protocol_ix(
    program_id: Pubkey,
    payer: Pubkey,
    admin: Pubkey,
    treasury: Pubkey,
    creation_fee: u64,
    execution_fee: u64,
    num_shards: u8,
) -> Instruction {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);

    let mut data = vec![10u8];
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(treasury.as_ref());
    data.extend_from_slice(&creation_fee.to_le_bytes());
    data.extend_from_slice(&execution_fee.to_le_bytes());
    data.push(num_shards);

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(config_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data,
    }
}

/// Build an `UpdateProtocol` (discriminator 11) instruction.
///
/// Note the parameter list: there is no `new_admin`. That is the finding, not
/// an omission in this helper — see `update_protocol.rs:67-70`.
pub fn update_protocol_ix(
    program_id: Pubkey,
    admin: Pubkey,
    creation_fee: u64,
    execution_fee: u64,
    enabled: u8,
    new_treasury: Pubkey,
) -> Instruction {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);

    let mut data = vec![11u8];
    data.extend_from_slice(&creation_fee.to_le_bytes());
    data.extend_from_slice(&execution_fee.to_le_bytes());
    data.push(enabled);
    data.extend_from_slice(&[0u8; 7]); // padding
    data.extend_from_slice(new_treasury.as_ref());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(config_pda, false),
        ],
        data,
    }
}

/// Build an `InitializeTreasuryShard` (discriminator 14) instruction.
pub fn init_shard_ix(
    program_id: Pubkey,
    payer: Pubkey,
    admin: Pubkey,
    shard_id: u8,
) -> Instruction {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    let (shard_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &[shard_id]],
        &program_id,
    );

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(shard_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: vec![14u8, shard_id],
    }
}

/// Build a `ProposeProtocolAdmin` (discriminator 15) instruction.
pub fn propose_admin_ix(program_id: Pubkey, admin: Pubkey, new_admin: Pubkey) -> Instruction {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    let mut data = vec![15u8];
    data.extend_from_slice(new_admin.as_ref());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(config_pda, false),
        ],
        data,
    }
}

/// Build an `AcceptProtocolAdmin` (discriminator 16) instruction.
pub fn accept_admin_ix(program_id: Pubkey, new_admin: Pubkey) -> Instruction {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(new_admin, true),
            AccountMeta::new(config_pda, false),
        ],
        data: vec![16u8],
    }
}

/// Lamports currently sitting in treasury shard 0.
pub fn shard_balance(svm: &LiteSVM, program_id: Pubkey) -> u64 {
    let (shard_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &[0u8]],
        &program_id,
    );
    svm.get_account(&shard_pda).map(|a| a.lamports).unwrap_or(0)
}

/// The four accounts `try_collect_fee` requires as a suffix, keyed to an
/// arbitrary fee payer (not necessarily `context.payer`).
pub fn fee_suffix_for(program_id: Pubkey, fee_payer: Pubkey) -> Vec<AccountMeta> {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    let (record_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::FEE_RECORD, fee_payer.as_ref()],
        &program_id,
    );
    let (shard_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &[0u8]],
        &program_id,
    );

    vec![
        AccountMeta::new_readonly(config_pda, false),
        AccountMeta::new(record_pda, false),
        AccountMeta::new(shard_pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ]
}

// ─── Time ────────────────────────────────────────────────────────────────
//
// Session expiries, action expiries and recurring windows are Unix seconds
// (`Clock::unix_timestamp`). litesvm starts its clock at zero, where a slot
// passed in place of a time would look just as plausible as a time; every
// suite starts at a real date instead, from which any slot is decades past.

/// The Unix time every suite starts at: 2026-10-04 00:00 UTC, the day devnet
/// reached slot 507,081,509.
pub const TEST_UNIX_TIME: i64 = 1_791_072_000;

fn start_the_clock(svm: &mut LiteSVM) {
    let mut clock = svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.unix_timestamp = TEST_UNIX_TIME;
    svm.set_sysvar(&clock);
}

/// The cluster's Unix time, as the program reads it.
pub fn unix_now(svm: &LiteSVM) -> u64 {
    svm.get_sysvar::<solana_sdk::clock::Clock>().unix_timestamp as u64
}

/// Move the clock's Unix time to `unix` (the slot stays), and the blockhash
/// on, so the same transaction can be sent again at the new time.
pub fn set_unix_time(svm: &mut LiteSVM, unix: u64) {
    let mut clock = svm.get_sysvar::<solana_sdk::clock::Clock>();
    clock.unix_timestamp = unix as i64;
    svm.set_sysvar(&clock);
    advance(svm);
}

/// Advance the blockhash so a byte-identical transaction can be sent again.
///
/// litesvm does not tick between `send_transaction` calls, so replaying the
/// same instruction with the same signers produces the same signature and the
/// bank rejects it as `AlreadyProcessed`. Several tests below deliberately
/// send the identical transaction before and after a config change — that is
/// the point of the comparison — so they call this in between.
pub fn advance(svm: &mut LiteSVM) {
    svm.expire_blockhash();
}

/// Send one or more instructions, returning the result instead of panicking.
///
/// The error variant is large because it is litesvm's own
/// `FailedTransactionMetadata`, which carries the full log buffer — exactly what
/// a failing test needs to print. Boxing it here would ripple through every call
/// site and every assertion helper to hide a cost that only materialises on a
/// path that is about to abort the test anyway.
#[allow(clippy::result_large_err)]
pub fn try_send(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    ixs: &[Instruction],
    signers: &[&Keypair],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let message = v0::Message::try_compile(&fee_payer.pubkey(), ixs, &[], svm.latest_blockhash())
        .expect("Failed to compile message");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), signers)
        .expect("Failed to sign transaction");
    svm.send_transaction(tx)
}

/// Assert a transaction failed with a specific `ProgramError::Custom` code.
///
/// Generic in the success type so it also takes the results of the helpers that
/// return something useful on the happy path, like the PDA they created.
pub fn assert_custom_error<T>(
    result: Result<T, litesvm::types::FailedTransactionMetadata>,
    expected: u32,
    context: &str,
) {
    use solana_sdk::instruction::InstructionError;
    use solana_sdk::transaction::TransactionError;

    match result {
        Ok(_) => panic!("{context}: expected custom error {expected}, transaction SUCCEEDED"),
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
                assert_eq!(
                    code,
                    expected,
                    "{context}: expected custom error {expected}, got {code}\n{}",
                    failed.meta.pretty_logs()
                );
            },
            other => panic!(
                "{context}: expected custom error {expected}, got {other:?}\n{}",
                failed.meta.pretty_logs()
            ),
        },
    }
}

/// Read the raw `ProtocolConfig` bytes.
pub fn read_config(svm: &LiteSVM, program_id: Pubkey) -> Vec<u8> {
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    svm.get_account(&config_pda)
        .expect("ProtocolConfig account missing")
        .data
}

/// Read the 32-byte `admin` field out of `ProtocolConfig`.
pub fn config_admin(svm: &LiteSVM, program_id: Pubkey) -> Pubkey {
    let data = read_config(svm, program_id);
    Pubkey::try_from(&data[config_offsets::ADMIN..config_offsets::ADMIN + 32])
        .expect("admin slice is not 32 bytes")
}

/// Serialize compact instructions in the wire format `Execute` expects:
/// `[count u8]` then per instruction
/// `[program_idx u8][n_accounts u8][account_idx...][data_len u16 LE][data...]`
pub fn encode_compact(instructions: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![instructions.len() as u8];
    for (program_idx, account_idxs, data) in instructions {
        out.push(*program_idx);
        out.push(account_idxs.len() as u8);
        out.extend_from_slice(account_idxs);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// `System::Transfer` instruction data.
pub fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

/// Every PDA belonging to one Ed25519-owned wallet.
pub struct WalletFixture {
    pub user_seed: [u8; 32],
    pub owner: Keypair,
    pub wallet_pda: Pubkey,
    pub vault_pda: Pubkey,
    pub owner_auth_pda: Pubkey,
}

/// Create a wallet with a single Ed25519 Owner authority, and fund its vault.
pub fn create_ed25519_wallet(context: &mut TestContext, vault_lamports: u64) -> WalletFixture {
    create_ed25519_wallet_with(
        context,
        vault_lamports,
        rand::random::<[u8; 32]>(),
        Keypair::new(),
    )
}

/// [`create_ed25519_wallet`] at a chosen seed and owner, so every PDA, and the
/// bump search that finds it, is the same from run to run. Compute-unit
/// measurements need that: each extra bump `find_program_address` tries costs
/// about 1,500 CU.
pub fn create_ed25519_wallet_with(
    context: &mut TestContext,
    vault_lamports: u64,
    user_seed: [u8; 32],
    owner: Keypair,
) -> WalletFixture {
    let (wallet_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::WALLET, &user_seed],
        &context.program_id,
    );
    let (vault_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::VAULT, wallet_pda.as_ref()],
        &context.program_id,
    );
    let (owner_auth_pda, owner_bump) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet_pda.as_ref(),
            owner.pubkey().as_ref(),
        ],
        &context.program_id,
    );

    let mut data = vec![0u8]; // CreateWallet
    data.extend_from_slice(&user_seed);
    data.push(0); // Ed25519
    data.push(owner_bump);
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(owner.pubkey().as_ref());

    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new(wallet_pda, false),
                AccountMeta::new(vault_pda, false),
                AccountMeta::new(owner_auth_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            ],
            context,
        ),
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer]).expect("CreateWallet failed");

    if vault_lamports > 0 {
        context
            .svm
            .airdrop(&vault_pda, vault_lamports)
            .expect("Failed to fund vault");
    }

    WalletFixture {
        user_seed,
        owner,
        vault_pda,
        wallet_pda,
        owner_auth_pda,
    }
}

/// Account list for an `Execute` that moves `lamports` from the vault to
/// `recipient`, authorized by an Ed25519 authority.
///
/// Index layout — the compact instruction below refers to these positions:
///   `0` payer · `1` wallet · `2` authority · `3` vault
///   `4` system program (inner program id) · `5` recipient · `6` owner signer
pub fn ed25519_execute_accounts(
    context: &TestContext,
    wallet: &WalletFixture,
    recipient: Pubkey,
) -> Vec<AccountMeta> {
    with_protocol_fee_accounts(
        vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(wallet.vault_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        context,
    )
}

/// Instruction data for the `Execute` described by `ed25519_execute_accounts`:
/// one inner `System::Transfer` from account 3 (vault) to account 5 (recipient).
pub fn vault_transfer_execute_data(lamports: u64) -> Vec<u8> {
    let mut data = vec![4u8]; // Execute
    data.extend_from_slice(&encode_compact(&[(
        4,          // program_id_index -> system program
        vec![3, 5], // vault (from), recipient (to)
        system_transfer_data(lamports),
    )]));
    data
}

// ─── Sessions ────────────────────────────────────────────────────────────

/// Create a session key for `wallet`, authorized by its Ed25519 owner.
///
/// `actions` is the raw action buffer (empty = unrestricted session).
pub fn create_session_with_actions(
    context: &mut TestContext,
    wallet: &WalletFixture,
    actions: &[u8],
) -> Keypair {
    let session = Keypair::new();
    let session_pda = session_pda_for(context.program_id, wallet, &session);

    // A little over a day, in seconds.
    let expires_at = unix_now(&context.svm) + 100_000;

    let mut data = vec![5u8]; // CreateSession
    data.extend_from_slice(session.pubkey().as_ref());
    data.extend_from_slice(&expires_at.to_le_bytes());
    data.extend_from_slice(&(actions.len() as u16).to_le_bytes());
    data.extend_from_slice(actions);

    // CreateSession is discriminator 5 — not fee-eligible, so no fee suffix.
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new_readonly(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(session_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
        .expect("CreateSession failed");

    session
}

pub fn session_pda_for(program_id: Pubkey, wallet: &WalletFixture, session: &Keypair) -> Pubkey {
    Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::SESSION,
            wallet.wallet_pda.as_ref(),
            session.pubkey().as_ref(),
        ],
        &program_id,
    )
    .0
}

/// Read the raw action buffer stored after the 80-byte session header.
pub fn session_actions(svm: &LiteSVM, session_pda: Pubkey) -> Vec<u8> {
    let data = svm.get_account(&session_pda).expect("session exists").data;
    if data.len() > 80 {
        data[80..].to_vec()
    } else {
        Vec::new()
    }
}

// ─── Action buffer encoding (see state/action.rs) ────────────────────────
//
// Each action is `[type u8][data_len u16 LE][expires_at u64 LE][data...]`.
// `expires_at` is Unix seconds; 0 means "never expires".

fn action(action_type: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![action_type];
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // expires_at = never
    out.extend_from_slice(data);
    out
}

/// `SolLimit` — lifetime lamport cap. Data: `[remaining u64]`.
pub fn action_sol_limit(remaining: u64) -> Vec<u8> {
    action(1, &remaining.to_le_bytes())
}

/// `ProgramWhitelist` — allow CPI only to this program. Data: `[program 32]`.
pub fn action_program_whitelist(program: Pubkey) -> Vec<u8> {
    action(10, program.as_ref())
}

/// `TokenLimit` — lifetime cap for one mint. Data: `[mint 32][remaining u64]`.
pub fn action_token_limit(mint: Pubkey, remaining: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(&remaining.to_le_bytes());
    action(4, &data)
}

/// `SolRecurringLimit` — lamport cap per window of `window` seconds.
/// Data: `[limit u64][spent u64][window u64][last_reset u64]`.
pub fn action_sol_recurring_limit(limit: u64, window: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(&limit.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // spent
    data.extend_from_slice(&window.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // last_reset
    action(2, &data)
}

/// `SolMaxPerTx` — lamports per Execute. Data: `[max u64]`.
pub fn action_sol_max_per_tx(max: u64) -> Vec<u8> {
    action(3, &max.to_le_bytes())
}

/// `TokenRecurringLimit` — cap per window of `window` seconds for one mint.
/// Data: `[mint 32][limit u64][spent u64][window u64][last_reset u64]`.
pub fn action_token_recurring_limit(mint: Pubkey, limit: u64, window: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(&limit.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // spent
    data.extend_from_slice(&window.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // last_reset
    action(5, &data)
}

/// `TokenMaxPerTx` — cap per Execute for one mint. Data: `[mint 32][max u64]`.
pub fn action_token_max_per_tx(mint: Pubkey, max: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(&max.to_le_bytes());
    action(6, &data)
}

/// `ProgramBlacklist` — refuse CPI to this program. Data: `[program 32]`.
pub fn action_program_blacklist(program: Pubkey) -> Vec<u8> {
    action(11, program.as_ref())
}

/// A `u64` field of action `action_idx` in a policy buffer stored from byte 80:
/// a session's actions, or an Ed25519 authority's policy. `field_off` is
/// relative to the action's data (`SolLimit.remaining` is 0,
/// `TokenLimit.remaining` 32).
pub fn session_action_u64(
    svm: &LiteSVM,
    policy_account: Pubkey,
    action_idx: usize,
    field_off: usize,
) -> u64 {
    let buf = session_actions(svm, policy_account);
    let mut cursor = 0;
    for _ in 0..action_idx {
        let data_len = u16::from_le_bytes([buf[cursor + 1], buf[cursor + 2]]) as usize;
        cursor += 11 + data_len;
    }
    let at = cursor + 11 + field_off;
    u64::from_le_bytes(buf[at..at + 8].try_into().unwrap())
}

// ─── SPL Token (layout-level fixtures) ───────────────────────────────────
//
// Accounts are written directly rather than built through SPL Token
// instructions: the byte offsets below are exactly the ones
// `processor/execute/actions.rs` reads, so writing them by hand keeps the
// test and the code under test talking about the same layout.

pub fn spl_token_id() -> Pubkey {
    Pubkey::try_from("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

/// Mint layout, 82 bytes:
/// `[auth_tag u32][auth 32][supply u64][decimals u8][init u8][freeze_tag u32][freeze 32]`
pub fn create_mint(svm: &mut LiteSVM, mint: Pubkey, authority: Pubkey, supply: u64) {
    let mut data = vec![0u8; 82];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
    data[4..36].copy_from_slice(authority.as_ref());
    data[36..44].copy_from_slice(&supply.to_le_bytes());
    data[44] = 6; // decimals
    data[45] = 1; // is_initialized
                  // freeze authority stays COption::None

    svm.set_account(
        mint,
        solana_sdk::account::Account {
            lamports: 1_461_600,
            data,
            owner: spl_token_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set mint account");
}

/// Token account layout, 165 bytes. The three fields the session guard
/// snapshots are `owner` (32..64), `delegate` (72..108) and `close_authority`
/// (129..165).
pub fn create_token_account(
    svm: &mut LiteSVM,
    address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
) {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate: COption::None (tag 72..76 stays zero)
    data[108] = 1; // AccountState::Initialized
                   // is_native: None, delegated_amount: 0, close_authority: None

    svm.set_account(
        address,
        solana_sdk::account::Account {
            lamports: 2_039_280,
            data,
            owner: spl_token_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set token account");
}

/// The `owner` field of a token account (bytes 32..64).
pub fn token_account_owner(svm: &LiteSVM, address: Pubkey) -> Pubkey {
    let data = svm.get_account(&address).expect("token account").data;
    Pubkey::try_from(&data[32..64]).expect("owner field")
}

/// The `delegate` COption of a token account (bytes 72..108).
pub fn token_account_delegate(svm: &LiteSVM, address: Pubkey) -> Option<Pubkey> {
    let data = svm.get_account(&address).expect("token account").data;
    if u32::from_le_bytes(data[72..76].try_into().unwrap()) == 1 {
        Some(Pubkey::try_from(&data[76..108]).expect("delegate field"))
    } else {
        None
    }
}

/// `SetAuthority` instruction data.
/// `[6][authority_type u8][new_authority_tag u8][new_authority 32]`
/// authority_type: 0 MintTokens · 1 FreezeAccount · 2 AccountOwner · 3 CloseAccount
pub fn spl_set_authority_data(authority_type: u8, new_authority: Pubkey) -> Vec<u8> {
    let mut data = Vec::with_capacity(35);
    data.push(6);
    data.push(authority_type);
    data.push(1); // COption::Some
    data.extend_from_slice(new_authority.as_ref());
    data
}

pub fn spl_token_2022_id() -> Pubkey {
    Pubkey::try_from("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
}

pub fn ata_program_id() -> Pubkey {
    Pubkey::try_from("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
}

/// The wrapped-SOL mint. litesvm does not create it; [`create_native_mint`]
/// writes it.
pub fn native_mint() -> Pubkey {
    Pubkey::try_from("So11111111111111111111111111111111111111112").unwrap()
}

/// The associated token account of `owner` for `mint` under `token_program`.
pub fn ata_address(owner: Pubkey, mint: Pubkey, token_program: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program_id(),
    )
    .0
}

/// A mint under `program`, written by hand like [`create_mint`].
///
/// `extensions` is Token-2022 TLV (`[type u16][len u16][value]` …). When it is
/// not empty the base is padded to 165 bytes and byte 165 is the account type,
/// 1 (Mint), as Token-2022 lays an extended mint out.
#[allow(clippy::too_many_arguments)]
pub fn create_mint_with(
    svm: &mut LiteSVM,
    program: Pubkey,
    mint: Pubkey,
    authority: Pubkey,
    freeze: Option<Pubkey>,
    supply: u64,
    decimals: u8,
    extensions: &[u8],
) {
    let mut data = vec![0u8; 82];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
    data[4..36].copy_from_slice(authority.as_ref());
    data[36..44].copy_from_slice(&supply.to_le_bytes());
    data[44] = decimals;
    data[45] = 1; // is_initialized
    if let Some(freeze) = freeze {
        data[46..50].copy_from_slice(&1u32.to_le_bytes());
        data[50..82].copy_from_slice(freeze.as_ref());
    }
    if !extensions.is_empty() {
        data.resize(165, 0);
        data.push(1); // AccountType::Mint
        data.extend_from_slice(extensions);
    }
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        mint,
        solana_sdk::account::Account {
            lamports,
            data,
            owner: program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set mint account");
}

/// The wrapped-SOL mint under SPL Token: 9 decimals, no authority.
pub fn create_native_mint(svm: &mut LiteSVM) {
    create_mint_with(
        svm,
        spl_token_id(),
        native_mint(),
        Pubkey::default(),
        None,
        0,
        9,
        &[],
    );
    // A native mint has no mint authority.
    let mut account = svm.get_account(&native_mint()).unwrap();
    account.data[0..36].fill(0);
    svm.set_account(native_mint(), account).unwrap();
}

/// The optional fields of a hand-written token account.
#[derive(Default)]
pub struct TokenAccountOpts {
    /// `(delegate, delegated_amount)`.
    pub delegate: Option<(Pubkey, u64)>,
    pub close_authority: Option<Pubkey>,
    /// Makes the account native (wSOL): `is_native = Some(reserve)`, and its
    /// lamports `reserve + amount`.
    pub native_reserve: Option<u64>,
    /// Lamports above what the account needs.
    pub extra_lamports: u64,
    /// Token-2022 TLV. When not empty, byte 165 is the account type, 2
    /// (Account), and the TLV follows.
    pub extensions: Vec<u8>,
}

/// A token account under `program`, every field written by hand at the
/// offsets `processor/execute/actions.rs` reads.
pub fn create_token_account_with(
    svm: &mut LiteSVM,
    program: Pubkey,
    address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    opts: TokenAccountOpts,
) {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    if let Some((delegate, delegated_amount)) = opts.delegate {
        data[72..76].copy_from_slice(&1u32.to_le_bytes());
        data[76..108].copy_from_slice(delegate.as_ref());
        data[121..129].copy_from_slice(&delegated_amount.to_le_bytes());
    }
    data[108] = 1; // AccountState::Initialized
    if let Some(reserve) = opts.native_reserve {
        data[109..113].copy_from_slice(&1u32.to_le_bytes());
        data[113..121].copy_from_slice(&reserve.to_le_bytes());
    }
    if let Some(close_authority) = opts.close_authority {
        data[129..133].copy_from_slice(&1u32.to_le_bytes());
        data[133..165].copy_from_slice(close_authority.as_ref());
    }
    if !opts.extensions.is_empty() {
        data.push(2); // AccountType::Account
        data.extend_from_slice(&opts.extensions);
    }
    let lamports = match opts.native_reserve {
        Some(reserve) => reserve + amount,
        None => svm.minimum_balance_for_rent_exemption(data.len()),
    } + opts.extra_lamports;
    svm.set_account(
        address,
        solana_sdk::account::Account {
            lamports,
            data,
            owner: program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set token account");
}

/// The `amount` of a token account (bytes 64..72).
pub fn token_amount(svm: &LiteSVM, address: Pubkey) -> u64 {
    let data = svm.get_account(&address).expect("token account").data;
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

/// The `close_authority` COption of a token account (bytes 129..165).
pub fn token_account_close_authority(svm: &LiteSVM, address: Pubkey) -> Option<Pubkey> {
    let data = svm.get_account(&address).expect("token account").data;
    if u32::from_le_bytes(data[129..133].try_into().unwrap()) == 1 {
        Some(Pubkey::try_from(&data[133..165]).expect("close authority field"))
    } else {
        None
    }
}

// SPL Token instruction data. Tags are the same in SPL Token 3.5.0 and
// Token-2022 5.0.2, the versions litesvm 0.6 loads.

/// `Transfer`: `[3][amount u64]`. Accounts: source, destination, authority.
pub fn spl_transfer_data(amount: u64) -> Vec<u8> {
    spl_amount_data(3, amount)
}

/// `Approve`: `[4][amount u64]`. Accounts: source, delegate, owner.
pub fn spl_approve_data(amount: u64) -> Vec<u8> {
    spl_amount_data(4, amount)
}

/// `Burn`: `[8][amount u64]`. Accounts: account, mint, authority.
pub fn spl_burn_data(amount: u64) -> Vec<u8> {
    spl_amount_data(8, amount)
}

/// `CloseAccount`: `[9]`. Accounts: account, destination, owner.
pub fn spl_close_account_data() -> Vec<u8> {
    vec![9]
}

/// `FreezeAccount`: `[10]`. Accounts: account, mint, freeze authority.
pub fn spl_freeze_account_data() -> Vec<u8> {
    vec![10]
}

/// `TransferChecked`: `[12][amount u64][decimals u8]`. Accounts: source, mint,
/// destination, authority.
pub fn spl_transfer_checked_data(amount: u64, decimals: u8) -> Vec<u8> {
    let mut data = spl_amount_data(12, amount);
    data.push(decimals);
    data
}

/// `SyncNative`: `[17]`. Accounts: the native account.
pub fn spl_sync_native_data() -> Vec<u8> {
    vec![17]
}

/// `InitializeAccount3`: `[18][owner 32]`. Accounts: account, mint.
pub fn spl_initialize_account3_data(owner: Pubkey) -> Vec<u8> {
    let mut data = vec![18];
    data.extend_from_slice(owner.as_ref());
    data
}

/// Token-2022 `Reallocate`: `[29][extension type u16]…`. Accounts: account,
/// payer, system program, owner.
pub fn token_2022_reallocate_data(extension_types: &[u16]) -> Vec<u8> {
    let mut data = vec![29];
    for t in extension_types {
        data.extend_from_slice(&t.to_le_bytes());
    }
    data
}

/// Token-2022 `WithdrawExcessLamports`: `[38]`. Accounts: source, destination,
/// authority.
pub fn token_2022_withdraw_excess_lamports_data() -> Vec<u8> {
    vec![38]
}

/// ATA `CreateIdempotent`: `[1]`. Accounts: funder, ATA, owner, mint, system
/// program, token program.
pub fn ata_create_idempotent_data() -> Vec<u8> {
    vec![1]
}

fn spl_amount_data(tag: u8, amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(tag);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

// ─── Execute, generalised ────────────────────────────────────────────────

/// A compact account index with the forward-signer bit set: the inner
/// instruction may use this outer signer's signature (see
/// `compact::ACCOUNT_INDEX_FORWARD_SIGNER`).
pub fn forward_signer(index: u8) -> u8 {
    index | 0x80
}

/// Account list for an `Execute` authorized by `authority_pda` — a session or
/// an authority — with `extra` from index 4, then the fee suffix:
///   `0` payer · `1` wallet · `2` authority · `3` vault · `4..` `extra`
///
/// The key that authenticates `authority_pda` goes in `extra` as a signer.
/// Generalises `repro_h4`'s `token_execute_accounts`.
pub fn execute_accounts(
    context: &TestContext,
    wallet: &WalletFixture,
    authority_pda: Pubkey,
    extra: Vec<AccountMeta>,
) -> Vec<AccountMeta> {
    let mut accounts = vec![
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(wallet.wallet_pda, false),
        AccountMeta::new(authority_pda, false),
        AccountMeta::new(wallet.vault_pda, false),
    ];
    accounts.extend(extra);
    with_protocol_fee_accounts(accounts, context)
}

/// `Execute` instruction data: discriminator 4, then the compact instructions.
pub fn execute_data(instructions: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut data = vec![4u8];
    data.extend_from_slice(&encode_compact(instructions));
    data
}

/// A one-transfer `Execute` authorized by an Ed25519 authority PDA and its
/// signer, laid out as [`ed25519_execute_accounts`].
pub fn execute_as(
    context: &TestContext,
    wallet: &WalletFixture,
    authority_pda: Pubkey,
    signer: &Keypair,
    recipient: Pubkey,
    lamports: u64,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new_readonly(wallet.wallet_pda, false),
                AccountMeta::new(authority_pda, false),
                AccountMeta::new(wallet.vault_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(recipient, false),
                AccountMeta::new_readonly(signer.pubkey(), true),
            ],
            context,
        ),
        data: vault_transfer_execute_data(lamports),
    }
}

/// Load a pre-built fixture `.so`, searching the places the build script and
/// the various `CARGO_TARGET_DIR` conventions put it.
pub fn load_fixture_program(svm: &mut LiteSVM, crate_name: &str) -> Pubkey {
    let file = format!("{}.so", crate_name.replace('-', "_"));
    let candidates = [
        format!("../test-fixtures/{crate_name}/target/deploy/{file}"),
        format!("../test-fixtures/{crate_name}/target/sbpf-solana-solana/release/{file}"),
        format!("../target/deploy/{file}"),
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            assert_sbpf_v0(std::path::Path::new(path));
            let program_id = Pubkey::new_unique();
            svm.add_program_from_file(program_id, path)
                .unwrap_or_else(|e| panic!("Failed to load fixture {path}: {e:?}"));
            return program_id;
        }
    }

    panic!(
        "Fixture `{crate_name}` not built. Run:\n\n    ./scripts/build-repro-fixtures.sh\n\n\
         Searched:\n{}",
        candidates
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

pub fn setup_test() -> TestContext {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();
    start_the_clock(&mut svm);

    // Airdrop to payer
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("Failed to airdrop");

    // Load program
    let program_id = load_program(&mut svm);
    initialize_protocol(&mut svm, program_id);

    TestContext {
        svm,
        payer,
        program_id,
    }
}

/// The devnet id compiled into the `devnet`-featured binary. The program now
/// refuses to run anywhere else (M-2), so tests cannot load it at a random
/// address the way they used to.
/// The id the program under test was compiled for. It follows the cluster
/// feature, so a devnet build and a sunset build each load at their own address
/// — M-2 refuses to run anywhere else. Loading an artifact built for a
/// different feature fails every instruction with 4017 WrongProgramAddress.
pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array(lazorkit_program::ID);

fn load_program(svm: &mut LiteSVM) -> Pubkey {
    svm.add_program_from_file(PROGRAM_ID, sbf_artifact())
        .expect("Failed to load program");

    PROGRAM_ID
}

/// Locate the SBF artifact and refuse to run against a stale one.
///
/// Two things make this worth doing properly. `cargo build-sbf` and `cargo test`
/// do not always agree on the target directory — depending on how the shell was
/// invoked, one writes `target/deploy` while the other's `CARGO_TARGET_DIR`
/// points elsewhere — so both locations can hold an artifact and the older one
/// wins by being hardcoded. And a stale artifact does not fail; it passes the
/// old assertions and fails the new ones for reasons invisible in the diff. That
/// has cost real debugging time three times in this branch, once presenting as a
/// permission error and once as an unexplained zero field.
pub fn sbf_artifact_path() -> std::path::PathBuf {
    sbf_artifact()
}

fn sbf_artifact() -> std::path::PathBuf {
    use std::{path::PathBuf, time::SystemTime};

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut candidates: Vec<PathBuf> = vec![manifest.join("../target/deploy")];
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(&dir).join("deploy"));
        candidates.push(manifest.join("..").join(&dir).join("deploy"));
    }

    let modified = |p: &PathBuf| -> Option<SystemTime> { p.metadata().ok()?.modified().ok() };

    let artifact = candidates
        .iter()
        .map(|d| d.join("lazorkit_program.so"))
        .filter(|p| p.exists())
        .max_by_key(|p| modified(p).unwrap_or(SystemTime::UNIX_EPOCH));

    let Some(artifact) = artifact else {
        panic!(
            "no lazorkit_program.so found in {candidates:?}\n             run: cargo build-sbf --features devnet"
        );
    };

    // Newest source file under program/src, compared against the artifact.
    fn newest(dir: &std::path::Path, out: &mut Option<SystemTime>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                newest(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(t) = entry.metadata().and_then(|m| m.modified()) {
                    if out.is_none_or(|best| t > best) {
                        *out = Some(t);
                    }
                }
            }
        }
    }

    let mut newest_source = None;
    newest(&manifest.join("src"), &mut newest_source);

    if let (Some(source), Some(built)) = (newest_source, modified(&artifact)) {
        assert!(
            built >= source,
            "{} is older than program/src — every assertion below would be \
             testing the previous binary.\nrun: cargo build-sbf --features devnet",
            artifact.display()
        );
    }

    assert_sbpf_v0(&artifact);
    artifact
}

/// Refuse an artifact built for an SBPF version litesvm 0.6 cannot load.
///
/// `cargo-build-sbf` 4.4.0 (on crates.io since 2026-09-22, and what the Agave
/// `stable` installer puts on CI) changed its default `--arch` from v0 to v3.
/// litesvm 0.6's loader rejects a v3 ELF, and `add_program` unwraps that error,
/// so every test died inside litesvm (`lib.rs:700`, `InvalidAccountData`) with
/// nothing pointing at the build. The deployed binaries are SBPFv0
/// (docs/mainnet-deploy-checklist.md §2), so that is what the suites load:
/// build with `--arch v0`, as `scripts/build-repro-fixtures.sh` does.
fn assert_sbpf_v0(path: &std::path::Path) {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    // ELF64: e_flags is the u32 at 0x30. SBPF records its version there.
    let e_flags = bytes
        .get(0x30..0x34)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or_else(|| panic!("{} is not an ELF file", path.display()));
    assert_eq!(
        e_flags,
        0,
        "{} is not an SBPF v0 binary (ELF e_flags {e_flags:#x}; a v3 build has 0x3). \
         litesvm 0.6 loads only v0, which is what this program deploys as.\n\
         rebuild with: cargo build-sbf --features devnet --arch v0 \
         (or ./scripts/build-repro-fixtures.sh)",
        path.display()
    );
}

/// Initialise the protocol as `PROTOCOL_INIT_AUTHORITY`.
///
/// The per-test payer cannot do this any more: `initialize_protocol` is gated on
/// a pubkey compiled into the binary, because ProtocolConfig is the root of the
/// fee system and there is no earlier on-chain account to anchor trust to.
fn initialize_protocol(svm: &mut LiteSVM, program_id: Pubkey) {
    let authority = init_authority();
    svm.airdrop(&authority.pubkey(), 1_000_000_000)
        .expect("Failed to fund init authority");
    let payer = &authority;
    let (config_pda, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::PROTOCOL_CONFIG], &program_id);
    let shard_id = [0u8];
    let (shard_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &shard_id],
        &program_id,
    );

    let mut init_data = vec![10u8];
    init_data.extend_from_slice(payer.pubkey().as_ref()); // admin
    init_data.extend_from_slice(payer.pubkey().as_ref()); // treasury
    init_data.extend_from_slice(&5_000u64.to_le_bytes());
    init_data.extend_from_slice(&2_000u64.to_le_bytes());
    init_data.push(1); // one shard is enough for host-side tests

    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: init_data,
    };
    send_single_ix(svm, payer, init_ix, &[payer]);

    let shard_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(shard_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: vec![14u8, 0u8],
    };
    send_single_ix(svm, payer, shard_ix, &[payer]);
}

fn send_single_ix(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction, signers: &[&Keypair]) {
    let message = v0::Message::try_compile(&payer.pubkey(), &[ix], &[], svm.latest_blockhash())
        .expect("Failed to compile setup message");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), signers)
        .expect("Failed to sign setup transaction");
    svm.send_transaction(tx)
        .expect("Failed to initialize strict-fee test state");
}

pub fn protocol_fee_account_metas(context: &TestContext) -> Vec<AccountMeta> {
    let (config_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::PROTOCOL_CONFIG],
        &context.program_id,
    );
    let (record_pda, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::FEE_RECORD,
            context.payer.pubkey().as_ref(),
        ],
        &context.program_id,
    );
    let shard_id = [0u8];
    let (shard_pda, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::TREASURY_SHARD, &shard_id],
        &context.program_id,
    );

    vec![
        AccountMeta::new_readonly(config_pda, false),
        AccountMeta::new(record_pda, false),
        AccountMeta::new(shard_pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ]
}

pub fn with_protocol_fee_accounts(
    mut accounts: Vec<AccountMeta>,
    context: &TestContext,
) -> Vec<AccountMeta> {
    accounts.extend(protocol_fee_account_metas(context));
    accounts
}

// ─────────────────────────────────────────────────────────────────────────
// Authority management
// ─────────────────────────────────────────────────────────────────────────

/// Rank values, mirroring `processor::authority::manage`.
pub const RANK_OWNER: u8 = 0;
pub const RANK_ADMIN: u8 = 1;
pub const RANK_DELEGATE: u8 = 2;

/// The authority PDA an Ed25519 key would occupy on this wallet.
pub fn authority_pda_for(program_id: Pubkey, wallet_pda: Pubkey, key: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet_pda.as_ref(),
            key.as_ref(),
        ],
        &program_id,
    )
    .0
}

/// `AddAuthority` for an Ed25519 key, optionally carrying a policy.
///
/// Large `Err` variant is litesvm's `FailedTransactionMetadata` — see the note
/// on [`try_send`].
#[allow(clippy::result_large_err)]
pub fn add_ed25519_authority(
    context: &mut TestContext,
    wallet: &WalletFixture,
    authorizer_pda: Pubkey,
    authorizer_key: &Keypair,
    new_key: &Keypair,
    rank: u8,
    policy: &[u8],
) -> Result<Pubkey, litesvm::types::FailedTransactionMetadata> {
    let new_auth_pda = authority_pda_for(context.program_id, wallet.wallet_pda, &new_key.pubkey());

    let mut data = vec![1u8]; // AddAuthority
    data.push(0); // authority_type = Ed25519
    data.push(rank);
    data.extend_from_slice(&[0u8; 6]); // padding
    data.extend_from_slice(new_key.pubkey().as_ref());
    // `[policy_len u16][policy]` sits between the key material and the auth
    // payload — the same shape CreateSession uses for its actions, and inside
    // the signed region for the same reason.
    data.extend_from_slice(&(policy.len() as u16).to_le_bytes());
    data.extend_from_slice(policy);

    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            // Writable: AddAuthority maintains the wallet's owner_count.
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(authorizer_pda, false),
            AccountMeta::new(new_auth_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(authorizer_key.pubkey(), true),
        ],
        data,
    };

    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, authorizer_key])?;
    Ok(new_auth_pda)
}

/// `AddAuthority` authorized by the wallet's original Owner.
#[allow(clippy::result_large_err)]
pub fn owner_adds_ed25519(
    context: &mut TestContext,
    wallet: &WalletFixture,
    new_key: &Keypair,
    rank: u8,
    policy: &[u8],
) -> Result<Pubkey, litesvm::types::FailedTransactionMetadata> {
    let owner_pda = wallet.owner_auth_pda;
    let owner_key = wallet.owner.insecure_clone();
    add_ed25519_authority(
        context, wallet, owner_pda, &owner_key, new_key, rank, policy,
    )
}

/// A `RemoveAuthority` instruction, authorized by an Ed25519 authority.
///
/// Separate from [`remove_authority`] so several can be batched into one
/// transaction, which is how the ordering rules get tested.
pub fn remove_authority_ix(
    context: &TestContext,
    wallet: &WalletFixture,
    authorizer_pda: Pubkey,
    authorizer_key: &Keypair,
    target_pda: Pubkey,
) -> Instruction {
    Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            // Writable: RemoveAuthority maintains the wallet's owner_count.
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(authorizer_pda, false),
            AccountMeta::new(target_pda, false),
            AccountMeta::new(Pubkey::new_unique(), false), // refund destination
            AccountMeta::new_readonly(authorizer_key.pubkey(), true),
        ],
        data: vec![2u8], // RemoveAuthority, empty Ed25519 payload
    }
}

/// `RemoveAuthority`, authorized by an Ed25519 authority.
#[allow(clippy::result_large_err)]
pub fn remove_authority(
    context: &mut TestContext,
    wallet: &WalletFixture,
    authorizer_pda: Pubkey,
    authorizer_key: &Keypair,
    target_pda: Pubkey,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let ix = remove_authority_ix(context, wallet, authorizer_pda, authorizer_key, target_pda);
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, authorizer_key])?;
    Ok(())
}

/// The wallet's `owner_count`.
pub fn wallet_owner_count(svm: &LiteSVM, wallet_pda: Pubkey) -> u32 {
    let data = svm.get_account(&wallet_pda).expect("wallet account").data;
    u32::from_le_bytes(data[4..8].try_into().expect("owner_count field"))
}

/// The `role` byte of an authority account.
pub fn authority_role(svm: &LiteSVM, authority_pda: Pubkey) -> u8 {
    svm.get_account(&authority_pda)
        .expect("authority account")
        .data[2]
}

/// The `counter` odometer of an authority account (bytes 8..12).
pub fn authority_counter(svm: &LiteSVM, authority_pda: Pubkey) -> u32 {
    let data = svm
        .get_account(&authority_pda)
        .expect("authority account")
        .data;
    u32::from_le_bytes(data[8..12].try_into().expect("counter field"))
}

// ─────────────────────────────────────────────────────────────────────────
// Passkeys (Secp256r1)
//
// What a WebAuthn client does, done by hand: hash the challenge the program
// will recompute, wrap it in clientDataJSON, sign authenticatorData ‖
// SHA256(clientDataJSON) with the P-256 key, and hand the program both halves.
// One copy here, so a change to the challenge layout is one edit for every
// suite that signs as a passkey.
// ─────────────────────────────────────────────────────────────────────────

/// The Secp256r1 challenge, in the order `auth/secp256r1/mod.rs` hashes it:
/// `SHA256(discriminator || prefix14 || signed_payload || payer || wallet ||
/// counter_le4 || program_id)`.
///
/// `wallet` is the authenticating authority's own wallet — its header's
/// `wallet` field. It is what stops an assertion made for one wallet from
/// verifying on another wallet the same passkey also controls.
pub fn secp256r1_challenge(
    discriminator: u8,
    prefix14: &[u8],
    signed_payload: &[u8],
    payer: &Pubkey,
    wallet: &Pubkey,
    counter: u32,
    program_id: &Pubkey,
) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update([discriminator]);
    h.update(prefix14);
    h.update(signed_payload);
    h.update(payer.as_ref());
    h.update(wallet.as_ref());
    h.update(counter.to_le_bytes());
    h.update(program_id.as_ref());
    h.finalize().into()
}

/// The fixed 14-byte head of a Secp256r1 auth payload, and the only part of it
/// the challenge covers: `[slot u64][counter u32][sysvar_ix_index u8][reserved u8]`.
pub fn secp256r1_prefix(slot: u64, counter: u32, sysvar_ix_index: u8) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(14);
    prefix.extend_from_slice(&slot.to_le_bytes());
    prefix.extend_from_slice(&counter.to_le_bytes());
    prefix.push(sysvar_ix_index);
    prefix.push(0);
    prefix
}

/// Sign `challenge` as a passkey would.
///
/// Returns the precompile instruction, which must sit immediately before the
/// program's, and the full auth payload:
/// `prefix14 ‖ authDataLen u16 ‖ authenticatorData ‖ cdjLen u16 ‖ clientDataJSON`.
pub fn passkey_assertion(
    signing_key: &p256::ecdsa::SigningKey,
    rp_id: &str,
    prefix14: &[u8],
    challenge: &[u8; 32],
) -> (Instruction, Vec<u8>) {
    use p256::ecdsa::{signature::Signer as _, Signature, VerifyingKey};
    use sha2::Digest;

    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
        base64url_no_pad(challenge),
        rp_id
    );
    let cdj_hash: [u8; 32] = sha2::Sha256::digest(client_data_json.as_bytes()).into();

    let rp_id_hash: [u8; 32] = sha2::Sha256::digest(rp_id.as_bytes()).into();
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0x01); // user present
    authenticator_data.extend_from_slice(&1u32.to_be_bytes()); // webauthn counter

    let mut message = authenticator_data.clone();
    message.extend_from_slice(&cdj_hash);

    // The Secp256r1 precompile requires a low-S signature; p256 does not
    // normalize by default.
    let sig: Signature = signing_key.sign(&message);
    let sig = sig.normalize_s().unwrap_or(sig);
    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    let pubkey_compressed: [u8; 33] = VerifyingKey::from(signing_key)
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    let precompile_ix = build_secp256r1_precompile_ix(&pubkey_compressed, &sig_bytes, &message);

    let mut auth_payload = prefix14.to_vec();
    auth_payload.extend_from_slice(&(authenticator_data.len() as u16).to_le_bytes());
    auth_payload.extend_from_slice(&authenticator_data);
    auth_payload.extend_from_slice(&(client_data_json.len() as u16).to_le_bytes());
    auth_payload.extend_from_slice(client_data_json.as_bytes());

    (precompile_ix, auth_payload)
}

pub fn base64url_no_pad(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        out.push(A[((b >> 18) & 0x3f) as usize] as char);
        out.push(A[((b >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((b >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(b & 0x3f) as usize] as char);
        }
    }
    out
}

/// The Secp256r1 precompile instruction, in the exact fixed-offset layout the
/// program's introspection requires (signature@16, pubkey@80, message@114, all
/// indices self-referential 0xFFFF). The generic SDK builder lays the fields out
/// differently, so this mirrors `buildSecp256r1PrecompileIx` in sdk-legacy.
pub fn build_secp256r1_precompile_ix(
    pubkey33: &[u8; 33],
    sig64: &[u8; 64],
    message: &[u8],
) -> Instruction {
    const HEADER: usize = 16;
    let sig_off = HEADER;
    let pk_off = sig_off + 64;
    let msg_off = pk_off + 33 + 1; // 1 byte alignment padding
    let mut data = vec![0u8; msg_off + message.len()];
    data[0] = 1; // num signatures
    data[1] = 0; // padding
    data[2..4].copy_from_slice(&(sig_off as u16).to_le_bytes());
    data[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[6..8].copy_from_slice(&(pk_off as u16).to_le_bytes());
    data[8..10].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[10..12].copy_from_slice(&(msg_off as u16).to_le_bytes());
    data[12..14].copy_from_slice(&(message.len() as u16).to_le_bytes());
    data[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());
    data[sig_off..sig_off + 64].copy_from_slice(sig64);
    data[pk_off..pk_off + 33].copy_from_slice(pubkey33);
    data[msg_off..msg_off + message.len()].copy_from_slice(message);
    Instruction {
        program_id: "Secp256r1SigVerify1111111111111111111111111"
            .parse()
            .unwrap(),
        accounts: vec![],
        data,
    }
}

/// A passkey as the program sees it: the P-256 key, the credential id hash
/// that seeds its authority PDA, and the relying party it was registered for.
pub struct Passkey {
    pub signing_key: p256::ecdsa::SigningKey,
    pub credential_id_hash: [u8; 32],
    pub rp_id: &'static str,
}

impl Passkey {
    pub fn new() -> Self {
        Self {
            signing_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            credential_id_hash: rand::random(),
            rp_id: "lazorkit.test",
        }
    }
}

impl Default for Passkey {
    fn default() -> Self {
        Self::new()
    }
}

/// A v2 wallet whose only Owner is a passkey.
pub struct PasskeyWallet {
    pub wallet: Pubkey,
    pub vault: Pubkey,
    pub authority: Pubkey,
}

/// `CreateWallet` with `pk` as the Owner. Called twice with the same passkey it
/// gives one credential and one key on two wallets, each with its own counter.
pub fn create_passkey_wallet(context: &mut TestContext, pk: &Passkey) -> PasskeyWallet {
    let program_id = context.program_id;
    let user_seed = rand::random::<[u8; 32]>();
    let (wallet, _) =
        Pubkey::find_program_address(&[lazorkit_program::seeds::WALLET, &user_seed], &program_id);
    let (vault, _) = Pubkey::find_program_address(
        &[lazorkit_program::seeds::VAULT, wallet.as_ref()],
        &program_id,
    );
    let (authority, auth_bump) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.as_ref(),
            &pk.credential_id_hash,
        ],
        &program_id,
    );

    // [0][user_seed 32][type 1][bump][padding 6][credential_id_hash 32][pubkey 33][rpIdLen][rpId]
    let mut data = vec![0u8];
    data.extend_from_slice(&user_seed);
    data.push(1); // Secp256r1
    data.push(auth_bump);
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(&pk.credential_id_hash);
    data.extend_from_slice(
        p256::ecdsa::VerifyingKey::from(&pk.signing_key)
            .to_encoded_point(true)
            .as_bytes(),
    );
    data.push(pk.rp_id.len() as u8);
    data.extend_from_slice(pk.rp_id.as_bytes());

    let ix = Instruction {
        program_id,
        accounts: with_protocol_fee_accounts(
            vec![
                AccountMeta::new(context.payer.pubkey(), true),
                AccountMeta::new(wallet, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(authority, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            ],
            context,
        ),
        data,
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer]).expect("CreateWallet (passkey) failed");

    PasskeyWallet {
        wallet,
        vault,
        authority,
    }
}
