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

/// Load the program and fund a payer, but do **not** run `initialize_protocol`.
///
/// This is the state every fresh deployment is in for the window between
/// `solana program deploy` landing and the team's init transaction confirming.
pub fn setup_uninitialized() -> TestContext {
    let payer = Keypair::new();
    let mut svm = LiteSVM::new();
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
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);

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
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);

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
pub fn init_shard_ix(program_id: Pubkey, payer: Pubkey, admin: Pubkey, shard_id: u8) -> Instruction {
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);
    let (shard_pda, _) =
        Pubkey::find_program_address(&[b"treasury_shard", &[shard_id]], &program_id);

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

/// The four accounts `try_collect_fee` requires as a suffix, keyed to an
/// arbitrary fee payer (not necessarily `context.payer`).
pub fn fee_suffix_for(program_id: Pubkey, fee_payer: Pubkey) -> Vec<AccountMeta> {
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);
    let (record_pda, _) =
        Pubkey::find_program_address(&[b"fee_record", fee_payer.as_ref()], &program_id);
    let (shard_pda, _) = Pubkey::find_program_address(&[b"treasury_shard", &[0u8]], &program_id);

    vec![
        AccountMeta::new_readonly(config_pda, false),
        AccountMeta::new(record_pda, false),
        AccountMeta::new(shard_pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ]
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
pub fn assert_custom_error(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
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
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);
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
    let user_seed = rand::random::<[u8; 32]>();
    let owner = Keypair::new();

    let (wallet_pda, _) =
        Pubkey::find_program_address(&[b"wallet", &user_seed], &context.program_id);
    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"vault", wallet_pda.as_ref()], &context.program_id);
    let (owner_auth_pda, owner_bump) = Pubkey::find_program_address(
        &[b"authority", wallet_pda.as_ref(), owner.pubkey().as_ref()],
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
        4,                            // program_id_index -> system program
        vec![3, 5],                   // vault (from), recipient (to)
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

    let clock: solana_sdk::clock::Clock = context.svm.get_sysvar();
    let expires_at = clock.slot + 100_000;

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
            b"session",
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
// `expires_at = 0` means "never expires".

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

    // Airdrop to payer
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("Failed to airdrop");

    // Load program
    let program_id = load_program(&mut svm);
    initialize_protocol(&mut svm, &payer, program_id);

    TestContext {
        svm,
        payer,
        program_id,
    }
}

fn load_program(svm: &mut LiteSVM) -> Pubkey {
    // LazorKit program ID (deterministic for tests)
    let program_id = Pubkey::new_unique();

    // Load the compiled program
    let path = "../target/deploy/lazorkit_program.so";
    svm.add_program_from_file(program_id, path)
        .expect("Failed to load program");

    program_id
}

fn initialize_protocol(svm: &mut LiteSVM, payer: &Keypair, program_id: Pubkey) {
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &program_id);
    let shard_id = [0u8];
    let (shard_pda, _) = Pubkey::find_program_address(&[b"treasury_shard", &shard_id], &program_id);

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
    let (config_pda, _) = Pubkey::find_program_address(&[b"protocol_config"], &context.program_id);
    let (record_pda, _) = Pubkey::find_program_address(
        &[b"fee_record", context.payer.pubkey().as_ref()],
        &context.program_id,
    );
    let shard_id = [0u8];
    let (shard_pda, _) =
        Pubkey::find_program_address(&[b"treasury_shard", &shard_id], &context.program_id);

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
