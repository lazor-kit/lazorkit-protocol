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
