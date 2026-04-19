use assertions::check_zero_data;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::{
    error::ProtocolError,
    state::{
        integrator_record::FeeRecord, protocol_config::ProtocolConfig, AccountDiscriminator,
        CURRENT_ACCOUNT_VERSION,
    },
    utils::initialize_pda_account,
};

/// Processes the `RegisterPayer` instruction.
///
/// Creates a FeeRecord PDA keyed by the payer's pubkey.
/// Requires protocol admin signature.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer (funds rent)
/// 2. `[]` ProtocolConfig PDA
/// 3. `[signer]` Admin (must match config.admin)
/// 4. `[writable]` FeeRecord PDA (derived from `["fee_record", target_payer]`)
/// 5. `[]` System Program
/// 6. `[]` Rent Sysvar
///
/// # Instruction Data:
/// `[target_payer(32)]` = 32 bytes (the payer pubkey to register)
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let target_payer: &[u8; 32] = instruction_data[0..32].try_into().unwrap();

    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let admin = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let record_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent_sysvar = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify admin is signer
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify config_pda is owned by this program before reading admin
    // from its data for authorization. Defense-in-depth.
    if config_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read config and verify admin
    let config_data = config_pda.try_borrow_data()?;
    if config_data.len() < core::mem::size_of::<ProtocolConfig>()
        || config_data[0] != AccountDiscriminator::ProtocolConfig as u8
    {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
    if admin.key() != &config.admin {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    drop(config_data);

    // Verify PDA: ["fee_record", target_payer]
    let (record_key, record_bump) =
        find_program_address(&[b"fee_record", target_payer], program_id);
    if record_pda.key() != &record_key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Ensure not already registered
    check_zero_data(
        record_pda,
        ProgramError::Custom(ProtocolError::IntegratorAlreadyRegistered as u32),
    )?;

    let rent = Rent::from_account_info(rent_sysvar)?;
    let space = core::mem::size_of::<FeeRecord>();
    let rent_lamports = rent.minimum_balance(space);

    let bump_arr = [record_bump];
    let seeds = [
        Seed::from(b"fee_record"),
        Seed::from(target_payer.as_ref()),
        Seed::from(&bump_arr),
    ];

    initialize_pda_account(
        payer,
        record_pda,
        system_program,
        space,
        rent_lamports,
        program_id,
        &seeds,
    )?;

    let clock = Clock::get()?;

    let record = FeeRecord {
        discriminator: AccountDiscriminator::FeeRecord as u8,
        bump: record_bump,
        version: CURRENT_ACCOUNT_VERSION,
        _padding: [0; 5],
        total_fees_paid: 0,
        tx_count: 0,
        wallet_count: 0,
        registered_at: clock.slot,
    };

    let mut data = record_pda.try_borrow_mut_data()?;
    let record_bytes =
        unsafe { core::slice::from_raw_parts(&record as *const _ as *const u8, space) };
    data[..space].copy_from_slice(record_bytes);

    Ok(())
}
