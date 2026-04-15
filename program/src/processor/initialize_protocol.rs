use assertions::check_zero_data;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{
    error::ProtocolError,
    state::{protocol_config::ProtocolConfig, AccountDiscriminator, CURRENT_ACCOUNT_VERSION},
    utils::initialize_pda_account,
};

/// Processes the `InitializeProtocol` instruction.
///
/// Creates the global ProtocolConfig PDA. Can only be called once.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer
/// 2. `[writable]` ProtocolConfig PDA
/// 3. `[]` System Program
/// 4. `[]` Rent Sysvar
///
/// # Instruction Data:
/// `[admin(32)][treasury(32)][creation_fee(8)][execution_fee(8)][num_shards(1)]` = 81 bytes
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 81 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let admin: &[u8; 32] = instruction_data[0..32].try_into().unwrap();
    let treasury: &[u8; 32] = instruction_data[32..64].try_into().unwrap();
    let creation_fee = u64::from_le_bytes(instruction_data[64..72].try_into().unwrap());
    let execution_fee = u64::from_le_bytes(instruction_data[72..80].try_into().unwrap());
    let num_shards = instruction_data[80];

    if num_shards == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent_sysvar = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify PDA
    let (config_key, config_bump) = find_program_address(&[b"protocol_config"], program_id);
    if config_pda.key() != &config_key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Ensure not already initialized
    check_zero_data(
        config_pda,
        ProgramError::Custom(ProtocolError::ProtocolAlreadyInitialized as u32),
    )?;

    let rent = Rent::from_account_info(rent_sysvar)?;
    let space = core::mem::size_of::<ProtocolConfig>();
    let rent_lamports = rent.minimum_balance(space);

    let bump_arr = [config_bump];
    let seeds = [Seed::from(b"protocol_config"), Seed::from(&bump_arr)];

    initialize_pda_account(
        payer,
        config_pda,
        system_program,
        space,
        rent_lamports,
        program_id,
        &seeds,
    )?;

    // Write config data
    let config = ProtocolConfig {
        discriminator: AccountDiscriminator::ProtocolConfig as u8,
        version: CURRENT_ACCOUNT_VERSION,
        bump: config_bump,
        enabled: 1,
        num_shards,
        _padding: [0; 3],
        admin: Pubkey::from(*admin),
        treasury: Pubkey::from(*treasury),
        creation_fee,
        execution_fee,
    };

    let mut data = config_pda.try_borrow_mut_data()?;
    let config_bytes =
        unsafe { core::slice::from_raw_parts(&config as *const _ as *const u8, space) };
    data[..space].copy_from_slice(config_bytes);

    Ok(())
}
