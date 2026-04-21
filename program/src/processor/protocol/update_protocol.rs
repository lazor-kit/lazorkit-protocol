use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use crate::{
    error::ProtocolError,
    state::{protocol_config::ProtocolConfig, AccountDiscriminator},
};

/// Processes the `UpdateProtocol` instruction.
///
/// Updates fee amounts, treasury, or enabled flag. Admin must sign.
///
/// # Accounts:
/// 1. `[signer]` Admin
/// 2. `[writable]` ProtocolConfig PDA
///
/// # Instruction Data:
/// `[creation_fee(8)][execution_fee(8)][enabled(1)][_padding(7)][new_treasury(32)]` = 56 bytes
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 56 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let creation_fee = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
    let execution_fee = u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());
    let enabled = instruction_data[16];
    // 7 bytes padding at [17..24]
    let new_treasury: &[u8; 32] = instruction_data[24..56].try_into().unwrap();

    let account_info_iter = &mut accounts.iter();
    let admin = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify config_pda is owned by this program before reading its fields
    // for authorization decisions. Defense-in-depth.
    if config_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let data = config_pda.try_borrow_data()?;
    if data.len() < core::mem::size_of::<ProtocolConfig>()
        || data[0] != AccountDiscriminator::ProtocolConfig as u8
    {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    let config = unsafe { &*(data.as_ptr() as *const ProtocolConfig) };
    if admin.key() != &config.admin {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    drop(data);

    let mut data = config_pda.try_borrow_mut_data()?;
    let config_mut = unsafe { &mut *(data.as_mut_ptr() as *mut ProtocolConfig) };
    config_mut.creation_fee = creation_fee;
    config_mut.execution_fee = execution_fee;
    config_mut.enabled = enabled;
    config_mut.treasury = Pubkey::from(*new_treasury);

    Ok(())
}
