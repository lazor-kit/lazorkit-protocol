use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, sysvars::rent::Rent,
    ProgramResult,
};

use crate::{
    error::ProtocolError,
    state::{protocol_config::ProtocolConfig, treasury_shard::TreasuryShard, AccountDiscriminator},
};

/// Processes the `WithdrawTreasury` instruction.
///
/// Sweeps accumulated SOL from a TreasuryShard PDA to the treasury wallet.
/// Only the protocol admin can call this.
///
/// # Accounts:
/// 1. `[signer]` Admin
/// 2. `[]` ProtocolConfig PDA
/// 3. `[writable]` TreasuryShard PDA
/// 4. `[writable]` Treasury destination (must match config.treasury)
/// 5. `[]` Rent Sysvar
pub fn process(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let admin = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let shard_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let treasury = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent_sysvar = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read config, verify admin + treasury
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
    if treasury.key() != &config.treasury {
        return Err(ProtocolError::InvalidTreasury.into());
    }
    drop(config_data);

    // Verify shard
    let shard_data = shard_pda.try_borrow_data()?;
    if shard_data.len() < core::mem::size_of::<TreasuryShard>()
        || shard_data[0] != AccountDiscriminator::TreasuryShard as u8
    {
        return Err(ProtocolError::InvalidIntegratorRecord.into());
    }
    drop(shard_data);

    // Sweep: keep rent-exempt minimum in shard
    let rent = Rent::from_account_info(rent_sysvar)?;
    let min_balance = rent.minimum_balance(core::mem::size_of::<TreasuryShard>());
    let current_balance = shard_pda.lamports();

    if current_balance <= min_balance {
        return Ok(());
    }

    let sweep_amount = current_balance
        .checked_sub(min_balance)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    if sweep_amount == 0 {
        return Ok(());
    }

    // Direct lamport manipulation — program owns TreasuryShard
    unsafe {
        let shard_lamports = shard_pda.borrow_mut_lamports_unchecked();
        *shard_lamports = min_balance;
        let treasury_lamports = treasury.borrow_mut_lamports_unchecked();
        *treasury_lamports = treasury_lamports
            .checked_add(sweep_amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok(())
}
