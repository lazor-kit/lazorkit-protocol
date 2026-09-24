use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{
    error::ProtocolError,
    state::{protocol_config::ProtocolConfig, treasury_shard::TreasuryShard},
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
    program_id: &Pubkey,
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

    // CRITICAL: verify config_pda AND shard_pda are owned by this program.
    //
    // Without the config ownership check, any attacker could supply a
    // fake ProtocolConfig (owned by their own program) with attacker-controlled
    // `admin` and `treasury` fields, passing the admin-signer and treasury
    // checks below. They'd then get direct lamport manipulation on the real
    // (LazorKit-owned) shard_pda — which Solana's runtime allows because
    // LazorKit owns the shard — draining all treasury shards to themselves.
    ProtocolConfig::load(program_id, config_pda)?;
    if shard_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read config, verify admin + treasury
    let config_data = config_pda.try_borrow_data()?;
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
    if admin.key() != &config.admin {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    if treasury.key() != &config.treasury {
        return Err(ProtocolError::InvalidTreasury.into());
    }
    drop(config_data);

    // Verify shard: type, then re-derive its canonical PDA from its own
    // shard_id — matching `try_collect_fee`. Not strictly required (only the
    // admin-gated `initialize_treasury_shard` can mint a program-owned shard, at
    // canonical addresses), but pinning the address here removes the reliance on
    // that invariant and keeps every shard read consistent.
    let shard_id = {
        let shard_data = shard_pda.try_borrow_data()?;
        TreasuryShard::check(&shard_data).map_err(|_| ProtocolError::InvalidTreasuryShard)?;
        let shard = unsafe { &*(shard_data.as_ptr() as *const TreasuryShard) };
        shard.shard_id
    };
    let (expected_shard_key, _) =
        find_program_address(&[crate::seeds::TREASURY_SHARD, &[shard_id]], program_id);
    if shard_pda.key() != &expected_shard_key {
        return Err(ProtocolError::InvalidTreasuryShard.into());
    }

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
