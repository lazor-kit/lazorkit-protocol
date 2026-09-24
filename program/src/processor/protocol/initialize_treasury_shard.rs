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
    state::{protocol_config::ProtocolConfig, treasury_shard::TreasuryShard, AccountDiscriminator},
    utils::initialize_pda_account,
};

/// Processes the `InitializeTreasuryShard` instruction.
///
/// Creates a single TreasuryShard PDA. Call once per shard (0..num_shards-1).
///
/// # Accounts:
/// 1. `[signer, writable]` Payer
/// 2. `[]` ProtocolConfig PDA
/// 3. `[signer]` Admin
/// 4. `[writable]` TreasuryShard PDA
/// 5. `[]` System Program
/// 6. `[]` Rent Sysvar
///
/// # Instruction Data:
/// `[shard_id(1)]` = 1 byte
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let shard_id = instruction_data[0];

    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // M-6. The payer's signature was only ever enforced as a side effect: the
    // System Program demands it during the funding CPI. `initialize_pda_account`
    // skips that CPI when the PDA already holds enough lamports — anyone can
    // pre-fund a PDA — so on that path nothing checked it at all.
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let admin = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let shard_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent_sysvar = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Pin the address, the owner and the header before reading admin and
    // num_shards for an authorization decision.
    ProtocolConfig::load(program_id, config_pda)?;

    // Read config and verify admin + shard_id in range
    let config_data = config_pda.try_borrow_data()?;
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
    if admin.key() != &config.admin {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    if shard_id >= config.num_shards {
        return Err(ProgramError::InvalidInstructionData);
    }
    drop(config_data);

    // Verify PDA
    let shard_id_arr = [shard_id];
    let (shard_key, shard_bump) =
        find_program_address(&[crate::seeds::TREASURY_SHARD, &shard_id_arr], program_id);
    if shard_pda.key() != &shard_key {
        return Err(ProgramError::InvalidSeeds);
    }

    check_zero_data(shard_pda, ProgramError::AccountAlreadyInitialized)?;

    let rent = Rent::from_account_info(rent_sysvar)?;
    let space = core::mem::size_of::<TreasuryShard>();
    let rent_lamports = rent.minimum_balance(space);

    let bump_arr = [shard_bump];
    let seeds = [
        Seed::from(crate::seeds::TREASURY_SHARD),
        Seed::from(shard_id_arr.as_ref()),
        Seed::from(&bump_arr),
    ];

    initialize_pda_account(
        payer,
        shard_pda,
        system_program,
        space,
        rent_lamports,
        program_id,
        &seeds,
    )?;

    let shard = TreasuryShard {
        discriminator: AccountDiscriminator::TreasuryShard as u8,
        bump: shard_bump,
        shard_id,
        _padding: [0; 5],
    };

    let mut data = shard_pda.try_borrow_mut_data()?;
    let shard_bytes =
        unsafe { core::slice::from_raw_parts(&shard as *const _ as *const u8, space) };
    data[..space].copy_from_slice(shard_bytes);

    Ok(())
}
