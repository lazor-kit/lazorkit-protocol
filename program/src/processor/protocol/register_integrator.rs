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
    state::{integrator_record::FeeRecord, AccountDiscriminator, CURRENT_ACCOUNT_VERSION},
    utils::initialize_pda_account,
};

/// Processes the `RegisterPayer` instruction.
///
/// Creates a FeeRecord PDA keyed by the payer's pubkey. Permissionless:
/// any payer registers themselves, paying their own rent. There is no
/// admin gate — fee collection works regardless of whether a FeeRecord
/// exists, so this only enables stats tracking for that payer.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer (funds rent; must equal target_payer)
/// 2. `[writable]` FeeRecord PDA (derived from `["fee_record", payer]`)
/// 3. `[]` System Program
/// 4. `[]` Rent Sysvar
///
/// # Instruction Data:
/// (none) — the payer signer is the registration target
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
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

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let target_payer: &[u8; 32] = payer.key();

    // Verify PDA: ["fee_record", payer]
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
