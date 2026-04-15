use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::{
    processor::{authority, execute, session, wallet},
    state::{
        integrator_record::FeeRecord, protocol_config::ProtocolConfig,
        treasury_shard::TreasuryShard, AccountDiscriminator,
    },
    utils::SYSTEM_PROGRAM_ID,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (discriminator, data) = instruction_data.split_first().unwrap();

    // For fee-eligible instructions, try to detect and collect protocol fees
    let processor_accounts = match discriminator {
        0 | 4 | 7 => try_collect_fee(program_id, *discriminator, accounts)?,
        _ => accounts,
    };

    match discriminator {
        0 => wallet::create::process(program_id, processor_accounts, data),
        1 => authority::manage::process_add_authority(program_id, processor_accounts, data),
        2 => authority::manage::process_remove_authority(program_id, processor_accounts, data),
        3 => authority::transfer_ownership::process(program_id, processor_accounts, data),
        4 => execute::immediate::process(program_id, processor_accounts, data),
        5 => session::create::process(program_id, processor_accounts, data),
        6 => execute::authorize::process(program_id, processor_accounts, data),
        7 => execute::deferred::process(program_id, processor_accounts, data),
        8 => execute::reclaim::process(program_id, processor_accounts, data),
        9 => session::revoke::process(program_id, processor_accounts, data),
        10 => crate::processor::protocol::initialize_protocol::process(program_id, accounts, data),
        11 => crate::processor::protocol::update_protocol::process(program_id, accounts, data),
        12 => crate::processor::protocol::register_integrator::process(program_id, accounts, data),
        13 => crate::processor::protocol::withdraw_treasury::process(program_id, accounts, data),
        14 => crate::processor::protocol::initialize_treasury_shard::process(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Detect protocol fee accounts at the end of the accounts array.
///
/// Convention: SDK appends 4 accounts for fee-eligible instructions:
///   `[protocol_config, fee_record, treasury_shard, system_program]`
///
/// Detection (last 4 accounts):
///   - accounts[n-4]: owner == program_id, data[0] == 5 (ProtocolConfig)
///   - accounts[n-3]: owner == program_id, data[0] == 6 (FeeRecord)
///   - accounts[n-2]: owner == program_id, data[0] == 7 (TreasuryShard)
///   - accounts[n-1]: key == SYSTEM_PROGRAM_ID
///
/// Fee goes from payer → treasury_shard. FeeRecord only gets counter updates.
fn try_collect_fee<'a>(
    program_id: &Pubkey,
    discriminator: u8,
    accounts: &'a [AccountInfo],
) -> Result<&'a [AccountInfo], ProgramError> {
    if accounts.len() < 5 {
        return Ok(accounts);
    }

    let n = accounts.len();
    let maybe_config = &accounts[n - 4];
    let maybe_record = &accounts[n - 3];
    let maybe_shard = &accounts[n - 2];
    let maybe_system = &accounts[n - 1];

    // Quick check: system program at the end?
    if maybe_system.key() != &SYSTEM_PROGRAM_ID {
        return Ok(accounts);
    }

    // Check config
    if maybe_config.owner() != program_id {
        return Ok(accounts);
    }
    let config_data = maybe_config.try_borrow_data()?;
    if config_data.is_empty()
        || config_data[0] != AccountDiscriminator::ProtocolConfig as u8
        || config_data.len() < core::mem::size_of::<ProtocolConfig>()
    {
        drop(config_data);
        return Ok(accounts);
    }
    let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };

    if config.enabled == 0 {
        drop(config_data);
        return Ok(&accounts[..n - 4]);
    }

    let fee = match discriminator {
        0 => config.creation_fee,
        4 | 7 => config.execution_fee,
        _ => 0,
    };
    drop(config_data);

    if fee == 0 {
        return Ok(&accounts[..n - 4]);
    }

    // Check fee record
    if maybe_record.owner() != program_id {
        return Ok(accounts);
    }
    let record_data = maybe_record.try_borrow_data()?;
    if record_data.is_empty()
        || record_data[0] != AccountDiscriminator::FeeRecord as u8
        || record_data.len() < core::mem::size_of::<FeeRecord>()
    {
        drop(record_data);
        return Ok(accounts);
    }
    drop(record_data);

    // Check treasury shard
    if maybe_shard.owner() != program_id {
        return Ok(accounts);
    }
    let shard_data = maybe_shard.try_borrow_data()?;
    if shard_data.is_empty()
        || shard_data[0] != AccountDiscriminator::TreasuryShard as u8
        || shard_data.len() < core::mem::size_of::<TreasuryShard>()
    {
        drop(shard_data);
        return Ok(accounts);
    }
    drop(shard_data);

    // Transfer fee from payer (accounts[0]) to treasury shard via System Program
    let payer = &accounts[0];
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut transfer_data = [0u8; 12];
    transfer_data[0..4].copy_from_slice(&2u32.to_le_bytes());
    transfer_data[4..12].copy_from_slice(&fee.to_le_bytes());

    let transfer_accounts = [
        AccountMeta {
            pubkey: payer.key(),
            is_signer: true,
            is_writable: true,
        },
        AccountMeta {
            pubkey: maybe_shard.key(),
            is_signer: false,
            is_writable: true,
        },
    ];

    let transfer_ix = Instruction {
        program_id: &Pubkey::from(SYSTEM_PROGRAM_ID),
        accounts: &transfer_accounts,
        data: &transfer_data,
    };

    invoke(&transfer_ix, &[payer, maybe_shard, maybe_system])?;

    // Update fee record counters (no SOL, just tracking)
    let mut record_data = maybe_record.try_borrow_mut_data()?;
    let record = unsafe { &mut *(record_data.as_mut_ptr() as *mut FeeRecord) };

    record.total_fees_paid = record
        .total_fees_paid
        .checked_add(fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    match discriminator {
        0 => {
            record.wallet_count = record
                .wallet_count
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        },
        4 | 7 => {
            record.tx_count = record
                .tx_count
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        },
        _ => {},
    }
    drop(record_data);

    Ok(&accounts[..n - 4])
}
