use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    instruction::{AccountMeta, Instruction, Seed},
    program::invoke,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::{
    error::ProtocolError,
    processor::{authority, execute, session, wallet},
    state::{
        integrator_record::FeeRecord, protocol_config::ProtocolConfig,
        treasury_shard::TreasuryShard, AccountDiscriminator, CURRENT_ACCOUNT_VERSION,
    },
    utils::{initialize_pda_account, SYSTEM_PROGRAM_ID},
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
        14 => crate::processor::protocol::initialize_treasury_shard::process(
            program_id, accounts, data,
        ),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Strict fee collection for fee-eligible instructions on the commercial
/// binary. Every CreateWallet (disc 0) / Execute (disc 4) /
/// ExecuteDeferred (disc 7) MUST carry a valid suffix:
///
///   `[protocol_config, fee_record, treasury_shard, system_program]`
///
/// at positions `[n-4, n-3, n-2, n-1]`. Anything else returns a custom
/// `ProtocolError` — there is no silent skip path. This is the strict
/// counterpart to the original opt-in implementation; see
/// `docs/proposals/2026-05-strict-fee-enforcement.md` for rationale.
///
/// Behaviour summary:
///   1. Reject (4008) if fewer than 5 accounts or sentinel `system_program`
///      missing.
///   2. Reject (4009) if `ProtocolConfig` PDA is system-owned, has the
///      wrong discriminator, or is too small. This covers the "deployed
///      but admin hasn't run `initialize_protocol` yet" bootstrap state.
///   3. Reject (4003) if `ProtocolConfig.enabled == 0`.
///   4. Reject (4012) if the resolved fee for this discriminator is 0.
///   5. Reject (4010) if `TreasuryShard` PDA is invalid.
///   6. **Auto-initialize** `FeeRecord` PDA inline if it's system-owned
///      (first-time payer). Reject (4011) if the address doesn't match
///      the canonical `[b"fee_record", payer]` PDA, or is owned by
///      another program.
///   7. Transfer `fee` lamports from `payer` (signer at index 0) to
///      `treasury_shard`.
///   8. Bump `FeeRecord.total_fees_paid + wallet_count` (disc 0) or
///      `+ tx_count` (disc 4/7).
///
/// Returns `&accounts[..n-4]` on success — the inner processor sees only
/// its own account list, with the four fee-suffix accounts stripped.
///
/// Foundation binary (`program-v2`) strips this entire function via
/// `scripts/fee-paths.txt`, so its entrypoint never invokes fee logic.
fn try_collect_fee<'a>(
    program_id: &Pubkey,
    discriminator: u8,
    accounts: &'a [AccountInfo],
) -> Result<&'a [AccountInfo], ProgramError> {
    if accounts.len() < 5 {
        return Err(ProtocolError::FeeAccountsRequired.into());
    }

    let n = accounts.len();
    let maybe_config = &accounts[n - 4];
    let maybe_record = &accounts[n - 3];
    let maybe_shard = &accounts[n - 2];
    let maybe_system = &accounts[n - 1];

    // Trailing `system_program` sentinel.
    if maybe_system.key() != &SYSTEM_PROGRAM_ID {
        return Err(ProtocolError::FeeAccountsRequired.into());
    }

    // ProtocolConfig must be program-owned + correct discriminator + sized.
    // The pre-init bootstrap state (system-owned PDA) is rejected here —
    // admin must run `initialize_protocol` before any fee-eligible ix.
    if maybe_config.owner() != program_id {
        return Err(ProtocolError::ProtocolNotInitialized.into());
    }
    let (creation_fee, execution_fee, enabled) = {
        let config_data = maybe_config.try_borrow_data()?;
        if config_data.is_empty()
            || config_data[0] != AccountDiscriminator::ProtocolConfig as u8
            || config_data.len() < core::mem::size_of::<ProtocolConfig>()
        {
            return Err(ProtocolError::ProtocolNotInitialized.into());
        }
        let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
        (config.creation_fee, config.execution_fee, config.enabled)
    };

    if enabled == 0 {
        return Err(ProtocolError::ProtocolDisabled.into());
    }

    let fee = match discriminator {
        0 => creation_fee,
        4 | 7 => execution_fee,
        // The entrypoint dispatcher (caller) restricts us to {0, 4, 7}.
        _ => unreachable!("try_collect_fee called with non-fee-eligible discriminator"),
    };

    // Strict mode rejects zero-fee config to prevent silent degradation
    // back to the pre-strict opt-in behaviour.
    if fee == 0 {
        return Err(ProtocolError::FeeNotConfigured.into());
    }

    // TreasuryShard validation (admin must have called
    // `initialize_treasury_shard` for this shard id). The account must be
    // both shaped like a TreasuryShard and live at the canonical PDA for
    // the shard id stored in its data.
    if maybe_shard.owner() != program_id {
        return Err(ProtocolError::InvalidTreasuryShard.into());
    }
    let shard_id = {
        let shard_data = maybe_shard.try_borrow_data()?;
        if shard_data.is_empty()
            || shard_data[0] != AccountDiscriminator::TreasuryShard as u8
            || shard_data.len() < core::mem::size_of::<TreasuryShard>()
        {
            return Err(ProtocolError::InvalidTreasuryShard.into());
        }
        let shard = unsafe { &*(shard_data.as_ptr() as *const TreasuryShard) };
        shard.shard_id
    };
    let shard_id_arr = [shard_id];
    let (expected_shard_key, _) =
        find_program_address(&[b"treasury_shard", &shard_id_arr], program_id);
    if maybe_shard.key() != &expected_shard_key {
        return Err(ProtocolError::InvalidTreasuryShard.into());
    }

    // Payer must sign — every processor that accepts disc 0/4/7 already
    // requires this, but we re-assert defensively because we're about to
    // run an inline `system::create_account` CPI signed by the payer.
    let payer = &accounts[0];
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // FeeRecord — auto-create if system-owned, accept if program-owned + valid,
    // reject otherwise. Always verify the PDA address matches the canonical
    // seed for this payer BEFORE any state mutation.
    let target_payer: &[u8; 32] = payer.key();
    let (expected_record_key, record_bump) =
        find_program_address(&[b"fee_record", target_payer], program_id);
    if maybe_record.key() != &expected_record_key {
        return Err(ProtocolError::InvalidFeeRecord.into());
    }

    let record_owner = maybe_record.owner();
    if record_owner == &SYSTEM_PROGRAM_ID {
        // First-time payer: create + initialize the FeeRecord PDA inline.
        // Uses Sysvar::get() syscalls (no extra account in tx layout).
        let rent = Rent::get()?;
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
            maybe_record,
            maybe_system,
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
        let record_bytes =
            unsafe { core::slice::from_raw_parts(&record as *const _ as *const u8, space) };
        let mut data = maybe_record.try_borrow_mut_data()?;
        data[..space].copy_from_slice(record_bytes);
    } else if record_owner != program_id {
        // Account exists but is owned by some foreign program — reject
        // before any further work.
        return Err(ProtocolError::InvalidFeeRecord.into());
    } else {
        // Owned by us — verify it's a valid FeeRecord, not some other
        // account that happens to live at the canonical seed.
        let rec = maybe_record.try_borrow_data()?;
        if rec.is_empty()
            || rec[0] != AccountDiscriminator::FeeRecord as u8
            || rec.len() < core::mem::size_of::<FeeRecord>()
        {
            return Err(ProtocolError::InvalidFeeRecord.into());
        }
    }

    // Transfer fee: payer → treasury_shard.
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

    // Bump FeeRecord counters (always — strict mode requires it).
    {
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
            _ => unreachable!(),
        }
    }

    Ok(&accounts[..n - 4])
}
