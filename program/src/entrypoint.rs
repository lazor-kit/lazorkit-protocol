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
    // M-2. The cluster ID is compiled in (see `assertions`), but nothing checked
    // that the binary is actually running at it. A copy deployed at another
    // address derives an entirely separate PDA space, so it cannot reach real
    // accounts — what it can do is mint look-alike wallets and authorities at
    // addresses that look right to a client pointed at the wrong id.
    if program_id != &assertions::ID {
        return Err(ProtocolError::WrongProgramAddress.into());
    }

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
        15 => crate::processor::protocol::rotate_admin::process_propose(program_id, accounts, data),
        16 => crate::processor::protocol::rotate_admin::process_accept(program_id, accounts, data),
        17 => crate::processor::migrate::process(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Strict fee collection for fee-eligible instructions on the commercial
/// binary. Every CreateWallet (disc 0) / Execute (disc 4) /
/// ExecuteDeferred (disc 7) MUST carry a valid suffix:
///
///   `[protocol_config, fee_record, treasury_shard, system_program]`
///
/// at positions `[n-4, n-3, n-2, n-1]`. A malformed suffix (missing accounts, a
/// non-canonical config) is rejected — but when the protocol is simply not
/// configured to charge, collection is *skipped*, not rejected (item 3 below).
/// That skip is the C-1 fix: reverting a fund-moving instruction on a config
/// flag would let an admin freeze every user's funds. An earlier design rejected
/// in all three unconfigured cases; this is deliberately not that.
///
/// Behaviour summary:
///   1. Reject (4008) if fewer than 5 accounts or sentinel `system_program`
///      missing.
///   2. Reject (4009) if the supplied `ProtocolConfig` is not the canonical
///      PDA, or is program-owned but malformed.
///   3. **Skip collection** — charge nothing, strip the suffix, continue — when
///      the protocol is not initialised, is disabled, or resolves a zero fee
///      for this discriminator. v1 reverted in all three cases, which meant an
///      admin flipping `enabled` could strand every user's funds; see the
///      inline note at the skip branch.
///   4. Reject (4010) if `TreasuryShard` PDA is invalid.
///   5. **Auto-initialize** `FeeRecord` PDA inline if it's system-owned
///      (first-time payer). Reject (4011) if the address doesn't match
///      the canonical `[crate::seeds::FEE_RECORD, payer]` PDA, or is owned by
///      another program.
///   6. Transfer `fee` lamports from `payer` (signer at index 0) to
///      `treasury_shard`.
///   7. Bump `FeeRecord.total_fees_paid + wallet_count` (disc 0) or
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

    // Pin the ProtocolConfig address before reading a single byte of it.
    //
    // This is load-bearing rather than defence in depth. Everything below treats
    // an unconfigured protocol as "charge nothing and continue", so a caller who
    // could substitute a different account for the config would be able to skip
    // the fee at will. The shard and fee-record addresses were already pinned;
    // the config was the one that was not.
    let (expected_config_key, _) =
        find_program_address(&[crate::seeds::PROTOCOL_CONFIG], program_id);
    if maybe_config.key() != &expected_config_key {
        return Err(ProtocolError::ProtocolNotInitialized.into());
    }

    // Read the config if there is one. A protocol that has not been initialised
    // yet leaves this PDA system-owned; that is the bootstrap window, not an
    // error.
    let configured = if maybe_config.owner() == program_id {
        let config_data = maybe_config.try_borrow_data()?;
        ProtocolConfig::check(&config_data).map_err(|_| ProtocolError::ProtocolNotInitialized)?;
        let config = unsafe { &*(config_data.as_ptr() as *const ProtocolConfig) };
        Some((config.creation_fee, config.execution_fee, config.enabled))
    } else {
        None
    };

    let fee = match configured {
        Some((creation_fee, execution_fee, 1)) => match discriminator {
            0 => creation_fee,
            4 | 7 => execution_fee,
            // The entrypoint dispatcher (caller) restricts us to {0, 4, 7}.
            _ => return Err(ProgramError::InvalidInstructionData),
        },
        // Uninitialised, or `enabled` set to anything but 1.
        _ => 0,
    };

    // Nothing to charge — skip collection and hand the processor its accounts.
    //
    // This branch is the fix for the freeze. Discriminators 4 and 7 are the only
    // paths that CPI with the vault PDA as signer, so when this function
    // reverted on `enabled == 0` or a zero fee, an admin flipping one byte left
    // every user unable to move their own funds, with no instruction able to
    // recover them. A fee is revenue; a revert is custody. Losing revenue while
    // the protocol is misconfigured is the correct trade against holding user
    // funds hostage to a config flag.
    if fee == 0 {
        return Ok(&accounts[..n - 4]);
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
        TreasuryShard::check(&shard_data).map_err(|_| ProtocolError::InvalidTreasuryShard)?;
        let shard = unsafe { &*(shard_data.as_ptr() as *const TreasuryShard) };
        shard.shard_id
    };
    let shard_id_arr = [shard_id];
    let (expected_shard_key, _) =
        find_program_address(&[crate::seeds::TREASURY_SHARD, &shard_id_arr], program_id);
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
        find_program_address(&[crate::seeds::FEE_RECORD, target_payer], program_id);
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
            Seed::from(crate::seeds::FEE_RECORD),
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
        FeeRecord::check(&rec).map_err(|_| ProtocolError::InvalidFeeRecord)?;
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
            // Unreachable: the caller already refused anything outside {0,4,7}
            // when it picked the fee. A `unreachable!()` here would compile to a
            // panic that costs code size to say nothing useful, and in BPF a
            // panic and an error land in the same place anyway.
            _ => return Err(ProgramError::InvalidInstructionData),
        }
    }

    Ok(&accounts[..n - 4])
}
