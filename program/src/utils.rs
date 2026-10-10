use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

/// System Program ID (11111111111111111111111111111111)
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
///
/// Single source of truth. This constant was previously duplicated in
/// `execute/actions.rs` and `processor/migrate.rs`, and the Token-2022 copy in
/// `actions.rs` was WRONG (diverged at byte 8), silently disabling every
/// Token-2022 spending limit and authority-freeze check in the policy engine.
/// Kept here once, pinned by a test, so it cannot diverge again.
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// SPL Token-2022 program id (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const SPL_TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

#[cfg(test)]
mod spl_id_tests {
    use super::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};

    /// The canonical base58 ids, decoded. A wrong constant here fails open (a
    /// real token account is never recognised), so pin the exact bytes. Values
    /// verified against `solana_sdk::pubkey!` in-test.
    #[test]
    fn spl_ids_match_canonical() {
        assert_eq!(
            SPL_TOKEN_PROGRAM_ID,
            solana_sdk::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").to_bytes()
        );
        assert_eq!(
            SPL_TOKEN_2022_PROGRAM_ID,
            solana_sdk::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").to_bytes()
        );
    }
}

/// The cluster's Unix time, in seconds, as the `u64` that session expiries,
/// action expiries and recurring-limit windows are stored in.
///
/// Every duration a person reads off a screen ("until 6:50 PM", "50 USDC a
/// day") is measured with this, not with slots: slots run at whatever pace the
/// cluster manages (about 400 ms on mainnet, faster on devnet), so a duration
/// written in slots is only ever "about" one in time. `unix_timestamp` is the
/// stake-weighted median of the validators' own clocks, held within a bounded
/// drift of the PoH estimate, so it can run slightly fast or slow, never far.
///
/// What stays in slots is what is about landing a transaction rather than about
/// a person's time: the Secp256r1 signature's age (`auth::secp256r1`, the same
/// 150-slot horizon as a recent blockhash) and the deferred-execution window
/// (`Authorize`'s `expiry_offset`, signed as a slot count).
///
/// A negative timestamp never occurs on a real cluster. It is refused rather
/// than read as 0, which would put every expiry in the future.
#[inline]
pub fn unix_now(clock: &pinocchio::sysvars::clock::Clock) -> Result<u64, ProgramError> {
    u64::try_from(clock.unix_timestamp).map_err(|_| ProgramError::InvalidArgument)
}

/// Wrapper around the `sol_get_stack_height` syscall
pub fn get_stack_height() -> u64 {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_get_stack_height()
    }
    #[cfg(not(target_os = "solana"))]
    0
}

#[inline(always)]
pub fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Safely initializes a PDA account using transfer-allocate-assign pattern.
///
/// This prevents DoS attacks where malicious actors pre-fund target accounts
/// with small amounts of lamports, causing the System Program's `create_account`
/// instruction to fail (since it rejects accounts with non-zero balances).
///
/// The transfer-allocate-assign pattern works in three steps:
/// 1. **Transfer**: Add lamports to reach rent-exemption (if needed)
/// 2. **Allocate**: Set the account's data size
/// 3. **Assign**: Transfer ownership to the target program
///
/// # Security
/// - Prevents Issue #4: Create Account DoS vulnerability
/// - Still enforces rent-exemption requirements
/// - Properly assigns ownership to prevent unauthorized access
/// - Works even if account is pre-funded by attacker
///
/// # Arguments
/// * `payer` - Account paying for initialization (must be signer & writable)
/// * `target_pda` - PDA being initialized (will be writable)
/// * `system_program` - System Program account
/// * `space` - Number of bytes to allocate for account data
/// * `rent_lamports` - Minimum lamports for rent-exemption
/// * `owner` - Program that will own this account
/// * `pda_seeds` - Seeds for PDA signing (for allocate & assign)
///
/// # Errors
/// Returns ProgramError if:
/// - Payer has insufficient funds
/// - Any CPI call fails
/// - Account is already owned by another program
pub fn initialize_pda_account(
    payer: &AccountInfo,
    target_pda: &AccountInfo,
    system_program: &AccountInfo,
    space: usize,
    rent_lamports: u64,
    owner: &Pubkey,
    pda_seeds: &[Seed],
) -> ProgramResult {
    // Validate System Program ID
    if system_program.key() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let current_balance = target_pda.lamports();

    // Step 1: Transfer lamports if needed to reach rent-exemption
    if current_balance < rent_lamports {
        let transfer_amount = rent_lamports
            .checked_sub(current_balance)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // System Program Transfer instruction (discriminator: 2)
        let mut transfer_data = Vec::with_capacity(12);
        transfer_data.extend_from_slice(&2u32.to_le_bytes());
        transfer_data.extend_from_slice(&transfer_amount.to_le_bytes());

        let transfer_accounts = [
            AccountMeta {
                pubkey: payer.key(),
                is_signer: true,
                is_writable: true,
            },
            AccountMeta {
                pubkey: target_pda.key(),
                is_signer: false,
                is_writable: true,
            },
        ];

        let transfer_ix = Instruction {
            program_id: &Pubkey::from(SYSTEM_PROGRAM_ID),
            accounts: &transfer_accounts,
            data: &transfer_data,
        };

        pinocchio::program::invoke(&transfer_ix, &[&payer, &target_pda, &system_program])?;
    }

    // Step 2: Allocate space
    // System Program Allocate instruction (discriminator: 8)
    let mut allocate_data = Vec::with_capacity(12);
    allocate_data.extend_from_slice(&8u32.to_le_bytes());
    allocate_data.extend_from_slice(&(space as u64).to_le_bytes());

    let allocate_accounts = [AccountMeta {
        pubkey: target_pda.key(),
        is_signer: true,
        is_writable: true,
    }];

    let allocate_ix = Instruction {
        program_id: &Pubkey::from(SYSTEM_PROGRAM_ID),
        accounts: &allocate_accounts,
        data: &allocate_data,
    };

    let signer: Signer = pda_seeds.into();
    invoke_signed(&allocate_ix, &[&target_pda, &system_program], &[signer])?;

    // Step 3: Assign ownership to target program
    // System Program Assign instruction (discriminator: 1)
    let mut assign_data = Vec::with_capacity(36);
    assign_data.extend_from_slice(&1u32.to_le_bytes());
    assign_data.extend_from_slice(owner.as_ref());

    let assign_accounts = [AccountMeta {
        pubkey: target_pda.key(),
        is_signer: true,
        is_writable: true,
    }];

    let assign_ix = Instruction {
        program_id: &Pubkey::from(SYSTEM_PROGRAM_ID),
        accounts: &assign_accounts,
        data: &assign_data,
    };

    let signer: Signer = pda_seeds.into();
    invoke_signed(&assign_ix, &[&target_pda, &system_program], &[signer])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_all_zero;

    #[test]
    fn is_all_zero_detects_empty_and_zero_slices() {
        assert!(is_all_zero(&[]));
        assert!(is_all_zero(&[0; 32]));
    }

    #[test]
    fn is_all_zero_rejects_any_nonzero_byte() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        assert!(!is_all_zero(&bytes));
    }
}

#[cfg(test)]
mod unix_now_tests {
    use super::unix_now;
    use pinocchio::sysvars::clock::Clock;

    fn clock(unix_timestamp: i64) -> Clock {
        Clock {
            slot: 507_081_509,
            epoch_start_timestamp: 0,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp,
        }
    }

    #[test]
    fn reads_the_timestamp_not_the_slot() {
        assert_eq!(unix_now(&clock(1_791_331_200)), Ok(1_791_331_200));
        assert_eq!(unix_now(&clock(0)), Ok(0));
    }

    #[test]
    fn refuses_a_negative_timestamp() {
        assert!(unix_now(&clock(-1)).is_err());
        assert!(unix_now(&clock(i64::MIN)).is_err());
    }
}
