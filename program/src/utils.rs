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

/// The marker the runtime appends when it derives a program address.
const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

/// Most seeds [`is_program_address`] takes, the bump not counted.
const MAX_CHECKED_SEEDS: usize = 3;

/// Whether `address` is the program address of `seeds` and `bump` under
/// `program_id`: `sha256(seeds ‖ bump ‖ program_id ‖ "ProgramDerivedAddress")`.
///
/// This is the runtime's `create_program_address` without its last step, the
/// check that the hash is not a point on the curve, and costs one `sol_sha256`
/// (about 150 CU here) where `create_program_address` costs 1,500 and
/// `find_program_address` 1,500 for every bump it tries.
///
/// Dropping the curve check is sound only for a bump this program stored after
/// `find_program_address` returned it for these same seeds: that hash is a
/// valid program address by construction, so equality with it is exactly
/// "`address` is the canonical PDA". The callers keep to that:
///
/// - the vault bump comes from the wallet account, written by `CreateWallet`
///   from its own search over `[VAULT, wallet]`;
/// - the config, shard and fee-record bumps come from the account being
///   checked, which this program owns and wrote from its own search.
///
/// In the fee record's case the stored bump was found for the record's own
/// payer; hashed with any other payer it matches the address only through a
/// SHA-256 collision, so a record cannot be passed off as another payer's.
///
/// Never call this with a bump that came from instruction data.
#[inline]
pub fn is_program_address(
    seeds: &[&[u8]],
    bump: u8,
    program_id: &Pubkey,
    address: &Pubkey,
) -> bool {
    if seeds.len() > MAX_CHECKED_SEEDS {
        return false;
    }
    let bump = [bump];
    let mut vals: [&[u8]; MAX_CHECKED_SEEDS + 3] = [&[]; MAX_CHECKED_SEEDS + 3];
    vals[..seeds.len()].copy_from_slice(seeds);
    vals[seeds.len()] = &bump;
    vals[seeds.len() + 1] = program_id.as_ref();
    vals[seeds.len() + 2] = PDA_MARKER;
    let vals = &vals[..seeds.len() + 3];

    #[cfg(target_os = "solana")]
    {
        let mut hash = [0u8; 32];
        unsafe {
            pinocchio::syscalls::sol_sha256(
                vals.as_ptr() as *const u8,
                vals.len() as u64,
                hash.as_mut_ptr(),
            );
        }
        &hash == address
    }

    #[cfg(all(not(target_os = "solana"), test))]
    {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for v in vals {
            h.update(v);
        }
        let hash: [u8; 32] = h.finalize().into();
        &hash == address
    }

    #[cfg(all(not(target_os = "solana"), not(test)))]
    {
        core::hint::black_box((vals, address));
        panic!("is_program_address is only available on target `solana`")
    }
}

/// The bump `Execute` and `ExecuteDeferred` sign for `vault_pda` with, after
/// checking it is `wallet_pda`'s vault, `[VAULT, wallet]`.
///
/// A wallet that records its vault's bump (every wallet created from this
/// build on) has the address checked with one hash ([`is_program_address`]);
/// one that records none (byte 3 is 0) is searched for, as before.
///
/// `wallet_data` must have passed `WalletAccount::check`, and `wallet_pda` must
/// be owned by this program: the stored bump is trusted because only this
/// program writes it.
#[inline]
pub fn vault_signer_bump(
    wallet_pda: &AccountInfo,
    wallet_data: &[u8],
    vault_pda: &AccountInfo,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let seeds: [&[u8]; 2] = [crate::seeds::VAULT, wallet_pda.key().as_ref()];
    match crate::state::wallet::WalletAccount::vault_bump(wallet_data) {
        Some(bump) => {
            if !is_program_address(&seeds, bump, program_id, vault_pda.key()) {
                return Err(ProgramError::InvalidSeeds);
            }
            Ok(bump)
        },
        None => {
            let (vault_key, bump) = pinocchio::pubkey::find_program_address(&seeds, program_id);
            if vault_pda.key() != &vault_key {
                return Err(ProgramError::InvalidSeeds);
            }
            Ok(bump)
        },
    }
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
mod program_address_tests {
    use super::is_program_address;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    /// The hash matches the runtime's derivation for the canonical bump, and
    /// nothing else: another bump, another seed or another program id.
    #[test]
    fn matches_find_program_address_for_the_canonical_bump_only() {
        let program_id = SdkPubkey::new_unique();
        for i in 0..64u8 {
            let wallet = [i; 32];
            let seeds: [&[u8]; 2] = [crate::seeds::VAULT, &wallet];
            let (pda, bump) = SdkPubkey::find_program_address(&seeds, &program_id);
            let pid = program_id.to_bytes();
            let pda = pda.to_bytes();
            assert!(is_program_address(&seeds, bump, &pid, &pda));
            assert!(!is_program_address(
                &seeds,
                bump.wrapping_sub(1),
                &pid,
                &pda
            ));
            let other = [i ^ 0xFF; 32];
            assert!(!is_program_address(
                &[crate::seeds::VAULT, &other],
                bump,
                &pid,
                &pda
            ));
            assert!(!is_program_address(
                &seeds,
                bump,
                &SdkPubkey::new_unique().to_bytes(),
                &pda
            ));
        }
    }

    #[test]
    fn single_and_three_seed_derivations_match_too() {
        let program_id = SdkPubkey::new_unique();
        let pid = program_id.to_bytes();
        let one: [&[u8]; 1] = [crate::seeds::PROTOCOL_CONFIG];
        let (pda, bump) = SdkPubkey::find_program_address(&one, &program_id);
        assert!(is_program_address(&one, bump, &pid, &pda.to_bytes()));
        let three: [&[u8]; 3] = [crate::seeds::AUTHORITY, &[1; 32], &[2; 32]];
        let (pda, bump) = SdkPubkey::find_program_address(&three, &program_id);
        assert!(is_program_address(&three, bump, &pid, &pda.to_bytes()));
    }

    #[test]
    fn more_seeds_than_it_takes_never_match() {
        let pid = [9u8; 32];
        let four: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        assert!(!is_program_address(&four, 255, &pid, &[0u8; 32]));
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
