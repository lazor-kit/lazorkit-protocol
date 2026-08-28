use assertions::{check_zero_data, sol_assert_bytes_eq};
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::rent::Rent,
    ProgramResult,
};

/// Rank values. Owner manages everything, Admin manages Delegates, a Delegate
/// manages nothing and must carry a policy.
pub const RANK_OWNER: u8 = 0;
pub const RANK_ADMIN: u8 = 1;
pub const RANK_DELEGATE: u8 = 2;

/// Highest rank value that has a meaning. Anything above it is refused rather
/// than stored — without this an Owner could mint a rank-255 authority that
/// executes but that no rule below can ever revoke.
pub const RANK_MAX: u8 = RANK_DELEGATE;

/// May an authority of rank `actor` create one of rank `new_rank`?
///
/// Owner grants any rank, including Owner: a person with several devices holds
/// several passkeys, and making each of them an Owner is what lets a surviving
/// device revoke a lost one. Admin grants only Delegates. A Delegate grants
/// nothing.
///
/// Rank alone is not the whole answer — a Delegate additionally requires a
/// policy, and an authority that carries a policy itself may not grant at all.
/// Both are enforced at the call site, where the policy bytes are in hand.
#[inline]
pub fn can_add(actor: u8, new_rank: u8) -> bool {
    if new_rank > RANK_MAX {
        return false;
    }
    match actor {
        RANK_OWNER => true,
        RANK_ADMIN => new_rank == RANK_DELEGATE,
        _ => false,
    }
}

/// May an authority of rank `actor` remove one of rank `target`, given how many
/// Owners the wallet currently has?
///
/// The `owner_count > 1` condition is the whole reason the count exists. A
/// wallet with no Owner is not frozen — its authorities keep spending — but
/// nothing can ever be added or revoked again, so a lost device stays valid
/// forever. Removing the last Owner is therefore refused, and losing ownership
/// deliberately goes through TransferOwnership instead.
///
/// Self-removal is refused at the call site, where the two PDAs are in hand.
#[inline]
pub fn can_remove(actor: u8, target: u8, owner_count: u32) -> bool {
    match (actor, target) {
        (RANK_OWNER, RANK_OWNER) => owner_count > 1,
        (RANK_OWNER, t) => t <= RANK_MAX,
        (RANK_ADMIN, RANK_DELEGATE) => true,
        _ => false,
    }
}

/// Cap on an authority's policy buffer, matching the session cap in
/// `session/create.rs` — the BPF heap is 32 KB, and 16 actions of ~128 bytes
/// fit comfortably inside 2 KB.
pub const MAX_POLICY_BUFFER_SIZE: usize = 2048;

use crate::{
    auth::{
        ed25519::Ed25519Authenticator, secp256r1::Secp256r1Authenticator, traits::Authenticator,
    },
    error::AuthError,
    state::{
        action::validate_actions_buffer, authority::AuthorityAccountHeader,
        policy::authority_fixed_len, AccountDiscriminator,
    },
    utils::is_all_zero,
};

/// Arguments for the `AddAuthority` instruction.
///
/// Layout:
/// - `authority_type`: 0 for Ed25519, 1 for Secp256r1.
/// - `new_role`: Role to assign (1=Admin, 2=Spender).
///
/// `Owner` is intentionally excluded here. Ownership changes must use
/// `TransferOwnership`, which atomically closes the old owner authority.
/// - `_padding`: Reserved to align to 8-byte boundary.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct AddAuthorityArgs {
    pub authority_type: u8,
    pub new_role: u8,
    pub _padding: [u8; 6],
}

impl AddAuthorityArgs {
    pub fn from_bytes(data: &[u8]) -> Result<(Self, &[u8]), ProgramError> {
        if data.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (fixed, rest) = data.split_at(8);

        // Manual deserialization for safety
        let authority_type = fixed[0];
        let new_role = fixed[1];

        let args = Self {
            authority_type,
            new_role,
            _padding: [0; 6],
        };

        Ok((args, rest))
    }
}

/// Processes the `AddAuthority` instruction.
///
/// Adds a new authority to the wallet.
///
/// # Logic:
/// 1. **Authentication**: Verifies the `admin_authority` (must be Admin or Owner).
/// 2. **Authorization**: Checks permission levels:
///    - `Owner` (0) can add Admin (1) or Spender (2).
///    - `Admin` (1) can only add `Spender` (2).
/// 3. **Execution**: Creates a new PDA `["authority", wallet, id_hash]` and initializes it.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer.
/// 2. `[]` Wallet PDA.
/// 3. `[signer]` Admin Authority: Existing authority authorizing this action.
/// 4. `[writable]` New Authority: The PDA to create.
/// 5. `[]` System Program.
pub fn process_add_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (args, rest) = AddAuthorityArgs::from_bytes(instruction_data)?;

    let (id_seed, full_auth_data) = match args.authority_type {
        0 => {
            if rest.len() < 32 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let (pubkey, _) = rest.split_at(32);
            if is_all_zero(pubkey) {
                return Err(AuthError::InvalidPubkey.into());
            }
            (pubkey, pubkey)
        },
        1 => {
            // [credential_id_hash(32)] [pubkey(33)] [rpIdLen(1)] [rpId(N)]
            if rest.len() < 66 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let (credential_id_hash, rest_after_cred) = rest.split_at(32);
            let compressed_pubkey = &rest_after_cred[..33];
            if is_all_zero(credential_id_hash) || is_all_zero(compressed_pubkey) {
                return Err(AuthError::InvalidPubkey.into());
            }
            let rp_id_len = rest_after_cred[33] as usize;
            if rp_id_len == 0 || rp_id_len > 253 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let total_auth_data = 32 + 33 + 1 + rp_id_len;
            if rest.len() < total_auth_data {
                return Err(ProgramError::InvalidInstructionData);
            }
            let full_auth_data = &rest[..total_auth_data];
            (credential_id_hash, full_auth_data)
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    };

    // Optional policy, laid out exactly as CreateSession lays out its actions:
    // `[policy_len u16 LE][policy]` after the key material and before the
    // Secp256r1 auth payload. Putting it before the auth payload is what keeps
    // it inside the signed region — a policy the passkey holder did not sign
    // would be a policy somebody else chose.
    let key_data_end = 8 + full_auth_data.len();
    if instruction_data.len() < key_data_end {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (policy, data_payload_len) = if instruction_data.len() >= key_data_end + 2 {
        let policy_len = u16::from_le_bytes(
            instruction_data[key_data_end..key_data_end + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        if policy_len > MAX_POLICY_BUFFER_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let start = key_data_end + 2;
        if instruction_data.len() < start + policy_len {
            return Err(ProgramError::InvalidInstructionData);
        }
        (
            &instruction_data[start..start + policy_len],
            start + policy_len,
        )
    } else {
        (&instruction_data[key_data_end..key_data_end], key_data_end)
    };

    if !policy.is_empty() {
        validate_actions_buffer(policy)?;
    }

    let (data_payload, authority_payload) = instruction_data.split_at(data_payload_len);

    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let wallet_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let admin_auth_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let new_auth_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if wallet_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if admin_auth_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    // Validate Wallet Discriminator (Issue #7)
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    crate::state::wallet::WalletAccount::check(wallet_data)?;

    let rent_sysvar_info = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent = Rent::from_account_info(rent_sysvar_info)?;

    // Check removed here, moved to type-specific logic
    // if !admin_auth_pda.is_writable() {
    //    return Err(ProgramError::InvalidAccountData);
    // }

    let admin_data = unsafe { admin_auth_pda.borrow_mut_data_unchecked() };
    AuthorityAccountHeader::check(admin_data)?;

    // Safe Copy of Header using read_unaligned
    let admin_header =
        unsafe { std::ptr::read_unaligned(admin_data.as_ptr() as *const AuthorityAccountHeader) };

    if admin_header.wallet != *wallet_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Unified Authentication
    // Include payer + target in signed payload to prevent account swap attacks
    let mut ed25519_payload = Vec::with_capacity(64);
    ed25519_payload.extend_from_slice(payer.key().as_ref());
    ed25519_payload.extend_from_slice(new_auth_pda.key().as_ref());

    match admin_header.authority_type {
        0 => {
            // Ed25519: Include payer + new_auth_pda in signed payload
            Ed25519Authenticator.authenticate(
                accounts,
                admin_data,
                &[],
                &ed25519_payload,
                &[1],
                program_id,
            )?;
        },
        1 => {
            // Secp256r1 (WebAuthn) - Must be Writable
            if !admin_auth_pda.is_writable() {
                return Err(ProgramError::InvalidAccountData);
            }
            // Secp256r1: Include payer in signed payload
            let mut extended_data_payload = Vec::with_capacity(data_payload.len() + 32);
            extended_data_payload.extend_from_slice(data_payload);
            extended_data_payload.extend_from_slice(payer.key().as_ref());

            Secp256r1Authenticator.authenticate(
                accounts,
                admin_data,
                authority_payload,
                &extended_data_payload,
                &[1],
                program_id,
            )?;
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    }

    // Authorization
    if !can_add(admin_header.role, args.new_role) {
        return Err(AuthError::PermissionDenied.into());
    }

    // A Delegate must carry a policy.
    //
    // This is what closes H-2. `role` gated management operations and nothing
    // else — Execute never read it — so "Spender" named a tier that had exactly
    // the same power over the vault as Owner. Requiring the policy makes the
    // name true: rank says what you may manage, the policy says what you may
    // spend, and a Delegate manages nothing.
    if args.new_role == RANK_DELEGATE && policy.is_empty() {
        return Err(AuthError::DelegateRequiresPolicy.into());
    }

    // An authority that is itself bounded may not mint authorities.
    //
    // Comparing two policies to check the grant is no broader than the granter's
    // is a hard problem; refusing the grant outright sidesteps it. Without this,
    // an Admin capped at 1 SOL/day could mint a Delegate capped at 100.
    if admin_header.policy_len != 0 {
        return Err(AuthError::PolicyBearingAuthorityCannotDelegate.into());
    }

    // Logic
    let (new_auth_key, bump) = find_program_address(
        &[crate::seeds::AUTHORITY, wallet_pda.key().as_ref(), id_seed],
        program_id,
    );
    if !sol_assert_bytes_eq(new_auth_pda.key().as_ref(), new_auth_key.as_ref(), 32) {
        return Err(ProgramError::InvalidSeeds);
    }
    check_zero_data(new_auth_pda, ProgramError::AccountAlreadyInitialized)?;

    // Fixed sizes per auth type (see wallet/create.rs for layout).
    let header_size = std::mem::size_of::<AuthorityAccountHeader>();
    let fixed_len =
        authority_fixed_len(args.authority_type).ok_or(AuthError::InvalidAuthenticationKind)?;
    let space = fixed_len + policy.len();
    let rent_lamports = rent.minimum_balance(space);

    // Use secure transfer-allocate-assign pattern to prevent DoS (Issue #4)
    let bump_arr = [bump];
    let seeds = [
        Seed::from(crate::seeds::AUTHORITY),
        Seed::from(wallet_pda.key().as_ref()),
        Seed::from(id_seed),
        Seed::from(&bump_arr),
    ];

    crate::utils::initialize_pda_account(
        payer,
        new_auth_pda,
        system_program,
        space,
        rent_lamports,
        program_id,
        &seeds,
    )?;

    // A new Owner changes the wallet's own state, which is why `wallet` is
    // writable on this instruction. Done before the authority is written so a
    // failure here leaves nothing behind.
    if args.new_role == RANK_OWNER {
        let wallet_data = unsafe { wallet_pda.borrow_mut_data_unchecked() };
        let next = crate::state::wallet::WalletAccount::owner_count(wallet_data)
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        crate::state::wallet::WalletAccount::set_owner_count(wallet_data, next);
    }

    let data = unsafe { new_auth_pda.borrow_mut_data_unchecked() };
    let header = AuthorityAccountHeader {
        discriminator: AccountDiscriminator::Authority as u8,
        authority_type: args.authority_type,
        role: args.new_role,
        bump,
        version: crate::state::CURRENT_ACCOUNT_VERSION,
        _padding1: [0; 3],
        counter: 0,
        policy_len: policy.len() as u16,
        _padding2: [0; 2],
        wallet: *wallet_pda.key(),
    };
    // `write_unaligned`, matching every other header write and every reader.
    // This site used to store through a plain `*mut` deref, which is only sound
    // if the account data happens to be 8-aligned — true in practice, undefined
    // by the language, and inconsistent with the `read_unaligned` on the way back.
    unsafe {
        std::ptr::write_unaligned(data.as_mut_ptr() as *mut AuthorityAccountHeader, header);
    }

    // Write variable data. For Secp256r1 hash rpId once here so every Execute
    // saves a sol_sha256 syscall.
    match args.authority_type {
        0 => {
            data[header_size..header_size + 32].copy_from_slice(&full_auth_data[..32]);
        },
        1 => {
            data[header_size..header_size + 32].copy_from_slice(&full_auth_data[..32]);
            data[header_size + 32..header_size + 32 + 33]
                .copy_from_slice(&full_auth_data[32..32 + 33]);
            let rp_id_len = full_auth_data[32 + 33] as usize;
            let rp_id = &full_auth_data[32 + 33 + 1..32 + 33 + 1 + rp_id_len];
            let rp_id_hash_offset = header_size + 32 + 33;
            #[cfg(target_os = "solana")]
            unsafe {
                let _ = pinocchio::syscalls::sol_sha256(
                    [rp_id].as_ptr() as *const u8,
                    1,
                    data[rp_id_hash_offset..rp_id_hash_offset + 32].as_mut_ptr(),
                );
            }
            #[cfg(not(target_os = "solana"))]
            {
                let _ = rp_id;
                data[rp_id_hash_offset..rp_id_hash_offset + 32].fill(0);
            }
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    }

    // The policy trails the key material, at the offset PolicyLocation derives
    // from this account's own discriminator and authority type.
    if !policy.is_empty() {
        data[fixed_len..fixed_len + policy.len()].copy_from_slice(policy);
    }

    Ok(())
}

/// Processes the `RemoveAuthority` instruction.
///
/// Removes an existing authority and refunds rent to the destination.
///
/// # Logic:
/// 1. **Authentication**: Verifies the `admin_authority`.
/// 2. **Authorization**:
///    - `Owner` can remove anyone (except potentially the last owner, though not explicitly enforced here).
///    - `Admin` can only remove `Spender`.
/// 3. **Execution**: Securely closes the account by zeroing data and transferring lamports.
///
/// # Accounts:
/// 1. `[signer]` Payer.
/// 2. `[]` Wallet PDA.
/// 3. `[signer]` Admin Authority.
/// 4. `[writable]` Target Authority: PDA to verify and close.
/// 5. `[writable]` Refund Destination.
pub fn process_remove_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // For RemoveAuthority, all instruction_data is authority_payload
    // Issue #13: Bind signature to specific target accounts to prevent reuse
    let authority_payload = instruction_data;

    // Build data_payload with target pubkeys (computed after parsing accounts)

    let account_info_iter = &mut accounts.iter();
    let _payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let wallet_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let admin_auth_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let target_auth_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let refund_dest = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if wallet_pda.owner() != program_id
        || admin_auth_pda.owner() != program_id
        || target_auth_pda.owner() != program_id
    {
        return Err(ProgramError::IllegalOwner);
    }

    // Validate Wallet Discriminator (Issue #7)
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    crate::state::wallet::WalletAccount::check(wallet_data)?;

    if !admin_auth_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Safe copy header using read_unaligned
    let admin_data = unsafe { admin_auth_pda.borrow_mut_data_unchecked() };
    AuthorityAccountHeader::check(admin_data)?;
    let admin_header =
        unsafe { std::ptr::read_unaligned(admin_data.as_ptr() as *const AuthorityAccountHeader) };
    if admin_header.wallet != *wallet_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Issue #13: Build data_payload with target pubkeys to prevent signature reuse
    // Signature is now bound to specific target_auth_pda and refund_dest
    let mut data_payload = Vec::with_capacity(64);
    data_payload.extend_from_slice(target_auth_pda.key().as_ref());
    data_payload.extend_from_slice(refund_dest.key().as_ref());

    // Authentication
    match admin_header.authority_type {
        0 => {
            // Ed25519: Include data_payload in signature verification
            Ed25519Authenticator.authenticate(
                accounts,
                admin_data,
                &[],
                &data_payload,
                &[2],
                program_id,
            )?;
        },
        1 => {
            Secp256r1Authenticator.authenticate(
                accounts,
                admin_data,
                authority_payload,
                &data_payload,
                &[2],
                program_id,
            )?;
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    }

    // Authorization - ALWAYS validate target authority
    let target_data = unsafe { target_auth_pda.borrow_data_unchecked() };
    AuthorityAccountHeader::check(target_data)?;
    // Safe copy target header using read_unaligned
    let target_header =
        unsafe { std::ptr::read_unaligned(target_data.as_ptr() as *const AuthorityAccountHeader) };

    // ALWAYS verify discriminator

    // ALWAYS verify target belongs to THIS wallet (CRITICAL SECURITY CHECK)
    if target_header.wallet != *wallet_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Prevent self-removal — removing yourself could lock the wallet
    if admin_auth_pda.key() == target_auth_pda.key() {
        return Err(AuthError::PermissionDenied.into());
    }

    // Role-based permission check, including the "not the last Owner" rule.
    let owner_count = crate::state::wallet::WalletAccount::owner_count(unsafe {
        wallet_pda.borrow_data_unchecked()
    });
    if !can_remove(admin_header.role, target_header.role, owner_count) {
        return Err(AuthError::PermissionDenied.into());
    }

    // Guard: if target == refund_dest the double-write would burn lamports and
    // trigger a Solana lamport conservation error, aborting after doing work.
    if target_auth_pda.key() == refund_dest.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    if target_header.role == RANK_OWNER {
        let wallet_data = unsafe { wallet_pda.borrow_mut_data_unchecked() };
        // `can_remove` already refused a count of 1, so this cannot wrap. The
        // checked form is here because a future caller might not.
        let next = crate::state::wallet::WalletAccount::owner_count(wallet_data)
            .checked_sub(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        crate::state::wallet::WalletAccount::set_owner_count(wallet_data, next);
    }

    let target_lamports = unsafe { *target_auth_pda.borrow_mut_lamports_unchecked() };
    let refund_lamports = unsafe { *refund_dest.borrow_mut_lamports_unchecked() };
    unsafe {
        *refund_dest.borrow_mut_lamports_unchecked() = refund_lamports
            .checked_add(target_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *target_auth_pda.borrow_mut_lamports_unchecked() = 0;
    }
    let target_data = unsafe { target_auth_pda.borrow_mut_data_unchecked() };
    target_data.fill(0);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_authority_args_from_bytes() {
        // [type(1)][role(1)][padding(6)]
        let mut data = Vec::new();
        data.push(0); // Ed25519
        data.push(2); // Spender
        data.extend_from_slice(&[0; 6]); // padding

        let extra_data = [1u8; 32];
        data.extend_from_slice(&extra_data);

        let (args, rest) = AddAuthorityArgs::from_bytes(&data).unwrap();
        assert_eq!(args.authority_type, 0);
        assert_eq!(args.new_role, 2);
        assert_eq!(rest, &extra_data);
    }

    #[test]
    fn test_add_authority_args_too_short() {
        let data = vec![0u8; 7]; // Need 8
        assert!(AddAuthorityArgs::from_bytes(&data).is_err());
    }
}

#[cfg(test)]
mod rank_rules {
    use super::*;

    /// Every (actor, target) pair, so a change to either rule has to be a
    /// deliberate edit to this table rather than a silent widening.
    #[test]
    fn can_add_table() {
        let expected = [
            // (actor, new_rank, allowed)
            (RANK_OWNER, RANK_OWNER, true),
            (RANK_OWNER, RANK_ADMIN, true),
            (RANK_OWNER, RANK_DELEGATE, true),
            (RANK_ADMIN, RANK_OWNER, false),
            (RANK_ADMIN, RANK_ADMIN, false),
            (RANK_ADMIN, RANK_DELEGATE, true),
            (RANK_DELEGATE, RANK_OWNER, false),
            (RANK_DELEGATE, RANK_ADMIN, false),
            (RANK_DELEGATE, RANK_DELEGATE, false),
        ];
        for (actor, new_rank, allowed) in expected {
            assert_eq!(
                can_add(actor, new_rank),
                allowed,
                "can_add(actor={actor}, new_rank={new_rank})"
            );
        }
    }

    /// An unknown rank is refused rather than stored. Storing one would create
    /// an authority that executes but that no `can_remove` arm can revoke.
    #[test]
    fn can_add_refuses_ranks_that_have_no_meaning() {
        for new_rank in [RANK_MAX + 1, 42, u8::MAX] {
            for actor in [RANK_OWNER, RANK_ADMIN, RANK_DELEGATE] {
                assert!(
                    !can_add(actor, new_rank),
                    "actor={actor} new_rank={new_rank}"
                );
            }
        }
        // And an actor whose stored rank is nonsense grants nothing.
        for actor in [RANK_MAX + 1, 42, u8::MAX] {
            assert!(!can_add(actor, RANK_DELEGATE));
        }
    }

    #[test]
    fn can_remove_table() {
        let expected = [
            // (actor, target, owner_count, allowed)
            (RANK_OWNER, RANK_OWNER, 1, false), // the rule the count exists for
            (RANK_OWNER, RANK_OWNER, 2, true),
            (RANK_OWNER, RANK_OWNER, 9, true),
            (RANK_OWNER, RANK_ADMIN, 1, true),
            (RANK_OWNER, RANK_DELEGATE, 1, true),
            (RANK_ADMIN, RANK_OWNER, 9, false),
            (RANK_ADMIN, RANK_ADMIN, 9, false),
            (RANK_ADMIN, RANK_DELEGATE, 1, true),
            (RANK_DELEGATE, RANK_OWNER, 9, false),
            (RANK_DELEGATE, RANK_ADMIN, 9, false),
            (RANK_DELEGATE, RANK_DELEGATE, 9, false),
        ];
        for (actor, target, owner_count, allowed) in expected {
            assert_eq!(
                can_remove(actor, target, owner_count),
                allowed,
                "can_remove(actor={actor}, target={target}, owner_count={owner_count})"
            );
        }
    }

    /// A count of zero should be unreachable, but if it ever happened the answer
    /// must still be "no" rather than an underflow.
    #[test]
    fn can_remove_owner_is_refused_at_zero() {
        assert!(!can_remove(RANK_OWNER, RANK_OWNER, 0));
    }

    /// Removing an Owner is the only decision the count participates in.
    #[test]
    fn owner_count_does_not_affect_other_removals() {
        for owner_count in [0, 1, 2, 7] {
            assert!(can_remove(RANK_OWNER, RANK_ADMIN, owner_count));
            assert!(can_remove(RANK_OWNER, RANK_DELEGATE, owner_count));
            assert!(can_remove(RANK_ADMIN, RANK_DELEGATE, owner_count));
        }
    }
}
