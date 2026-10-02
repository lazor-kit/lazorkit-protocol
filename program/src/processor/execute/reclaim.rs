use crate::{error::AuthError, state::deferred::DeferredExecAccount};
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

/// v1's DeferredExec discriminator. v2 renumbered it to `0x24`.
const V1_DISC_DEFERRED: u8 = 4;
/// v1 field offsets, identical to v2's. Established on chain: on 2026-09-24 the
/// 16 v1 accounts selected on devnet by the payer read from these offsets were
/// exactly the 16 the v1 program then accepted `ReclaimDeferred` for.
const V1_OFF_PAYER: usize = 136;
const V1_OFF_EXPIRES_AT: usize = 168;

/// Process the ReclaimDeferred instruction.
///
/// Closes an expired DeferredExec account and refunds rent to the original payer.
/// Only the original payer can reclaim, and only after the authorization has expired.
///
/// # Accounts:
/// 1. `[signer]` Payer (must match stored payer)
/// 2. `[writable]` DeferredExec PDA (closed)
/// 3. `[writable]` Refund destination
///
/// # Instruction Data (after discriminator):
///   (none)
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let deferred_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let refund_dest = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Validate signer
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify ownership
    if deferred_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read DeferredExec account — a v2 one, or a v1 one left behind by the
    // upgrade. Only the payer and the expiry matter here, and both sit at the
    // same offsets in either layout (payer 136..168, expires_at 168..176), so a
    // v1 account is read field by field rather than through the v2 struct,
    // whose header check would rightly refuse its discriminator.
    let deferred_data = unsafe { deferred_pda.borrow_mut_data_unchecked() };
    let (stored_payer, expires_at) = if deferred_data.first() == Some(&V1_DISC_DEFERRED) {
        if deferred_data.len() < DeferredExecAccount::MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let payer: [u8; 32] = deferred_data[V1_OFF_PAYER..V1_OFF_PAYER + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let expires_at = u64::from_le_bytes(
            deferred_data[V1_OFF_EXPIRES_AT..V1_OFF_EXPIRES_AT + 8]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?,
        );
        (Pubkey::from(payer), expires_at)
    } else {
        DeferredExecAccount::check(deferred_data)?;
        let deferred = unsafe {
            std::ptr::read_unaligned(deferred_data.as_ptr() as *const DeferredExecAccount)
        };
        (deferred.payer, deferred.expires_at)
    };

    // Only the original payer can reclaim, and the rent goes back to it. Binding
    // the destination matters because the payer is usually a paymaster that
    // signs whatever LazorKit transaction it is handed: with a free
    // destination, anyone could route a sponsored reclaim to themselves.
    if stored_payer != *payer.key() {
        return Err(AuthError::UnauthorizedReclaim.into());
    }
    if refund_dest.key() != &stored_payer {
        return Err(AuthError::UnauthorizedReclaim.into());
    }

    // Can only reclaim after expiry
    let clock = Clock::get()?;
    if clock.slot <= expires_at {
        return Err(AuthError::DeferredAuthorizationNotExpired.into());
    }

    // Guard: if refund_dest == deferred_pda the double-write below burns the
    // lamports — the second store wins and the balance lands at zero — and the
    // runtime's conservation check then aborts the whole transaction after the
    // data has already been cleared. The other two closers in this program
    // (`manage::process_remove_authority`, `transfer_ownership`) already had
    // this; reclaim did not.
    if refund_dest.key() == deferred_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Close the account — zero data and drain lamports
    for byte in deferred_data.iter_mut() {
        *byte = 0;
    }

    let deferred_lamports = deferred_pda.lamports();
    let refund_lamports = unsafe { *refund_dest.borrow_mut_lamports_unchecked() };
    unsafe {
        *refund_dest.borrow_mut_lamports_unchecked() = refund_lamports
            .checked_add(deferred_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *deferred_pda.borrow_mut_lamports_unchecked() = 0;
    }

    Ok(())
}
