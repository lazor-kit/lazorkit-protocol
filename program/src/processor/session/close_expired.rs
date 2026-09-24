//! CloseExpiredSession — close a session nobody can use any more, and keep the
//! rent.
//!
//! Before expiry a session ends one way: `RevokeSession`, signed by the
//! wallet's own Owner or Admin. That stays. After expiry the account is inert —
//! `execute::immediate` refuses any session where `current_slot >
//! expires_at`, so what remains is rent locked in an account that will never
//! authorise anything again, and the only key that could free it belongs to a
//! user with no reason to come back.
//!
//! So after expiry anyone may close it and keep the rent. Cleanup stops being a
//! chore nobody does and becomes something that pays for itself.
//!
//! It accepts a **v1** session as well as a v2 one. The two headers are
//! byte-identical apart from the discriminator — `wallet` at 8, `session_key`
//! at 40, `expires_at` at 72 in both — and the v1 sessions stranded by the
//! upgrade have no other way home.
//!
//! Accounts:
//!
//! ```text
//!  0. [signer]           caller — pays the fee, and is free to name itself below
//!  1. [writable]         session PDA (closed)
//!  2. [writable]         refund destination for the rent
//! ```
//!
//! Instruction data after the discriminator: none.
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    error::AuthError,
    state::{session::SESSION_HEADER_SIZE, AccountDiscriminator},
};

/// v1's Session discriminator. v2 renumbered it to `0x23`; both are closed here.
const V1_DISC_SESSION: u8 = 3;
/// `expires_at` sits at the same offset in both layouts.
const OFF_EXPIRES_AT: usize = 72;

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let caller = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let refund_dest = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Somebody has to sign, so the transaction has an author and a fee payer.
    // Which key it is does not matter: that is the point of the instruction.
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Draining into the account being drained would zero the refund.
    if refund_dest.key() == session_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    if session_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let session_data = unsafe { session_pda.borrow_mut_data_unchecked() };
    if session_data.len() < SESSION_HEADER_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    // Only this program writes accounts it owns, and it writes these two
    // discriminators at session PDAs alone — so ownership plus the tag is what
    // makes this a session, in either protocol version.
    let discriminator = session_data[0];
    if discriminator != V1_DISC_SESSION && discriminator != AccountDiscriminator::Session as u8 {
        return Err(ProgramError::InvalidAccountData);
    }

    let expires_at = u64::from_le_bytes(
        session_data[OFF_EXPIRES_AT..OFF_EXPIRES_AT + 8]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    );
    // The same comparison `execute` uses. One slot looser here and a caller
    // could close a session that is still authorised in its final slot.
    if Clock::get()?.slot <= expires_at {
        return Err(AuthError::SessionNotExpired.into());
    }

    for byte in session_data.iter_mut() {
        *byte = 0;
    }

    let session_lamports = session_pda.lamports();
    let refund_lamports = unsafe { *refund_dest.borrow_mut_lamports_unchecked() };
    unsafe {
        *refund_dest.borrow_mut_lamports_unchecked() = refund_lamports
            .checked_add(session_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *session_pda.borrow_mut_lamports_unchecked() = 0;
    }

    Ok(())
}
