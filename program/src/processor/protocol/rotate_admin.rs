//! Two-step rotation of the protocol admin.
//!
//! v1 had no rotation at all. `update_protocol` could write fees, the enabled
//! flag and the treasury, but not `admin` — so a lost key ended the protocol's
//! ability to govern itself and a compromised one could never be evicted. That
//! is half of C-1; the other half was the freeze switch that key controlled.
//!
//! Rotation is two-step on purpose. A one-step transfer to a mistyped address,
//! or to a key nobody actually holds, would hand governance to nobody with no
//! way back — the same permanence that made the missing rotation so costly.
//! Requiring the incoming admin to accept proves the key exists and is
//! controlled before it takes effect.
//!
//! Proposing the all-zero key cancels a pending rotation.

use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use crate::{error::ProtocolError, state::protocol_config::ProtocolConfig};

/// Read the config, verifying it is the canonical PDA, program-owned and valid.
///
/// The address check matters: every caller below makes an authorisation
/// decision from `config.admin`, so a substituted account is a substituted
/// authorisation.
fn load_config(program_id: &Pubkey, config_pda: &AccountInfo) -> Result<(), ProgramError> {
    let (expected, _) =
        pinocchio::pubkey::find_program_address(&[crate::seeds::PROTOCOL_CONFIG], program_id);
    if config_pda.key() != &expected {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }
    if config_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if !config_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    let data = config_pda.try_borrow_data()?;
    ProtocolConfig::check(&data).map_err(|_| ProtocolError::InvalidProtocolAdmin)?;
    Ok(())
}

/// Processes `ProposeProtocolAdmin`.
///
/// # Accounts:
/// 1. `[signer]` Current admin
/// 2. `[writable]` ProtocolConfig PDA
///
/// # Instruction Data:
/// `[new_admin(32)]` — all zero cancels a pending rotation.
pub fn process_propose(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_admin: &[u8; 32] = instruction_data[0..32].try_into().unwrap();

    let admin = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    load_config(program_id, config_pda)?;

    let mut data = config_pda.try_borrow_mut_data()?;
    let config = unsafe { &mut *(data.as_mut_ptr() as *mut ProtocolConfig) };
    if admin.key() != &config.admin {
        return Err(ProtocolError::InvalidProtocolAdmin.into());
    }

    config.pending_admin = Pubkey::from(*new_admin);
    Ok(())
}

/// Processes `AcceptProtocolAdmin`.
///
/// # Accounts:
/// 1. `[signer]` Pending admin
/// 2. `[writable]` ProtocolConfig PDA
pub fn process_accept(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let new_admin = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let config_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;

    if !new_admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    load_config(program_id, config_pda)?;

    let mut data = config_pda.try_borrow_mut_data()?;
    let config = unsafe { &mut *(data.as_mut_ptr() as *mut ProtocolConfig) };

    // The zero key means "no rotation pending"; it is also what an
    // uninitialised field reads as, so it must never be acceptable.
    if config.pending_admin == Pubkey::default() || new_admin.key() != &config.pending_admin {
        return Err(ProtocolError::NoPendingAdmin.into());
    }

    config.admin = config.pending_admin;
    config.pending_admin = Pubkey::default();
    Ok(())
}
