//! Who paid an account's rent, and the one place its rent may go back to.
//!
//! Every account this program creates is funded by the instruction's `payer`,
//! which on a sponsored flow is a relayer rather than the wallet's owner. The
//! instructions that close an account — `RevokeSession`, `CloseExpiredSession`,
//! `RemoveAuthority`, `TransferOwnership` (for the Owner it replaces) — used to
//! send the rent to a destination the caller chose. The rent belongs to whoever
//! paid it, so from layout revision 2 an authority and a session record that
//! account, and those instructions refuse any other destination with
//! `RefundDestinationMismatch` (3039).
//!
//! The payer is stored right after the account's fixed part — a session's
//! 80-byte header, an authority's key material — and before its policy, so no
//! field an existing reader uses moves:
//!
//! ```text
//!   session   [header 0..80][payer 80..112][actions 112..]
//!   authority [header 0..48][key material ..80 | ..145][payer +32][policy ..]
//! ```
//!
//! `DeferredExec` recorded its payer from the start, and `ExecuteDeferred` and
//! `ReclaimDeferred` already refund only to it. A wallet, a `FeeRecord`, the
//! `ProtocolConfig` and the treasury shards are never closed.
//!
//! # Accounts written before revision 2
//!
//! A revision-1 authority or session (and a v1 one in the sunset binary)
//! records no payer, and nothing on chain says who paid. Such an account keeps
//! the old rule: the destination the closing instruction names. That is
//! deliberate:
//!
//! - **Closing must stay possible.** Revoking a session and removing an
//!   authority are how an Owner cuts off a lost key. A rule a revision-1 account
//!   cannot satisfy would make it unrevocable.
//! - **The vault is no better a guess.** It belongs to the wallet's owner, so a
//!   refund there reaches the same person as an owner-chosen destination.
//! - **It cannot repeat.** Every account created from this revision on records
//!   its payer, so a revision-1 account is closed at most once and never
//!   recreated in that shape: the set of accounts under the old rule only
//!   shrinks.

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::{
    error::AuthError,
    state::{policy::authority_key_end, session::SESSION_HEADER_SIZE, AccountDiscriminator},
};

/// Bytes a recorded rent payer takes.
pub const RENT_PAYER_LEN: usize = 32;

/// The first layout revision that records the rent payer, for authorities and
/// sessions alike.
pub const RECORDS_PAYER_FROM: u8 = 2;

/// Where a session at layout revision `version` records its rent payer, if it
/// does.
#[inline]
pub fn session_payer_offset(version: u8) -> Option<usize> {
    (version >= RECORDS_PAYER_FROM).then_some(SESSION_HEADER_SIZE)
}

/// Where an authority of `authority_type` at layout revision `version` records
/// its rent payer, if it does: right after its key material.
#[inline]
pub fn authority_payer_offset(authority_type: u8, version: u8) -> Option<usize> {
    if version < RECORDS_PAYER_FROM {
        return None;
    }
    authority_key_end(authority_type)
}

/// The rent payer `data` records: `Ok(None)` for an account written before
/// revision 2 (or a v1 one), which records none.
///
/// `data` must already have passed its type's `check` (or, for a v1 session,
/// the discriminator test in `CloseExpiredSession`): this reads the version
/// byte and the payer, nothing else. A recording account too short to hold its
/// payer is malformed and refused.
pub fn recorded_payer(data: &[u8]) -> Result<Option<Pubkey>, ProgramError> {
    let disc = *data.first().ok_or(ProgramError::InvalidAccountData)?;
    let offset = if disc == AccountDiscriminator::Session as u8 {
        session_payer_offset(*data.get(2).ok_or(ProgramError::InvalidAccountData)?)
    } else if disc == AccountDiscriminator::Authority as u8 {
        let auth_type = *data.get(1).ok_or(ProgramError::InvalidAccountData)?;
        let version = *data.get(4).ok_or(ProgramError::InvalidAccountData)?;
        if version >= RECORDS_PAYER_FROM && authority_key_end(auth_type).is_none() {
            return Err(AuthError::InvalidAuthenticationKind.into());
        }
        authority_payer_offset(auth_type, version)
    } else {
        // v1 accounts (discriminators 1..=7) and any other type: no payer.
        None
    };
    let Some(offset) = offset else {
        return Ok(None);
    };
    let bytes: [u8; RENT_PAYER_LEN] = data
        .get(offset..offset + RENT_PAYER_LEN)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Some(Pubkey::from(bytes)))
}

/// Write `payer` where an account at layout revision `version` records it.
/// Used at creation, after the fixed part has been written.
#[inline]
pub fn write_payer(data: &mut [u8], offset: usize, payer: &Pubkey) -> Result<(), ProgramError> {
    data.get_mut(offset..offset + RENT_PAYER_LEN)
        .ok_or(ProgramError::InvalidAccountData)?
        .copy_from_slice(payer.as_ref());
    Ok(())
}

/// Refuse to close `data`'s account into anything but the payer it records.
/// An account that records none (see the module note) may close anywhere.
#[inline]
pub fn check_refund_destination(
    data: &[u8],
    refund_dest: &AccountInfo,
) -> Result<(), ProgramError> {
    match recorded_payer(data)? {
        Some(payer) if refund_dest.key() != &payer => {
            Err(AuthError::RefundDestinationMismatch.into())
        },
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::policy::{
        authority_policy_offset, session_policy_offset, AUTHORITY_ED25519_FIXED_LEN,
        AUTHORITY_SECP256R1_FIXED_LEN,
    };

    const PAYER: [u8; 32] = [0x5A; 32];

    fn session(version: u8, len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0] = AccountDiscriminator::Session as u8;
        d[2] = version;
        d
    }

    fn authority(auth_type: u8, version: u8, len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0] = AccountDiscriminator::Authority as u8;
        d[1] = auth_type;
        d[4] = version;
        d
    }

    #[test]
    fn a_revision_2_session_records_its_payer_between_header_and_actions() {
        let mut d = session(2, 112 + 19);
        write_payer(&mut d, session_payer_offset(2).unwrap(), &PAYER).unwrap();
        assert_eq!(recorded_payer(&d), Ok(Some(PAYER)));
        assert_eq!(&d[80..112], &PAYER);
        // The payer ends exactly where the actions begin.
        assert_eq!(session_policy_offset(2), Some(80 + RENT_PAYER_LEN));
    }

    #[test]
    fn a_revision_2_authority_records_its_payer_after_the_key_material() {
        for (auth_type, key_end) in [
            (0u8, AUTHORITY_ED25519_FIXED_LEN),
            (1, AUTHORITY_SECP256R1_FIXED_LEN),
        ] {
            let mut d = authority(auth_type, 2, key_end + RENT_PAYER_LEN);
            let offset = authority_payer_offset(auth_type, 2).unwrap();
            assert_eq!(offset, key_end);
            write_payer(&mut d, offset, &PAYER).unwrap();
            assert_eq!(recorded_payer(&d), Ok(Some(PAYER)));
            assert_eq!(
                authority_policy_offset(auth_type, 2),
                Some(offset + RENT_PAYER_LEN)
            );
        }
    }

    #[test]
    fn revision_1_and_v1_accounts_record_no_payer() {
        assert_eq!(recorded_payer(&session(1, 80)), Ok(None));
        assert_eq!(recorded_payer(&authority(0, 1, 80)), Ok(None));
        assert_eq!(recorded_payer(&authority(1, 1, 145)), Ok(None));
        // v1's Session (3) and Authority (2) discriminators.
        for v1_disc in [2u8, 3] {
            let mut d = vec![0u8; 145];
            d[0] = v1_disc;
            d[2] = 2;
            d[4] = 2;
            assert_eq!(recorded_payer(&d), Ok(None), "v1 discriminator {v1_disc}");
        }
    }

    #[test]
    fn a_recording_account_too_short_for_its_payer_is_malformed() {
        assert_eq!(
            recorded_payer(&session(2, 100)),
            Err(ProgramError::InvalidAccountData)
        );
        assert_eq!(
            recorded_payer(&authority(0, 2, 100)),
            Err(ProgramError::InvalidAccountData)
        );
    }

    #[test]
    fn a_recording_authority_of_unknown_type_is_refused() {
        assert_eq!(
            recorded_payer(&authority(7, 2, 200)),
            Err(AuthError::InvalidAuthenticationKind.into())
        );
    }
}
