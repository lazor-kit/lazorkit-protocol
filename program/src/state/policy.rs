//! Where an account's policy buffer lives.
//!
//! A policy is a flat action buffer appended after an account's fixed header.
//! Sessions have carried one since v1; authorities gain one here, and the same
//! evaluation engine serves both.
//!
//! # Why this is a type and not a `usize`
//!
//! The engine used to hardcode `SESSION_HEADER_SIZE` (80) at ten sites, which
//! made it silently session-only. The obvious generalisation — thread a
//! `header_len: usize` through — would be a trap, because the two account types'
//! sizes overlap in a way that fails quietly rather than loudly:
//!
//!   - a Session is 80 bytes plus its actions
//!   - an Ed25519 Authority is *exactly* 80 bytes
//!   - a Secp256r1 Authority is 145
//!
//! So `session::has_actions`, which is `len > 80`, already returns `true` for
//! every Secp256r1 authority — harmless today only because it is called solely
//! inside the session branch. Pass an authority with the session's 80 and the
//! engine reads its stored pubkey and rpIdHash as an action buffer: it parses
//! as garbage, or worse, as a plausible action whose limits nobody chose.
//!
//! [`PolicyLocation`] can only be produced by [`PolicyLocation::of`], which
//! derives the offset from the account's own discriminator and, for
//! authorities, its `authority_type`. There is no constructor that takes a
//! number, so no call site can supply the wrong one.

use crate::state::{authority::AuthorityAccountHeader, AccountDiscriminator};

/// Byte length of the fixed part of an Ed25519 authority: header + pubkey.
pub const AUTHORITY_ED25519_FIXED_LEN: usize = 48 + 32;

/// Byte length of the fixed part of a Secp256r1 authority:
/// header + credential-id hash + compressed pubkey + rpIdHash.
pub const AUTHORITY_SECP256R1_FIXED_LEN: usize = 48 + 32 + 33 + 32;

/// The offset at which an account's policy buffer begins.
///
/// Opaque by design — see the module note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyLocation(usize);

impl PolicyLocation {
    /// Resolve where `account_data`'s policy buffer would start.
    ///
    /// Returns `None` for account types that cannot carry a policy, and for
    /// malformed data. Note this says where the buffer *would* start, not that
    /// one is present — use [`Self::is_present`] for that.
    #[inline]
    pub fn of(account_data: &[u8]) -> Option<Self> {
        let disc = *account_data.first()?;

        if disc == AccountDiscriminator::Session as u8 {
            return Some(Self(crate::state::session::SESSION_HEADER_SIZE));
        }

        if disc == AccountDiscriminator::Authority as u8 {
            // The key material's length depends on the authority type, which
            // lives in the header this offset is being computed for.
            let auth_type = *account_data.get(1)?;
            return match auth_type {
                0 => Some(Self(AUTHORITY_ED25519_FIXED_LEN)),
                1 => Some(Self(AUTHORITY_SECP256R1_FIXED_LEN)),
                _ => None,
            };
        }

        None
    }

    /// Absolute offset of the policy buffer within the account's data.
    #[inline]
    pub fn offset(self) -> usize {
        self.0
    }

    /// Translate an offset relative to the policy buffer into an absolute one.
    #[inline]
    pub fn abs(self, relative: usize) -> usize {
        self.0 + relative
    }

    /// Whether `account_data` actually carries a non-empty policy.
    #[inline]
    pub fn is_present(self, account_data: &[u8]) -> bool {
        account_data.len() > self.0
    }

    /// The policy bytes, or an empty slice when there are none.
    #[inline]
    pub fn slice(self, account_data: &[u8]) -> &[u8] {
        if account_data.len() > self.0 {
            &account_data[self.0..]
        } else {
            &[]
        }
    }
}

/// Fixed length of an authority account of the given type, before any policy.
#[inline]
pub fn authority_fixed_len(authority_type: u8) -> Option<usize> {
    match authority_type {
        0 => Some(AUTHORITY_ED25519_FIXED_LEN),
        1 => Some(AUTHORITY_SECP256R1_FIXED_LEN),
        _ => None,
    }
}

/// Length of the policy an authority account carries, from its header.
#[inline]
pub fn authority_policy_len(header: &AuthorityAccountHeader) -> usize {
    header.policy_len as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::session::SESSION_HEADER_SIZE;

    fn account(disc: AccountDiscriminator, auth_type: u8, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        data[0] = disc as u8;
        if len > 1 {
            data[1] = auth_type;
        }
        data
    }

    #[test]
    fn session_policy_starts_after_the_session_header() {
        let data = account(AccountDiscriminator::Session, 0, 100);
        assert_eq!(
            PolicyLocation::of(&data).map(|l| l.offset()),
            Some(SESSION_HEADER_SIZE)
        );
    }

    #[test]
    fn authority_policy_offset_follows_the_key_material() {
        let ed = account(AccountDiscriminator::Authority, 0, 80);
        assert_eq!(
            PolicyLocation::of(&ed).map(|l| l.offset()),
            Some(AUTHORITY_ED25519_FIXED_LEN)
        );

        let secp = account(AccountDiscriminator::Authority, 1, 145);
        assert_eq!(
            PolicyLocation::of(&secp).map(|l| l.offset()),
            Some(AUTHORITY_SECP256R1_FIXED_LEN)
        );
    }

    /// The trap this type exists to prevent: an Ed25519 authority is exactly
    /// the size of a session header, and a Secp256r1 one is larger, so a bare
    /// `usize` of 80 would make both look like sessions carrying a policy.
    #[test]
    fn an_authority_is_never_measured_with_the_session_header() {
        let secp = account(AccountDiscriminator::Authority, 1, 145);
        let loc = PolicyLocation::of(&secp).expect("resolvable");
        assert_ne!(loc.offset(), SESSION_HEADER_SIZE);
        assert!(
            !loc.is_present(&secp),
            "a 145-byte Secp256r1 authority carries no policy, though it is \
             longer than a session header"
        );
    }

    #[test]
    fn other_account_types_have_no_policy() {
        for disc in [
            AccountDiscriminator::Wallet,
            AccountDiscriminator::DeferredExec,
            AccountDiscriminator::ProtocolConfig,
            AccountDiscriminator::FeeRecord,
            AccountDiscriminator::TreasuryShard,
        ] {
            let data = account(disc, 0, 200);
            assert_eq!(PolicyLocation::of(&data), None, "{disc:?}");
        }
    }

    #[test]
    fn unknown_authority_type_is_unresolvable() {
        let data = account(AccountDiscriminator::Authority, 9, 200);
        assert_eq!(PolicyLocation::of(&data), None);
    }

    #[test]
    fn empty_data_is_unresolvable() {
        assert_eq!(PolicyLocation::of(&[]), None);
    }

    #[test]
    fn slice_and_abs_agree() {
        let mut data = account(AccountDiscriminator::Session, 0, SESSION_HEADER_SIZE + 4);
        data[SESSION_HEADER_SIZE] = 0xAB;
        let loc = PolicyLocation::of(&data).unwrap();
        assert!(loc.is_present(&data));
        assert_eq!(loc.slice(&data)[0], 0xAB);
        assert_eq!(data[loc.abs(0)], 0xAB);
    }
}
