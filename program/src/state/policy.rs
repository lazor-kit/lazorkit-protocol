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
//!   - a Session is 80 bytes plus its actions (layout revision 1)
//!   - an Ed25519 Authority is *exactly* 80 bytes (revision 1)
//!   - a Secp256r1 Authority is 145 (revision 1)
//!
//! (From revision 2 a session and an authority also record their rent payer,
//! 32 bytes between the fixed part and the policy, so each offset depends on
//! the revision as well: see `state::rent_payer`.)
//!
//! So `session::has_actions`, which is `len > 80`, already returns `true` for
//! every Secp256r1 authority — harmless today only because it is called solely
//! inside the session branch. Pass an authority with the session's 80 and the
//! engine reads its stored pubkey and rpIdHash as an action buffer: it parses
//! as garbage, or worse, as a plausible action whose limits nobody chose.
//!
//! [`PolicyLocation`] can only be produced by [`PolicyLocation::of`], which
//! derives the offset from the account's own discriminator, layout revision
//! and, for authorities, its `authority_type`. There is no constructor that
//! takes a number, so no call site can supply the wrong one.

use crate::state::{
    authority::AuthorityAccountHeader, rent_payer::RENT_PAYER_LEN, session::SESSION_HEADER_SIZE,
    AccountDiscriminator,
};

/// Byte offset of a session's `version` field.
const SESSION_VERSION_OFFSET: usize = 2;
/// Byte offset of an authority's `version` field.
const AUTHORITY_VERSION_OFFSET: usize = 4;

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
    /// Returns `None` for account types that cannot carry a policy, for a
    /// layout revision this binary does not know, and for malformed data. Note
    /// this says where the buffer *would* start, not that one is present — use
    /// [`Self::is_present`] for that.
    ///
    /// The offset depends on the layout revision as well as the type: from
    /// revision 2 an authority or a session records its rent payer between its
    /// fixed part and its policy (see `state::rent_payer`). A `None` here must
    /// never be read as "no policy" for an account the caller has not also
    /// passed through its type's `check`, which refuses an unknown revision.
    #[inline]
    pub fn of(account_data: &[u8]) -> Option<Self> {
        let disc = *account_data.first()?;

        if disc == AccountDiscriminator::Session as u8 {
            let version = *account_data.get(SESSION_VERSION_OFFSET)?;
            return session_policy_offset(version).map(Self);
        }

        if disc == AccountDiscriminator::Authority as u8 {
            // The key material's length depends on the authority type, which
            // lives in the header this offset is being computed for.
            let auth_type = *account_data.get(1)?;
            let version = *account_data.get(AUTHORITY_VERSION_OFFSET)?;
            return authority_policy_offset(auth_type, version).map(Self);
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

/// Where an authority's key material ends, by authority type: the whole
/// account in layout revision 1 when it carries no policy.
#[inline]
pub fn authority_key_end(authority_type: u8) -> Option<usize> {
    match authority_type {
        0 => Some(AUTHORITY_ED25519_FIXED_LEN),
        1 => Some(AUTHORITY_SECP256R1_FIXED_LEN),
        _ => None,
    }
}

/// Where an authority's policy starts: after its key material in revision 1,
/// after its key material and its rent payer from revision 2.
#[inline]
pub fn authority_policy_offset(authority_type: u8, version: u8) -> Option<usize> {
    let key_end = authority_key_end(authority_type)?;
    match version {
        1 => Some(key_end),
        2 => Some(key_end + RENT_PAYER_LEN),
        _ => None,
    }
}

/// Where a session's actions start: after its 80-byte header in revision 1,
/// after the header and its rent payer from revision 2.
#[inline]
pub fn session_policy_offset(version: u8) -> Option<usize> {
    match version {
        1 => Some(SESSION_HEADER_SIZE),
        2 => Some(SESSION_HEADER_SIZE + RENT_PAYER_LEN),
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

    /// An account of `disc` at layout revision `version`, `len` bytes long.
    fn account(disc: AccountDiscriminator, auth_type: u8, version: u8, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        data[0] = disc as u8;
        if disc == AccountDiscriminator::Authority {
            data[1] = auth_type;
            data[AUTHORITY_VERSION_OFFSET] = version;
        } else if len > SESSION_VERSION_OFFSET {
            data[SESSION_VERSION_OFFSET] = version;
        }
        data
    }

    #[test]
    fn session_policy_starts_after_the_header_and_from_revision_2_the_payer() {
        let v1 = account(AccountDiscriminator::Session, 0, 1, 200);
        assert_eq!(
            PolicyLocation::of(&v1).map(|l| l.offset()),
            Some(SESSION_HEADER_SIZE)
        );
        let v2 = account(AccountDiscriminator::Session, 0, 2, 200);
        assert_eq!(PolicyLocation::of(&v2).map(|l| l.offset()), Some(112));
    }

    #[test]
    fn authority_policy_offset_follows_the_key_material_and_from_revision_2_the_payer() {
        for (auth_type, key_end) in [
            (0, AUTHORITY_ED25519_FIXED_LEN),
            (1, AUTHORITY_SECP256R1_FIXED_LEN),
        ] {
            let v1 = account(AccountDiscriminator::Authority, auth_type, 1, 300);
            assert_eq!(PolicyLocation::of(&v1).map(|l| l.offset()), Some(key_end));
            let v2 = account(AccountDiscriminator::Authority, auth_type, 2, 300);
            assert_eq!(
                PolicyLocation::of(&v2).map(|l| l.offset()),
                Some(key_end + RENT_PAYER_LEN)
            );
        }
    }

    /// A revision this binary does not know resolves to nothing rather than to
    /// a guess. The type's `check` refuses it before any policy is read.
    #[test]
    fn an_unknown_revision_is_unresolvable() {
        for version in [0u8, 3, u8::MAX] {
            let s = account(AccountDiscriminator::Session, 0, version, 200);
            assert_eq!(PolicyLocation::of(&s), None, "session revision {version}");
            let a = account(AccountDiscriminator::Authority, 0, version, 200);
            assert_eq!(PolicyLocation::of(&a), None, "authority revision {version}");
        }
    }

    /// The trap this type exists to prevent: an Ed25519 authority is exactly
    /// the size of a session header, and a Secp256r1 one is larger, so a bare
    /// `usize` of 80 would make both look like sessions carrying a policy.
    #[test]
    fn an_authority_is_never_measured_with_the_session_header() {
        for (version, len) in [(1, 145), (2, 177)] {
            let secp = account(AccountDiscriminator::Authority, 1, version, len);
            let loc = PolicyLocation::of(&secp).expect("resolvable");
            assert_ne!(loc.offset(), SESSION_HEADER_SIZE);
            assert!(
                !loc.is_present(&secp),
                "a {len}-byte Secp256r1 authority carries no policy, though it is \
                 longer than a session header"
            );
        }
        // Revision 2: an Ed25519 authority without a policy is 112 bytes, its
        // payer at 80..112, which must not read as a policy either.
        let ed = account(AccountDiscriminator::Authority, 0, 2, 112);
        let loc = PolicyLocation::of(&ed).expect("resolvable");
        assert!(!loc.is_present(&ed));
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
            let data = account(disc, 0, 1, 200);
            assert_eq!(PolicyLocation::of(&data), None, "{disc:?}");
        }
    }

    #[test]
    fn unknown_authority_type_is_unresolvable() {
        let data = account(AccountDiscriminator::Authority, 9, 1, 200);
        assert_eq!(PolicyLocation::of(&data), None);
    }

    #[test]
    fn empty_data_is_unresolvable() {
        assert_eq!(PolicyLocation::of(&[]), None);
    }

    #[test]
    fn slice_and_abs_agree() {
        for version in [1u8, 2] {
            let start = session_policy_offset(version).unwrap();
            let mut data = account(AccountDiscriminator::Session, 0, version, start + 4);
            data[start] = 0xAB;
            let loc = PolicyLocation::of(&data).unwrap();
            assert!(loc.is_present(&data));
            assert_eq!(loc.slice(&data)[0], 0xAB);
            assert_eq!(data[loc.abs(0)], 0xAB);
        }
    }
}
