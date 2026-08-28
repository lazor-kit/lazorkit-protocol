pub mod action;
pub mod authority;
pub mod deferred;
pub mod integrator_record;
pub mod protocol_config;
pub mod session;
pub mod treasury_shard;
pub mod wallet;

use pinocchio::program_error::ProgramError;

use crate::error::ProtocolError;

/// Protocol major version.
///
/// Encoded in two places, both deliberately: the PDA seed prefix
/// (`crate::seeds`) and the high nibble of every account discriminator below.
/// Together they make each major version's account space provably disjoint from
/// every other's, which is what lets a version ship without migration code.
///
/// Bump this when a change alters the meaning of any account's bytes. See
/// `docs/upgrade-procedure.md`.
pub const PROTOCOL_VERSION: u8 = 2;

/// Discriminators for account types to ensure type safety.
///
/// The high nibble is the protocol version, the low nibble the account type. A
/// v1 account (discriminators `1..=7`) therefore fails the very first byte check
/// on every read path in this binary — the intended outcome, since v1 accounts
/// are abandoned rather than migrated.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountDiscriminator {
    /// The main Wallet account (Trust Anchor).
    Wallet = 0x21,
    /// An Authority account (Owner/Admin/Spender).
    Authority = 0x22,
    /// A Session account (Ephemeral Spender).
    Session = 0x23,
    /// A Deferred Execution authorization account.
    DeferredExec = 0x24,
    /// Global protocol configuration.
    ProtocolConfig = 0x25,
    /// Per-payer fee tracking record.
    FeeRecord = 0x26,
    /// Treasury shard for fee collection.
    TreasuryShard = 0x27,
}

/// Current account layout revision *within* [`PROTOCOL_VERSION`].
///
/// Written into every account's `version` byte at creation and — unlike in v1,
/// where the byte was written at ten sites and read at none — validated on every
/// read via [`check_header`]. A layout revision that stays address- and
/// discriminator-compatible bumps this instead of [`PROTOCOL_VERSION`].
pub const CURRENT_ACCOUNT_VERSION: u8 = 1;

/// Byte offset of the `version` field, per account type.
///
/// These differ because each struct grew its own way; `TreasuryShard` has no
/// version field at all, which is why the offset is optional.
pub mod version_offset {
    pub const WALLET: Option<usize> = Some(2);
    pub const AUTHORITY: Option<usize> = Some(4);
    pub const SESSION: Option<usize> = Some(2);
    pub const DEFERRED_EXEC: Option<usize> = Some(1);
    pub const PROTOCOL_CONFIG: Option<usize> = Some(1);
    pub const FEE_RECORD: Option<usize> = Some(2);
    pub const TREASURY_SHARD: Option<usize> = None;
}

/// Validate an account's discriminator, length and layout version in one place.
///
/// Every read path goes through this rather than checking `data[0]` by hand, so
/// that adding a version gate later is a change to one function instead of a
/// hunt through twenty-odd call sites — which is exactly the position v1 was in.
///
/// `min_len` is checked first: a truncated account cannot be trusted to have a
/// version byte at all.
#[inline]
pub fn check_header(
    data: &[u8],
    expected: AccountDiscriminator,
    version_offset: Option<usize>,
    min_len: usize,
) -> Result<(), ProgramError> {
    if data.len() < min_len {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != expected as u8 {
        return Err(ProgramError::InvalidAccountData);
    }
    if let Some(offset) = version_offset {
        if data[offset] != CURRENT_ACCOUNT_VERSION {
            return Err(ProtocolError::AccountVersionMismatch.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(disc: u8, version: u8, len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        data[0] = disc;
        if len > 2 {
            data[2] = version;
        }
        data
    }

    #[test]
    fn discriminators_encode_the_protocol_version() {
        for disc in [
            AccountDiscriminator::Wallet,
            AccountDiscriminator::Authority,
            AccountDiscriminator::Session,
            AccountDiscriminator::DeferredExec,
            AccountDiscriminator::ProtocolConfig,
            AccountDiscriminator::FeeRecord,
            AccountDiscriminator::TreasuryShard,
        ] {
            assert_eq!(
                (disc as u8) >> 4,
                PROTOCOL_VERSION,
                "{disc:?} does not carry the protocol version in its high nibble"
            );
        }
    }

    /// The whole point of renumbering: a v1 account must not read as a v2 one.
    #[test]
    fn v1_discriminators_are_rejected() {
        for v1_disc in 1u8..=7 {
            let data = header(v1_disc, CURRENT_ACCOUNT_VERSION, 8);
            assert_eq!(
                check_header(
                    &data,
                    AccountDiscriminator::Wallet,
                    version_offset::WALLET,
                    8
                ),
                Err(ProgramError::InvalidAccountData),
                "v1 discriminator {v1_disc} was not rejected"
            );
        }
    }

    #[test]
    fn accepts_a_well_formed_header() {
        let data = header(
            AccountDiscriminator::Wallet as u8,
            CURRENT_ACCOUNT_VERSION,
            8,
        );
        assert_eq!(
            check_header(
                &data,
                AccountDiscriminator::Wallet,
                version_offset::WALLET,
                8
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_future_layout_version() {
        let data = header(
            AccountDiscriminator::Wallet as u8,
            CURRENT_ACCOUNT_VERSION + 1,
            8,
        );
        assert_eq!(
            check_header(
                &data,
                AccountDiscriminator::Wallet,
                version_offset::WALLET,
                8
            ),
            Err(ProtocolError::AccountVersionMismatch.into())
        );
    }

    #[test]
    fn rejects_a_truncated_account_before_touching_the_version_byte() {
        let data = vec![AccountDiscriminator::Wallet as u8];
        assert_eq!(
            check_header(
                &data,
                AccountDiscriminator::Wallet,
                version_offset::WALLET,
                8
            ),
            Err(ProgramError::InvalidAccountData)
        );
    }

    /// TreasuryShard has no version field; the check must not read past its end.
    #[test]
    fn tolerates_an_account_type_without_a_version_field() {
        let mut data = vec![0u8; 8];
        data[0] = AccountDiscriminator::TreasuryShard as u8;
        assert_eq!(
            check_header(
                &data,
                AccountDiscriminator::TreasuryShard,
                version_offset::TREASURY_SHARD,
                8
            ),
            Ok(())
        );
    }
}
