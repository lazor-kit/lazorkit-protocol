use no_padding::NoPadding;
use pinocchio::pubkey::Pubkey;

/// Size of the fixed session header (excluding actions).
pub const SESSION_HEADER_SIZE: usize = 80;

#[repr(C, align(8))]
#[derive(NoPadding)]
/// Ephemeral Session Account.
///
/// Represents a temporary delegated authority with an expiration time.
/// Optional actions may follow the 80-byte header as a flat byte buffer.
///
/// `expires_at` is Unix time in seconds (`Clock::unix_timestamp`). Builds
/// before time-based expiry wrote a slot here. Read as a time, any slot a
/// cluster has reached is decades in the past, so such a session is expired:
/// `Execute` refuses it (3009) and `CloseExpiredSession` closes it.
pub struct SessionAccount {
    /// Account discriminator (must be `3` for Session).
    pub discriminator: u8, // 1
    /// Bump seed for this PDA.
    pub bump: u8, // 1
    /// Account Version.
    pub version: u8, // 1
    /// Padding for alignment.
    pub _padding: [u8; 5], // 5
    /// The wallet this session belongs to.
    pub wallet: Pubkey, // 32
    /// The ephemeral public key authorized to sign.
    pub session_key: Pubkey, // 32
    /// Unix time (seconds) after which this session is refused. A session is
    /// live while `unix_timestamp <= expires_at`.
    pub expires_at: u64, // 8
}

/// Whether a session expiring at `expires_at` is still live at `now`, both in
/// the same unit: Unix seconds for a v2 session. Live through its `expires_at`
/// second, refused from the next. `Execute` and `CloseExpiredSession` both
/// decide with this, so no second exists in which a session can both execute
/// and be closed.
#[inline]
pub fn is_live(expires_at: u64, now: u64) -> bool {
    now <= expires_at
}

/// Returns true if the session account data contains actions after the header.
#[inline]
pub fn has_actions(session_data: &[u8]) -> bool {
    session_data.len() > SESSION_HEADER_SIZE
}

/// Returns the actions buffer slice (bytes after the 80-byte header).
/// Returns empty slice if no actions.
#[inline]
pub fn actions_slice(session_data: &[u8]) -> &[u8] {
    if session_data.len() > SESSION_HEADER_SIZE {
        &session_data[SESSION_HEADER_SIZE..]
    } else {
        &[]
    }
}

impl SessionAccount {
    /// Minimum byte length for this account to be readable.
    pub const MIN_LEN: usize = core::mem::size_of::<Self>();

    /// Validate discriminator, length and layout version before trusting any
    /// field. Every read path calls this instead of comparing `data[0]` by
    /// hand, so a future version gate is one edit rather than a hunt through
    /// every processor.
    #[inline]
    pub fn check(data: &[u8]) -> Result<(), pinocchio::program_error::ProgramError> {
        crate::state::check_header(
            data,
            crate::state::AccountDiscriminator::Session,
            crate::state::version_offset::SESSION,
            Self::MIN_LEN,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// About 2026-10-04, when devnet was at slot 507,081,509.
    const NOW: u64 = 1_791_158_400;

    #[test]
    fn live_through_the_expiry_second() {
        assert!(is_live(NOW, NOW));
        assert!(is_live(NOW + 1, NOW));
        assert!(!is_live(NOW - 1, NOW));
    }

    /// A session written before time-based expiry stores a slot. Read as Unix
    /// time, any slot a cluster has reached is decades ago: such a session is
    /// expired, never live longer than it was meant to be.
    #[test]
    fn a_slot_read_as_a_time_is_long_expired() {
        // Devnet's slot on 2026-10-04, plus the longest session the old rule
        // allowed (6,480,000 slots), is in 1986 as a time (1987-01-01 is
        // 536,457,600).
        let devnet_slot_expiry: u64 = 507_081_509 + 6_480_000;
        assert!(devnet_slot_expiry < 536_457_600);
        assert!(!is_live(devnet_slot_expiry, NOW));
        // Mainnet's slots grow more slowly than devnet's.
        assert!(!is_live(500_000_000, NOW));
    }
}
