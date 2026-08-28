use no_padding::NoPadding;

/// Treasury shard account — holds accumulated protocol fees.
///
/// Multiple shards (e.g. 16) spread write contention.
/// Admin withdraws via WithdrawTreasury instruction.
///
/// PDA seeds: `["treasury_shard", shard_id(u8)]`
#[repr(C, align(8))]
#[derive(NoPadding, Debug, Clone, Copy)]
pub struct TreasuryShard {
    /// Account discriminator (must be `7` for TreasuryShard).
    pub discriminator: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Shard index.
    pub shard_id: u8,
    /// Padding for 8-byte alignment.
    pub _padding: [u8; 5],
}

impl TreasuryShard {
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
            crate::state::AccountDiscriminator::TreasuryShard,
            crate::state::version_offset::TREASURY_SHARD,
            Self::MIN_LEN,
        )
    }
}
