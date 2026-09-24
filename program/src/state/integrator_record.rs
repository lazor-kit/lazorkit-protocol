use no_padding::NoPadding;

/// Per-payer fee record tracking cumulative fees for reward distribution.
///
/// Each payer (integrator's gas relay) gets one of these.
/// Fees go to treasury shards; this record only tracks amounts.
///
/// PDA seeds: `["fee_record", payer_pubkey]`
#[repr(C, align(8))]
#[derive(NoPadding, Debug, Clone, Copy)]
pub struct FeeRecord {
    /// Account discriminator (must be `6` for FeeRecord).
    pub discriminator: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Account version.
    pub version: u8,
    /// Padding for 8-byte alignment.
    pub _padding: [u8; 5],
    /// Total fees paid by this payer (cumulative, for reward calc).
    pub total_fees_paid: u64,
    /// Total fee-eligible transactions.
    pub tx_count: u32,
    /// Total wallets created by this payer.
    pub wallet_count: u32,
    /// Slot when this payer was registered.
    pub registered_at: u64,
}

impl FeeRecord {
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
            crate::state::AccountDiscriminator::FeeRecord,
            crate::state::version_offset::FEE_RECORD,
            Self::MIN_LEN,
        )
    }
}
