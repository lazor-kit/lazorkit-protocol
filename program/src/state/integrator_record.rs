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
