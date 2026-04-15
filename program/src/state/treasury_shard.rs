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
