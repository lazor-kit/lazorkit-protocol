use no_padding::NoPadding;
use pinocchio::pubkey::Pubkey;

/// Global protocol configuration account.
///
/// Stores fee amounts, admin key, treasury, and shard count.
/// Read-only during fee collection; writable only via UpdateProtocol.
///
/// PDA seeds: `["protocol_config"]`
#[repr(C, align(8))]
#[derive(NoPadding, Debug, Clone, Copy)]
pub struct ProtocolConfig {
    /// Account discriminator (must be `5` for ProtocolConfig).
    pub discriminator: u8,
    /// Account version.
    pub version: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Whether fee collection is enabled (0 = disabled, 1 = enabled).
    pub enabled: u8,
    /// Number of treasury shards (e.g. 16 or 32).
    pub num_shards: u8,
    /// Padding for 8-byte alignment.
    pub _padding: [u8; 3],
    /// Admin pubkey — can update config, register payers, withdraw.
    pub admin: Pubkey,
    /// Treasury destination for WithdrawTreasury (admin's wallet).
    pub treasury: Pubkey,
    /// Fee in lamports charged on CreateWallet.
    pub creation_fee: u64,
    /// Fee in lamports charged on Execute / ExecuteDeferred.
    pub execution_fee: u64,
}
