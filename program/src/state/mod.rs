pub mod action;
pub mod authority;
pub mod deferred;
pub mod integrator_record;
pub mod protocol_config;
pub mod session;
pub mod treasury_shard;
pub mod wallet;

/// Discriminators for account types to ensure type safety.
#[repr(u8)]
pub enum AccountDiscriminator {
    /// The main Wallet account (Trust Anchor).
    Wallet = 1,
    /// An Authority account (Owner/Admin/Spender).
    Authority = 2,
    /// A Session account (Ephemeral Spender).
    Session = 3,
    /// A Deferred Execution authorization account.
    DeferredExec = 4,
    /// Global protocol configuration.
    ProtocolConfig = 5,
    /// Per-payer fee tracking record.
    FeeRecord = 6,
    /// Treasury shard for fee collection.
    TreasuryShard = 7,
}

/// Helper constant for versioning.
///
/// Current account logic version.
pub const CURRENT_ACCOUNT_VERSION: u8 = 1;
