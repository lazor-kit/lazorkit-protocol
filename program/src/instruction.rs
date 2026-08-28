use shank::ShankInstruction;

/// Shank IDL facade enum describing all program instructions and their required accounts.
/// This is used only for IDL generation and does not affect runtime behavior.
#[derive(ShankInstruction)]
pub enum ProgramIx {
    /// Create a new wallet
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, writable, name = "wallet", desc = "Wallet PDA")]
    #[account(2, writable, name = "vault", desc = "Vault PDA")]
    #[account(3, writable, name = "authority", desc = "Initial owner authority PDA")]
    #[account(4, name = "system_program", desc = "System Program")]
    #[account(5, name = "rent_sysvar", desc = "Rent Sysvar")]
    CreateWallet {
        user_seed: Vec<u8>,
        auth_type: u8,
        auth_pubkey: [u8; 33],
        credential_hash: [u8; 32],
    },

    /// Add a new authority to the wallet
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, writable, name = "wallet", desc = "Wallet PDA (owner_count)")]
    #[account(
        2,
        writable,
        name = "admin_authority",
        desc = "Admin authority PDA authorizing this action (counter incremented)"
    )]
    #[account(
        3,
        writable,
        name = "new_authority",
        desc = "New authority PDA to be created"
    )]
    #[account(4, name = "system_program", desc = "System Program")]
    #[account(5, name = "rent_sysvar", desc = "Rent Sysvar")]
    #[account(
        6,
        signer,
        optional,
        name = "authorizer_signer",
        desc = "Optional signer for Ed25519 authentication"
    )]
    AddAuthority {
        new_type: u8,
        new_pubkey: [u8; 33],
        new_hash: [u8; 32],
        new_role: u8,
    },

    /// Remove an authority from the wallet
    #[account(0, signer, writable, name = "payer", desc = "Transaction payer")]
    #[account(1, writable, name = "wallet", desc = "Wallet PDA (owner_count)")]
    #[account(
        2,
        writable,
        name = "admin_authority",
        desc = "Admin authority PDA authorizing this action (counter incremented)"
    )]
    #[account(
        3,
        writable,
        name = "target_authority",
        desc = "Authority PDA to be removed"
    )]
    #[account(
        4,
        writable,
        name = "refund_destination",
        desc = "Account to receive rent refund"
    )]
    #[account(
        5,
        optional,
        name = "auth_extra",
        desc = "Ed25519: signer keypair | Secp256r1: sysvar_instructions"
    )]
    RemoveAuthority,

    /// Transfer ownership (atomic swap of Owner role)
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(
        2,
        writable,
        name = "current_owner_authority",
        desc = "Current owner authority PDA"
    )]
    #[account(
        3,
        writable,
        name = "new_owner_authority",
        desc = "New owner authority PDA to be created"
    )]
    #[account(
        4,
        writable,
        name = "refund_destination",
        desc = "Account to receive rent refund from closed current owner"
    )]
    #[account(5, name = "system_program", desc = "System Program")]
    #[account(6, name = "rent_sysvar", desc = "Rent Sysvar")]
    #[account(
        7,
        signer,
        optional,
        name = "authorizer_signer",
        desc = "Optional signer for Ed25519 authentication"
    )]
    TransferOwnership {
        new_type: u8,
        new_pubkey: [u8; 33],
        new_hash: [u8; 32],
    },

    /// Execute transactions
    #[account(0, signer, writable, name = "payer", desc = "Transaction payer")]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(
        2,
        writable,
        name = "authority",
        desc = "Authority or Session PDA authorizing execution (counter incremented)"
    )]
    #[account(
        3,
        writable,
        name = "vault",
        desc = "Vault PDA (signer for CPI, lamports debited)"
    )]
    #[account(
        4,
        optional,
        name = "sysvar_instructions",
        desc = "Sysvar Instructions (required for Secp256r1)"
    )]
    Execute { instructions: Vec<u8> },

    /// Create a new session key
    #[account(
        0,
        signer,
        name = "payer",
        desc = "Transaction payer and rent contributor"
    )]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(
        2,
        writable,
        name = "admin_authority",
        desc = "Admin/Owner authority PDA authorizing logic (counter incremented)"
    )]
    #[account(3, writable, name = "session", desc = "New session PDA to be created")]
    #[account(4, name = "system_program", desc = "System Program")]
    #[account(5, name = "rent_sysvar", desc = "Rent Sysvar")]
    #[account(
        6,
        signer,
        optional,
        name = "authorizer_signer",
        desc = "Optional signer for Ed25519 authentication"
    )]
    CreateSession {
        session_key: [u8; 32],
        expires_at: i64,
    },

    /// Authorize deferred execution (TX1 of 2-transaction flow)
    ///
    /// Verifies Secp256r1 signature over instruction/account hashes, then creates
    /// a DeferredExec PDA storing the authorization for later execution.
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(
        2,
        writable,
        name = "authority",
        desc = "Authority PDA (counter incremented)"
    )]
    #[account(
        3,
        writable,
        name = "deferred_exec",
        desc = "DeferredExec PDA to be created"
    )]
    #[account(4, name = "system_program", desc = "System Program")]
    #[account(5, name = "rent_sysvar", desc = "Rent Sysvar")]
    #[account(
        6,
        name = "sysvar_instructions",
        desc = "Sysvar Instructions (for Secp256r1 precompile introspection)"
    )]
    Authorize {
        instructions_hash: [u8; 32],
        accounts_hash: [u8; 32],
        expiry_offset: u16,
    },

    /// Execute a previously authorized deferred execution (TX2 of 2-transaction flow)
    ///
    /// Verifies compact instructions against stored hashes, executes via CPI
    /// with vault PDA signing, then closes the DeferredExec account.
    #[account(0, signer, writable, name = "payer", desc = "Transaction payer")]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(2, writable, name = "vault", desc = "Vault PDA (signer for CPI)")]
    #[account(
        3,
        writable,
        name = "deferred_exec",
        desc = "DeferredExec PDA (read and closed)"
    )]
    #[account(
        4,
        writable,
        name = "refund_destination",
        desc = "Account to receive rent refund from closed DeferredExec"
    )]
    ExecuteDeferred { instructions: Vec<u8> },

    /// Reclaim an expired DeferredExec account and refund rent
    ///
    /// Only the original payer can reclaim, and only after the authorization has expired.
    #[account(
        0,
        signer,
        name = "payer",
        desc = "Original payer (must match stored payer)"
    )]
    #[account(
        1,
        writable,
        name = "deferred_exec",
        desc = "Expired DeferredExec PDA to close"
    )]
    #[account(
        2,
        writable,
        name = "refund_destination",
        desc = "Account to receive rent refund"
    )]
    ReclaimDeferred,

    /// Revoke a session key early (before expiry)
    ///
    /// Only Owner or Admin can revoke. Closes the session account and refunds rent.
    #[account(0, signer, writable, name = "payer", desc = "Transaction payer")]
    #[account(1, name = "wallet", desc = "Wallet PDA")]
    #[account(
        2,
        writable,
        name = "admin_authority",
        desc = "Owner/Admin authority PDA (counter incremented for Secp256r1)"
    )]
    #[account(3, writable, name = "session", desc = "Session PDA to revoke")]
    #[account(
        4,
        writable,
        name = "refund_destination",
        desc = "Account to receive rent refund"
    )]
    #[account(
        5,
        optional,
        name = "auth_extra",
        desc = "Ed25519: signer keypair | Secp256r1: sysvar_instructions"
    )]
    RevokeSession,

    /// Initialize the protocol fee configuration (one-time setup)
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, writable, name = "protocol_config", desc = "ProtocolConfig PDA")]
    #[account(2, name = "system_program", desc = "System Program")]
    #[account(3, name = "rent_sysvar", desc = "Rent Sysvar")]
    InitializeProtocol {
        admin: [u8; 32],
        treasury: [u8; 32],
        creation_fee: u64,
        execution_fee: u64,
        num_shards: u8,
    },

    /// Update protocol fee configuration
    #[account(0, signer, name = "admin", desc = "Protocol admin")]
    #[account(1, writable, name = "protocol_config", desc = "ProtocolConfig PDA")]
    UpdateProtocol {
        creation_fee: u64,
        execution_fee: u64,
        enabled: u8,
        new_treasury: [u8; 32],
    },

    /// Register a payer for fee-stats tracking. Permissionless: the payer
    /// signer is the registration target. Fee-paying instructions require
    /// the canonical FeeRecord PDA; this instruction lets clients create it
    /// before their first fee-paying transaction.
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor; the FeeRecord is keyed by this pubkey"
    )]
    #[account(
        1,
        writable,
        name = "fee_record",
        desc = "FeeRecord PDA derived from [\"fee_record\", payer]"
    )]
    #[account(2, name = "system_program", desc = "System Program")]
    #[account(3, name = "rent_sysvar", desc = "Rent Sysvar")]
    RegisterPayer,

    /// Withdraw accumulated fees from a treasury shard
    #[account(0, signer, name = "admin", desc = "Protocol admin")]
    #[account(1, name = "protocol_config", desc = "ProtocolConfig PDA")]
    #[account(2, writable, name = "treasury_shard", desc = "TreasuryShard PDA")]
    #[account(3, writable, name = "treasury", desc = "Treasury destination")]
    #[account(4, name = "rent_sysvar", desc = "Rent Sysvar")]
    WithdrawTreasury,

    /// Initialize a treasury shard
    #[account(
        0,
        signer,
        writable,
        name = "payer",
        desc = "Payer and rent contributor"
    )]
    #[account(1, name = "protocol_config", desc = "ProtocolConfig PDA")]
    #[account(2, signer, name = "admin", desc = "Protocol admin")]
    #[account(3, writable, name = "treasury_shard", desc = "TreasuryShard PDA")]
    #[account(4, name = "system_program", desc = "System Program")]
    #[account(5, name = "rent_sysvar", desc = "Rent Sysvar")]
    InitializeTreasuryShard { shard_id: u8 },
}

// `ProgramIx` above is the only instruction enum. A second hand-written
// `LazorKitInstruction` used to sit here, duplicating every variant with its
// own account comments and consumed by nothing — not the dispatcher, which
// matches raw discriminator bytes in `entrypoint.rs`, and not the IDL, which
// shank derives from `ProgramIx`. It had already drifted: it described none of
// the v2 account or payload changes. Removed rather than updated, because the
// version that gets updated is the one something reads.
