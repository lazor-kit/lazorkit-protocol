use pinocchio::program_error::ProgramError;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum AuthError {
    InvalidAuthorityPayload = 3001,
    PermissionDenied = 3002,
    InvalidInstruction = 3003,
    InvalidPubkey = 3004,
    InvalidMessageHash = 3005,
    SignatureReused = 3006,
    InvalidSignatureAge = 3007,
    InvalidSessionDuration = 3008,
    SessionExpired = 3009,
    AuthorityDoesNotSupportSession = 3010,
    InvalidAuthenticationKind = 3011,
    InvalidMessage = 3012,
    SelfReentrancyNotAllowed = 3013,
    DeferredAuthorizationExpired = 3014,
    DeferredHashMismatch = 3015,
    InvalidExpiryWindow = 3016,
    UnauthorizedReclaim = 3017,
    DeferredAuthorizationNotExpired = 3018,
    InvalidSessionAccount = 3019,
    // Session action errors
    ActionBufferInvalid = 3020,
    ActionProgramNotWhitelisted = 3021,
    ActionProgramBlacklisted = 3022,
    ActionSolMaxPerTxExceeded = 3023,
    ActionSolLimitExceeded = 3024,
    ActionSolRecurringLimitExceeded = 3025,
    ActionTokenLimitExceeded = 3026,
    ActionTokenRecurringLimitExceeded = 3027,
    ActionWhitelistBlacklistConflict = 3028,
    ActionTokenMaxPerTxExceeded = 3029,
    // Session vault + token invariants (defense against System::Assign / SetAuthority escapes)
    SessionVaultOwnerChanged = 3030,
    SessionVaultDataLenChanged = 3031,
    SessionTokenAuthorityChanged = 3032,
    // Rank + policy (authority-level spending limits)
    /// A Delegate authority was created without a policy. Rank says what an
    /// authority may manage; the policy says what it may spend. A Delegate
    /// manages nothing, so without a policy it would be an unbounded spender
    /// wearing a restricted name — which is exactly what H-2 was.
    DelegateRequiresPolicy = 3033,
    /// An authority that carries a policy tried to create another authority.
    /// Comparing two policies to prove the grant is no broader than the
    /// granter's is hard; refusing the grant sidesteps it.
    PolicyBearingAuthorityCannotDelegate = 3034,
}

impl From<AuthError> for ProgramError {
    fn from(e: AuthError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum ProtocolError {
    ProtocolAlreadyInitialized = 4001,
    InvalidProtocolAdmin = 4002,
    ProtocolDisabled = 4003,
    InvalidIntegratorRecord = 4004,
    InsufficientFeeBalance = 4005,
    IntegratorAlreadyRegistered = 4006,
    InvalidTreasury = 4007,
    // Strict-fee enforcement errors (entrypoint::try_collect_fee).
    // The commercial binary requires every fee-eligible instruction
    // (disc 0/4/7) to carry a valid `[ProtocolConfig, FeeRecord,
    // TreasuryShard, SystemProgram]` suffix and to result in a
    // successful payer→shard transfer. Any deviation returns one
    // of the codes below; there is no silent-skip path.
    /// Caller passed fewer than 5 accounts, or the trailing
    /// `SystemProgram` sentinel is missing.
    FeeAccountsRequired = 4008,
    /// `ProtocolConfig` PDA does not exist or has the wrong account
    /// discriminator. Admin must call `initialize_protocol` first.
    ProtocolNotInitialized = 4009,
    /// `TreasuryShard` PDA owner ≠ program or wrong discriminator.
    /// Admin must call `initialize_treasury_shard` for the picked shard.
    InvalidTreasuryShard = 4010,
    /// `FeeRecord` PDA address does not match the canonical seed for
    /// the payer, or the account is owned by a foreign program.
    InvalidFeeRecord = 4011,
    /// `ProtocolConfig.creation_fee` (or `execution_fee`) is `0` —
    /// admin must update via `update_protocol` to a non-zero value.
    /// Strict mode rejects zero-fee config to prevent silent
    /// degradation to the pre-strict opt-in behaviour.
    FeeNotConfigured = 4012,
    /// An account carries the right discriminator but a `version` byte this
    /// binary does not implement. Distinct from `InvalidAccountData` so an
    /// operator can tell "wrong account" from "account written by a different
    /// build" — the latter means a deploy or a migration went wrong.
    AccountVersionMismatch = 4013,
    /// A fee above `MAX_PROTOCOL_FEE_LAMPORTS` was written to the config. An
    /// unbounded fee is a freeze in disguise, so the ceiling is enforced at
    /// write time rather than left to the admin's discretion.
    FeeExceedsMaximum = 4014,
    /// `initialize_protocol` was called by something other than the init
    /// authority compiled into this binary. The protocol config is the root of
    /// the fee system and has no prior on-chain trust anchor, so the anchor is
    /// the binary itself.
    UnauthorizedInitializer = 4015,
    /// `accept_protocol_admin` was called by an account that is not the pending
    /// admin, or no rotation is pending.
    NoPendingAdmin = 4016,
    /// The binary is executing at an address other than the one compiled into
    /// it. Every PDA this program derives uses its own id as the program id, so
    /// a copy deployed elsewhere derives a disjoint address space — it cannot
    /// touch real accounts, but it can mint look-alike ones at addresses a
    /// client that trusts the wrong id would resolve.
    WrongProgramAddress = 4017,
}

impl From<ProtocolError> for ProgramError {
    fn from(e: ProtocolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
