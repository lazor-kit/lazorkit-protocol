//! Processor modules for handling program instructions.
//!
//! Each module corresponds to a specific instruction in the IDL.

pub mod authorize;
pub mod create_session;
pub mod create_wallet;
pub mod execute;
pub mod execute_deferred;
pub mod initialize_protocol;
pub mod initialize_treasury_shard;
pub mod manage_authority;
pub mod reclaim_deferred;
pub mod register_integrator;
pub mod revoke_session;
pub mod transfer_ownership;
pub mod update_protocol;
pub mod withdraw_treasury;
