//! Processor modules for handling program instructions.
//!
//! Organized by domain:
//! - `wallet` — wallet creation
//! - `authority` — authority management and ownership transfer
//! - `execute` — immediate execution, deferred execution, authorization
//! - `session` — session creation and revocation
//! - `protocol` — protocol fee management (initialize, update, register, withdraw, shards)

pub mod authority;
pub mod execute;
pub mod protocol;
pub mod session;
pub mod wallet;
