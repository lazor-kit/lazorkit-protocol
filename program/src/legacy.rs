//! v1 account shapes, for the one path in v2 that must read them: migration.
//!
//! v2 renamed every PDA seed (`lk2:` prefix) and renumbered every account
//! discriminator (`0x2N`) precisely so a v1 account can never be mistaken for a
//! v2 one. That separation is a security property and nothing outside this
//! module is allowed to weaken it.
//!
//! `MigrateWallet` is the sanctioned exception. It runs at the same program id
//! as the retired v1 binary, so it — and only it — can still sign for a v1 vault
//! and move what a user left there onto v2. To do that it needs the old seeds
//! and the old discriminators, kept here, deliberately apart from
//! [`crate::seeds`] and [`crate::state`], so the two address spaces never share
//! a constant by accident.
//!
//! The authority header is byte-compatible between v1 and v2: the only header
//! field v2 changed was four padding bytes at offset 12, which v1 always wrote
//! as zero. So a v1 authority read through v2's `AuthorityAccountHeader` reports
//! `policy_len == 0` and its `wallet` and key material sit at the same offsets.
//! Migration relies on that; the only thing that must not be reused is the
//! discriminator check, which is why this module carries the old values.

/// v1 PDA seeds — bare, un-prefixed. The v2 equivalents in [`crate::seeds`] all
/// carry the `lk2:` prefix.
pub mod seeds {
    pub const WALLET: &[u8] = b"wallet";
    pub const VAULT: &[u8] = b"vault";
    pub const AUTHORITY: &[u8] = b"authority";
}

/// v1 account discriminators. v2 uses `0x2N` for the same types.
pub mod discriminator {
    pub const WALLET: u8 = 1;
    pub const AUTHORITY: u8 = 2;
}
