//! PDA seed prefixes, namespaced by protocol major version.
//!
//! # Why every seed carries a version prefix
//!
//! The program keeps its address across major versions, so PDA addresses are a
//! pure function of the seeds. Without a namespace, a v2 binary deployed over a
//! v1 program inherits v1's accounts at exactly the addresses it would want to
//! use for its own.
//!
//! For accounts keyed by random material — `[WALLET, user_seed]` with a 32-byte
//! random seed — that collision is theoretical. For the singletons it is
//! certain: v1's `["protocol_config"]` and `["treasury_shard", id]` resolve to
//! one address each. A v2 binary would find those occupied by v1 data it rejects on
//! discriminator, and `initialize_protocol` cannot recreate them because
//! `check_zero_data` requires `data_len() == 0`, which an existing 88-byte
//! account can never satisfy. The protocol would be permanently
//! un-initialisable, with no instruction able to repair it.
//!
//! Prefixing every seed with the protocol major version makes each version's
//! address space disjoint from every other by construction. The rule for future
//! upgrades is therefore mechanical rather than a judgement call: **a change
//! that alters the meaning of any account's bytes bumps
//! [`crate::state::PROTOCOL_VERSION`] and the prefix along with it.** See
//! `docs/upgrade-procedure.md`.
//!
//! # Constraints
//!
//! A single seed is capped at 32 bytes by the runtime. The longest prefix here
//! is `lk2:protocol_config` at 19 bytes, and the prefixes are standalone seeds
//! rather than concatenated onto variable material, so there is no interaction
//! with the caller's own seed lengths.

/// Wallet PDA — `[WALLET, user_seed(32)]`.
pub const WALLET: &[u8] = b"lk2:wallet";

/// Vault PDA — `[VAULT, wallet]`. Holds the wallet's assets; system-owned, and
/// signed for by this program during `Execute`.
pub const VAULT: &[u8] = b"lk2:vault";

/// Authority PDA — `[AUTHORITY, wallet, id_seed]`, where `id_seed` is the
/// Ed25519 pubkey or the Secp256r1 credential-id hash.
pub const AUTHORITY: &[u8] = b"lk2:authority";

/// Session PDA — `[SESSION, wallet, session_key]`.
pub const SESSION: &[u8] = b"lk2:session";

/// Deferred execution PDA — `[DEFERRED, wallet, authority, counter(4)]`.
pub const DEFERRED: &[u8] = b"lk2:deferred";

/// Global protocol configuration — `[PROTOCOL_CONFIG]`. Singleton.
pub const PROTOCOL_CONFIG: &[u8] = b"lk2:protocol_config";

/// Treasury shard — `[TREASURY_SHARD, shard_id(1)]`. Singleton per shard id.
pub const TREASURY_SHARD: &[u8] = b"lk2:treasury_shard";

/// Per-payer fee record — `[FEE_RECORD, payer]`.
pub const FEE_RECORD: &[u8] = b"lk2:fee_record";

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[(&str, &[u8])] = &[
        ("WALLET", WALLET),
        ("VAULT", VAULT),
        ("AUTHORITY", AUTHORITY),
        ("SESSION", SESSION),
        ("DEFERRED", DEFERRED),
        ("PROTOCOL_CONFIG", PROTOCOL_CONFIG),
        ("TREASURY_SHARD", TREASURY_SHARD),
        ("FEE_RECORD", FEE_RECORD),
    ];

    /// The runtime rejects any single seed longer than 32 bytes.
    #[test]
    fn every_seed_fits_the_runtime_limit() {
        for (name, seed) in ALL {
            assert!(
                seed.len() <= 32,
                "{name} is {} bytes, over the 32-byte seed limit",
                seed.len()
            );
        }
    }

    /// The namespace is the whole point; a prefix-less seed would collide with v1.
    #[test]
    fn every_seed_carries_the_version_namespace() {
        let expected = format!("lk{}:", crate::state::PROTOCOL_VERSION);
        for (name, seed) in ALL {
            let s = core::str::from_utf8(seed).expect("seeds are ascii");
            assert!(
                s.starts_with(&expected),
                "{name} = {s:?} is missing the {expected:?} namespace"
            );
        }
    }

    /// Two account types sharing a prefix would derive colliding addresses
    /// whenever their remaining seeds happen to match.
    #[test]
    fn seeds_are_distinct() {
        for (i, (name_a, a)) in ALL.iter().enumerate() {
            for (name_b, b) in ALL.iter().skip(i + 1) {
                assert_ne!(a, b, "{name_a} and {name_b} share a seed");
            }
        }
    }
}
