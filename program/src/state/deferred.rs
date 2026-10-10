use no_padding::NoPadding;
use pinocchio::pubkey::Pubkey;

/// Deferred Execution Authorization Account.
///
/// Created during the `Authorize` instruction (tx1) to store a pre-authorized
/// set of instructions for later execution. The `ExecuteDeferred` instruction (tx2)
/// verifies the hashes and executes the instructions, then closes this account.
///
/// This enables large payloads (e.g., Jupiter swaps) that do not fit a single
/// Secp256r1 Execute transaction. A v0 transaction is capped at 1232 bytes and
/// a passkey Execute's own overhead is about 887 of them (portal clientDataJSON,
/// no ALT), leaving about 345 bytes for inner instructions: about 305 with a
/// compute-unit limit, under 200 when Chrome pads clientDataJSON. Measured
/// 2026-09-29 with sdk-legacy 1.2.0.
#[repr(C, align(8))]
#[derive(NoPadding, Debug, Clone, Copy)]
pub struct DeferredExecAccount {
    /// Account discriminator (must be `4` for DeferredExec).
    pub discriminator: u8,
    /// Account version.
    pub version: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// [`DEFERRED_FLAG_OWNER`] when an Owner authorized this execution, else 0.
    ///
    /// Lives in what was the first padding byte, so the account stays 176
    /// bytes and every later field keeps its offset. Zero — what every
    /// DeferredExec written before this field held — means "not authorized by
    /// an Owner", the stricter reading: `ExecuteDeferred` then holds the vault
    /// to the invariants every non-Owner signer is held to. A pending
    /// authorization from before the field existed can therefore only lose
    /// power, never gain it, and needs no version gate.
    pub flags: u8,
    /// Padding for alignment.
    pub _padding: [u8; 4],
    /// SHA256 of the serialized compact instructions bytes.
    pub instructions_hash: [u8; 32],
    /// SHA256 of all account pubkeys referenced by compact instructions.
    pub accounts_hash: [u8; 32],
    /// The wallet this authorization is for.
    pub wallet: Pubkey,
    /// The authority that created this authorization.
    pub authority: Pubkey,
    /// The payer who funded this account (receives rent refund on close).
    pub payer: Pubkey,
    /// Absolute slot at which this authorization expires.
    pub expires_at: u64,
}
// Layout: 1+1+1+1+4+32+32+32+32+32+8 = 176 bytes

/// [`DeferredExecAccount::flags`] bit: the authority that signed `Authorize`
/// was an Owner, so `ExecuteDeferred` runs with an Owner's full power over the
/// vault. Without it the vault invariants apply (see
/// `processor::execute::actions::VaultGuard`).
pub const DEFERRED_FLAG_OWNER: u8 = 1 << 0;

impl DeferredExecAccount {
    /// Minimum byte length for this account to be readable.
    pub const MIN_LEN: usize = core::mem::size_of::<Self>();

    /// Whether an Owner authorized this execution. False for every account
    /// written before `flags` existed, which `ExecuteDeferred` then guards.
    #[inline]
    pub fn authorized_by_owner(&self) -> bool {
        self.flags & DEFERRED_FLAG_OWNER != 0
    }

    /// Validate discriminator, length and layout version before trusting any
    /// field. Every read path calls this instead of comparing `data[0]` by
    /// hand, so a future version gate is one edit rather than a hunt through
    /// every processor.
    #[inline]
    pub fn check(data: &[u8]) -> Result<(), pinocchio::program_error::ProgramError> {
        crate::state::check_header(
            data,
            crate::state::AccountDiscriminator::DeferredExec,
            crate::state::version_offset::DEFERRED_EXEC,
            Self::MIN_LEN,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(flags: u8) -> DeferredExecAccount {
        DeferredExecAccount {
            discriminator: 0x24,
            version: 1,
            bump: 255,
            flags,
            _padding: [0; 4],
            instructions_hash: [1; 32],
            accounts_hash: [2; 32],
            wallet: [3; 32],
            authority: [4; 32],
            payer: [5; 32],
            expires_at: 6,
        }
    }

    /// `flags` took the first padding byte; nothing else moved. ReclaimDeferred
    /// reads `payer` and `expires_at` at fixed offsets in v1 and v2 accounts
    /// alike, so those two offsets in particular must hold.
    #[test]
    fn flags_sit_in_the_old_padding_and_nothing_else_moves() {
        assert_eq!(core::mem::size_of::<DeferredExecAccount>(), 176);
        let a = account(DEFERRED_FLAG_OWNER);
        let base = &a as *const DeferredExecAccount as usize;
        let off = |p: *const u8| p as usize - base;
        assert_eq!(off(&a.flags as *const u8), 3);
        assert_eq!(off(a._padding.as_ptr()), 4);
        assert_eq!(off(a.instructions_hash.as_ptr()), 8);
        assert_eq!(off(a.accounts_hash.as_ptr()), 40);
        assert_eq!(off(a.wallet.as_ref().as_ptr()), 72);
        assert_eq!(off(a.authority.as_ref().as_ptr()), 104);
        assert_eq!(off(a.payer.as_ref().as_ptr()), 136);
        assert_eq!(off(&a.expires_at as *const u64 as *const u8), 168);
    }

    #[test]
    fn only_the_owner_bit_lifts_the_guard() {
        // Zero is what every account written before the field held.
        assert!(!account(0).authorized_by_owner());
        assert!(account(DEFERRED_FLAG_OWNER).authorized_by_owner());
        for flags in 0..=u8::MAX {
            assert_eq!(
                account(flags).authorized_by_owner(),
                flags & DEFERRED_FLAG_OWNER != 0
            );
        }
    }
}
