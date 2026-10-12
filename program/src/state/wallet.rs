use no_padding::NoPadding;

// Main Wallet Account.
// Acts as the trust anchor. Assets are stored in the separate Vault PDA.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct WalletAccount {
    /// Account discriminator (`AccountDiscriminator::Wallet`).
    pub discriminator: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Layout revision (`state::layout_version`).
    pub version: u8,
    /// The canonical bump of this wallet's vault PDA, `[VAULT, wallet]`, or 0
    /// when the wallet does not record it. This byte was padding, so every
    /// wallet created before it was used holds 0; read it only through
    /// [`Self::vault_bump`].
    ///
    /// `Execute` and `ExecuteDeferred` sign for the vault with this bump and
    /// check the vault's address with one hash of the seeds, rather than
    /// searching for the bump on every call (1,500 CU per bump tried). 0 falls
    /// back to the search, which is also right for the one wallet in 2^255
    /// whose canonical bump really is 0: no layout revision is needed.
    pub vault_bump: u8,
    /// How many authorities on this wallet hold rank Owner.
    ///
    /// A wallet is born with one. Owners may add and remove Owners, and this
    /// count is what stops the last one being removed — a wallet whose Owners
    /// are all gone can still spend, but nothing can ever be added or revoked
    /// again, which is the failure the removal rules exist to prevent.
    ///
    /// Read and written only through [`Self::owner_count`] and
    /// [`Self::set_owner_count`], which take the raw account data — the header
    /// is stored unaligned and every other reader in the program uses
    /// `read_unaligned` for the same reason.
    pub owner_count: u32,
}

impl WalletAccount {
    /// Minimum byte length for this account to be readable.
    pub const MIN_LEN: usize = core::mem::size_of::<Self>();

    /// Byte offset of [`Self::owner_count`] within the account.
    pub const OWNER_COUNT_OFFSET: usize = 4;

    /// Byte offset of [`Self::vault_bump`] within the account.
    pub const VAULT_BUMP_OFFSET: usize = 3;

    /// The vault's canonical bump, when this wallet records it; `None` for a
    /// wallet created before the byte was used (it holds 0). A nonzero value
    /// was written only by `CreateWallet`, from its own bump search, so it is
    /// the canonical bump. Call [`Self::check`] first.
    #[inline]
    pub fn vault_bump(data: &[u8]) -> Option<u8> {
        match data[Self::VAULT_BUMP_OFFSET] {
            0 => None,
            bump => Some(bump),
        }
    }

    /// Read the owner count out of raw account data.
    ///
    /// Call [`Self::check`] first; this does no validation of its own.
    #[inline]
    pub fn owner_count(data: &[u8]) -> u32 {
        u32::from_le_bytes(
            data[Self::OWNER_COUNT_OFFSET..Self::OWNER_COUNT_OFFSET + 4]
                .try_into()
                .expect("checked length"),
        )
    }

    /// Write the owner count into raw account data.
    #[inline]
    pub fn set_owner_count(data: &mut [u8], count: u32) {
        data[Self::OWNER_COUNT_OFFSET..Self::OWNER_COUNT_OFFSET + 4]
            .copy_from_slice(&count.to_le_bytes());
    }

    /// Validate discriminator, length and layout version before trusting any
    /// field. Every read path calls this instead of comparing `data[0]` by
    /// hand, so a future version gate is one edit rather than a hunt through
    /// every processor.
    #[inline]
    pub fn check(data: &[u8]) -> Result<(), pinocchio::program_error::ProgramError> {
        crate::state::check_header(
            data,
            crate::state::AccountDiscriminator::Wallet,
            crate::state::version_offset::WALLET,
            crate::state::layout_version::WALLET,
            Self::MIN_LEN,
        )
    }
}
