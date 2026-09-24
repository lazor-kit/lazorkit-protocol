use no_padding::NoPadding;

// Main Wallet Account.
// Acts as the trust anchor. Assets are stored in the separate Vault PDA.
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct WalletAccount {
    /// Account discriminator (must be `1` for Wallet).
    pub discriminator: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Account Version.
    pub version: u8,
    /// Padding for alignment.
    pub _padding: [u8; 1],
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
            Self::MIN_LEN,
        )
    }
}
