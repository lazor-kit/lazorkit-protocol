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
    pub _padding: [u8; 5],
}

impl WalletAccount {
    /// Minimum byte length for this account to be readable.
    pub const MIN_LEN: usize = core::mem::size_of::<Self>();

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
