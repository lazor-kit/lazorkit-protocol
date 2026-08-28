use no_padding::NoPadding;
use pinocchio::pubkey::Pubkey;

/// Hard ceiling on either protocol fee, enforced wherever the config is written.
///
/// Without it, `execution_fee = u64::MAX` is a freeze wearing a fee's clothes:
/// nobody can pay it, discriminators 4 and 7 are the only paths that move funds
/// out of a vault, and the config still reads as `enabled` so nothing looks
/// wrong. 0.01 SOL is roughly 2000x the launch creation fee — enough headroom
/// that pricing is unconstrained in practice, low enough that the worst an admin
/// can do is overcharge rather than confiscate.
pub const MAX_PROTOCOL_FEE_LAMPORTS: u64 = 10_000_000;

/// The only account allowed to run `initialize_protocol`.
///
/// `ProtocolConfig` is the root of the fee system and there is no earlier
/// on-chain account to anchor trust to — before it exists, the program owns
/// nothing that could authorise its creation. So the anchor is the binary
/// itself. Without this, the first caller after any deploy becomes admin
/// permanently, which is C-1.
///
/// The devnet value is a **committed test keypair**
/// (`keys/devnet-init-authority.json`). Devnet is a test cluster carrying no
/// value, and committing it keeps the local suites able to initialise a
/// protocol without a shared secret. Devnet's protocol config therefore offers
/// no security guarantee — say so in any devnet-facing docs. Mainnet uses a key
/// held offline.
#[cfg(all(feature = "mainnet", not(feature = "devnet")))]
pub const PROTOCOL_INIT_AUTHORITY: Pubkey =
    pinocchio_pubkey::pubkey!("4fZM6RPRLkeW8T5dDctZjWaqidFDACyW41Kqztj7uL5V");

#[cfg(all(feature = "devnet", not(feature = "mainnet")))]
pub const PROTOCOL_INIT_AUTHORITY: Pubkey =
    pinocchio_pubkey::pubkey!("9AmBA2C7VwtoQXXowpqBsLC4azNXm81BCSXZNiQM6BsW");

/// Global protocol configuration account.
///
/// Stores fee amounts, admin key, treasury, and shard count.
/// Read-only during fee collection; writable only via UpdateProtocol.
///
/// PDA seeds: `[crate::seeds::PROTOCOL_CONFIG]`
#[repr(C, align(8))]
#[derive(NoPadding, Debug, Clone, Copy)]
pub struct ProtocolConfig {
    /// Account discriminator — `AccountDiscriminator::ProtocolConfig`.
    pub discriminator: u8,
    /// Account version.
    pub version: u8,
    /// Bump seed for this PDA.
    pub bump: u8,
    /// Whether fee collection is enabled (0 = disabled, 1 = enabled).
    pub enabled: u8,
    /// Number of treasury shards (e.g. 16 or 32).
    pub num_shards: u8,
    /// Padding for 8-byte alignment.
    pub _padding: [u8; 3],
    /// Admin pubkey — can update config, register payers, withdraw.
    pub admin: Pubkey,
    /// Treasury destination for WithdrawTreasury (admin's wallet).
    pub treasury: Pubkey,
    /// Fee in lamports charged on CreateWallet.
    pub creation_fee: u64,
    /// Fee in lamports charged on Execute / ExecuteDeferred.
    pub execution_fee: u64,
    /// Proposed next admin, all-zero when no rotation is pending.
    ///
    /// Rotation is two-step — the current admin proposes, the proposed admin
    /// accepts — so a typo or a key nobody holds cannot silently take
    /// governance with it. v1 had no rotation at all: `update_protocol` could
    /// write every field except `admin`, which made a lost or compromised admin
    /// key terminal for the protocol.
    pub pending_admin: Pubkey,
}

impl ProtocolConfig {
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
            crate::state::AccountDiscriminator::ProtocolConfig,
            crate::state::version_offset::PROTOCOL_CONFIG,
            Self::MIN_LEN,
        )
    }

    /// The one address a ProtocolConfig may live at.
    #[inline]
    pub fn pda(program_id: &Pubkey) -> Pubkey {
        pinocchio::pubkey::find_program_address(&[crate::seeds::PROTOCOL_CONFIG], program_id).0
    }

    /// Pin the account to that address, confirm this program owns it, and
    /// validate the header — in that order, before any field is read.
    ///
    /// M-3. Every caller already checked ownership, which in practice is enough:
    /// the only ProtocolConfig that can exist is the one `initialize_protocol`
    /// created at this address. But the config is where the fee ceiling, the
    /// admin and the treasury live, so "in practice" is the wrong standard —
    /// `try_collect_fee` already pins the shard and fee-record PDAs, and this
    /// was the inconsistency.
    #[inline]
    pub fn load(
        program_id: &Pubkey,
        account: &pinocchio::account_info::AccountInfo,
    ) -> Result<(), pinocchio::program_error::ProgramError> {
        use pinocchio::program_error::ProgramError;

        if account.key() != &Self::pda(program_id) {
            return Err(crate::error::ProtocolError::InvalidProtocolAdmin.into());
        }
        if account.owner() != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let data = account.try_borrow_data()?;
        Self::check(&data)
            .map_err(|_| ProgramError::from(crate::error::ProtocolError::InvalidProtocolAdmin))
    }
}

#[cfg(test)]
mod layout {
    use super::*;

    /// The byte counts quoted in `docs/Architecture.md` and the CHANGELOG.
    /// Cheap to assert, and the alternative is documentation that drifts.
    #[test]
    fn sizes_match_the_documented_layout() {
        assert_eq!(core::mem::size_of::<ProtocolConfig>(), 120);
        assert_eq!(
            core::mem::size_of::<crate::state::wallet::WalletAccount>(),
            8
        );
        assert_eq!(
            core::mem::size_of::<crate::state::authority::AuthorityAccountHeader>(),
            48
        );
    }

    /// 0.01 SOL. The number appears in the docs as the reason an unpayable fee
    /// cannot stand in for the freeze C-1 removed.
    #[test]
    fn the_fee_ceiling_is_a_hundredth_of_a_sol() {
        assert_eq!(MAX_PROTOCOL_FEE_LAMPORTS, 10_000_000);
    }
}
