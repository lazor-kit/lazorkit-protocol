use crate::auth::traits::Authenticator;
use crate::error::AuthError;
use crate::state::authority::AuthorityAccountHeader;
use crate::utils::get_stack_height;
use assertions::sol_assert_bytes_eq;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// Authentication for an Ed25519 authority: the key must be among the
/// transaction's signers, and this program must be running top-level.
///
/// `auth_payload` and `signed_payload` are ignored because, **top-level**, the
/// runtime has already verified an Ed25519 signature over the entire transaction
/// message — every instruction, every account key, the header privileges — so a
/// signature over `signed_payload` would cover a strict subset of that.
///
/// That reasoning holds ONLY at the top level. Under a CPI, the transaction the
/// runtime verified is the *caller's*, which the authority signed for a different
/// program; the inner LazorKit instruction is chosen by the caller, not the
/// signer, yet Solana propagates the authority's `is_signer` flag into the CPI.
/// Without the guard below, a wrapper program a user signed any transaction for
/// could re-enter AddAuthority / RemoveAuthority / TransferOwnership /
/// CreateSession / RevokeSession / MigrateWallet / Execute and act with the
/// user's authority. This is the H-1 class; the guard is what makes "the tx
/// signature covers the intent" true. The Secp256r1 authenticator carries the
/// identical guard (a passkey signs the payload, not the transaction).
pub struct Ed25519Authenticator;

impl Authenticator for Ed25519Authenticator {
    fn authenticate(
        &self,
        accounts: &[AccountInfo],
        authority_data: &mut [u8],
        _auth_payload: &[u8],
        _signed_payload: &[u8],
        _discriminator: &[u8],
        _program_id: &Pubkey,
    ) -> Result<(), ProgramError> {
        // Anti-CPI: an Ed25519 authority is authenticated by its key being a
        // transaction signer, and a signer flag survives into a CPI. Only a
        // top-level instruction was actually signed with this intent.
        if get_stack_height() > 1 {
            return Err(AuthError::PermissionDenied.into());
        }

        if authority_data.len() < std::mem::size_of::<AuthorityAccountHeader>() + 32 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Header is at specific offset, but we just need variable data here for key
        let header_size = std::mem::size_of::<AuthorityAccountHeader>();
        // Ed25519 key is immediately after header
        let pubkey_bytes = &authority_data[header_size..header_size + 32];

        for account in accounts {
            if account.is_signer() && sol_assert_bytes_eq(account.key().as_ref(), pubkey_bytes, 32)
            {
                return Ok(());
            }
        }

        Err(ProgramError::MissingRequiredSignature)
    }
}
