use crate::auth::traits::Authenticator;
use crate::state::authority::AuthorityAccountHeader;
use assertions::sol_assert_bytes_eq;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// Authentication for an Ed25519 authority: the key must be among the
/// transaction's signers.
///
/// M-1 flagged `auth_payload` and `signed_payload` as ignored here, which reads
/// like a control that does nothing. It is the opposite: the runtime has already
/// verified an Ed25519 signature over the entire transaction message — every
/// instruction, every account key, and the privileges in the header — before
/// this program ran. A signature over `signed_payload` would cover a strict
/// subset of that. Verifying one would cost a precompile round trip to learn
/// less than is already known, so the parameters are ignored deliberately.
///
/// The asymmetry with Secp256r1 is real and load-bearing: a passkey signs
/// nothing at the transaction level, so for that path the payload is the *only*
/// binding and every byte of it matters.
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
