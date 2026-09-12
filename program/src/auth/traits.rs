use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

/// Trait for defining the authentication logic for different authority types.
///
/// The two implementations bind their approval in fundamentally different ways,
/// which is why some parameters are unused in one of them:
///
/// - **Secp256r1** verifies a passkey signature over `signed_payload` via the
///   precompile. Nothing else ties that key to this transaction, so every byte
///   the approval is meant to cover has to be inside `signed_payload`.
/// - **Ed25519** looks for the key among the transaction's own signers. The
///   runtime has already verified a signature over the whole message — every
///   instruction, every account key, and the privileges in the message header —
///   which is a strictly wider binding than `signed_payload` describes. There is
///   no second signature to check, and `auth_payload`/`signed_payload` are
///   therefore ignored rather than unimplemented (M-1).
pub trait Authenticator {
    /// Authenticate the execution request.
    ///
    /// # Arguments
    /// * `accounts` - The full slice of accounts passed to the instruction.
    /// * `authority_data` - The mutable data of the authority account.
    /// * `auth_payload` - The authentication payload (e.g. signature, proof).
    ///   Ignored by Ed25519 — see above.
    /// * `signed_payload` - The message that was signed. Ignored by Ed25519 —
    ///   see above.
    /// * `discriminator` - The instruction opcode byte(s).
    /// * `program_id` - This program's public key (included in Secp256r1 challenge hash).
    fn authenticate(
        &self,
        accounts: &[AccountInfo],
        authority_data: &mut [u8],
        auth_payload: &[u8],
        signed_payload: &[u8],
        discriminator: &[u8],
        program_id: &Pubkey,
    ) -> Result<(), ProgramError>;
}
