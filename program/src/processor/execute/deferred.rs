use crate::{
    compact::{compute_accounts_hash, parse_compact_instructions_ref_with_len},
    error::AuthError,
    state::deferred::DeferredExecAccount,
    utils::get_stack_height,
};
use pinocchio::{
    account_info::AccountInfo,
    instruction::{Account, AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed_unchecked,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

/// Process the ExecuteDeferred instruction (deferred execution tx2).
///
/// Verifies the compact instructions against the stored hash, executes them
/// via CPI with vault PDA signing, then closes the DeferredExec account.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer
/// 2. `[]` Wallet PDA
/// 3. `[writable]` Vault PDA (signer for CPI)
/// 4. `[writable]` DeferredExec PDA (read + closed)
/// 5. `[writable]` Refund destination (receives rent refund)
/// 6. `...` Inner accounts referenced by compact instructions
///
/// # Instruction Data (after discriminator):
///   [compact_instructions(variable)]
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Anti-CPI guard, matching `immediate.rs`. ExecuteDeferred is already
    // hash-locked to what the passkey signed and single-use, so a wrapper gains
    // nothing by re-entering it — but keep the guard for parity, so the two
    // vault-signing entry points are constrained identically.
    if get_stack_height() > 1 {
        return Err(AuthError::PermissionDenied.into());
    }

    // Parse accounts
    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let payer_key = payer.key();
    // ExecuteDeferred has no session branch — its authorization came from the
    // Authorize step, which is Secp256r1 only — so nothing narrows forwarding
    // beyond the payer exclusion.
    let session_key: Option<Pubkey> = None;
    let wallet_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let vault_pda = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let deferred_pda = accounts.get(3).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let refund_dest = accounts.get(4).ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Validate payer
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify ownership of wallet and deferred
    if wallet_pda.owner() != program_id || deferred_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Validate Wallet discriminator
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    crate::state::wallet::WalletAccount::check(wallet_data)?;

    // Read DeferredExec account (read-only borrow for validation)
    DeferredExecAccount::check(unsafe { deferred_pda.borrow_data_unchecked() })?;

    let deferred = unsafe {
        let data = deferred_pda.borrow_data_unchecked();
        std::ptr::read_unaligned(data.as_ptr() as *const DeferredExecAccount)
    };

    // Verify wallet matches
    if deferred.wallet != *wallet_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify refund destination matches stored payer
    if deferred.payer != *refund_dest.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check expiry
    let clock = Clock::get()?;
    if clock.slot > deferred.expires_at {
        return Err(AuthError::DeferredAuthorizationExpired.into());
    }

    // Parse compact instructions and track consumed length. We hash the
    // raw instruction_data[..consumed] directly — the parse/encode format
    // is byte-identical, so there's no need to re-serialize.
    let (compact_instructions, compact_len) =
        parse_compact_instructions_ref_with_len(instruction_data)?;

    // Verify instructions hash against the exact bytes we parsed from
    let instructions_hash = compute_sha256(&instruction_data[..compact_len]);
    if instructions_hash != deferred.instructions_hash {
        return Err(AuthError::DeferredHashMismatch.into());
    }

    // Verify accounts hash
    let accounts_hash = compute_accounts_hash(accounts, &compact_instructions)?;
    if accounts_hash != deferred.accounts_hash {
        return Err(AuthError::DeferredHashMismatch.into());
    }

    // Derive vault PDA and verify
    let (vault_key, vault_bump) = find_program_address(
        &[crate::seeds::VAULT, wallet_pda.key().as_ref()],
        program_id,
    );

    if vault_pda.key() != &vault_key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Close the DeferredExec account BEFORE CPI execution.
    // All validation is complete — hashes verified, expiry checked.
    // Closing before CPI avoids stale-pointer issues with invoke_signed_unchecked.
    // If any CPI fails, the entire transaction reverts atomically.
    let deferred_lamports = unsafe { *deferred_pda.borrow_mut_lamports_unchecked() };
    let refund_lamports = unsafe { *refund_dest.borrow_mut_lamports_unchecked() };
    unsafe {
        *refund_dest.borrow_mut_lamports_unchecked() = refund_lamports
            .checked_add(deferred_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *deferred_pda.borrow_mut_lamports_unchecked() = 0;
    }
    let close_data = unsafe { deferred_pda.borrow_mut_data_unchecked() };
    close_data.fill(0);

    // Reuse Vecs across inner CPI iterations — allocated once, cleared +
    // repushed each iteration. Same optimisation as execute::immediate.
    const MAX_INNER_ACCOUNTS: usize = 32;
    let mut account_metas: Vec<AccountMeta> = Vec::with_capacity(MAX_INNER_ACCOUNTS);
    let mut cpi_accounts: Vec<Account> = Vec::with_capacity(MAX_INNER_ACCOUNTS);

    let vault_bump_arr = [vault_bump];
    let seeds = [
        Seed::from(crate::seeds::VAULT),
        Seed::from(wallet_pda.key().as_ref()),
        Seed::from(&vault_bump_arr),
    ];

    // Execute each compact instruction via CPI with vault PDA signing.
    //
    // Signer forwarding is intentional here: any outer account that signed
    // the LazorKit transaction remains a signer for matching inner CPI
    // accounts, and the vault PDA is added as the wallet-controlled signer.
    // This is part of the paymaster model: a payer/paymaster that signs the
    // outer transaction must inspect the full transaction before signing.
    for compact_ix in &compact_instructions {
        let decompressed = compact_ix.decompress(accounts)?;

        // Prevent self-reentrancy
        if decompressed.program_id.as_ref() == program_id.as_ref() {
            return Err(AuthError::SelfReentrancyNotAllowed.into());
        }

        account_metas.clear();
        cpi_accounts.clear();
        // Signer forwarding is opt-in and never covers the fee payer.
        //
        // v1 forwarded every outer signer into every inner instruction that
        // referenced it, which let a session limited to 0.001 SOL move 2 SOL
        // out of the paymaster's own wallet: the action limits watch the
        // vault, and the paymaster is not the vault.
        //
        // Three conditions now, and the high bit alone is not enough. It is
        // real consent for a Secp256r1 authority — the compact bytes are in
        // the signed payload, so the passkey holder signs the elevation. It
        // is *not* consent in the session branch, where the session key
        // holder is the adversary and would simply set the bit. So a session
        // may only ever conscript its own signature, and nobody may ever
        // conscript the fee payer's. Compared by key, not by position, so
        // passing the payer twice cannot launder it.
        for (i, &acc) in decompressed.accounts.iter().enumerate() {
            let forwarded = decompressed.forward_signer[i]
                && acc.is_signer()
                && acc.key() != payer_key
                && session_key.is_none_or(|sk| acc.key() == &sk);

            account_metas.push(AccountMeta {
                pubkey: acc.key(),
                is_signer: forwarded || acc.key() == vault_pda.key(),
                is_writable: acc.is_writable(),
            });
            cpi_accounts.push(Account::from(acc));
        }

        let ix = Instruction {
            program_id: decompressed.program_id,
            accounts: &account_metas,
            data: decompressed.data,
        };

        let signer: Signer = (&seeds).into();

        unsafe {
            invoke_signed_unchecked(&ix, &cpi_accounts, &[signer]);
        }
    }

    Ok(())
}

/// Compute SHA256 hash of bytes.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    #[allow(unused_assignments)]
    let mut hash = [0u8; 32];
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_sha256([data].as_ptr() as *const u8, 1, hash.as_mut_ptr());
    }
    #[cfg(not(target_os = "solana"))]
    {
        hash = [0xAA; 32];
        let _ = data;
    }
    hash
}
