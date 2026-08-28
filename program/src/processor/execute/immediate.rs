use crate::{
    auth::{
        ed25519::Ed25519Authenticator, secp256r1::Secp256r1Authenticator, traits::Authenticator,
    },
    compact::{compute_accounts_hash, parse_compact_instructions_ref_with_len},
    error::AuthError,
    processor::execute::actions::{
        evaluate_post_actions, evaluate_pre_actions, snapshot_token_authorities,
        snapshot_token_balances, verify_token_authorities_unchanged,
    },
    state::{authority::AuthorityAccountHeader, policy::PolicyLocation, AccountDiscriminator},
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

/// Process the Execute instruction.
///
/// Executes a batch of condensed "Compact Instructions" on behalf of the wallet.
///
/// # Logic:
/// 1. **Authentication**: Verifies that the signer is a valid `Authority` or `Session` for this wallet.
/// 2. **Session Checks**: If authenticated via Session, enforces slot expiry and action permissions.
/// 3. **Decompression**: Expands `CompactInstructions` (index-based references) into full Solana instructions.
/// 4. **Execution**: Invokes the Instructions via CPI, signing with the Vault PDA.
///
/// # Accounts:
/// 1. `[signer]` Payer.
/// 2. `[]` Wallet PDA.
/// 3. `[signer]` Authority or Session PDA.
/// 4. `[signer]` Vault PDA (Signer for CPI).
/// 5. `...` Inner accounts referenced by instructions.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Anti-CPI guard for every authentication branch, not just two of them.
    // The Secp256r1 authenticator and the session branch each carried their
    // own copy of this check; the Ed25519 branch did not, so any program the
    // authority signed a transaction for could re-enter Execute and drive the
    // vault PDA. Hoisting it above the discriminator match closes that gap and
    // makes the per-branch copies redundant.
    if get_stack_height() > 1 {
        return Err(AuthError::PermissionDenied.into());
    }

    // Parse accounts
    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // M-6. The payer's signature was only ever enforced as a side effect: the
    // System Program demands it during the funding CPI. `initialize_pda_account`
    // skips that CPI when the PDA already holds enough lamports — anyone can
    // pre-fund a PDA — so on that path nothing checked it at all.
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // Compared by key rather than by position when deciding what may be
    // forwarded, so the same account passed twice cannot launder the payer.
    let payer_key = payer.key();
    let wallet_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let authority_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let vault_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Remaining accounts are for inner instructions
    let inner_accounts_start = 4;
    let _inner_accounts = &accounts[inner_accounts_start..];

    // Verify ownership
    if wallet_pda.owner() != program_id || authority_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    // Validate Wallet Discriminator (Issue #7)
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    crate::state::wallet::WalletAccount::check(wallet_data)?;

    if !authority_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read authority header
    let authority_data = unsafe { authority_pda.borrow_mut_data_unchecked() };

    // Authenticate based on discriminator
    let discriminator = if !authority_data.is_empty() {
        authority_data[0]
    } else {
        return Err(ProgramError::InvalidAccountData);
    };

    // Parse compact instructions and get their consumed byte length. The
    // length is used to split `instruction_data` into the compact-instructions
    // prefix (the data_payload bound into the Secp256r1 signature) and the
    // auth payload suffix. Tracking the parse cursor avoids re-serializing
    // just to measure length.
    let (compact_instructions, compact_len) =
        parse_compact_instructions_ref_with_len(instruction_data)?;

    // Where this account's policy lives, if it carries one. Resolved from the
    // account's own discriminator and authority type rather than passed in, so
    // an authority can never be measured with the session header's offset —
    // an Ed25519 authority is *exactly* 80 bytes, so that mistake would read
    // its stored pubkey as an action buffer. See state::policy.
    //
    // This is what makes the engine serve both account types: a session with
    // actions and an authority with a policy take the same path from here on.
    let policy = PolicyLocation::of(authority_data).filter(|loc| loc.is_present(authority_data));

    // Set on the session branch. `None` means "no session-specific restriction",
    // which is what an authority-authenticated Execute wants.
    let mut session_key: Option<Pubkey> = None;

    // One clock read for both branches — policy evaluation needs the slot
    // whether the caller is a session or a policy-bearing authority.
    let current_slot = Clock::get()?.slot;

    // Bound to the enum rather than to numeric literals. The v1 code matched on
    // bare `2` and `3`, which silently stopped matching anything the moment the
    // discriminators were renumbered — every Execute failed with a flat
    // InvalidAccountData and no indication of why.
    const DISC_AUTHORITY: u8 = AccountDiscriminator::Authority as u8;
    const DISC_SESSION: u8 = AccountDiscriminator::Session as u8;

    match discriminator {
        DISC_AUTHORITY => {
            // Authority
            AuthorityAccountHeader::check(authority_data)?;
            let authority_header = unsafe {
                std::ptr::read_unaligned(authority_data.as_ptr() as *const AuthorityAccountHeader)
            };

            if authority_header.wallet != *wallet_pda.key() {
                return Err(ProgramError::InvalidAccountData);
            }
            match authority_header.authority_type {
                0 => {
                    // Ed25519
                    Ed25519Authenticator.authenticate(
                        accounts,
                        authority_data,
                        &[],
                        &[],
                        &[4],
                        program_id,
                    )?;
                },
                1 => {
                    // Secp256r1 (WebAuthn)
                    let data_payload = &instruction_data[..compact_len];
                    let authority_payload = &instruction_data[compact_len..];
                    let accounts_hash = compute_accounts_hash(accounts, &compact_instructions)?;
                    let mut extended_payload = Vec::with_capacity(compact_len + 32);
                    extended_payload.extend_from_slice(data_payload);
                    extended_payload.extend_from_slice(&accounts_hash);

                    Secp256r1Authenticator.authenticate(
                        accounts,
                        authority_data,
                        authority_payload,
                        &extended_payload,
                        &[4],
                        program_id,
                    )?;
                },
                _ => return Err(AuthError::InvalidAuthenticationKind.into()),
            }
        },
        DISC_SESSION => {
            // Session — reuse the existing `authority_data` borrow; no re-borrow needed.

            // L5: anti-CPI guard, mirroring the Secp256r1 authenticator check.
            // A session-authenticated Execute is only valid as a top-level instruction
            // (stack_height == 1). Rejecting CPI entry prevents any future bugs where
            // a wrapper program could chain through Execute with forged account context.
            if get_stack_height() > 1 {
                return Err(AuthError::PermissionDenied.into());
            }

            if authority_data.len() < std::mem::size_of::<crate::state::session::SessionAccount>() {
                return Err(ProgramError::InvalidAccountData);
            }

            let session = unsafe {
                std::ptr::read_unaligned(
                    authority_data.as_ptr() as *const crate::state::session::SessionAccount
                )
            };

            // Verify Wallet
            if session.wallet != *wallet_pda.key() {
                return Err(ProgramError::InvalidAccountData);
            }

            // Verify Expiry
            if current_slot > session.expires_at {
                return Err(AuthError::SessionExpired.into());
            }

            // Verify Signer matches Session Key
            let mut signer_matched = false;
            for acc in accounts {
                if acc.is_signer() && *acc.key() == session.session_key {
                    signer_matched = true;
                    break;
                }
            }
            if !signer_matched {
                return Err(ProgramError::MissingRequiredSignature);
            }

            // Owned, not borrowed: `session` is a stack copy read out of the
            // account, so a reference to it dies with this arm.
            session_key = Some(session.session_key);
        },
        _ => return Err(ProgramError::InvalidAccountData),
    }

    // Pre-CPI policy checks (program whitelist/blacklist), for a session with
    // actions or an authority with a policy alike.
    if let Some(loc) = policy {
        evaluate_pre_actions(
            authority_data,
            loc,
            &compact_instructions,
            accounts,
            current_slot,
        )?;
    }

    // Get vault bump for signing
    let (vault_key, vault_bump) = find_program_address(
        &[crate::seeds::VAULT, wallet_pda.key().as_ref()],
        program_id,
    );

    // Verify vault PDA.
    if vault_pda.key() != &vault_key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Snapshot balances before CPI, for policy enforcement afterwards.
    let vault_lamports_before = if policy.is_some() {
        vault_pda.lamports()
    } else {
        0
    };
    let token_snapshots_before = match policy {
        // Reuse the existing `authority_data` borrow — no additional borrow of authority_pda.
        Some(loc) => snapshot_token_balances(authority_data, loc, accounts, vault_pda.key())?,
        None => Vec::new(),
    };

    // ── Session invariants (defense against System::Assign / SetAuthority escapes) ──
    // A session that whitelists System Program (a common pattern for SOL transfers)
    // could otherwise craft `System::Assign(vault, attacker)` — the lamport-based
    // limits see no outflow, but ownership of the vault silently transfers to the
    // attacker, who then drains it in a follow-up tx. Same class of attack via
    // SPL Token's `SetAuthority` / `Approve` on vault-owned token accounts.
    //
    // Snapshot the vault's metadata + every listed-mint vault-owned token account's
    // authority fields BEFORE the CPI loop; verify unchanged AFTER.
    let vault_owner_before = policy.map(|_| *vault_pda.owner());
    let vault_data_len_before = policy.map(|_| unsafe { vault_pda.borrow_data_unchecked().len() });
    let token_authority_snapshots = match policy {
        Some(loc) => snapshot_token_authorities(authority_data, loc, accounts, vault_pda.key())?,
        None => Vec::new(),
    };

    // Track gross SOL outflow across all CPIs (for SolMaxPerTx check)
    let mut vault_lamports_gross_out: u64 = 0;
    let mut prev_vault_lamports = vault_lamports_before;

    // Reuse the same Vecs across all inner CPIs — allocated once, cleared +
    // repushed each iteration. Saves 2 Vec::with_capacity allocations per
    // inner instruction vs. .collect()ing fresh Vecs each time.
    const MAX_INNER_ACCOUNTS: usize = 32;
    let mut account_metas: Vec<AccountMeta> = Vec::with_capacity(MAX_INNER_ACCOUNTS);
    let mut cpi_accounts: Vec<Account> = Vec::with_capacity(MAX_INNER_ACCOUNTS);

    // PDA signer seeds (constant across the loop)
    let vault_bump_arr = [vault_bump];
    let seeds = [
        Seed::from(crate::seeds::VAULT),
        Seed::from(wallet_pda.key().as_ref()),
        Seed::from(&vault_bump_arr),
    ];

    // Execute each compact instruction.
    //
    // Signer forwarding is intentional here: any outer account that signed
    // the LazorKit transaction remains a signer for matching inner CPI
    // accounts, and the vault PDA is added as the wallet-controlled signer.
    // This is part of the paymaster model: a payer/paymaster that signs the
    // outer transaction must inspect the full transaction before signing.
    for compact_ix in &compact_instructions {
        let decompressed = compact_ix.decompress(accounts)?;

        // Prevent self-reentrancy (Issue #10)
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

        // Track gross SOL outflow per CPI (used for SolMaxPerTx — not net balance diff).
        if policy.is_some() {
            let post = vault_pda.lamports();
            if prev_vault_lamports > post {
                vault_lamports_gross_out =
                    vault_lamports_gross_out.saturating_add(prev_vault_lamports - post);
            }
            prev_vault_lamports = post;
        }
    }

    // ── Post-CPI session invariants ────────────────────────────────────
    // Verify vault's ownership and data layout were not tampered with. Any
    // change (System::Assign, Allocate, AllocateWithSeed, AssignWithSeed) is
    // rejected. This complements the balance-based limits below.
    if let Some(owner_before) = vault_owner_before {
        if *vault_pda.owner() != owner_before {
            return Err(AuthError::SessionVaultOwnerChanged.into());
        }
    }
    if let Some(len_before) = vault_data_len_before {
        let len_after = unsafe { vault_pda.borrow_data_unchecked().len() };
        if len_after != len_before {
            return Err(AuthError::SessionVaultDataLenChanged.into());
        }
    }
    // Verify no SetAuthority / Approve on listed-mint vault-owned token accounts.
    verify_token_authorities_unchanged(&token_authority_snapshots, accounts)?;

    // Post-CPI action checks (spending limits)
    // Reuse the existing `authority_data` borrow — no additional borrow of authority_pda.
    if let Some(loc) = policy {
        evaluate_post_actions(
            authority_data,
            loc,
            accounts,
            vault_pda.key(),
            vault_lamports_before,
            vault_pda.lamports(),
            vault_lamports_gross_out,
            &token_snapshots_before,
            current_slot,
        )?;
    }

    Ok(())
}
