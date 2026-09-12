//! `MigrateWallet` — move a v1 wallet's funds onto v2, authorized by the v1 key.
//!
//! v2 is an in-place upgrade at the same program id as the retired v1 binary.
//! Its `lk2:`-namespaced seeds make every v1 PDA unreachable through the normal
//! v2 paths, which is what strands a v1 vault. This instruction is the one
//! sanctioned bridge: because it runs at the same program id, it can still sign
//! for a v1 vault with the old seeds, and it moves what is there to a
//! destination the wallet's own key has approved.
//!
//! It is **not** a backdoor. Every migration is authorized by the wallet's own
//! v1 authority — an Ed25519 signer, or a Secp256r1 passkey signing a fresh
//! challenge that commits to the destination. The program never moves a user's
//! funds without the user's key, exactly as everywhere else. What it removes is
//! only the friction: one signed instruction sweeps SOL and every SPL token and
//! closes the v1 PDAs, rather than the user reconstructing v1 calls by hand.
//!
//! Accounts:
//!
//! ```text
//!  0. [signer, writable] payer
//!  1. [writable]         v1 wallet PDA (closed at the end)
//!  2. [writable]         v1 authority PDA (authenticates; closed at the end)
//!  3. [writable]         v1 vault PDA (source of SOL; authority over the ATAs)
//!  4. [writable]         destination (SOL sink; token ATAs must be owned by it)
//!  5. [writable]         refund destination for reclaimed v1 PDA rent
//!  6. []                 system program
//!  7. []                 sysvar instructions (Secp256r1 only)
//!  8. [signer]           Ed25519 signer (Ed25519 only; ignored for passkeys)
//!  9..                   per token, a triple:
//!                          [writable] source ATA, [writable] dest ATA,
//!                          []         token program (SPL Token or Token-2022)
//! ```
//!
//! The token program travels with each token, so one call can migrate a mix of
//! SPL Token and Token-2022 assets — which real vaults hold, and which a single
//! fixed token-program account could not.
//!
//! Instruction data: `[num_tokens(1)][auth_payload(variable)]` — the auth
//! payload is empty for an Ed25519 authority, and the WebAuthn assertion blob
//! (as in Execute) for a Secp256r1 passkey.

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Account, AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed_unchecked,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
};

use crate::{
    auth::{
        ed25519::Ed25519Authenticator, secp256r1::Secp256r1Authenticator, traits::Authenticator,
    },
    error::AuthError,
    legacy,
    state::authority::AuthorityAccountHeader,
    utils::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID},
};

/// Token-account field offsets. SPL program ids come from `crate::utils`.
const TOKEN_MINT_OFFSET: usize = 0;
const TOKEN_OWNER_OFFSET: usize = 32;
const TOKEN_AMOUNT_OFFSET: usize = 64;
const TOKEN_ACCOUNT_MIN_SIZE: usize = 165;

/// SPL instruction tags.
const SPL_TRANSFER: u8 = 3;
const SPL_CLOSE_ACCOUNT: u8 = 9;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (num_tokens, auth_payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let num_tokens = *num_tokens as usize;

    let mut it = accounts.iter();
    let mut next = || it.next().ok_or(ProgramError::NotEnoughAccountKeys);
    let payer = next()?;
    let v1_wallet = next()?;
    let v1_authority = next()?;
    let v1_vault = next()?;
    let destination = next()?;
    let refund_dest = next()?;
    let system_program = next()?;
    let _sysvar_ix = next()?;
    let _auth_signer = next()?;

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── Ownership and shape of the v1 accounts ──────────────────────────
    if v1_wallet.owner() != program_id || v1_authority.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    {
        let w = unsafe { v1_wallet.borrow_data_unchecked() };
        if w.is_empty() || w[0] != legacy::discriminator::WALLET {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    // Authenticate against the v1 authority. Its header is byte-compatible with
    // v2's, so this reads `wallet`, `authority_type` and the key material at the
    // usual offsets — only the discriminator differs, and we check that by hand
    // rather than through the v2 header validator, which would reject a `2`.
    let auth_header = {
        let d = unsafe { v1_authority.borrow_data_unchecked() };
        if d.len() < core::mem::size_of::<AuthorityAccountHeader>() {
            return Err(ProgramError::InvalidAccountData);
        }
        if d[0] != legacy::discriminator::AUTHORITY {
            return Err(ProgramError::InvalidAccountData);
        }
        unsafe { core::ptr::read_unaligned(d.as_ptr() as *const AuthorityAccountHeader) }
    };
    if auth_header.wallet != *v1_wallet.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Only an Owner may migrate. Migration moves every lamport and token out of
    // the vault and closes the wallet — the most Owner-level action there is.
    // Without this, ANY authority whose key signs — a bounded Delegate capped at
    // 0.001 SOL, an Admin — could drain and close the entire wallet, defeating
    // the spending policy that is the only thing limiting a non-Owner. `role` is
    // the v1 rank byte, at the same offset v2 uses (0 = Owner).
    if auth_header.role != 0 {
        return Err(AuthError::PermissionDenied.into());
    }

    // The signature approves *this* migration and only this one: the destination
    // the funds go to (so a relayer cannot redirect the sweep), the wallet being
    // migrated (so a signature for wallet A cannot be replayed against wallet B
    // the same key also controls), how many token accounts move (so a relayer
    // cannot drop `num_tokens` to zero, sweep only the SOL, and let the
    // unconditional close strand the tokens), and the rent-refund destination (so
    // a relayer cannot redirect the reclaimed PDA/ATA rent to itself). Ed25519
    // ignores this — its transaction signature already covers the data byte and
    // every account — but building it for both is harmless.
    let mut signed_payload = Vec::with_capacity(32 + 32 + 1 + 32 + num_tokens * 32);
    signed_payload.extend_from_slice(destination.key().as_ref());
    signed_payload.extend_from_slice(v1_wallet.key().as_ref());
    signed_payload.push(num_tokens as u8);
    signed_payload.extend_from_slice(refund_dest.key().as_ref());
    // Bind the exact token accounts that move, not merely how many. Binding the
    // count alone is not enough: a relayer could keep `num_tokens` unchanged but
    // swap the source ATAs for dust it created (any party may create a
    // vault-owned ATA), migrate the dust, and let the unconditional close below
    // strand the user's real tokens in the now-orphaned vault. Folding each
    // source ATA key into the signed payload puts them inside the Secp256r1
    // challenge, so any swap / drop / reorder fails authentication (3005).
    // Ed25519 already binds every account through its transaction signature.
    for i in 0..num_tokens {
        let source_ata = accounts
            .get(9 + i * 3)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        signed_payload.extend_from_slice(source_ata.key().as_ref());
    }

    let auth_data = unsafe { v1_authority.borrow_mut_data_unchecked() };
    match auth_header.authority_type {
        0 => {
            Ed25519Authenticator.authenticate(
                accounts,
                auth_data,
                &[],
                &signed_payload,
                &[17],
                program_id,
            )?;
        },
        1 => {
            Secp256r1Authenticator.authenticate(
                accounts,
                auth_data,
                auth_payload,
                &signed_payload,
                &[17],
                program_id,
            )?;
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    }

    // ── The v1 vault, and the seeds v2 signs for it with ────────────────
    let (vault_key, vault_bump) = find_program_address(
        &[legacy::seeds::VAULT, v1_wallet.key().as_ref()],
        program_id,
    );
    if v1_vault.key() != &vault_key {
        return Err(ProgramError::InvalidSeeds);
    }
    let vault_bump_arr = [vault_bump];
    let vault_seeds = [
        Seed::from(legacy::seeds::VAULT),
        Seed::from(v1_wallet.key().as_ref()),
        Seed::from(&vault_bump_arr),
    ];

    // ── SPL tokens: move each fully, then close the emptied source ──────
    // Each token is a (source, dest, token_program) triple, so a vault holding
    // both SPL Token and Token-2022 migrates in one call.
    let mut rest = &accounts[9..];
    for _ in 0..num_tokens {
        let source_ata = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        let dest_ata = rest.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
        let token_program = rest.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
        rest = &rest[3..];

        let token_owner = token_program.key().as_ref();
        if token_owner != &SPL_TOKEN_PROGRAM_ID && token_owner != &SPL_TOKEN_2022_PROGRAM_ID {
            return Err(ProgramError::IncorrectProgramId);
        }
        if source_ata.owner().as_ref() != token_owner || dest_ata.owner().as_ref() != token_owner {
            return Err(ProgramError::IllegalOwner);
        }

        let amount = {
            let s = unsafe { source_ata.borrow_data_unchecked() };
            let d = unsafe { dest_ata.borrow_data_unchecked() };
            if s.len() < TOKEN_ACCOUNT_MIN_SIZE || d.len() < TOKEN_ACCOUNT_MIN_SIZE {
                return Err(ProgramError::InvalidAccountData);
            }
            // Source must be the vault's own token account…
            if &s[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32] != v1_vault.key().as_ref() {
                return Err(ProgramError::InvalidAccountData);
            }
            // …the destination must belong to the approved destination…
            if &d[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32] != destination.key().as_ref() {
                return Err(ProgramError::InvalidAccountData);
            }
            // …and both must be the same mint, so nothing lands in the wrong ATA.
            if s[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32]
                != d[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32]
            {
                return Err(ProgramError::InvalidAccountData);
            }
            u64::from_le_bytes(
                s[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            )
        };

        if amount > 0 {
            let mut transfer_data = [0u8; 9];
            transfer_data[0] = SPL_TRANSFER;
            transfer_data[1..9].copy_from_slice(&amount.to_le_bytes());
            invoke_signed_vault(
                token_program.key(),
                &[
                    meta_w(source_ata.key()),
                    meta_w(dest_ata.key()),
                    meta_signer(v1_vault.key()),
                ],
                &transfer_data,
                &[source_ata, dest_ata, v1_vault],
                &vault_seeds,
            );
        }

        // Reclaim the now-empty ATA's rent for the user.
        let close_data = [SPL_CLOSE_ACCOUNT];
        invoke_signed_vault(
            token_program.key(),
            &[
                meta_w(source_ata.key()),
                meta_w(refund_dest.key()),
                meta_signer(v1_vault.key()),
            ],
            &close_data,
            &[source_ata, refund_dest, v1_vault],
            &vault_seeds,
        );
    }

    // ── SOL: sweep the whole vault to the destination ───────────────────
    let vault_lamports = v1_vault.lamports();
    if vault_lamports > 0 {
        let mut transfer_data = [0u8; 12];
        transfer_data[0..4].copy_from_slice(&2u32.to_le_bytes()); // System::Transfer
        transfer_data[4..12].copy_from_slice(&vault_lamports.to_le_bytes());
        invoke_signed_vault(
            system_program.key(),
            &[meta_signer_w(v1_vault.key()), meta_w(destination.key())],
            &transfer_data,
            &[v1_vault, destination],
            &vault_seeds,
        );
    }

    // ── Close the v1 wallet and authority, rent to the refund destination ─
    close_program_account(v1_authority, refund_dest)?;
    close_program_account(v1_wallet, refund_dest)?;

    Ok(())
}

/// `invoke_signed` with the vault PDA seeds, over an ad-hoc account/meta list.
fn invoke_signed_vault(
    program: &Pubkey,
    metas: &[AccountMeta],
    data: &[u8],
    infos: &[&AccountInfo],
    vault_seeds: &[Seed],
) {
    let ix = Instruction {
        program_id: program,
        accounts: metas,
        data,
    };
    let cpi: Vec<Account> = infos.iter().map(|i| Account::from(*i)).collect();
    let signer: Signer = vault_seeds.into();
    unsafe {
        invoke_signed_unchecked(&ix, &cpi, &[signer]);
    }
}

fn meta_w(key: &Pubkey) -> AccountMeta<'_> {
    AccountMeta {
        pubkey: key,
        is_signer: false,
        is_writable: true,
    }
}
fn meta_signer(key: &Pubkey) -> AccountMeta<'_> {
    AccountMeta {
        pubkey: key,
        is_signer: true,
        is_writable: false,
    }
}
fn meta_signer_w(key: &Pubkey) -> AccountMeta<'_> {
    AccountMeta {
        pubkey: key,
        is_signer: true,
        is_writable: true,
    }
}

/// Zero a program-owned account and move its lamports to `refund_dest`.
///
/// Mirrors the closers in `manage`/`reclaim`, including the guard against the
/// refund being the account itself — that double-write burns the lamports and
/// aborts the transaction after the data is already cleared.
fn close_program_account(account: &AccountInfo, refund_dest: &AccountInfo) -> ProgramResult {
    if account.key() == refund_dest.key() {
        return Err(ProgramError::InvalidAccountData);
    }
    let lamports = account.lamports();
    unsafe {
        *refund_dest.borrow_mut_lamports_unchecked() = refund_dest
            .borrow_mut_lamports_unchecked()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        *account.borrow_mut_lamports_unchecked() = 0;
        account.borrow_mut_data_unchecked().fill(0);
    }
    Ok(())
}
