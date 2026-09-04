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
//!  7. []                 SPL token program (only read when num_tokens > 0)
//!  8. []                 sysvar instructions (Secp256r1 only)
//!  9. [signer]           Ed25519 signer (Ed25519 only; ignored for passkeys)
//! 10..                   per token: [writable] source ATA, [writable] dest ATA
//! ```
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
};

/// SPL Token / Token-2022 program ids, and the token-account field offsets we
/// read. Same values `execute::actions` uses; repeated here so this money path
/// is self-contained.
const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
const SPL_TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];
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
    let token_program = next()?;
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

    // The passkey (or Ed25519 key) approves the destination, and nothing else
    // routes the funds. Binding the destination into the signed challenge is
    // what stops a relayer redirecting the sweep.
    let signed_payload = destination.key().as_ref();
    let auth_data = unsafe { v1_authority.borrow_mut_data_unchecked() };
    match auth_header.authority_type {
        0 => {
            Ed25519Authenticator.authenticate(
                accounts,
                auth_data,
                &[],
                signed_payload,
                &[17],
                program_id,
            )?;
        },
        1 => {
            Secp256r1Authenticator.authenticate(
                accounts,
                auth_data,
                auth_payload,
                signed_payload,
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
    let mut rest = &accounts[10..];
    for _ in 0..num_tokens {
        let source_ata = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        let dest_ata = rest.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
        rest = &rest[2..];

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
