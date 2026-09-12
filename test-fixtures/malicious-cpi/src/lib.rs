//! Test fixture — a minimal "wrapper" program that forwards one instruction to
//! another program via CPI, preserving every account's `is_signer` /
//! `is_writable` flag.
//!
//! This models the realistic threat for H-1: a user signs a transaction that
//! calls some third-party program, and that program re-enters LazorKit's
//! `Execute` with the user's signer flag still attached. Nothing here is
//! exotic — it is the CPI pattern every router, batcher and aggregator uses.
//!
//! Not part of the root workspace. Build with `scripts/build-repro-fixtures.sh`.

#![allow(unexpected_cfgs)]

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed_with_bounds,
    entrypoint,
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

/// Upper bound on forwarded accounts. Generous for the reproduction, and the
/// bounded variant returns `ProgramResult`, so an inner failure propagates
/// instead of being swallowed — that matters for the control case in the test,
/// where the session path is *supposed* to reject the CPI.
const MAX_FORWARDED_ACCOUNTS: usize = 32;

/// Accounts:
///   `0`      the program to invoke (e.g. the LazorKit program account)
///   `1..n`   accounts forwarded verbatim, flags preserved
///
/// Instruction data is forwarded verbatim as the inner instruction's data.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let target = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let forwarded = &accounts[1..];

    let mut metas: Vec<AccountMeta> = Vec::with_capacity(forwarded.len());
    let mut infos: Vec<&AccountInfo> = Vec::with_capacity(forwarded.len());
    for acc in forwarded {
        metas.push(AccountMeta {
            pubkey: acc.key(),
            // The whole point: an outer signer stays a signer one level down.
            is_signer: acc.is_signer(),
            is_writable: acc.is_writable(),
        });
        infos.push(acc);
    }

    let ix = Instruction {
        program_id: target.key(),
        accounts: &metas,
        data: instruction_data,
    };

    // No PDA seeds — this program signs for nothing. Every privilege the inner
    // instruction sees is inherited from the outer transaction.
    invoke_signed_with_bounds::<MAX_FORWARDED_ACCOUNTS>(&ix, &infos, &[])
}
