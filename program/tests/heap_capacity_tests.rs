//! Execute and ExecuteDeferred size their heap buffers exactly.
//!
//! The program's heap is pinocchio's default: a 32 KiB bump allocator that
//! never frees. A `Vec` that outgrows its capacity copies itself into a new
//! buffer and leaves the old one allocated, so every doubling also pays for all
//! the sizes before it. Two of the program's buffers grew that way:
//!
//! - the accounts-hash preimage (33 bytes per account the hash walks), started
//!   at a guess of four accounts per inner instruction;
//! - the account-meta and CPI-account buffers Execute and ExecuteDeferred reuse
//!   across inner instructions (16 + 56 bytes per account), started at 32.
//!
//! A 1232-byte transaction left little room to grow them. A v1 transaction
//! (SIMD-0385, 4096 bytes) leaves plenty: on devnet, against the deployed
//! program, a passkey Execute ran out of memory with one inner instruction of
//! 128 accounts, with 70 + 70 and with 100 + 30, while 127, 64 + 64 and 100 + 20
//! fitted. The previous build (devnet `3584aec7…`) fails every test here except
//! the 16-instruction cap the same way, "memory allocation failed, out of
//! memory" — including payloads that never pass 64 accounts in one instruction
//! (16 × 16), because the preimage alone doubled past half the heap.
//!
//! Both buffers are now sized once, from the parsed instructions. For any
//! payload this allocates no more than the old code did, so nothing that landed
//! before can fail now.
//!
//! What bounds a payload now is what it needs. A passkey Execute (no policy)
//! allocates, in order:
//!
//! ```text
//!   40 × k                   the parsed instruction list
//! + 33 × (k + M)             the accounts-hash preimage, in one piece
//! + compact bytes + 32       the signed payload
//! + 44                       the challenge, base64url
//! + 72 × w                   account metas + CPI accounts, widest instruction
//! + 9 × M                    each inner instruction's own account list and flags
//! ≤ 32760                    32 KiB less the allocator's 8-byte cursor
//! ```
//!
//! for `k` inner instructions referencing `M` accounts in all, `w` in the
//! widest, plus up to 7 bytes of alignment after each byte buffer.
//! ExecuteDeferred drops the signed payload and the challenge, an Ed25519 or
//! session Execute the preimage too; a policy adds its own allocations. One
//! inner instruction can now name all 255 accounts the format allows (127
//! before); 16 equal ones about 41 each (15 before).
//! `the_accounts_hash_preimage_is_the_remaining_ceiling` pins the new limit, and
//! the 16-instruction cap stays as it was.
//!
//! The inner program is SPL Memo v1, which litesvm preloads and which reads no
//! account: it stands in for the Noop program of the devnet measurements, so
//! only LazorKit's own work is measured. litesvm 0.6 caps a CPI at 128 account
//! infos (Agave 4.x allows 255), so no inner instruction here is wider.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test heap_capacity_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::TransactionError,
};

const DISC_EXECUTE: u8 = 4;
const DISC_AUTHORIZE: u8 = 6;
const DISC_EXECUTE_DEFERRED: u8 = 7;

/// Every layout below puts the inner program at 5 and the accounts its
/// instructions reference from 6 on, so one compact encoding serves all three.
const IDX_MEMO: u8 = 5;
const IDX_FIRST_FILLER: u8 = 6;

/// Distinct read-only accounts the inner instructions reference, round robin,
/// the way a route's instructions share its accounts. No more than 24: litesvm
/// 0.6's compute-budget pass (Agave 2.2) assumes a 1232-byte packet and panics
/// on a program id past the 38th static key. The heap does not depend on how
/// many of the referenced accounts are distinct.
const FILLERS: usize = 24;

/// Where the instructions sysvar sits in a passkey Execute (payer, wallet,
/// authority, vault, sysvar) and in Authorize (… system program, rent, sysvar).
const EXECUTE_SYSVAR_IX_INDEX: u8 = 4;
const AUTHORIZE_SYSVAR_IX_INDEX: u8 = 6;

const EXPIRY_OFFSET: u16 = 100;

fn memo_v1() -> Pubkey {
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"
        .parse()
        .unwrap()
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Landed,
    OutOfMemory,
    Failed(String),
}

#[allow(clippy::result_large_err)]
fn outcome(
    result: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
) -> Outcome {
    match result {
        Ok(_) => Outcome::Landed,
        Err(failed) if failed.meta.logs.iter().any(|l| l.contains("out of memory")) => {
            Outcome::OutOfMemory
        },
        Err(failed) => Outcome::Failed(format!("{:?}\n{}", failed.err, failed.meta.pretty_logs())),
    }
}

struct Payload {
    fillers: Vec<Pubkey>,
}

impl Payload {
    fn new() -> Self {
        Self {
            fillers: (0..FILLERS).map(|_| Pubkey::new_unique()).collect(),
        }
    }

    /// One memo instruction per entry, each referencing that many accounts.
    fn compact(&self, widths: &[usize]) -> Vec<u8> {
        let ixs: Vec<(u8, Vec<u8>, Vec<u8>)> = widths
            .iter()
            .map(|&n| {
                let accounts = (0..n)
                    .map(|j| IDX_FIRST_FILLER + (j % FILLERS) as u8)
                    .collect();
                (IDX_MEMO, accounts, b"lazorkit".to_vec())
            })
            .collect();
        encode_compact(&ixs)
    }

    /// The accounts hash over [`Self::compact`]: the memo program and every
    /// filler are read-only non-signers, so each flags byte is zero.
    fn accounts_hash(&self, widths: &[usize]) -> [u8; 32] {
        let mut preimage = Vec::new();
        for &n in widths {
            preimage.extend_from_slice(memo_v1().as_ref());
            preimage.push(0);
            for j in 0..n {
                preimage.extend_from_slice(self.fillers[j % FILLERS].as_ref());
                preimage.push(0);
            }
        }
        Sha256::digest(&preimage).into()
    }

    /// The accounts from index 5 on: the memo program, then the fillers.
    fn accounts(&self) -> Vec<AccountMeta> {
        let mut out = vec![AccountMeta::new_readonly(memo_v1(), false)];
        out.extend(
            self.fillers
                .iter()
                .map(|k| AccountMeta::new_readonly(*k, false)),
        );
        out
    }
}

fn compute_limit() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

#[allow(clippy::result_large_err)]
fn send(
    context: &mut TestContext,
    ixs: &[Instruction],
    signers: &[&Keypair],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    // A failed send leaves the authority's counter where it was, so the next
    // attempt can be byte-identical; a fresh blockhash keeps it a new signature.
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, ixs, signers)
}

/// The passkey signs `signed_payload` for `w`, as the next counter.
fn passkey_sign(
    context: &TestContext,
    pk: &Passkey,
    w: &PasskeyWallet,
    discriminator: u8,
    sysvar_ix_index: u8,
    signed_payload: &[u8],
) -> (Instruction, Vec<u8>, u32) {
    let counter = authority_counter(&context.svm, w.authority) + 1;
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, sysvar_ix_index);
    let challenge = secp256r1_challenge(
        discriminator,
        &prefix,
        signed_payload,
        &context.payer.pubkey(),
        &w.wallet,
        counter,
        &context.program_id,
    );
    let (precompile, auth_payload) =
        passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge);
    (precompile, auth_payload, counter)
}

struct PasskeyFixture {
    context: TestContext,
    pk: Passkey,
    w: PasskeyWallet,
    payload: Payload,
}

impl PasskeyFixture {
    fn new() -> Self {
        let mut context = setup_test();
        let pk = Passkey::new();
        let w = create_passkey_wallet(&mut context, &pk);
        Self {
            context,
            pk,
            w,
            payload: Payload::new(),
        }
    }

    /// A passkey Execute whose inner instructions reference `widths` accounts.
    /// Checks the counter moved exactly when the transaction landed.
    fn execute(&mut self, widths: &[usize]) -> Outcome {
        let compact = self.payload.compact(widths);
        let mut signed_payload = compact.clone();
        signed_payload.extend_from_slice(&self.payload.accounts_hash(widths));
        let (precompile, auth_payload, counter) = passkey_sign(
            &self.context,
            &self.pk,
            &self.w,
            DISC_EXECUTE,
            EXECUTE_SYSVAR_IX_INDEX,
            &signed_payload,
        );

        let mut data = vec![DISC_EXECUTE];
        data.extend_from_slice(&compact);
        data.extend_from_slice(&auth_payload);
        let mut accounts = vec![
            AccountMeta::new(self.context.payer.pubkey(), true),
            AccountMeta::new_readonly(self.w.wallet, false),
            AccountMeta::new(self.w.authority, false),
            AccountMeta::new(self.w.vault, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ];
        accounts.extend(self.payload.accounts());
        let execute = Instruction {
            program_id: self.context.program_id,
            accounts: with_protocol_fee_accounts(accounts, &self.context),
            data,
        };

        let payer = self.context.payer.insecure_clone();
        let result = outcome(send(
            &mut self.context,
            &[compute_limit(), precompile, execute],
            &[&payer],
        ));
        let expected = if result == Outcome::Landed {
            counter
        } else {
            counter - 1
        };
        assert_eq!(
            authority_counter(&self.context.svm, self.w.authority),
            expected
        );
        result
    }

    /// Authorize (tx1) then ExecuteDeferred (tx2) of the same payload. tx1
    /// stores two hashes and nothing else, so it is never the one at risk.
    fn authorize_and_execute_deferred(&mut self, widths: &[usize]) -> Outcome {
        let compact = self.payload.compact(widths);
        let instructions_hash: [u8; 32] = Sha256::digest(&compact).into();
        let mut signed_payload = Vec::with_capacity(66);
        signed_payload.extend_from_slice(&instructions_hash);
        signed_payload.extend_from_slice(&self.payload.accounts_hash(widths));
        signed_payload.extend_from_slice(&EXPIRY_OFFSET.to_le_bytes());
        let (precompile, auth_payload, counter) = passkey_sign(
            &self.context,
            &self.pk,
            &self.w,
            DISC_AUTHORIZE,
            AUTHORIZE_SYSVAR_IX_INDEX,
            &signed_payload,
        );

        let deferred = Pubkey::find_program_address(
            &[
                lazorkit_program::seeds::DEFERRED,
                self.w.wallet.as_ref(),
                self.w.authority.as_ref(),
                &counter.to_le_bytes(),
            ],
            &self.context.program_id,
        )
        .0;
        let payer = self.context.payer.insecure_clone();

        let mut data = vec![DISC_AUTHORIZE];
        data.extend_from_slice(&signed_payload);
        data.extend_from_slice(&auth_payload);
        let authorize = Instruction {
            program_id: self.context.program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(self.w.wallet, false),
                AccountMeta::new(self.w.authority, false),
                AccountMeta::new(deferred, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            ],
            data,
        };
        assert_eq!(
            outcome(send(&mut self.context, &[precompile, authorize], &[&payer])),
            Outcome::Landed,
            "Authorize"
        );

        // tx2: payer, wallet, vault, DeferredExec, refund destination (the
        // Authorize payer), then the payload's accounts from index 5.
        let mut data = vec![DISC_EXECUTE_DEFERRED];
        data.extend_from_slice(&compact);
        let mut accounts = vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(self.w.wallet, false),
            AccountMeta::new(self.w.vault, false),
            AccountMeta::new(deferred, false),
            AccountMeta::new(payer.pubkey(), false),
        ];
        accounts.extend(self.payload.accounts());
        let execute_deferred = Instruction {
            program_id: self.context.program_id,
            accounts: with_protocol_fee_accounts(accounts, &self.context),
            data,
        };
        let result = outcome(send(
            &mut self.context,
            &[compute_limit(), execute_deferred],
            &[&payer],
        ));
        let consumed = self
            .context
            .svm
            .get_account(&deferred)
            .is_none_or(|a| a.lamports == 0);
        assert_eq!(consumed, result == Outcome::Landed, "DeferredExec closed");
        result
    }
}

/// An Ed25519-authority Execute (the session branch allocates the same way):
/// no accounts hash, only the reused buffers and each inner instruction's own.
fn ed25519_execute(widths: &[usize]) -> Outcome {
    let mut context = setup_test();
    let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
    let payload = Payload::new();

    let mut data = vec![DISC_EXECUTE];
    data.extend_from_slice(&payload.compact(widths));
    let mut accounts = vec![
        AccountMeta::new(context.payer.pubkey(), true),
        AccountMeta::new_readonly(wallet.wallet_pda, false),
        AccountMeta::new(wallet.owner_auth_pda, false),
        AccountMeta::new(wallet.vault_pda, false),
        AccountMeta::new_readonly(wallet.owner.pubkey(), true),
    ];
    accounts.extend(payload.accounts());
    let execute = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(accounts, &context),
        data,
    };
    let payer = context.payer.insecure_clone();
    outcome(send(
        &mut context,
        &[compute_limit(), execute],
        &[&payer, &wallet.owner],
    ))
}

fn assert_lands(label: &str, result: Outcome) {
    assert_eq!(result, Outcome::Landed, "{label}");
}

/// The shapes that ran out of memory on devnet: an inner instruction over 64
/// accounts doubles the reused buffers to 128 entries while the preimage
/// doubles past 4224 bytes. 127 and 64 + 64 fitted before too, and stay as
/// controls.
#[test]
fn passkey_execute_with_an_inner_instruction_over_64_accounts() {
    let mut f = PasskeyFixture::new();
    for widths in [
        &[127][..],
        &[64, 64],
        &[128],
        &[70, 70],
        &[100, 30],
        &[100, 100],
        &[128, 64, 32],
    ] {
        assert_lands(&format!("passkey Execute {widths:?}"), f.execute(widths));
    }
}

/// Never more than 64 accounts in one instruction, and still out of memory
/// before: with 16 instructions the preimage started at 2112 bytes and doubled
/// to 16896, leaving the 2112-, 4224- and 8448-byte buffers behind it. A heap
/// rule that looks only at the widest instruction cannot see this.
#[test]
fn passkey_execute_with_many_narrow_inner_instructions() {
    let mut f = PasskeyFixture::new();
    for widths in [&[16usize; 16][..], &[32; 8], &[24; 16]] {
        assert_lands(&format!("passkey Execute {widths:?}"), f.execute(widths));
    }
}

/// ExecuteDeferred hashes the same accounts and reuses the same buffers.
#[test]
fn execute_deferred_with_an_inner_instruction_over_64_accounts() {
    let mut f = PasskeyFixture::new();
    for widths in [&[128][..], &[70, 70], &[16; 16]] {
        assert_lands(
            &format!("ExecuteDeferred {widths:?}"),
            f.authorize_and_execute_deferred(widths),
        );
    }
}

/// Without the accounts hash the reused buffers were the cost: 32 → 64 → 128
/// entries of 72 bytes, 16 KiB for 9 KiB of live data, next to each inner
/// instruction's own 9 bytes per account.
#[test]
fn ed25519_execute_with_wide_inner_instructions() {
    for widths in [&[128usize; 2][..], &[128; 16]] {
        assert_lands(
            &format!("Ed25519 Execute {widths:?}"),
            ed25519_execute(widths),
        );
    }
}

/// What still bounds a payload: the preimage is hashed in one piece, 33 bytes
/// for each program id and account, and 16 instructions of 64 accounts make
/// 1040 of them — 34320 bytes, more than the whole heap. Half of that lands
/// now, and ran out of memory before.
#[test]
fn the_accounts_hash_preimage_is_the_remaining_ceiling() {
    let mut f = PasskeyFixture::new();
    assert_eq!(f.execute(&[64; 16]), Outcome::OutOfMemory);
    assert_lands("passkey Execute [64; 8]", f.execute(&[64; 8]));
}

/// The 16-instruction cap is unchanged (`compact::MAX_COMPACT_INSTRUCTIONS`):
/// a 17th is refused at parse, whatever the transaction has room for.
#[test]
fn sixteen_inner_instructions_stay_the_cap() {
    let mut f = PasskeyFixture::new();
    assert_lands("passkey Execute [8; 16]", f.execute(&[8; 16]));
    match f.execute(&[1; 17]) {
        Outcome::Failed(err) => assert!(
            err.starts_with(&format!(
                "{:?}",
                TransactionError::InstructionError(2, InstructionError::InvalidInstructionData)
            )),
            "{err}"
        ),
        other => panic!("17 inner instructions: {other:?}"),
    }
}
