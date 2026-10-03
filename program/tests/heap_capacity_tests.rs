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
//! fitted. The builds before this fix (develop's `efea949f…`; devnet's
//! `3584aec7…` on the tests without a policy) fail every test here except the
//! 16-instruction cap and the legacy policy shape the same way, "memory
//! allocation failed, out of memory" — including payloads that never pass 64
//! accounts in one instruction (16 × 16), because the preimage alone doubled
//! past half the heap.
//!
//! Both buffers are now sized once, from the parsed instructions. For any
//! payload this allocates no more than the old code did, so nothing that landed
//! before can fail now.
//!
//! What bounds a payload now is what it needs, and that is a sum. In the order
//! the program allocates:
//!
//! ```text
//!   40k                       the parsed inner instructions
//! + ⌈33(k + M) + C + 76⌉₈     passkey only: the accounts-hash preimage, in one
//!                             piece, the signed payload (C + 32), the challenge (44)
//! + 32a + 192t                policy only: the actions; a copy of each vault token account
//! + 72w                       account metas + CPI accounts, widest instruction
//! + Σ (8nᵢ + ⌈nᵢ⌉₈)           each inner instruction's account list and flags
//! + 48t + 32a                 policy only: the mint list; the actions again
//! ≤ 32760                     32 KiB less the allocator's 8-byte cursor
//! ```
//!
//! for `k` inner instructions of `nᵢ` accounts (`M` in all, `w` in the widest)
//! in `C` compact bytes, `a` actions and `t` unique writable vault-owned token
//! accounts. `⌈x⌉₈` rounds up to a multiple of 8 (the next allocation's
//! alignment), except for the last allocation of all. ExecuteDeferred's
//! preimage term is `⌈33(k + M)⌉₈` and it has no policy; an Ed25519 or session
//! Execute has no preimage term. One inner instruction can now name all 255
//! accounts the format allows (127 before); 16 equal ones about 41 each (15
//! before). `the_accounts_hash_preimage_is_the_remaining_ceiling` pins the new
//! limit, the `policy_*` tests the largest policy shapes a v1 and a legacy
//! transaction can address, and the 16-instruction cap stays as it was.
//!
//! Without a policy the inner program is SPL Memo v1, which litesvm preloads
//! and which reads no account: it stands in for the Noop program of the devnet
//! measurements, so only LazorKit's own work is measured. litesvm 0.6 caps a
//! CPI at 128 account infos (Agave 4.x allows 255), so no inner instruction
//! here is wider.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test heap_capacity_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::{v0, AddressLookupTableAccount, Message, VersionedMessage},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::{TransactionError, VersionedTransaction},
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

// ─────────────────────────────────────────────────────────────────────────
// The policy path
// ─────────────────────────────────────────────────────────────────────────
//
// A signer with a policy (a session with actions, or a Delegate) adds four
// allocations of its own, each sized exactly (D13): its `a` actions parsed
// before the CPIs (32 bytes each), a 192-byte copy of each of the `t` unique
// writable vault token accounts in the Execute, the mint list after the CPIs
// (48 bytes per copy) and the actions parsed again: `64a + 240t`. `t` is what a
// v1 transaction raises. A legacy transaction's 1232 bytes hold about 30
// addresses; a v1 transaction holds 64, and a policy Execute can spend all it
// does not need on vault token accounts.
//
// The shapes below are the largest a transaction of each kind can address
// with the most actions a policy holds: one listed SPL `Transfer` out of the
// vault, then System transfers of 0 lamports from the vault to itself that
// name the vault token accounts after their two accounts, as wide as the heap
// allows. (SPL Memo v1 stops with an access violation when handed an account
// that has data, so it cannot stand in here.) litesvm 0.6 cannot send a v1
// transaction, so the same instruction reaches the program through a v0 lookup
// table: the heap depends on the account list the program is handed, not on how
// the message encoded it. The v1 size is counted from the instructions.

/// `state::action::MAX_ACTIONS`: the most actions a policy holds.
const POLICY_ACTIONS: usize = 16;
const TOKEN_LIMIT: u64 = 1_000;
const TRANSFER_AMOUNT: u64 = 100;

/// SIMD-0385 v1: 4096 bytes and 64 addresses. Legacy and v0: 1232 bytes.
const V1_MAX_BYTES: usize = 4096;
const V1_MAX_ADDRESSES: usize = 64;
const LEGACY_MAX_BYTES: usize = 1232;

/// Both policy layouts: `0` payer · `1` wallet · `2` session or authority ·
/// `3` vault · `4` session key or Instructions sysvar · `5` SPL Token ·
/// `6` the transfer's destination · `7` System · `8..` the vault token
/// accounts, the transfer's source first · then the fee suffix. The entrypoint
/// strips the fee suffix before Execute sees the list, so System is passed
/// again at 7; one key, so no address more.
const IDX_VAULT: u8 = 3;
const IDX_TOKEN: u8 = 5;
const IDX_DESTINATION: u8 = 6;
const IDX_SYSTEM: u8 = 7;
const IDX_FIRST_VAULT_TOKEN: u8 = 8;

enum PolicySigner {
    /// An Ed25519 session key and its session.
    Session { key: Keypair, pda: Pubkey },
    /// A passkey Delegate and its authority.
    Passkey { pk: Passkey, pda: Pubkey },
}

struct PolicyFixture {
    context: TestContext,
    wallet: WalletFixture,
    signer: PolicySigner,
    destination: Pubkey,
    /// `t` vault token accounts; the first is the transfer's source.
    vault_tokens: Vec<Pubkey>,
}

/// Sixteen `TokenLimit` actions: the transfer's mint first, then fifteen
/// more. No whitelist, so the System program may be called.
fn token_limits(mint: Pubkey) -> Vec<u8> {
    let mut policy = action_token_limit(mint, TOKEN_LIMIT);
    for _ in 1..POLICY_ACTIONS {
        policy.extend_from_slice(&action_token_limit(Pubkey::new_unique(), TOKEN_LIMIT));
    }
    policy
}

impl PolicyFixture {
    /// A wallet with `t` vault token accounts, each of its own mint, and a
    /// signer whose policy holds sixteen `TokenLimit` actions.
    fn new(t: usize, passkey: bool) -> Self {
        assert!(t >= 1, "the transfer's source is a vault token account");
        let mut context = setup_test();
        let wallet = create_ed25519_wallet(&mut context, 1_000_000_000);
        let mint = Pubkey::new_unique();
        create_mint(&mut context.svm, mint, Pubkey::new_unique(), u64::MAX / 2);
        let policy = token_limits(mint);

        let signer = if passkey {
            let pk = Passkey::new();
            let pda = owner_adds_passkey_delegate(&mut context, &wallet, &pk, &policy);
            PolicySigner::Passkey { pk, pda }
        } else {
            let key = create_session_with_actions(&mut context, &wallet, &policy);
            let pda = session_pda_for(context.program_id, &wallet, &key);
            PolicySigner::Session { key, pda }
        };

        let destination = Pubkey::new_unique();
        create_token_account(&mut context.svm, destination, mint, Pubkey::new_unique(), 0);
        let vault_tokens = (0..t)
            .map(|i| {
                let address = Pubkey::new_unique();
                let account_mint = if i == 0 { mint } else { Pubkey::new_unique() };
                create_token_account(
                    &mut context.svm,
                    address,
                    account_mint,
                    wallet.vault_pda,
                    5_000,
                );
                address
            })
            .collect();

        Self {
            context,
            wallet,
            signer,
            destination,
            vault_tokens,
        }
    }

    /// The listed transfer, then one System transfer per entry of `widths`,
    /// each of that many accounts: the vault twice, then vault token accounts,
    /// round robin.
    fn compact(&self, widths: &[usize]) -> Vec<u8> {
        let t = self.vault_tokens.len();
        let mut ixs = vec![(
            IDX_TOKEN,
            vec![IDX_FIRST_VAULT_TOKEN, IDX_DESTINATION, IDX_VAULT],
            spl_transfer_data(TRANSFER_AMOUNT),
        )];
        for &n in widths {
            assert!(n >= 2, "a System transfer names two accounts");
            let mut accounts = vec![IDX_VAULT, IDX_VAULT];
            accounts.extend((0..n - 2).map(|j| IDX_FIRST_VAULT_TOKEN + (j % t) as u8));
            ixs.push((IDX_SYSTEM, accounts, system_transfer_data(0)));
        }
        encode_compact(&ixs)
    }

    fn execute_accounts(&self) -> Vec<AccountMeta> {
        let (pda, fifth) = match &self.signer {
            PolicySigner::Session { key, pda } => {
                (*pda, AccountMeta::new_readonly(key.pubkey(), true))
            },
            PolicySigner::Passkey { pda, .. } => (
                *pda,
                AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
            ),
        };
        let mut accounts = vec![
            AccountMeta::new(self.context.payer.pubkey(), true),
            AccountMeta::new_readonly(self.wallet.wallet_pda, false),
            AccountMeta::new(pda, false),
            AccountMeta::new(self.wallet.vault_pda, false),
            fifth,
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new(self.destination, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];
        accounts.extend(
            self.vault_tokens
                .iter()
                .map(|k| AccountMeta::new(*k, false)),
        );
        with_protocol_fee_accounts(accounts, &self.context)
    }

    /// The Execute's instructions, with no ComputeBudget instruction (a v1
    /// transaction carries its limits in the message), and its signers beside
    /// the payer.
    fn instructions(&self, widths: &[usize]) -> (Vec<Instruction>, Vec<&Keypair>) {
        let compact = self.compact(widths);
        let accounts = self.execute_accounts();
        let mut data = vec![DISC_EXECUTE];
        data.extend_from_slice(&compact);
        match &self.signer {
            PolicySigner::Session { key, .. } => {
                let execute = Instruction {
                    program_id: self.context.program_id,
                    accounts,
                    data,
                };
                (vec![execute], vec![key])
            },
            PolicySigner::Passkey { pk, pda } => {
                let mut signed_payload = compact.clone();
                signed_payload.extend_from_slice(&accounts_hash_of(
                    &accounts,
                    &compact,
                    &self.context.payer.pubkey(),
                ));
                let w = PasskeyWallet {
                    wallet: self.wallet.wallet_pda,
                    vault: self.wallet.vault_pda,
                    authority: *pda,
                };
                let (precompile, auth_payload, _) = passkey_sign(
                    &self.context,
                    pk,
                    &w,
                    DISC_EXECUTE,
                    EXECUTE_SYSVAR_IX_INDEX,
                    &signed_payload,
                );
                data.extend_from_slice(&auth_payload);
                let execute = Instruction {
                    program_id: self.context.program_id,
                    accounts,
                    data,
                };
                (vec![precompile, execute], vec![])
            },
        }
    }

    /// Send the Execute with the vault token accounts in a lookup table, which
    /// keeps the static keys inside what litesvm's compute-budget pass
    /// accepts. Checks the listed transfer moved exactly when it landed.
    fn execute(&mut self, widths: &[usize]) -> Outcome {
        advance(&mut self.context.svm);
        let table = lookup_table(&mut self.context.svm, &self.vault_tokens);
        let payer = self.context.payer.insecure_clone();
        let (ixs, others) = self.instructions(widths);
        let mut all = vec![compute_limit()];
        all.extend(ixs);
        let mut signers = vec![&payer];
        signers.extend(others);
        let message = v0::Message::try_compile(
            &payer.pubkey(),
            &all,
            &[table],
            self.context.svm.latest_blockhash(),
        )
        .expect("compile the Execute");
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &signers)
            .expect("sign the Execute");

        let before = token_amount(&self.context.svm, self.destination);
        let result = outcome(self.context.svm.send_transaction(tx));
        let moved = token_amount(&self.context.svm, self.destination) - before;
        let expected = if result == Outcome::Landed {
            TRANSFER_AMOUNT
        } else {
            0
        };
        assert_eq!(moved, expected, "{widths:?}: the listed transfer");
        result
    }

    /// Addresses and bytes of the Execute as a v1 transaction (SIMD-0385, the
    /// layout `deploy/relayer/src/txv1.mjs` reads), with a priority fee and
    /// both limits in its config.
    fn v1_size(&self, widths: &[usize]) -> (usize, usize) {
        let (ixs, others) = self.instructions(widths);
        let message = Message::new(&ixs, Some(&self.context.payer.pubkey()));
        let addresses = message.account_keys.len();
        let instructions: usize = message
            .instructions
            .iter()
            .map(|ix| 4 + ix.accounts.len() + ix.data.len())
            .sum();
        // 0x81, three header bytes, the config mask, the blockhash and two
        // counts; the addresses; the fee and the two limits; the instructions;
        // the signatures.
        let bytes = 42 + 32 * addresses + 16 + instructions + 64 * (1 + others.len());
        (addresses, bytes)
    }

    /// Bytes of the Execute as a legacy transaction.
    fn legacy_size(&self, widths: &[usize]) -> usize {
        let (ixs, _) = self.instructions(widths);
        let message = Message::new(&ixs, Some(&self.context.payer.pubkey()));
        1 + 64 * message.header.num_required_signatures as usize + message.serialize().len()
    }
}

/// `AddAuthority`: a passkey Delegate carrying `policy`, added by the Owner.
fn owner_adds_passkey_delegate(
    context: &mut TestContext,
    wallet: &WalletFixture,
    pk: &Passkey,
    policy: &[u8],
) -> Pubkey {
    let pda = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.wallet_pda.as_ref(),
            &pk.credential_id_hash,
        ],
        &context.program_id,
    )
    .0;
    let mut data = vec![1u8, 1, RANK_DELEGATE];
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(&pk.credential_id_hash);
    data.extend_from_slice(
        p256::ecdsa::VerifyingKey::from(&pk.signing_key)
            .to_encoded_point(true)
            .as_bytes(),
    );
    data.push(pk.rp_id.len() as u8);
    data.extend_from_slice(pk.rp_id.as_bytes());
    data.extend_from_slice(&(policy.len() as u16).to_le_bytes());
    data.extend_from_slice(policy);
    let add = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };
    let payer = context.payer.insecure_clone();
    let owner = wallet.owner.insecure_clone();
    try_send(&mut context.svm, &payer, &[add], &[&payer, &owner])
        .expect("AddAuthority (passkey Delegate)");
    pda
}

/// The accounts hash over `compact`, each key with the privileges the runtime
/// gives it: the union over every entry of that key, and the fee payer always
/// a writable signer.
fn accounts_hash_of(accounts: &[AccountMeta], compact: &[u8], payer: &Pubkey) -> [u8; 32] {
    let flags = |index: usize| -> u8 {
        let key = accounts[index].pubkey;
        let (mut signer, mut writable) = (key == *payer, key == *payer);
        for meta in accounts.iter().filter(|m| m.pubkey == key) {
            signer |= meta.is_signer;
            writable |= meta.is_writable;
        }
        (signer as u8) | ((writable as u8) << 1)
    };
    let mut preimage = Vec::new();
    let mut entry = |byte: u8| {
        let index = (byte & 0x7f) as usize;
        preimage.extend_from_slice(accounts[index].pubkey.as_ref());
        preimage.push(flags(index));
    };
    // `[count]`, then per instruction `[program][n][accounts][len u16][data]`.
    let mut at = 1;
    for _ in 0..compact[0] {
        entry(compact[at]);
        let n = compact[at + 1] as usize;
        for &byte in &compact[at + 2..at + 2 + n] {
            entry(byte);
        }
        let len = u16::from_le_bytes([compact[at + 2 + n], compact[at + 3 + n]]) as usize;
        at += 4 + n + len;
    }
    Sha256::digest(&preimage).into()
}

/// An active address lookup table holding `addresses`, written directly: the
/// `ProgramState::LookupTable` header (bincode, padded to 56 bytes), then the
/// keys. Every key resolves, whatever the slot.
fn lookup_table(svm: &mut litesvm::LiteSVM, addresses: &[Pubkey]) -> AddressLookupTableAccount {
    const META_SIZE: usize = 56;
    let key = Pubkey::new_unique();
    let mut data = vec![0u8; META_SIZE];
    // ProgramState::LookupTable, never deactivated; last_extended_slot stays 0,
    // and every key was extended before it.
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    data[20] = addresses.len() as u8;
    for address in addresses {
        data.extend_from_slice(address.as_ref());
    }
    svm.set_account(
        key,
        solana_sdk::account::Account {
            lamports: 1_000_000_000,
            data,
            owner: "AddressLookupTab1e1111111111111111111111111"
                .parse()
                .unwrap(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set the lookup table");
    AddressLookupTableAccount {
        key,
        addresses: addresses.to_vec(),
    }
}

/// A session with sixteen actions and the most vault token accounts a v1
/// transaction can address beside it: 64, less the payer, the program, the
/// wallet, the session, the vault, the session key, SPL Token, the
/// destination and the four fee accounts, is 52. Fifteen System transfers of
/// 89 accounts fit the heap and 90 do not; the transaction has room for 102.
/// On the policy path the heap binds before a v1 transaction does. Develop's
/// build (`efea949f…`), whose reused buffers doubled from 32, ran out of
/// memory past 64.
#[test]
fn policy_session_at_the_v1_address_cap() {
    let t = V1_MAX_ADDRESSES - 12;
    let mut f = PolicyFixture::new(t, false);
    assert_eq!(f.v1_size(&[89; 15]).0, V1_MAX_ADDRESSES);
    assert!(f.v1_size(&[102; 15]).1 <= V1_MAX_BYTES);
    assert!(f.v1_size(&[103; 15]).1 > V1_MAX_BYTES);

    assert_lands("session, t = 52, 15 × 89", f.execute(&[89; 15]));
    assert_eq!(f.execute(&[90; 15]), Outcome::OutOfMemory);
    let PolicySigner::Session { pda, .. } = &f.signer else {
        unreachable!()
    };
    assert_eq!(
        session_action_u64(&f.context.svm, *pda, 0, 32),
        TOKEN_LIMIT - TRANSFER_AMOUNT,
        "charged once, by the Execute that landed"
    );
}

/// A passkey Delegate with sixteen actions: the passkey path's accounts hash,
/// signed payload and challenge, and the policy's allocations, together. Its
/// fixed addresses are the payer, the program, the Secp256r1 program, the
/// wallet, the authority, the vault, the Instructions sysvar, SPL Token, the
/// destination and the four fee accounts, which leaves 51 for vault token
/// accounts. Fifteen System transfers of 24 accounts fit and 25 do not
/// (develop: 8), where the transaction has room for 81 (with this suite's
/// clientDataJSON). The tightest path the program has.
#[test]
fn policy_passkey_delegate_at_the_v1_address_cap() {
    let t = V1_MAX_ADDRESSES - 13;
    let mut f = PolicyFixture::new(t, true);
    assert_eq!(f.v1_size(&[24; 15]).0, V1_MAX_ADDRESSES);
    assert!(f.v1_size(&[81; 15]).1 <= V1_MAX_BYTES);
    assert!(f.v1_size(&[82; 15]).1 > V1_MAX_BYTES);

    assert_lands("passkey Delegate, t = 51, 15 × 24", f.execute(&[24; 15]));
    assert_eq!(f.execute(&[25; 15]), Outcome::OutOfMemory);
}

/// A legacy transaction addresses at most 19 vault token accounts beside a
/// session with sixteen actions and one listed transfer, far from the heap's
/// limit on this build and on develop's alike. In 1232 bytes only an inner
/// instruction wider than 128 accounts tells the two builds apart (develop's
/// reused buffers doubled to 256 entries, 34,560 bytes, for it), and litesvm
/// 0.6 cannot pass one to a CPI.
#[test]
fn policy_session_at_the_legacy_size_cap() {
    let t = 19;
    assert!(PolicyFixture::new(t + 1, false).legacy_size(&[]) > LEGACY_MAX_BYTES);
    let mut f = PolicyFixture::new(t, false);
    assert!(f.legacy_size(&[]) <= LEGACY_MAX_BYTES);
    assert_lands("session, t = 19, legacy", f.execute(&[]));
}
