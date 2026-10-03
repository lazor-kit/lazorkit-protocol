//! D13 — what a policy does not name, SOL or a mint, may not leave the vault.
//!
//! A policy-bound signer (a session with actions, or a Delegate authority) used
//! to be limited only in the assets its actions named. A mint no `Token*`
//! action listed had no balance check at all, so a session holding
//! `TokenLimit(USDC)` and a whitelist of SPL Token could transfer every other
//! token in the vault; a policy with no `Sol*` action could spend all its SOL.
//! A listed mint leaked too: "before" was summed over the token accounts the
//! vault owned before the CPIs and "after" over those it owned after, so tokens
//! moved into a token account initialised for the vault during the Execute
//! counted as kept, and an `Approve` on that account went unseen.
//!
//! Now, for any Execute whose signer carries a policy:
//!
//! - the vault's net SOL may not fall unless a `Sol*` action names SOL (3037);
//! - the vault's net balance of a mint, over the writable vault-owned token
//!   accounts in the Execute before the CPIs, may not fall unless a `Token*`
//!   action names that mint (3038), and for a named mint that same net is what
//!   the limit is charged;
//! - each of those accounts keeps everything but its balance, and a token
//!   account that became vault-owned during the Execute carries no delegate
//!   and no close authority (3032).
//!
//! Positive flows `p*`, negative flows `n*`, regressions `r*` (unbounded
//! signers, the deferred path, the program check), heap shapes `h1_*`, the
//! runtime's 255-account limit `h2_*`, and compute units `c1_*`. On develop
//! every `n*` test but `n18` lands. Accounts are written by hand, at the
//! offsets the program reads; the SPL programs are the ones litesvm 0.6 loads
//! (SPL Token 3.5.0, Token-2022 5.0.2, ATA 1.1.1).
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test policy_unlisted_assets_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::{keypair::keypair_from_seed, Signer},
};

/// `AuthError::ActionUnlistedSolOutflow`
const ERR_UNLISTED_SOL: u32 = 3037;
/// `AuthError::ActionUnlistedTokenOutflow`
const ERR_UNLISTED_TOKEN: u32 = 3038;
/// `AuthError::SessionTokenAuthorityChanged`
const ERR_TOKEN_AUTHORITY_CHANGED: u32 = 3032;
/// `AuthError::ActionTokenLimitExceeded`
const ERR_TOKEN_LIMIT: u32 = 3026;
/// `AuthError::PermissionDenied`
const ERR_PERMISSION_DENIED: u32 = 3002;
/// `AuthError::ActionProgramBlacklisted`
const ERR_PROGRAM_BLACKLISTED: u32 = 3022;

const VAULT_LAMPORTS: u64 = 1_000_000_000;
const DECIMALS: u8 = 6;

/// `TokenLimit.remaining` and `SolLimit.remaining`, relative to the action data.
const TOKEN_REMAINING: usize = 32;
const SOL_REMAINING: usize = 0;
/// `TokenRecurringLimit.spent` and `SolRecurringLimit.spent`, likewise.
const TOKEN_RECURRING_SPENT: usize = 40;
const SOL_RECURRING_SPENT: usize = 8;

/// Every Execute here lays its accounts out as `0` payer · `1` wallet ·
/// `2` authority · `3` vault · `4` the actor's key, then whatever the test adds.
const IDX_VAULT: u8 = 3;
const IDX_ACTOR: u8 = 4;

fn memo_program_id() -> Pubkey {
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        .parse()
        .unwrap()
}

/// What signs an Execute: a session key and its session PDA, or an Ed25519
/// key and its authority PDA.
struct Actor {
    key: Keypair,
    pda: Pubkey,
}

/// The accounts and compact instructions of one Execute. The actor's key sits
/// at [`IDX_ACTOR`], writable, so an inner instruction can be forwarded its
/// signature or have it pay.
struct Exec {
    accounts: Vec<AccountMeta>,
    ixs: Vec<(u8, Vec<u8>, Vec<u8>)>,
    compute_limit: bool,
}

impl Exec {
    fn new(actor: &Actor) -> Self {
        Self {
            accounts: vec![AccountMeta::new(actor.key.pubkey(), true)],
            ixs: Vec::new(),
            compute_limit: false,
        }
    }

    /// Append an account and return its index. Appending the same key twice
    /// passes it twice.
    fn account(&mut self, meta: AccountMeta) -> u8 {
        self.accounts.push(meta);
        (3 + self.accounts.len()) as u8
    }

    fn writable(&mut self, key: Pubkey) -> u8 {
        self.account(AccountMeta::new(key, false))
    }

    fn readonly(&mut self, key: Pubkey) -> u8 {
        self.account(AccountMeta::new_readonly(key, false))
    }

    fn call(&mut self, program: u8, accounts: &[u8], data: Vec<u8>) {
        self.ixs.push((program, accounts.to_vec(), data));
    }
}

struct Fx {
    context: TestContext,
    wallet: WalletFixture,
}

impl Fx {
    fn new() -> Self {
        let mut context = setup_test();
        let wallet = create_ed25519_wallet(&mut context, VAULT_LAMPORTS);
        Self { context, wallet }
    }

    /// A fixture whose payer and wallet are the same on every run, so the
    /// fee record's and the vault's bump searches cost the same: each extra
    /// bump `find_program_address` tries is about 1,500 CU, more than the
    /// differences [`c1_compute_units_of_the_policy_path`] measures.
    fn deterministic() -> Self {
        let mut context = setup_test();
        let payer = keypair_from_seed(&[0x5A; 32]).unwrap();
        context
            .svm
            .airdrop(&payer.pubkey(), 10_000_000_000)
            .unwrap();
        context.payer = payer;
        let owner = keypair_from_seed(&[0x0E; 32]).unwrap();
        let wallet = create_ed25519_wallet_with(&mut context, VAULT_LAMPORTS, [0x77; 32], owner);
        Self { context, wallet }
    }

    fn vault(&self) -> Pubkey {
        self.wallet.vault_pda
    }

    /// A session carrying `actions`, its key funded so it can pay for things.
    fn session(&mut self, actions: &[u8]) -> Actor {
        let key = create_session_with_actions(&mut self.context, &self.wallet, actions);
        let pda = session_pda_for(self.context.program_id, &self.wallet, &key);
        self.context
            .svm
            .airdrop(&key.pubkey(), 1_000_000_000)
            .unwrap();
        Actor { key, pda }
    }

    /// An Ed25519 Delegate carrying `policy`, added by the Owner.
    fn delegate(&mut self, policy: &[u8]) -> Actor {
        let key = Keypair::new();
        let pda = owner_adds_ed25519(&mut self.context, &self.wallet, &key, RANK_DELEGATE, policy)
            .expect("AddAuthority (Delegate)");
        Actor { key, pda }
    }

    fn owner(&self) -> Actor {
        Actor {
            key: self.wallet.owner.insecure_clone(),
            pda: self.wallet.owner_auth_pda,
        }
    }

    fn mint(&mut self) -> Pubkey {
        self.mint_with(spl_token_id(), None)
    }

    fn mint_with(&mut self, program: Pubkey, freeze: Option<Pubkey>) -> Pubkey {
        let mint = Pubkey::new_unique();
        create_mint_with(
            &mut self.context.svm,
            program,
            mint,
            Pubkey::new_unique(),
            freeze,
            u64::MAX / 2,
            DECIMALS,
            &[],
        );
        mint
    }

    /// An SPL Token account with no options.
    fn token_account(&mut self, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
        self.token_account_with(
            spl_token_id(),
            mint,
            owner,
            amount,
            TokenAccountOpts::default(),
        )
    }

    fn token_account_with(
        &mut self,
        program: Pubkey,
        mint: Pubkey,
        owner: Pubkey,
        amount: u64,
        opts: TokenAccountOpts,
    ) -> Pubkey {
        let address = Pubkey::new_unique();
        create_token_account_with(
            &mut self.context.svm,
            program,
            address,
            mint,
            owner,
            amount,
            opts,
        );
        address
    }

    fn lamports(&self, key: &Pubkey) -> u64 {
        self.context.svm.get_balance(key).unwrap_or(0)
    }

    fn amount(&self, account: Pubkey) -> u64 {
        token_amount(&self.context.svm, account)
    }

    #[allow(clippy::result_large_err)]
    fn execute(
        &mut self,
        actor: &Actor,
        exec: Exec,
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        advance(&mut self.context.svm);
        let mut ixs = Vec::new();
        if exec.compute_limit {
            ixs.push(ComputeBudgetInstruction::set_compute_unit_limit(1_400_000));
        }
        ixs.push(Instruction {
            program_id: self.context.program_id,
            accounts: execute_accounts(&self.context, &self.wallet, actor.pda, exec.accounts),
            data: execute_data(&exec.ixs),
        });
        let payer = self.context.payer.insecure_clone();
        try_send(&mut self.context.svm, &payer, &ixs, &[&payer, &actor.key])
    }

    /// Execute and require success, printing the logs if it fails.
    fn execute_ok(&mut self, actor: &Actor, exec: Exec, what: &str) -> u64 {
        match self.execute(actor, exec) {
            Ok(meta) => meta.compute_units_consumed,
            Err(failed) => panic!(
                "{what}: expected success, got {:?}\n{}",
                failed.err,
                failed.meta.pretty_logs()
            ),
        }
    }
}

/// One SPL `Transfer` of `amount` from `source` to `destination`, authorized
/// by the account at `authority`.
fn transfer(exec: &mut Exec, token: u8, source: u8, destination: u8, authority: u8, amount: u64) {
    exec.call(
        token,
        &[source, destination, authority],
        spl_transfer_data(amount),
    );
}

fn token_limit_policy(mint: Pubkey, limit: u64) -> Vec<u8> {
    let mut actions = action_token_limit(mint, limit);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    actions
}

/// A TokenLimit(A) session with a vault account of A holding `amount`.
struct Listed {
    actor: Actor,
    mint: Pubkey,
    vault_ata: Pubkey,
}

fn listed_session(fx: &mut Fx, limit: u64, amount: u64) -> Listed {
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, amount);
    let actor = fx.session(&token_limit_policy(mint, limit));
    Listed {
        actor,
        mint,
        vault_ata,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Positive flows
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn p1_listed_transfer_within_limit_is_charged() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let dest = fx.token_account(a.mint, Pubkey::new_unique(), 0);

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(a.vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 400);
    fx.execute_ok(&a.actor, exec, "P1");

    assert_eq!(fx.amount(a.vault_ata), 4_600);
    assert_eq!(fx.amount(dest), 400);
    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        600
    );
}

#[test]
fn p2_unlisted_inflow_passes() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let b = fx.mint();
    let vault = fx.vault();
    let vault_b = fx.token_account(b, vault, 0);
    let session_b = fx.token_account(b, a.actor.key.pubkey(), 300);

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(session_b);
    let dst = exec.writable(vault_b);
    transfer(&mut exec, token, src, dst, forward_signer(IDX_ACTOR), 300);
    fx.execute_ok(&a.actor, exec, "P2");

    assert_eq!(fx.amount(vault_b), 300);
    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        1_000
    );
}

/// The shape of a swap: the listed mint goes out, an unlisted one comes in
/// to an account the vault already had. Only the listed mint is charged.
#[test]
fn p3_swap_shape_charges_the_listed_side_only() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let b = fx.mint();
    let vault = fx.vault();
    let session_key = a.actor.key.pubkey();
    let vault_b = fx.token_account(b, vault, 0);
    let session_a = fx.token_account(a.mint, session_key, 0);
    let session_b = fx.token_account(b, session_key, 250);

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let va = exec.writable(a.vault_ata);
    let sa = exec.writable(session_a);
    let sb = exec.writable(session_b);
    let vb = exec.writable(vault_b);
    transfer(&mut exec, token, va, sa, IDX_VAULT, 400);
    transfer(&mut exec, token, sb, vb, forward_signer(IDX_ACTOR), 250);
    fx.execute_ok(&a.actor, exec, "P3");

    assert_eq!(fx.amount(vault_b), 250);
    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        600
    );
}

/// The output ATA is created in the same Execute, paid by the vault: rent is
/// SOL leaving the vault, so the policy needs a SOL action to cover it.
#[test]
fn p4a_output_ata_created_by_the_vault_is_charged_to_sol_limit() {
    let mut fx = Fx::new();
    let a_mint = fx.mint();
    let b = fx.mint();
    let vault = fx.vault();
    let vault_a = fx.token_account(a_mint, vault, 5_000);
    let mut actions = action_sol_limit(10_000_000);
    actions.extend_from_slice(&token_limit_policy(a_mint, 1_000));
    actions.extend_from_slice(&action_program_whitelist(ata_program_id()));
    let actor = fx.session(&actions);
    let session_key = actor.key.pubkey();
    let session_a = fx.token_account(a_mint, session_key, 0);
    let session_b = fx.token_account(b, session_key, 250);
    let ata_b = ata_address(vault, b, spl_token_id());
    let vault_before = fx.lamports(&vault);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let ata = exec.readonly(ata_program_id());
    let system = exec.readonly(solana_sdk::system_program::id());
    let mint_b = exec.readonly(b);
    let new_ata = exec.writable(ata_b);
    let va = exec.writable(vault_a);
    let sa = exec.writable(session_a);
    let sb = exec.writable(session_b);
    exec.call(
        ata,
        &[IDX_VAULT, new_ata, IDX_VAULT, mint_b, system, token],
        ata_create_idempotent_data(),
    );
    transfer(&mut exec, token, va, sa, IDX_VAULT, 400);
    transfer(
        &mut exec,
        token,
        sb,
        new_ata,
        forward_signer(IDX_ACTOR),
        250,
    );
    fx.execute_ok(&actor, exec, "P4a");

    let rent = vault_before - fx.lamports(&vault);
    assert_eq!(rent, fx.context.svm.minimum_balance_for_rent_exemption(165));
    assert_eq!(fx.amount(ata_b), 250);
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 0, SOL_REMAINING),
        10_000_000 - rent
    );
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 1, TOKEN_REMAINING),
        600
    );
}

/// The same, with the session key paying the rent: no SOL leaves the vault,
/// so no SOL action is needed.
#[test]
fn p4b_output_ata_paid_by_the_session_key_needs_no_sol_action() {
    let mut fx = Fx::new();
    let a_mint = fx.mint();
    let b = fx.mint();
    let vault = fx.vault();
    let mut actions = token_limit_policy(a_mint, 1_000);
    actions.extend_from_slice(&action_program_whitelist(ata_program_id()));
    let actor = fx.session(&actions);
    let session_b = fx.token_account(b, actor.key.pubkey(), 250);
    let ata_b = ata_address(vault, b, spl_token_id());
    let vault_before = fx.lamports(&vault);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let ata = exec.readonly(ata_program_id());
    let system = exec.readonly(solana_sdk::system_program::id());
    let mint_b = exec.readonly(b);
    let new_ata = exec.writable(ata_b);
    let sb = exec.writable(session_b);
    exec.call(
        ata,
        &[
            forward_signer(IDX_ACTOR),
            new_ata,
            IDX_VAULT,
            mint_b,
            system,
            token,
        ],
        ata_create_idempotent_data(),
    );
    transfer(
        &mut exec,
        token,
        sb,
        new_ata,
        forward_signer(IDX_ACTOR),
        250,
    );
    fx.execute_ok(&actor, exec, "P4b");

    assert_eq!(fx.lamports(&vault), vault_before);
    assert_eq!(fx.amount(ata_b), 250);
}

/// Wrapping SOL spends SOL, charged to the SOL limit; the wSOL it buys is an
/// inflow.
#[test]
fn p5_wrap_sol_into_an_existing_native_account() {
    let mut fx = Fx::new();
    let vault = fx.vault();
    let reserve = fx.context.svm.minimum_balance_for_rent_exemption(165);
    let wsol = fx.token_account_with(
        spl_token_id(),
        native_mint(),
        vault,
        0,
        TokenAccountOpts {
            native_reserve: Some(reserve),
            ..Default::default()
        },
    );
    let mut actions = action_sol_limit(10_000_000);
    actions.extend_from_slice(&action_program_whitelist(solana_sdk::system_program::id()));
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let system = exec.readonly(solana_sdk::system_program::id());
    let token = exec.readonly(spl_token_id());
    let w = exec.writable(wsol);
    exec.call(system, &[IDX_VAULT, w], system_transfer_data(1_000_000));
    exec.call(token, &[w], spl_sync_native_data());
    fx.execute_ok(&actor, exec, "P5");

    assert_eq!(fx.amount(wsol), 1_000_000);
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 0, SOL_REMAINING),
        9_000_000
    );
}

/// A temporary wSOL account created, filled, and closed back to the vault
/// within the Execute: net SOL is unchanged, so no SOL action is needed.
#[test]
fn p6_temporary_wsol_round_trip_needs_no_sol_action() {
    let mut fx = Fx::new();
    create_native_mint(&mut fx.context.svm);
    let vault = fx.vault();
    let mut actions = action_program_whitelist(solana_sdk::system_program::id());
    actions.extend_from_slice(&action_program_whitelist(ata_program_id()));
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let actor = fx.session(&actions);
    let wsol_ata = ata_address(vault, native_mint(), spl_token_id());
    let vault_before = fx.lamports(&vault);

    let mut exec = Exec::new(&actor);
    let system = exec.readonly(solana_sdk::system_program::id());
    let ata = exec.readonly(ata_program_id());
    let token = exec.readonly(spl_token_id());
    let mint = exec.readonly(native_mint());
    let w = exec.writable(wsol_ata);
    exec.call(
        ata,
        &[IDX_VAULT, w, IDX_VAULT, mint, system, token],
        ata_create_idempotent_data(),
    );
    exec.call(system, &[IDX_VAULT, w], system_transfer_data(5_000_000));
    exec.call(token, &[w], spl_sync_native_data());
    exec.call(token, &[w, IDX_VAULT, IDX_VAULT], spl_close_account_data());
    fx.execute_ok(&actor, exec, "P6");

    assert_eq!(fx.lamports(&vault), vault_before);
    assert_eq!(fx.lamports(&wsol_ata), 0);
}

#[test]
fn p7_unlisted_mint_moved_between_vault_accounts_nets_to_zero() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let b = fx.mint();
    let vault = fx.vault();
    let b1 = fx.token_account(b, vault, 500);
    let b2 = fx.token_account(b, vault, 0);

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let x = exec.writable(b1);
    let y = exec.writable(b2);
    transfer(&mut exec, token, x, y, IDX_VAULT, 200);
    fx.execute_ok(&a.actor, exec, "P7");

    assert_eq!(fx.amount(b1), 300);
    assert_eq!(fx.amount(b2), 200);
}

/// `ImmutableOwner`: type 7, no value. Every Token-2022 ATA carries it.
fn immutable_owner_tlv() -> Vec<u8> {
    vec![7, 0, 0, 0]
}

#[test]
fn p8a_token_2022_account_with_an_extension_listed_transfer() {
    let mut fx = Fx::new();
    let t22 = spl_token_2022_id();
    let mint = fx.mint_with(t22, None);
    let vault = fx.vault();
    let opts = || TokenAccountOpts {
        extensions: immutable_owner_tlv(),
        ..Default::default()
    };
    let vault_t = fx.token_account_with(t22, mint, vault, 5_000, opts());
    let dest = fx.token_account_with(t22, mint, Pubkey::new_unique(), 0, opts());
    let mut actions = action_token_limit(mint, 1_000);
    actions.extend_from_slice(&action_program_whitelist(t22));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(t22);
    let src = exec.writable(vault_t);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 300);
    fx.execute_ok(&actor, exec, "P8a");

    assert_eq!(fx.amount(vault_t), 4_700);
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 0, TOKEN_REMAINING),
        700
    );
}

/// `TransferFeeConfig` (type 1, 108 bytes): both fees at `bps`, no cap.
fn transfer_fee_config_tlv(bps: u16) -> Vec<u8> {
    let mut v = vec![1, 0, 108, 0];
    v.extend_from_slice(&[0u8; 32]); // transfer_fee_config_authority: none
    v.extend_from_slice(&[0u8; 32]); // withdraw_withheld_authority: none
    v.extend_from_slice(&0u64.to_le_bytes()); // withheld_amount
    for _ in 0..2 {
        v.extend_from_slice(&0u64.to_le_bytes()); // epoch
        v.extend_from_slice(&u64::MAX.to_le_bytes()); // maximum_fee
        v.extend_from_slice(&bps.to_le_bytes());
    }
    v
}

/// `TransferFeeAmount` (type 2, 8 bytes): `withheld_amount`.
fn transfer_fee_amount_tlv() -> Vec<u8> {
    let mut v = vec![2, 0, 8, 0];
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

/// An inbound transfer of a transfer-fee mint raises the receiving account's
/// `withheld_amount`, in its extension area. Extension bytes are not frozen,
/// so receiving still works.
#[test]
fn p8b_inbound_transfer_fee_mint_changes_extension_bytes_and_passes() {
    let mut fx = Fx::new();
    let t22 = spl_token_2022_id();
    let mint = Pubkey::new_unique();
    create_mint_with(
        &mut fx.context.svm,
        t22,
        mint,
        Pubkey::new_unique(),
        None,
        u64::MAX / 2,
        DECIMALS,
        &transfer_fee_config_tlv(100),
    );
    let vault = fx.vault();
    let opts = || TokenAccountOpts {
        extensions: transfer_fee_amount_tlv(),
        ..Default::default()
    };
    let vault_t = fx.token_account_with(t22, mint, vault, 0, opts());
    let listed = fx.mint();
    let mut actions = token_limit_policy(listed, 1_000);
    actions.extend_from_slice(&action_program_whitelist(t22));
    let actor = fx.session(&actions);
    let session_t = fx.token_account_with(t22, mint, actor.key.pubkey(), 10_000, opts());

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(t22);
    let src = exec.writable(session_t);
    let m = exec.readonly(mint);
    let dst = exec.writable(vault_t);
    exec.call(
        token,
        &[src, m, dst, forward_signer(IDX_ACTOR)],
        spl_transfer_checked_data(10_000, DECIMALS),
    );
    fx.execute_ok(&actor, exec, "P8b");

    assert_eq!(fx.amount(vault_t), 9_900);
    let data = fx.context.svm.get_account(&vault_t).unwrap().data;
    let withheld = u64::from_le_bytes(data[170..178].try_into().unwrap());
    assert_eq!(
        withheld, 100,
        "the fee was withheld in the vault account's extension"
    );
}

/// A delegate the Owner set on a vault account survives a session's transfer.
#[test]
fn p9_an_owner_set_delegate_is_left_alone() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let delegate = Pubkey::new_unique();
    let vault_ata = fx.token_account_with(
        spl_token_id(),
        mint,
        vault,
        5_000,
        TokenAccountOpts {
            delegate: Some((delegate, 10)),
            ..Default::default()
        },
    );
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let actor = fx.session(&token_limit_policy(mint, 1_000));

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    fx.execute_ok(&actor, exec, "P9");

    assert_eq!(
        token_account_delegate(&fx.context.svm, vault_ata),
        Some(delegate)
    );
}

/// An account passed twice is counted once: the spend is charged exactly.
#[test]
fn p10_an_account_passed_twice_is_charged_once() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let dest = fx.token_account(a.mint, Pubkey::new_unique(), 0);

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(a.vault_ata);
    let _again = exec.writable(a.vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    fx.execute_ok(&a.actor, exec, "P10");

    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        900
    );
}

#[test]
fn p11_whitelist_only_session_moves_nothing_and_passes() {
    let mut fx = Fx::new();
    let actor = fx.session(&action_program_whitelist(memo_program_id()));
    let vault_before = fx.lamports(&fx.vault());

    let mut exec = Exec::new(&actor);
    let memo = exec.readonly(memo_program_id());
    exec.call(memo, &[], b"lazorkit".to_vec());
    fx.execute_ok(&actor, exec, "P11");

    assert_eq!(fx.lamports(&fx.vault()), vault_before);
}

/// The engine serves a Delegate's policy the same way it serves a session's.
#[test]
fn p12_delegate_transfers_a_listed_mint_within_its_limit() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let mut policy = action_sol_limit(1_000_000);
    policy.extend_from_slice(&token_limit_policy(mint, 1_000));
    let actor = fx.delegate(&policy);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 400);
    fx.execute_ok(&actor, exec, "P12");

    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 1, TOKEN_REMAINING),
        600
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Negative flows
// ─────────────────────────────────────────────────────────────────────────

/// A TokenLimit(A) session, and a vault account of an unlisted mint B.
struct Unlisted {
    listed: Listed,
    b: Pubkey,
    vault_b: Pubkey,
    dest_b: Pubkey,
}

fn unlisted_fixture(fx: &mut Fx) -> Unlisted {
    unlisted_fixture_with(fx, |a| token_limit_policy(a, 1_000))
}

/// [`unlisted_fixture`], the session's actions built for A by `actions`.
fn unlisted_fixture_with(fx: &mut Fx, actions: impl FnOnce(Pubkey) -> Vec<u8>) -> Unlisted {
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let actor = fx.session(&actions(mint));
    let b = fx.mint();
    let vault_b = fx.token_account(b, vault, 5_000);
    let dest_b = fx.token_account(b, Pubkey::new_unique(), 0);
    Unlisted {
        listed: Listed {
            actor,
            mint,
            vault_ata,
        },
        b,
        vault_b,
        dest_b,
    }
}

/// A transfer of `amount` of B out of the vault, which no action names.
fn unlisted_transfer_exec(u: &Unlisted, amount: u64) -> Exec {
    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(u.vault_b);
    let dst = exec.writable(u.dest_b);
    transfer(&mut exec, token, src, dst, IDX_VAULT, amount);
    exec
}

/// A transfer of `amount` of the listed mint A out of the vault.
fn listed_transfer_exec(fx: &mut Fx, u: &Unlisted, amount: u64) -> (Exec, Pubkey) {
    let dest = fx.token_account(u.listed.mint, Pubkey::new_unique(), 0);
    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(u.listed.vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, amount);
    (exec, dest)
}

#[test]
fn n1_transfer_of_an_unlisted_mint_is_refused() {
    let mut fx = Fx::new();
    let u = unlisted_fixture(&mut fx);

    let exec = unlisted_transfer_exec(&u, 100);
    assert_custom_error(fx.execute(&u.listed.actor, exec), ERR_UNLISTED_TOKEN, "N1");
    assert_eq!(fx.amount(u.vault_b), 5_000);
}

#[test]
fn n2_transfer_checked_of_an_unlisted_mint_is_refused() {
    let mut fx = Fx::new();
    let u = unlisted_fixture(&mut fx);

    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(u.vault_b);
    let mint = exec.readonly(u.b);
    let dst = exec.writable(u.dest_b);
    exec.call(
        token,
        &[src, mint, dst, IDX_VAULT],
        spl_transfer_checked_data(100, DECIMALS),
    );
    assert_custom_error(fx.execute(&u.listed.actor, exec), ERR_UNLISTED_TOKEN, "N2");
}

#[test]
fn n3_burn_of_an_unlisted_mint_is_refused() {
    let mut fx = Fx::new();
    let u = unlisted_fixture(&mut fx);

    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(u.vault_b);
    let mint = exec.writable(u.b);
    exec.call(token, &[src, mint, IDX_VAULT], spl_burn_data(100));
    assert_custom_error(fx.execute(&u.listed.actor, exec), ERR_UNLISTED_TOKEN, "N3");
}

#[test]
fn n4_token_2022_transfer_of_an_unlisted_mint_is_refused() {
    let mut fx = Fx::new();
    let t22 = spl_token_2022_id();
    let listed = fx.mint();
    let c = fx.mint_with(t22, None);
    let vault = fx.vault();
    let opts = || TokenAccountOpts {
        extensions: immutable_owner_tlv(),
        ..Default::default()
    };
    let vault_c = fx.token_account_with(t22, c, vault, 5_000, opts());
    let dest = fx.token_account_with(t22, c, Pubkey::new_unique(), 0, opts());
    let mut actions = action_token_limit(listed, 1_000);
    actions.extend_from_slice(&action_program_whitelist(t22));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(t22);
    let src = exec.writable(vault_c);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_TOKEN, "N4");
}

fn sol_transfer_exec(actor: &Actor, recipient: Pubkey, lamports: u64) -> Exec {
    let mut exec = Exec::new(actor);
    let system = exec.readonly(solana_sdk::system_program::id());
    let to = exec.writable(recipient);
    exec.call(system, &[IDX_VAULT, to], system_transfer_data(lamports));
    exec
}

#[test]
fn n5a_whitelist_only_session_cannot_spend_sol() {
    let mut fx = Fx::new();
    let actor = fx.session(&action_program_whitelist(solana_sdk::system_program::id()));
    let vault_before = fx.lamports(&fx.vault());
    let exec = sol_transfer_exec(&actor, Pubkey::new_unique(), 1_000_000);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_SOL, "N5a");
    assert_eq!(fx.lamports(&fx.vault()), vault_before);
}

#[test]
fn n5b_token_limit_only_session_cannot_spend_sol() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let actor = fx.session(&action_token_limit(mint, 1_000));
    let exec = sol_transfer_exec(&actor, Pubkey::new_unique(), 1);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_SOL, "N5b");
}

/// Rent the vault pays for a new account is SOL leaving the vault.
#[test]
fn n6_vault_funded_ata_needs_a_sol_action() {
    let mut fx = Fx::new();
    let b = fx.mint();
    let vault = fx.vault();
    let actor = fx.session(&action_program_whitelist(ata_program_id()));
    let ata_b = ata_address(vault, b, spl_token_id());

    let mut exec = Exec::new(&actor);
    let ata = exec.readonly(ata_program_id());
    let system = exec.readonly(solana_sdk::system_program::id());
    let token = exec.readonly(spl_token_id());
    let mint = exec.readonly(b);
    let new_ata = exec.writable(ata_b);
    exec.call(
        ata,
        &[IDX_VAULT, new_ata, IDX_VAULT, mint, system, token],
        ata_create_idempotent_data(),
    );
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_SOL, "N6");
}

/// A zeroed 165-byte account owned by SPL Token, ready for
/// `InitializeAccount3`: what anyone can create for the vault.
fn uninitialized_token_account(fx: &mut Fx) -> Pubkey {
    let address = Pubkey::new_unique();
    let lamports = fx.context.svm.minimum_balance_for_rent_exemption(165);
    fx.context
        .svm
        .set_account(
            address,
            solana_sdk::account::Account {
                lamports,
                data: vec![0u8; 165],
                owner: spl_token_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    address
}

/// Initialise a fresh token account C for the vault, move `amount` of the
/// listed mint into it, and optionally approve an attacker on it.
fn new_account_exec(
    a: &Listed,
    vault: Pubkey,
    c: Pubkey,
    amount: u64,
    approve: Option<Pubkey>,
) -> Exec {
    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let mint = exec.readonly(a.mint);
    let ata = exec.writable(a.vault_ata);
    let new = exec.writable(c);
    exec.call(token, &[new, mint], spl_initialize_account3_data(vault));
    transfer(&mut exec, token, ata, new, IDX_VAULT, amount);
    if let Some(attacker) = approve {
        let delegate = exec.readonly(attacker);
        exec.call(token, &[new, delegate, IDX_VAULT], spl_approve_data(amount));
    }
    exec
}

/// The new-account bypass: tokens moved into an account initialised for the
/// vault during the Execute, which is then approved to an attacker.
#[test]
fn n7a_new_vault_account_with_a_delegate_is_refused() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let c = uninitialized_token_account(&mut fx);
    let exec = new_account_exec(&a, fx.vault(), c, 400, Some(Pubkey::new_unique()));
    assert_custom_error(
        fx.execute(&a.actor, exec),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "N7a",
    );
    assert_eq!(fx.amount(a.vault_ata), 5_000);
}

/// Without the Approve it passes, and moving into the new account is spent.
#[test]
fn n7b_moving_into_a_new_vault_account_is_charged() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let c = uninitialized_token_account(&mut fx);
    let exec = new_account_exec(&a, fx.vault(), c, 400, None);
    fx.execute_ok(&a.actor, exec, "N7b");

    assert_eq!(fx.amount(c), 400);
    assert_eq!(token_account_owner(&fx.context.svm, c), fx.vault());
    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        600
    );
}

#[test]
fn n7c_moving_more_than_the_limit_into_a_new_vault_account_is_refused() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let c = uninitialized_token_account(&mut fx);
    let exec = new_account_exec(&a, fx.vault(), c, 1_500, None);
    assert_custom_error(fx.execute(&a.actor, exec), ERR_TOKEN_LIMIT, "N7c");
}

/// The session hands the vault an account of its own whose close authority
/// it keeps. SPL Token clears the delegate on an owner change but not a
/// non-native close authority.
#[test]
fn n8_session_account_moved_to_the_vault_keeps_its_close_authority() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let session_key = a.actor.key.pubkey();
    let d = fx.token_account_with(
        spl_token_id(),
        a.mint,
        session_key,
        0,
        TokenAccountOpts {
            close_authority: Some(session_key),
            ..Default::default()
        },
    );
    let vault = fx.vault();

    let mut exec = Exec::new(&a.actor);
    let token = exec.readonly(spl_token_id());
    let ata = exec.writable(a.vault_ata);
    let dd = exec.writable(d);
    exec.call(
        token,
        &[dd, forward_signer(IDX_ACTOR)],
        spl_set_authority_data(2, vault),
    );
    transfer(&mut exec, token, ata, dd, IDX_VAULT, 400);
    assert_custom_error(
        fx.execute(&a.actor, exec),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "N8",
    );
    assert_eq!(
        token_account_close_authority(&fx.context.svm, d),
        Some(session_key)
    );
    assert_eq!(token_account_owner(&fx.context.svm, d), session_key);
}

/// Re-approving the delegate the Owner set, for more, leaves the delegate
/// field alone and raises `delegated_amount`.
#[test]
fn n9_raising_an_existing_delegates_allowance_is_refused() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let delegate = Pubkey::new_unique();
    let vault_ata = fx.token_account_with(
        spl_token_id(),
        mint,
        vault,
        5_000,
        TokenAccountOpts {
            delegate: Some((delegate, 10)),
            ..Default::default()
        },
    );
    let actor = fx.session(&token_limit_policy(mint, 1_000));

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let d = exec.readonly(delegate);
    exec.call(token, &[src, d, IDX_VAULT], spl_approve_data(u64::MAX));
    assert_custom_error(fx.execute(&actor, exec), ERR_TOKEN_AUTHORITY_CHANGED, "N9");
}

#[test]
fn n10_freezing_a_vault_account_is_refused() {
    let mut fx = Fx::new();
    let vault = fx.vault();
    let mint = fx.mint_with(spl_token_id(), Some(vault));
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let actor = fx.session(&token_limit_policy(mint, 1_000));

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let acc = exec.writable(vault_ata);
    let m = exec.readonly(mint);
    exec.call(token, &[acc, m, IDX_VAULT], spl_freeze_account_data());
    assert_custom_error(fx.execute(&actor, exec), ERR_TOKEN_AUTHORITY_CHANGED, "N10");
}

/// Lamports above rent in a vault token account are vault SOL; no SOL action
/// sees them leave, so the account may not lose them.
#[test]
fn n11_withdrawing_excess_lamports_is_refused() {
    let mut fx = Fx::new();
    let t22 = spl_token_2022_id();
    let mint = fx.mint_with(t22, None);
    let vault = fx.vault();
    let vault_t = fx.token_account_with(
        t22,
        mint,
        vault,
        5_000,
        TokenAccountOpts {
            extensions: immutable_owner_tlv(),
            extra_lamports: 1_000_000,
            ..Default::default()
        },
    );
    let mut actions = action_token_limit(mint, 1_000);
    actions.extend_from_slice(&action_program_whitelist(t22));
    let actor = fx.session(&actions);
    let lamports_before = fx.lamports(&vault_t);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(t22);
    let src = exec.writable(vault_t);
    let dst = exec.writable(Pubkey::new_unique());
    exec.call(
        token,
        &[src, dst, IDX_VAULT],
        token_2022_withdraw_excess_lamports_data(),
    );
    assert_custom_error(fx.execute(&actor, exec), ERR_TOKEN_AUTHORITY_CHANGED, "N11");
    assert_eq!(fx.lamports(&vault_t), lamports_before);
}

#[test]
fn n12_reallocating_a_vault_account_is_refused() {
    let mut fx = Fx::new();
    let t22 = spl_token_2022_id();
    let mint = fx.mint_with(t22, None);
    let vault = fx.vault();
    let vault_t = fx.token_account_with(
        t22,
        mint,
        vault,
        5_000,
        TokenAccountOpts {
            extensions: immutable_owner_tlv(),
            ..Default::default()
        },
    );
    let mut actions = action_token_limit(mint, 1_000);
    actions.extend_from_slice(&action_program_whitelist(t22));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(t22);
    let acc = exec.writable(vault_t);
    let system = exec.readonly(solana_sdk::system_program::id());
    // MemoTransfer = 8.
    exec.call(
        token,
        &[acc, forward_signer(IDX_ACTOR), system, IDX_VAULT],
        token_2022_reallocate_data(&[8]),
    );
    assert_custom_error(fx.execute(&actor, exec), ERR_TOKEN_AUTHORITY_CHANGED, "N12");
    assert_eq!(
        fx.context.svm.get_account(&vault_t).unwrap().data.len(),
        170
    );
}

fn native_account(fx: &mut Fx, owner: Pubkey, amount: u64) -> Pubkey {
    let reserve = fx.context.svm.minimum_balance_for_rent_exemption(165);
    fx.token_account_with(
        spl_token_id(),
        native_mint(),
        owner,
        amount,
        TokenAccountOpts {
            native_reserve: Some(reserve),
            ..Default::default()
        },
    )
}

/// A native transfer lowers `amount` and lamports together, so the lamport
/// rule is satisfied and the mint rule decides: SolLimit does not name wSOL.
#[test]
fn n13_wsol_is_its_own_mint() {
    let mut fx = Fx::new();
    let vault = fx.vault();
    let w = native_account(&mut fx, vault, 1_000_000);
    let attacker_w = native_account(&mut fx, Pubkey::new_unique(), 0);
    let mut actions = action_sol_limit(u64::MAX);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(w);
    let dst = exec.writable(attacker_w);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 500_000);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_TOKEN, "N13");
}

#[test]
fn n14_delegate_with_a_sol_policy_cannot_move_tokens() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let mut policy = action_sol_limit(1_000_000);
    policy.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let actor = fx.delegate(&policy);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_TOKEN, "N14");
}

/// Net per mint, never across mints: receiving C does not pay for sending B.
#[test]
fn n15_no_cross_mint_netting() {
    let mut fx = Fx::new();
    let u = unlisted_fixture(&mut fx);
    let c = fx.mint();
    let vault = fx.vault();
    let vault_c = fx.token_account(c, vault, 0);
    let session_c = fx.token_account(c, u.listed.actor.key.pubkey(), 100);

    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let vb = exec.writable(u.vault_b);
    let db = exec.writable(u.dest_b);
    let sc = exec.writable(session_c);
    let vc = exec.writable(vault_c);
    transfer(&mut exec, token, vb, db, IDX_VAULT, 100);
    transfer(&mut exec, token, sc, vc, forward_signer(IDX_ACTOR), 100);
    assert_custom_error(fx.execute(&u.listed.actor, exec), ERR_UNLISTED_TOKEN, "N15");
}

#[test]
fn n16_unlisted_transfer_from_an_account_passed_twice_is_refused() {
    let mut fx = Fx::new();
    let u = unlisted_fixture(&mut fx);

    let mut exec = Exec::new(&u.listed.actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(u.vault_b);
    let _again = exec.writable(u.vault_b);
    let dst = exec.writable(u.dest_b);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    assert_custom_error(fx.execute(&u.listed.actor, exec), ERR_UNLISTED_TOKEN, "N16");
}

/// A per-transaction SOL cap names SOL and nothing else.
#[test]
fn n17_sol_max_per_tx_alone_names_sol_only() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let actor = fx.session(&action_sol_max_per_tx(1_000_000));

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_TOKEN, "N17 token");

    let recipient = Pubkey::new_unique();
    let exec = sol_transfer_exec(&actor, recipient, 500_000);
    fx.execute_ok(&actor, exec, "N17 SOL within the cap");
    assert_eq!(fx.lamports(&recipient), 500_000);
}

/// Closing a wSOL account the vault already had is unchanged by D13: its
/// lamports are gone, so it is refused as a token-account change.
#[test]
fn n18_closing_an_existing_wsol_account_is_refused() {
    let mut fx = Fx::new();
    let vault = fx.vault();
    let w = native_account(&mut fx, vault, 1_000_000);
    let mut actions = action_sol_limit(u64::MAX);
    actions.extend_from_slice(&action_program_whitelist(spl_token_id()));
    let actor = fx.session(&actions);

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let acc = exec.writable(w);
    exec.call(
        token,
        &[acc, IDX_VAULT, IDX_VAULT],
        spl_close_account_data(),
    );
    assert_custom_error(fx.execute(&actor, exec), ERR_TOKEN_AUTHORITY_CHANGED, "N18");
}

/// Every `Token*` type names its mint, not only `TokenLimit`: a
/// `TokenMaxPerTx(A)` session moves A within its cap, and B not at all.
#[test]
fn n19_token_max_per_tx_alone_names_its_mint_only() {
    let mut fx = Fx::new();
    let u = unlisted_fixture_with(&mut fx, |a| action_token_max_per_tx(a, 1_000));

    let exec = unlisted_transfer_exec(&u, 100);
    assert_custom_error(
        fx.execute(&u.listed.actor, exec),
        ERR_UNLISTED_TOKEN,
        "N19 B",
    );
    assert_eq!(fx.amount(u.vault_b), 5_000);

    let (exec, dest) = listed_transfer_exec(&mut fx, &u, 400);
    fx.execute_ok(&u.listed.actor, exec, "N19 A within the cap");
    assert_eq!(fx.amount(u.listed.vault_ata), 4_600);
    assert_eq!(fx.amount(dest), 400);
}

/// A `TokenRecurringLimit(A)` session moves A within its window's limit, and
/// the move is charged to `spent`; B it cannot move.
#[test]
fn n20_token_recurring_limit_alone_names_its_mint_only() {
    let mut fx = Fx::new();
    let u = unlisted_fixture_with(&mut fx, |a| action_token_recurring_limit(a, 1_000, 1_000));

    let exec = unlisted_transfer_exec(&u, 100);
    assert_custom_error(
        fx.execute(&u.listed.actor, exec),
        ERR_UNLISTED_TOKEN,
        "N20 B",
    );

    let (exec, dest) = listed_transfer_exec(&mut fx, &u, 400);
    fx.execute_ok(&u.listed.actor, exec, "N20 A within the limit");
    assert_eq!(fx.amount(dest), 400);
    assert_eq!(
        session_action_u64(
            &fx.context.svm,
            u.listed.actor.pda,
            0,
            TOKEN_RECURRING_SPENT
        ),
        400
    );
}

/// A recurring SOL limit names SOL and nothing else, and SOL it moves is
/// charged to `spent`.
#[test]
fn n21_sol_recurring_limit_alone_names_sol_only() {
    let mut fx = Fx::new();
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let actor = fx.session(&action_sol_recurring_limit(1_000_000, 1_000));

    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    assert_custom_error(fx.execute(&actor, exec), ERR_UNLISTED_TOKEN, "N21 token");

    let recipient = Pubkey::new_unique();
    let exec = sol_transfer_exec(&actor, recipient, 500_000);
    fx.execute_ok(&actor, exec, "N21 SOL within the limit");
    assert_eq!(fx.lamports(&recipient), 500_000);
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 0, SOL_RECURRING_SPENT),
        500_000
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Regressions
// ─────────────────────────────────────────────────────────────────────────

/// Everything D13 refuses a policy-bound signer, done by a signer with no
/// policy: an unlisted token transfer, a SOL transfer, an Approve, a
/// CloseAccount and a vault-funded ATA.
fn unbounded_signer_does_everything(fx: &mut Fx, actor: &Actor, what: &str) {
    let mint = fx.mint();
    let vault = fx.vault();
    let vault_ata = fx.token_account(mint, vault, 5_000);
    let empty = fx.token_account(mint, vault, 0);
    let dest = fx.token_account(mint, Pubkey::new_unique(), 0);
    let new_ata = ata_address(vault, mint, spl_token_id());
    let recipient = Pubkey::new_unique();

    let mut exec = Exec::new(actor);
    let token = exec.readonly(spl_token_id());
    let system = exec.readonly(solana_sdk::system_program::id());
    let ata = exec.readonly(ata_program_id());
    let m = exec.readonly(mint);
    let src = exec.writable(vault_ata);
    let dst = exec.writable(dest);
    let e = exec.writable(empty);
    let n = exec.writable(new_ata);
    let r = exec.writable(recipient);
    let d = exec.readonly(Pubkey::new_unique());
    transfer(&mut exec, token, src, dst, IDX_VAULT, 4_000);
    exec.call(system, &[IDX_VAULT, r], system_transfer_data(1_000_000));
    exec.call(token, &[src, d, IDX_VAULT], spl_approve_data(1_000));
    exec.call(token, &[e, IDX_VAULT, IDX_VAULT], spl_close_account_data());
    exec.call(
        ata,
        &[IDX_VAULT, n, IDX_VAULT, m, system, token],
        ata_create_idempotent_data(),
    );
    fx.execute_ok(actor, exec, what);

    assert_eq!(fx.amount(dest), 4_000);
    assert_eq!(fx.lamports(&recipient), 1_000_000);
    assert!(token_account_delegate(&fx.context.svm, vault_ata).is_some());
    assert_eq!(fx.lamports(&empty), 0);
    assert_eq!(token_account_owner(&fx.context.svm, new_ata), vault);
}

#[test]
fn r1_unrestricted_session_is_unchanged() {
    let mut fx = Fx::new();
    let actor = fx.session(&[]);
    unbounded_signer_does_everything(&mut fx, &actor, "R1");
}

#[test]
fn r2_owner_is_unchanged() {
    let mut fx = Fx::new();
    let actor = fx.owner();
    unbounded_signer_does_everything(&mut fx, &actor, "R2");
}

/// A policy-bound signer cannot reach ExecuteDeferred, which runs no policy:
/// a Delegate passkey is refused at Authorize.
#[test]
fn r7_delegate_passkey_cannot_authorize() {
    const DISC_AUTHORIZE: u8 = 6;
    const AUTHORIZE_SYSVAR_IX_INDEX: u8 = 6;

    let mut fx = Fx::new();
    let pk = Passkey::new();
    let wallet = fx.wallet.wallet_pda;
    let program_id = fx.context.program_id;
    let delegate_pda = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.as_ref(),
            &pk.credential_id_hash,
        ],
        &program_id,
    )
    .0;

    // AddAuthority: Secp256r1, rank Delegate, with a policy.
    let policy = action_sol_limit(1_000_000);
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
    data.extend_from_slice(&policy);
    let add = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(fx.context.payer.pubkey(), true),
            AccountMeta::new(wallet, false),
            AccountMeta::new(fx.wallet.owner_auth_pda, false),
            AccountMeta::new(delegate_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(fx.wallet.owner.pubkey(), true),
        ],
        data,
    };
    let payer = fx.context.payer.insecure_clone();
    let owner = fx.wallet.owner.insecure_clone();
    try_send(&mut fx.context.svm, &payer, &[add], &[&payer, &owner])
        .expect("AddAuthority (Delegate passkey)");
    assert_eq!(authority_role(&fx.context.svm, delegate_pda), RANK_DELEGATE);

    // Authorize a SOL transfer, signed by the Delegate's passkey.
    let compact = encode_compact(&[(5, vec![2, 4], system_transfer_data(1))]);
    let mut signed_payload = Vec::with_capacity(66);
    signed_payload.extend_from_slice(&Sha256::digest(&compact));
    signed_payload.extend_from_slice(&[0u8; 32]);
    signed_payload.extend_from_slice(&100u16.to_le_bytes());
    let counter = authority_counter(&fx.context.svm, delegate_pda) + 1;
    let slot = fx.context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, AUTHORIZE_SYSVAR_IX_INDEX);
    let challenge = secp256r1_challenge(
        DISC_AUTHORIZE,
        &prefix,
        &signed_payload,
        &payer.pubkey(),
        &wallet,
        counter,
        &program_id,
    );
    let (precompile, auth_payload) =
        passkey_assertion(&pk.signing_key, pk.rp_id, &prefix, &challenge);
    let deferred = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::DEFERRED,
            wallet.as_ref(),
            delegate_pda.as_ref(),
            &counter.to_le_bytes(),
        ],
        &program_id,
    )
    .0;
    let mut data = vec![DISC_AUTHORIZE];
    data.extend_from_slice(&signed_payload);
    data.extend_from_slice(&auth_payload);
    let authorize = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new(delegate_pda, false),
            AccountMeta::new(deferred, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        data,
    };
    assert_custom_error(
        try_send(
            &mut fx.context.svm,
            &payer,
            &[precompile, authorize],
            &[&payer],
        ),
        ERR_PERMISSION_DENIED,
        "R7",
    );
}

/// The whitelist and blacklist are now read from the parsed actions instead of
/// collected into Vecs; a blacklist still refuses exactly its program.
#[test]
fn r8_blacklist_still_refuses_its_program() {
    let mut fx = Fx::new();
    let mut actions = action_sol_limit(1_000_000);
    actions.extend_from_slice(&action_program_blacklist(solana_sdk::system_program::id()));
    let actor = fx.session(&actions);

    let exec = sol_transfer_exec(&actor, Pubkey::new_unique(), 1);
    assert_custom_error(fx.execute(&actor, exec), ERR_PROGRAM_BLACKLISTED, "R8");

    let mut exec = Exec::new(&actor);
    let memo = exec.readonly(memo_program_id());
    exec.call(memo, &[], b"lazorkit".to_vec());
    fx.execute_ok(&actor, exec, "R8 another program");
}

// ─────────────────────────────────────────────────────────────────────────
// Heap and compute units
// ─────────────────────────────────────────────────────────────────────────

/// A TokenLimit(A) session Execute with `t` writable vault token accounts of
/// distinct mints, one listed transfer out of the first. litesvm 0.6's
/// compute-budget pass panics on a program id past the 38th static key, so
/// `t` stays at 24 or below.
fn wide_execute(fx: &mut Fx, t: usize, compute_limit: bool) -> (Actor, Exec, Pubkey) {
    let a = listed_session(fx, 1_000, 5_000);
    let vault = fx.vault();
    let dest = fx.token_account(a.mint, Pubkey::new_unique(), 0);
    let others: Vec<Pubkey> = (1..t)
        .map(|_| {
            let mint = fx.mint();
            fx.token_account(mint, vault, 1_000)
        })
        .collect();

    let mut exec = Exec::new(&a.actor);
    exec.compute_limit = compute_limit;
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(a.vault_ata);
    let dst = exec.writable(dest);
    for other in others {
        exec.writable(other);
    }
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    (a.actor, exec, a.vault_ata)
}

#[test]
fn h1_heap_with_1_8_and_24_vault_token_accounts() {
    for t in [1, 8, 24] {
        let mut fx = Fx::new();
        let (actor, exec, _) = wide_execute(&mut fx, t, true);
        fx.execute_ok(&actor, exec, &format!("H1 t={t}"));
        assert_eq!(
            session_action_u64(&fx.context.svm, actor.pda, 0, TOKEN_REMAINING),
            900,
            "t={t}"
        );
    }
}

/// One vault token account passed many times is snapshotted once: the copy is
/// sized by unique keys, not by account entries.
#[test]
fn h1_heap_with_one_account_passed_many_times() {
    let mut fx = Fx::new();
    let a = listed_session(&mut fx, 1_000, 5_000);
    let dest = fx.token_account(a.mint, Pubkey::new_unique(), 0);

    let mut exec = Exec::new(&a.actor);
    exec.compute_limit = true;
    let token = exec.readonly(spl_token_id());
    let src = exec.writable(a.vault_ata);
    let dst = exec.writable(dest);
    // 192 bytes per entry would be 38 KiB for 200 entries, past the heap.
    for _ in 0..200 {
        exec.writable(a.vault_ata);
    }
    transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
    let cu = fx.execute_ok(&a.actor, exec, "H1 duplicates");
    println!("H1 one account passed 201 times: {cu} CU");

    assert_eq!(
        session_action_u64(&fx.context.svm, a.actor.pda, 0, TOKEN_REMAINING),
        900
    );
}

/// The runtime passes an instruction up to 255 accounts, one more than
/// pinocchio 0.9.2's entrypoint array held: it wrote the 255th past the end.
/// A 255-account Execute runs, reads its last account (the fee suffix's
/// system program; a shorter list would be 4008) and charges the listed mint
/// once. At 256 the runtime refuses the instruction before the program runs.
#[test]
fn h2_execute_at_the_runtime_account_limit() {
    use solana_sdk::{instruction::InstructionError, transaction::TransactionError};

    // payer, wallet, authority and vault, then the fee suffix.
    const OUTER: usize = 8;

    let build = |fx: &mut Fx, total: usize| {
        let a = listed_session(fx, 1_000, 5_000);
        let dest = fx.token_account(a.mint, Pubkey::new_unique(), 0);
        let mut exec = Exec::new(&a.actor);
        exec.compute_limit = true;
        let token = exec.readonly(spl_token_id());
        let src = exec.writable(a.vault_ata);
        let dst = exec.writable(dest);
        while OUTER + exec.accounts.len() < total {
            exec.writable(a.vault_ata);
        }
        transfer(&mut exec, token, src, dst, IDX_VAULT, 100);
        (a.actor, exec)
    };

    let mut fx = Fx::new();
    let (actor, exec) = build(&mut fx, 255);
    fx.execute_ok(&actor, exec, "H2 255 accounts");
    assert_eq!(
        session_action_u64(&fx.context.svm, actor.pda, 0, TOKEN_REMAINING),
        900
    );

    let mut fx = Fx::new();
    let (actor, exec) = build(&mut fx, 256);
    match fx.execute(&actor, exec) {
        Err(failed) => assert!(
            matches!(
                failed.err,
                TransactionError::InstructionError(_, InstructionError::MaxAccountsExceeded)
            ),
            "H2 256 accounts: {:?}",
            failed.err
        ),
        Ok(_) => panic!("H2 256 accounts: the runtime passed them"),
    }
}

/// Compute units for the policy path. Measured with the same transactions on
/// develop (devnet `3584aec7…`) and on this branch:
///
/// | shape                                    | develop | D13    |
/// |------------------------------------------|---------|--------|
/// | (a) whitelist + SolLimit, SOL, t = 0     | 24,128  | 23,779 |
/// | (b) TokenLimit, one transfer, t = 1      | 30,083  | 29,072 |
/// | (c) as (b), t = 8                        | 32,974  | 32,836 |
/// | (d) as (b), t = 24                       | 41,195  | 45,861 |
///
/// `t` counts writable vault token accounts. Each one costs D13 more than it
/// cost develop (about 810 CU against 510 between t = 8 and t = 24), while (b)
/// is cheaper because D13 drops develop's scans of the whole account list per
/// listed mint. (b) may cost no more than develop + 1,500 CU, and each ceiling
/// is this branch's measurement + 10%.
#[test]
fn c1_compute_units_of_the_policy_path() {
    // (a) whitelist(System) + SolLimit, one System transfer, t = 0.
    let mut fx = Fx::deterministic();
    let mut actions = action_sol_limit(1_000_000_000);
    actions.extend_from_slice(&action_program_whitelist(solana_sdk::system_program::id()));
    let actor = fx.session(&actions);
    let exec = sol_transfer_exec(&actor, Pubkey::new_unique(), 100_000);
    let a = fx.execute_ok(&actor, exec, "C1 (a)");

    // (b)–(d) TokenLimit(A), one listed transfer, t = 1, 8, 24.
    let wide = |t: usize| {
        let mut fx = Fx::deterministic();
        let (actor, exec, _) = wide_execute(&mut fx, t, false);
        fx.execute_ok(&actor, exec, &format!("C1 t={t}"))
    };
    let b = wide(1);
    let c = wide(8);
    let d = wide(24);
    println!("C1 compute units: (a) t=0 {a} · (b) t=1 {b} · (c) t=8 {c} · (d) t=24 {d}");

    const DEVELOP_B: u64 = 30_083;
    assert!(
        b <= DEVELOP_B + 1_500,
        "(b) {b} CU against develop's {DEVELOP_B}"
    );
    for (shape, measured, ceiling) in [
        ("(a)", a, 26_160),
        ("(b)", b, 31_980),
        ("(c)", c, 36_120),
        ("(d)", d, 50_450),
    ] {
        assert!(
            measured <= ceiling,
            "{shape}: {measured} CU, ceiling {ceiling}"
        );
    }
}
