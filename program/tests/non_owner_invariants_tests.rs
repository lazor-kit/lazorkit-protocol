//! The vault invariants hold for every signer but an Owner.
//!
//! After the CPI loop the program checks that the vault's owner and data
//! length are unchanged (3030 / 3031), that every writable vault-owned token
//! account kept everything but its balance, and that a token account that
//! became vault-owned during the Execute carries no delegate and no close
//! authority (3032). A change like that would outlive the signer — it survives
//! the session's expiry, `RevokeSession` and `RemoveAuthority` — so the checks
//! run for every non-Owner signer, policy or not, in Execute and in
//! ExecuteDeferred:
//!
//! - `m_*`: each signer kind × each invariant, in Execute. The Owner keeps
//!   full power; an Admin, a Delegate, a session without actions and a
//!   session with actions are refused every escape and still spend.
//! - `d_*`: ExecuteDeferred. `Authorize` records whether an Owner signed it; an
//!   Admin's deferred execution is guarded, an Owner's is not, and one written
//!   before the record existed (the byte is zero) is guarded.
//!
//! Run:  cargo test --features devnet -p lazorkit-program --test non_owner_invariants_tests

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};

/// `AuthError::SessionVaultOwnerChanged`
const ERR_VAULT_OWNER_CHANGED: u32 = 3030;
/// `AuthError::SessionVaultDataLenChanged`
const ERR_VAULT_DATA_LEN_CHANGED: u32 = 3031;
/// `AuthError::SessionTokenAuthorityChanged`
const ERR_TOKEN_AUTHORITY_CHANGED: u32 = 3032;

const VAULT_LAMPORTS: u64 = 1_000_000_000;
const VAULT_TOKENS: u64 = 5_000;

/// Every Execute here lays its accounts out as `0` payer · `1` wallet ·
/// `2` authority · `3` vault · `4` the actor's key, then what the case adds.
const IDX_VAULT: u8 = 3;
const IDX_ACTOR: u8 = 4;

// ─────────────────────────────────────────────────────────────────────────
// Signers
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Owner,
    Admin,
    Delegate,
    /// A session created with no actions.
    UnrestrictedSession,
    /// A session whose actions name SOL and the test mint.
    BoundedSession,
}

/// What signs an Execute: a key and the PDA it authenticates.
struct Actor {
    key: Keypair,
    pda: Pubkey,
}

/// A policy generous enough that only the invariants can refuse anything here:
/// SOL and the test mint named, no whitelist.
fn generous_policy(mint: Pubkey) -> Vec<u8> {
    let mut actions = action_sol_limit(10 * VAULT_LAMPORTS);
    actions.extend_from_slice(&action_token_limit(mint, u64::MAX / 4));
    actions
}

struct Fx {
    context: TestContext,
    wallet: WalletFixture,
    mint: Pubkey,
    /// A vault token account holding [`VAULT_TOKENS`].
    vault_ata: Pubkey,
    /// An empty vault token account, which `CloseAccount` would accept.
    vault_empty: Pubkey,
}

impl Fx {
    fn new() -> Self {
        let mut context = setup_test();
        let wallet = create_ed25519_wallet(&mut context, VAULT_LAMPORTS);
        let mint = Pubkey::new_unique();
        create_mint_with(
            &mut context.svm,
            spl_token_id(),
            mint,
            Pubkey::new_unique(),
            None,
            u64::MAX / 2,
            6,
            &[],
        );
        create_native_mint(&mut context.svm);
        let vault = wallet.vault_pda;
        let vault_ata = Pubkey::new_unique();
        create_token_account_with(
            &mut context.svm,
            spl_token_id(),
            vault_ata,
            mint,
            vault,
            VAULT_TOKENS,
            TokenAccountOpts::default(),
        );
        let vault_empty = Pubkey::new_unique();
        create_token_account_with(
            &mut context.svm,
            spl_token_id(),
            vault_empty,
            mint,
            vault,
            0,
            TokenAccountOpts::default(),
        );
        Self {
            context,
            wallet,
            mint,
            vault_ata,
            vault_empty,
        }
    }

    fn vault(&self) -> Pubkey {
        self.wallet.vault_pda
    }

    fn actor(&mut self, role: Role) -> Actor {
        let actor = match role {
            Role::Owner => Actor {
                key: self.wallet.owner.insecure_clone(),
                pda: self.wallet.owner_auth_pda,
            },
            Role::Admin => {
                let key = Keypair::new();
                let pda =
                    owner_adds_ed25519(&mut self.context, &self.wallet, &key, RANK_ADMIN, &[])
                        .expect("AddAuthority (Admin)");
                Actor { key, pda }
            },
            Role::Delegate => {
                let key = Keypair::new();
                let policy = generous_policy(self.mint);
                let pda = owner_adds_ed25519(
                    &mut self.context,
                    &self.wallet,
                    &key,
                    RANK_DELEGATE,
                    &policy,
                )
                .expect("AddAuthority (Delegate)");
                Actor { key, pda }
            },
            Role::UnrestrictedSession => self.session(&[]),
            Role::BoundedSession => {
                let policy = generous_policy(self.mint);
                self.session(&policy)
            },
        };
        // Funded, so a case can have it pay for something.
        self.context
            .svm
            .airdrop(&actor.key.pubkey(), 1_000_000_000)
            .unwrap();
        actor
    }

    fn session(&mut self, actions: &[u8]) -> Actor {
        let key = create_session_with_actions(&mut self.context, &self.wallet, actions);
        let pda = session_pda_for(self.context.program_id, &self.wallet, &key);
        Actor { key, pda }
    }

    fn token_account(
        &mut self,
        mint: Pubkey,
        owner: Pubkey,
        amount: u64,
        opts: TokenAccountOpts,
    ) -> Pubkey {
        let address = Pubkey::new_unique();
        create_token_account_with(
            &mut self.context.svm,
            spl_token_id(),
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

    #[allow(clippy::result_large_err)]
    fn execute(
        &mut self,
        actor: &Actor,
        exec: Exec,
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        advance(&mut self.context.svm);
        let ix = Instruction {
            program_id: self.context.program_id,
            accounts: execute_accounts(&self.context, &self.wallet, actor.pda, exec.accounts),
            data: execute_data(&exec.ixs),
        };
        let payer = self.context.payer.insecure_clone();
        try_send(&mut self.context.svm, &payer, &[ix], &[&payer, &actor.key])
    }
}

/// The accounts and compact instructions of one Execute. The actor's key sits
/// at [`IDX_ACTOR`], writable, so an inner instruction can be forwarded its
/// signature.
struct Exec {
    accounts: Vec<AccountMeta>,
    ixs: Compact,
}

impl Exec {
    fn new(actor: &Actor) -> Self {
        Self {
            accounts: vec![AccountMeta::new(actor.key.pubkey(), true)],
            ixs: Vec::new(),
        }
    }

    fn writable(&mut self, key: Pubkey) -> u8 {
        self.accounts.push(AccountMeta::new(key, false));
        (3 + self.accounts.len()) as u8
    }

    fn readonly(&mut self, key: Pubkey) -> u8 {
        self.accounts.push(AccountMeta::new_readonly(key, false));
        (3 + self.accounts.len()) as u8
    }

    fn call(&mut self, program: u8, accounts: &[u8], data: Vec<u8>) {
        self.ixs.push((program, accounts.to_vec(), data));
    }
}

/// Compact instructions as `encode_compact` takes them.
type Compact = Vec<(u8, Vec<u8>, Vec<u8>)>;

/// A check of the state a case leaves when it lands.
type Check = Box<dyn Fn(&Fx)>;

// ─────────────────────────────────────────────────────────────────────────
// Instruction data the SPL helpers in `common` do not have
// ─────────────────────────────────────────────────────────────────────────

/// `System::Assign`: `[1u32][owner 32]`. Accounts: the account (signer).
fn system_assign_data(owner: Pubkey) -> Vec<u8> {
    let mut data = 1u32.to_le_bytes().to_vec();
    data.extend_from_slice(owner.as_ref());
    data
}

/// `System::Allocate`: `[8u32][space u64]`. Accounts: the account (signer).
fn system_allocate_data(space: u64) -> Vec<u8> {
    let mut data = 8u32.to_le_bytes().to_vec();
    data.extend_from_slice(&space.to_le_bytes());
    data
}

/// SPL Token `Revoke`: `[5]`. Accounts: source, owner.
fn spl_revoke_data() -> Vec<u8> {
    vec![5]
}

/// Token-2022 `ImmutableOwner` TLV (type 7, length 0), which Token-2022 puts
/// on every ATA it creates.
fn immutable_owner_tlv() -> Vec<u8> {
    vec![7, 0, 0, 0]
}

/// A Token-2022 mint with no extensions, and a vault account of it holding
/// [`VAULT_TOKENS`] with `extra_lamports` above rent.
fn vault_token_2022_account(fx: &mut Fx, extra_lamports: u64) -> Pubkey {
    let t22 = spl_token_2022_id();
    let mint = Pubkey::new_unique();
    create_mint_with(
        &mut fx.context.svm,
        t22,
        mint,
        Pubkey::new_unique(),
        None,
        u64::MAX / 2,
        6,
        &[],
    );
    let address = Pubkey::new_unique();
    let vault = fx.vault();
    create_token_account_with(
        &mut fx.context.svm,
        t22,
        address,
        mint,
        vault,
        VAULT_TOKENS,
        TokenAccountOpts {
            extensions: immutable_owner_tlv(),
            extra_lamports,
            ..Default::default()
        },
    );
    address
}

// ─────────────────────────────────────────────────────────────────────────
// Cases
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Case {
    // Escapes: each leaves a grant that outlives the signer.
    /// I-0: `System::Assign(vault → another program)`.
    AssignVault,
    /// I-0: `System::Allocate(vault, 8)`.
    AllocateVault,
    /// I-2: `SetAuthority(AccountOwner)` on a vault token account.
    HandOverVaultTokenAccount,
    /// I-2: `SetAuthority(CloseAccount)` on a vault token account.
    SetCloseAuthorityOnVaultTokenAccount,
    /// I-2: `Approve` a delegate on a vault token account.
    ApproveDelegate,
    /// I-2: `Revoke` a delegate the Owner set.
    RevokeOwnersDelegate,
    /// I-2: `CloseAccount` on an empty vault token account.
    CloseVaultTokenAccount,
    /// I-2: `CloseAccount` on a wSOL account the vault already had (unwrap).
    UnwrapExistingWsol,
    /// I-3: hand the vault a token account whose close authority the actor keeps.
    GiveVaultAnAccountWithCloseAuthority,
    /// I-2: Token-2022 `Reallocate` of a vault Token-2022 account.
    Token2022Reallocate,
    /// I-2: Token-2022 `WithdrawExcessLamports` out of a vault Token-2022
    /// account.
    Token2022WithdrawExcessLamports,

    // Spending: what a non-Owner may still do.
    /// A SOL transfer out of the vault.
    SolTransfer,
    /// A token transfer out of a vault token account.
    TokenTransfer,
    /// A vault ATA, created and funded by the vault.
    CreateVaultAta,
    /// A temporary wSOL account created, filled, synced and closed back to the
    /// vault in one Execute, as a swap does.
    TemporaryWsolRoundTrip,
}

impl Case {
    /// The error a non-Owner gets, or `None` when the case lands for anyone.
    fn refused_with(self) -> Option<u32> {
        match self {
            Case::AssignVault => Some(ERR_VAULT_OWNER_CHANGED),
            Case::AllocateVault => Some(ERR_VAULT_DATA_LEN_CHANGED),
            Case::HandOverVaultTokenAccount
            | Case::SetCloseAuthorityOnVaultTokenAccount
            | Case::ApproveDelegate
            | Case::RevokeOwnersDelegate
            | Case::CloseVaultTokenAccount
            | Case::UnwrapExistingWsol
            | Case::GiveVaultAnAccountWithCloseAuthority
            | Case::Token2022Reallocate
            | Case::Token2022WithdrawExcessLamports => Some(ERR_TOKEN_AUTHORITY_CHANGED),
            Case::SolTransfer
            | Case::TokenTransfer
            | Case::CreateVaultAta
            | Case::TemporaryWsolRoundTrip => None,
        }
    }
}

/// Build the Execute for `case`, and a check of the state it should leave
/// when it lands.
fn build(fx: &mut Fx, actor: &Actor, case: Case) -> (Exec, Check) {
    let vault = fx.vault();
    let attacker = Pubkey::new_unique();
    let mut exec = Exec::new(actor);
    let check: Check = match case {
        Case::AssignVault => {
            let system = exec.readonly(solana_sdk::system_program::id());
            exec.call(system, &[IDX_VAULT], system_assign_data(attacker));
            Box::new(move |fx: &Fx| {
                assert_eq!(fx.context.svm.get_account(&vault).unwrap().owner, attacker)
            })
        },
        Case::AllocateVault => {
            let system = exec.readonly(solana_sdk::system_program::id());
            exec.call(system, &[IDX_VAULT], system_allocate_data(8));
            Box::new(move |fx: &Fx| {
                assert_eq!(fx.context.svm.get_account(&vault).unwrap().data.len(), 8)
            })
        },
        Case::HandOverVaultTokenAccount => {
            let token = exec.readonly(spl_token_id());
            let a = exec.writable(fx.vault_ata);
            exec.call(token, &[a, IDX_VAULT], spl_set_authority_data(2, attacker));
            let ata = fx.vault_ata;
            Box::new(move |fx: &Fx| assert_eq!(token_account_owner(&fx.context.svm, ata), attacker))
        },
        Case::SetCloseAuthorityOnVaultTokenAccount => {
            let token = exec.readonly(spl_token_id());
            let a = exec.writable(fx.vault_ata);
            exec.call(token, &[a, IDX_VAULT], spl_set_authority_data(3, attacker));
            let ata = fx.vault_ata;
            Box::new(move |fx: &Fx| {
                assert_eq!(
                    token_account_close_authority(&fx.context.svm, ata),
                    Some(attacker)
                )
            })
        },
        Case::ApproveDelegate => {
            let token = exec.readonly(spl_token_id());
            let a = exec.writable(fx.vault_ata);
            let d = exec.readonly(attacker);
            exec.call(token, &[a, d, IDX_VAULT], spl_approve_data(VAULT_TOKENS));
            let ata = fx.vault_ata;
            Box::new(move |fx: &Fx| {
                assert_eq!(token_account_delegate(&fx.context.svm, ata), Some(attacker))
            })
        },
        Case::RevokeOwnersDelegate => {
            let owners_delegate = Pubkey::new_unique();
            let mint = fx.mint;
            let acc = fx.token_account(
                mint,
                vault,
                100,
                TokenAccountOpts {
                    delegate: Some((owners_delegate, 50)),
                    ..Default::default()
                },
            );
            let token = exec.readonly(spl_token_id());
            let a = exec.writable(acc);
            exec.call(token, &[a, IDX_VAULT], spl_revoke_data());
            Box::new(move |fx: &Fx| assert_eq!(token_account_delegate(&fx.context.svm, acc), None))
        },
        Case::CloseVaultTokenAccount => {
            let token = exec.readonly(spl_token_id());
            let e = exec.writable(fx.vault_empty);
            exec.call(token, &[e, IDX_VAULT, IDX_VAULT], spl_close_account_data());
            let empty = fx.vault_empty;
            Box::new(move |fx: &Fx| assert_eq!(fx.lamports(&empty), 0))
        },
        Case::UnwrapExistingWsol => {
            let reserve = fx.context.svm.minimum_balance_for_rent_exemption(165);
            let wsol = fx.token_account(
                native_mint(),
                vault,
                1_000_000,
                TokenAccountOpts {
                    native_reserve: Some(reserve),
                    ..Default::default()
                },
            );
            let token = exec.readonly(spl_token_id());
            let w = exec.writable(wsol);
            exec.call(token, &[w, IDX_VAULT, IDX_VAULT], spl_close_account_data());
            Box::new(move |fx: &Fx| assert_eq!(fx.lamports(&wsol), 0))
        },
        Case::GiveVaultAnAccountWithCloseAuthority => {
            // SPL Token clears the delegate on an owner change but keeps a
            // non-native close authority, so the actor could close the
            // account later — rent, and anything paid into it meanwhile.
            let key = actor.key.pubkey();
            let mint = fx.mint;
            let acc = fx.token_account(
                mint,
                key,
                0,
                TokenAccountOpts {
                    close_authority: Some(key),
                    ..Default::default()
                },
            );
            let token = exec.readonly(spl_token_id());
            let a = exec.writable(acc);
            exec.call(
                token,
                &[a, forward_signer(IDX_ACTOR)],
                spl_set_authority_data(2, vault),
            );
            Box::new(move |fx: &Fx| {
                assert_eq!(token_account_owner(&fx.context.svm, acc), vault);
                assert_eq!(
                    token_account_close_authority(&fx.context.svm, acc),
                    Some(key)
                );
            })
        },
        Case::Token2022Reallocate => {
            let acc = vault_token_2022_account(fx, 0);
            let len_before = fx.context.svm.get_account(&acc).unwrap().data.len();
            let token = exec.readonly(spl_token_2022_id());
            let a = exec.writable(acc);
            let system = exec.readonly(solana_sdk::system_program::id());
            // MemoTransfer = 8. The actor pays for the new space.
            exec.call(
                token,
                &[a, forward_signer(IDX_ACTOR), system, IDX_VAULT],
                token_2022_reallocate_data(&[8]),
            );
            Box::new(move |fx: &Fx| {
                assert!(fx.context.svm.get_account(&acc).unwrap().data.len() > len_before)
            })
        },
        Case::Token2022WithdrawExcessLamports => {
            let excess = 1_000_000;
            let acc = vault_token_2022_account(fx, excess);
            let token = exec.readonly(spl_token_2022_id());
            let src = exec.writable(acc);
            let dst = exec.writable(attacker);
            exec.call(
                token,
                &[src, dst, IDX_VAULT],
                token_2022_withdraw_excess_lamports_data(),
            );
            Box::new(move |fx: &Fx| assert_eq!(fx.lamports(&attacker), excess))
        },
        Case::SolTransfer => {
            let system = exec.readonly(solana_sdk::system_program::id());
            let r = exec.writable(attacker);
            exec.call(system, &[IDX_VAULT, r], system_transfer_data(250_000_000));
            Box::new(move |fx: &Fx| assert_eq!(fx.lamports(&attacker), 250_000_000))
        },
        Case::TokenTransfer => {
            let mint = fx.mint;
            let dest = fx.token_account(mint, attacker, 0, TokenAccountOpts::default());
            let token = exec.readonly(spl_token_id());
            let src = exec.writable(fx.vault_ata);
            let dst = exec.writable(dest);
            exec.call(
                token,
                &[src, dst, IDX_VAULT],
                spl_transfer_data(VAULT_TOKENS),
            );
            Box::new(move |fx: &Fx| assert_eq!(token_amount(&fx.context.svm, dest), VAULT_TOKENS))
        },
        Case::CreateVaultAta => {
            let mint = fx.mint;
            let new_ata = ata_address(vault, mint, spl_token_id());
            let system = exec.readonly(solana_sdk::system_program::id());
            let ata = exec.readonly(ata_program_id());
            let token = exec.readonly(spl_token_id());
            let m = exec.readonly(mint);
            let n = exec.writable(new_ata);
            exec.call(
                ata,
                &[IDX_VAULT, n, IDX_VAULT, m, system, token],
                ata_create_idempotent_data(),
            );
            Box::new(move |fx: &Fx| {
                assert_eq!(token_account_owner(&fx.context.svm, new_ata), vault)
            })
        },
        Case::TemporaryWsolRoundTrip => {
            let wsol_ata = ata_address(vault, native_mint(), spl_token_id());
            let vault_before = fx.lamports(&vault);
            let system = exec.readonly(solana_sdk::system_program::id());
            let ata = exec.readonly(ata_program_id());
            let token = exec.readonly(spl_token_id());
            let m = exec.readonly(native_mint());
            let w = exec.writable(wsol_ata);
            exec.call(
                ata,
                &[IDX_VAULT, w, IDX_VAULT, m, system, token],
                ata_create_idempotent_data(),
            );
            exec.call(system, &[IDX_VAULT, w], system_transfer_data(5_000_000));
            exec.call(token, &[w], spl_sync_native_data());
            exec.call(token, &[w, IDX_VAULT, IDX_VAULT], spl_close_account_data());
            Box::new(move |fx: &Fx| {
                assert_eq!(fx.lamports(&vault), vault_before);
                assert_eq!(fx.lamports(&wsol_ata), 0);
            })
        },
    };
    (exec, check)
}

/// Run `case` as `role`. An Owner lands every case; anyone else lands the
/// spending cases and is refused every escape with its invariant's error, and
/// the vault and its token accounts are left as they were.
fn run(role: Role, case: Case) {
    let mut fx = Fx::new();
    let actor = fx.actor(role);
    let (exec, check) = build(&mut fx, &actor, case);
    let what = format!("{role:?} × {case:?}");

    let watched = [fx.vault(), fx.vault_ata, fx.vault_empty];
    let before: Vec<_> = watched
        .iter()
        .map(|k| fx.context.svm.get_account(k))
        .collect();

    match (role, case.refused_with()) {
        (Role::Owner, _) | (_, None) => {
            if let Err(failed) = fx.execute(&actor, exec) {
                panic!(
                    "{what}: expected success, got {:?}\n{}",
                    failed.err,
                    failed.meta.pretty_logs()
                );
            }
            check(&fx);
        },
        (_, Some(code)) => {
            assert_custom_error(fx.execute(&actor, exec), code, &what);
            let after: Vec<_> = watched
                .iter()
                .map(|k| fx.context.svm.get_account(k))
                .collect();
            assert_eq!(before, after, "{what}: nothing moved");
        },
    }
}

/// One `#[test]` per signer kind × case, so a failure names both.
macro_rules! matrix {
    ($($role:ident => $prefix:ident),* $(,)?) => {
        $(
            mod $prefix {
                use super::*;

                #[test] fn assign_vault() { run(Role::$role, Case::AssignVault) }
                #[test] fn allocate_vault() { run(Role::$role, Case::AllocateVault) }
                #[test] fn hand_over_vault_token_account() {
                    run(Role::$role, Case::HandOverVaultTokenAccount)
                }
                #[test] fn set_close_authority_on_vault_token_account() {
                    run(Role::$role, Case::SetCloseAuthorityOnVaultTokenAccount)
                }
                #[test] fn approve_delegate() { run(Role::$role, Case::ApproveDelegate) }
                #[test] fn revoke_owners_delegate() { run(Role::$role, Case::RevokeOwnersDelegate) }
                #[test] fn close_vault_token_account() {
                    run(Role::$role, Case::CloseVaultTokenAccount)
                }
                #[test] fn unwrap_existing_wsol() { run(Role::$role, Case::UnwrapExistingWsol) }
                #[test] fn give_vault_an_account_with_close_authority() {
                    run(Role::$role, Case::GiveVaultAnAccountWithCloseAuthority)
                }
                #[test] fn token_2022_reallocate() { run(Role::$role, Case::Token2022Reallocate) }
                #[test] fn token_2022_withdraw_excess_lamports() {
                    run(Role::$role, Case::Token2022WithdrawExcessLamports)
                }
                #[test] fn sol_transfer() { run(Role::$role, Case::SolTransfer) }
                #[test] fn token_transfer() { run(Role::$role, Case::TokenTransfer) }
                #[test] fn create_vault_ata() { run(Role::$role, Case::CreateVaultAta) }
                #[test] fn temporary_wsol_round_trip() {
                    run(Role::$role, Case::TemporaryWsolRoundTrip)
                }
            }
        )*
    };
}

matrix! {
    Owner => m_owner,
    Admin => m_admin,
    Delegate => m_delegate,
    UnrestrictedSession => m_unrestricted_session,
    BoundedSession => m_bounded_session,
}

/// An unrestricted session leaves no delegate behind: its Approve of a key of
/// its own on a vault token account is refused, and once the session is
/// revoked that key has no right to spend.
#[test]
fn m_unrestricted_session_cannot_leave_a_delegate_behind() {
    let mut fx = Fx::new();
    let actor = fx.actor(Role::UnrestrictedSession);
    let mut exec = Exec::new(&actor);
    let token = exec.readonly(spl_token_id());
    let a = exec.writable(fx.vault_ata);
    exec.call(
        token,
        &[a, IDX_ACTOR, IDX_VAULT],
        spl_approve_data(VAULT_TOKENS),
    );
    assert_custom_error(
        fx.execute(&actor, exec),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "unrestricted session Approve",
    );
    assert_eq!(token_account_delegate(&fx.context.svm, fx.vault_ata), None);
    assert_eq!(token_amount(&fx.context.svm, fx.vault_ata), VAULT_TOKENS);
}

// ─────────────────────────────────────────────────────────────────────────
// ExecuteDeferred
// ─────────────────────────────────────────────────────────────────────────

const DISC_AUTHORIZE: u8 = 6;
const DISC_EXECUTE_DEFERRED: u8 = 7;
/// Where the instructions sysvar sits in Authorize: after payer, wallet,
/// authority, DeferredExec, system program and rent.
const AUTHORIZE_SYSVAR_IX_INDEX: u8 = 6;
const EXPIRY_OFFSET: u16 = 100;
/// Byte 3 of a DeferredExec: `flags`.
const DEFERRED_FLAGS_OFFSET: usize = 3;
const DEFERRED_FLAG_OWNER: u8 = 1;

/// ExecuteDeferred's fixed accounts: 0 payer · 1 wallet · 2 vault ·
/// 3 DeferredExec · 4 refund (the payer); what a case adds starts at 5.
const D_IDX_VAULT: u8 = 2;
const D_FIRST_EXTRA: u8 = 5;

/// A passkey authority on a wallet with an Ed25519 Owner, or the passkey Owner
/// of a wallet of its own.
struct PasskeySigner {
    pk: Passkey,
    wallet: Pubkey,
    vault: Pubkey,
    authority: Pubkey,
}

/// A wallet whose only Owner is a passkey.
fn passkey_owner(context: &mut TestContext) -> PasskeySigner {
    let pk = Passkey::new();
    let w = create_passkey_wallet(context, &pk);
    context.svm.airdrop(&w.vault, VAULT_LAMPORTS).unwrap();
    PasskeySigner {
        pk,
        wallet: w.wallet,
        vault: w.vault,
        authority: w.authority,
    }
}

/// A passkey Admin, added by the Ed25519 Owner of a fresh wallet.
fn passkey_admin(context: &mut TestContext) -> PasskeySigner {
    let wallet = create_ed25519_wallet(context, VAULT_LAMPORTS);
    let pk = Passkey::new();
    let (authority, _) = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::AUTHORITY,
            wallet.wallet_pda.as_ref(),
            &pk.credential_id_hash,
        ],
        &context.program_id,
    );
    let mut data = vec![1u8]; // AddAuthority
    data.push(1); // Secp256r1
    data.push(RANK_ADMIN);
    data.extend_from_slice(&[0u8; 6]);
    data.extend_from_slice(&pk.credential_id_hash);
    data.extend_from_slice(
        p256::ecdsa::VerifyingKey::from(&pk.signing_key)
            .to_encoded_point(true)
            .as_bytes(),
    );
    data.push(pk.rp_id.len() as u8);
    data.extend_from_slice(pk.rp_id.as_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // no policy
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(context.payer.pubkey(), true),
            AccountMeta::new(wallet.wallet_pda, false),
            AccountMeta::new(wallet.owner_auth_pda, false),
            AccountMeta::new(authority, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(wallet.owner.pubkey(), true),
        ],
        data,
    };
    let payer = context.payer.insecure_clone();
    try_send(&mut context.svm, &payer, &[ix], &[&payer, &wallet.owner])
        .expect("AddAuthority (passkey Admin)");
    assert_eq!(authority_role(&context.svm, authority), RANK_ADMIN);
    PasskeySigner {
        pk,
        wallet: wallet.wallet_pda,
        vault: wallet.vault_pda,
        authority,
    }
}

/// tx2's accounts before the fee suffix, for `extra` after the fixed five.
fn deferred_accounts(
    context: &TestContext,
    s: &PasskeySigner,
    deferred: Pubkey,
    extra: &[AccountMeta],
) -> Vec<AccountMeta> {
    let payer = context.payer.pubkey();
    let mut accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(s.wallet, false),
        AccountMeta::new(s.vault, false),
        AccountMeta::new(deferred, false),
        AccountMeta::new(payer, false), // refund destination: the payer
    ];
    accounts.extend_from_slice(extra);
    accounts
}

/// The accounts hash the program will compute in tx2: each instruction's
/// program id, then each account it references, with the signer and writable
/// flags the runtime reports for that key across the whole message.
fn deferred_accounts_hash(
    context: &TestContext,
    accounts: &[AccountMeta],
    ixs: &[(u8, Vec<u8>, Vec<u8>)],
) -> [u8; 32] {
    let mut message = accounts.to_vec();
    message.extend(protocol_fee_account_metas(context));
    let payer = context.payer.pubkey();
    let flags = |key: &Pubkey| -> u8 {
        let signer = *key == payer || message.iter().any(|m| m.pubkey == *key && m.is_signer);
        let writable = *key == payer || message.iter().any(|m| m.pubkey == *key && m.is_writable);
        (signer as u8) | ((writable as u8) << 1)
    };
    let mut preimage = Vec::new();
    for (program, idxs, _) in ixs {
        for idx in std::iter::once(program).chain(idxs.iter()) {
            let key = accounts[(*idx & 0x7f) as usize].pubkey;
            preimage.extend_from_slice(key.as_ref());
            preimage.push(flags(&key));
        }
    }
    Sha256::digest(&preimage).into()
}

/// tx1: `s` authorizes `ixs` over `extra`. Returns the DeferredExec.
fn authorize(
    context: &mut TestContext,
    s: &PasskeySigner,
    extra: &[AccountMeta],
    ixs: &[(u8, Vec<u8>, Vec<u8>)],
) -> Pubkey {
    let counter = authority_counter(&context.svm, s.authority) + 1;
    let deferred = Pubkey::find_program_address(
        &[
            lazorkit_program::seeds::DEFERRED,
            s.wallet.as_ref(),
            s.authority.as_ref(),
            &counter.to_le_bytes(),
        ],
        &context.program_id,
    )
    .0;
    let compact = encode_compact(ixs);
    let accounts = deferred_accounts(context, s, deferred, extra);
    let accounts_hash = deferred_accounts_hash(context, &accounts, ixs);
    let instructions_hash: [u8; 32] = Sha256::digest(&compact).into();

    let mut signed_payload = Vec::with_capacity(66);
    signed_payload.extend_from_slice(&instructions_hash);
    signed_payload.extend_from_slice(&accounts_hash);
    signed_payload.extend_from_slice(&EXPIRY_OFFSET.to_le_bytes());

    let payer = context.payer.insecure_clone();
    let slot = context.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let prefix = secp256r1_prefix(slot, counter, AUTHORIZE_SYSVAR_IX_INDEX);
    let challenge = secp256r1_challenge(
        DISC_AUTHORIZE,
        &prefix,
        &signed_payload,
        &payer.pubkey(),
        &s.wallet,
        counter,
        &context.program_id,
    );
    let (precompile, auth_payload) =
        passkey_assertion(&s.pk.signing_key, s.pk.rp_id, &prefix, &challenge);

    let mut data = vec![DISC_AUTHORIZE];
    data.extend_from_slice(&signed_payload);
    data.extend_from_slice(&auth_payload);
    let ix = Instruction {
        program_id: context.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(s.wallet, false),
            AccountMeta::new(s.authority, false),
            AccountMeta::new(deferred, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
        ],
        data,
    };
    if let Err(failed) = try_send(&mut context.svm, &payer, &[precompile, ix], &[&payer]) {
        panic!(
            "Authorize failed: {:?}\n{}",
            failed.err,
            failed.meta.pretty_logs()
        );
    }
    deferred
}

#[allow(clippy::result_large_err)]
fn execute_deferred(
    context: &mut TestContext,
    s: &PasskeySigner,
    deferred: Pubkey,
    extra: &[AccountMeta],
    ixs: &[(u8, Vec<u8>, Vec<u8>)],
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    advance(&mut context.svm);
    let payer = context.payer.insecure_clone();
    let mut data = vec![DISC_EXECUTE_DEFERRED];
    data.extend_from_slice(&encode_compact(ixs));
    let ix = Instruction {
        program_id: context.program_id,
        accounts: with_protocol_fee_accounts(
            deferred_accounts(context, s, deferred, extra),
            context,
        ),
        data,
    };
    try_send(&mut context.svm, &payer, &[ix], &[&payer])
}

fn deferred_flags(context: &TestContext, deferred: Pubkey) -> u8 {
    context.svm.get_account(&deferred).unwrap().data[DEFERRED_FLAGS_OFFSET]
}

/// `System::Assign(vault → attacker)` as a deferred payload.
fn deferred_assign(attacker: Pubkey) -> (Vec<AccountMeta>, Compact) {
    let extra = vec![AccountMeta::new_readonly(
        solana_sdk::system_program::id(),
        false,
    )];
    let ixs = vec![(
        D_FIRST_EXTRA,
        vec![D_IDX_VAULT],
        system_assign_data(attacker),
    )];
    (extra, ixs)
}

#[test]
fn d_authorize_records_whether_an_owner_signed() {
    let mut context = setup_test();
    let recipient = Pubkey::new_unique();
    let extra = vec![
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new(recipient, false),
    ];
    let ixs = vec![(
        D_FIRST_EXTRA,
        vec![D_IDX_VAULT, D_FIRST_EXTRA + 1],
        system_transfer_data(1_000),
    )];

    let owner = passkey_owner(&mut context);
    let d = authorize(&mut context, &owner, &extra, &ixs);
    assert_eq!(deferred_flags(&context, d), DEFERRED_FLAG_OWNER, "Owner");

    let admin = passkey_admin(&mut context);
    let d = authorize(&mut context, &admin, &extra, &ixs);
    assert_eq!(deferred_flags(&context, d), 0, "Admin");
}

#[test]
fn d_admin_deferred_assign_of_the_vault_is_refused() {
    let mut context = setup_test();
    let admin = passkey_admin(&mut context);
    let attacker = Pubkey::new_unique();
    let (extra, ixs) = deferred_assign(attacker);
    let d = authorize(&mut context, &admin, &extra, &ixs);
    assert_custom_error(
        execute_deferred(&mut context, &admin, d, &extra, &ixs),
        ERR_VAULT_OWNER_CHANGED,
        "Admin deferred Assign",
    );
    assert_eq!(
        context.svm.get_account(&admin.vault).unwrap().owner,
        solana_sdk::system_program::id()
    );
}

#[test]
fn d_admin_deferred_allocate_of_the_vault_is_refused() {
    let mut context = setup_test();
    let admin = passkey_admin(&mut context);
    let extra = vec![AccountMeta::new_readonly(
        solana_sdk::system_program::id(),
        false,
    )];
    let ixs = vec![(D_FIRST_EXTRA, vec![D_IDX_VAULT], system_allocate_data(8))];
    let d = authorize(&mut context, &admin, &extra, &ixs);
    assert_custom_error(
        execute_deferred(&mut context, &admin, d, &extra, &ixs),
        ERR_VAULT_DATA_LEN_CHANGED,
        "Admin deferred Allocate",
    );
}

#[test]
fn d_admin_deferred_token_authority_changes_are_refused() {
    let mut context = setup_test();
    let admin = passkey_admin(&mut context);
    let mint = Pubkey::new_unique();
    create_mint(&mut context.svm, mint, Pubkey::new_unique(), 1_000);
    let attacker = Pubkey::new_unique();

    for (what, data) in [
        (
            "SetAuthority(AccountOwner)",
            spl_set_authority_data(2, attacker),
        ),
        (
            "SetAuthority(CloseAccount)",
            spl_set_authority_data(3, attacker),
        ),
    ] {
        let acc = Pubkey::new_unique();
        create_token_account(&mut context.svm, acc, mint, admin.vault, 1_000);
        let extra = vec![
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new(acc, false),
        ];
        let ixs = vec![(D_FIRST_EXTRA, vec![D_FIRST_EXTRA + 1, D_IDX_VAULT], data)];
        let d = authorize(&mut context, &admin, &extra, &ixs);
        assert_custom_error(
            execute_deferred(&mut context, &admin, d, &extra, &ixs),
            ERR_TOKEN_AUTHORITY_CHANGED,
            what,
        );
        assert_eq!(
            token_account_owner(&context.svm, acc),
            admin.vault,
            "{what}"
        );
    }

    // Approve: source, delegate, owner.
    let acc = Pubkey::new_unique();
    create_token_account(&mut context.svm, acc, mint, admin.vault, 1_000);
    let extra = vec![
        AccountMeta::new_readonly(spl_token_id(), false),
        AccountMeta::new(acc, false),
        AccountMeta::new_readonly(attacker, false),
    ];
    let ixs = vec![(
        D_FIRST_EXTRA,
        vec![D_FIRST_EXTRA + 1, D_FIRST_EXTRA + 2, D_IDX_VAULT],
        spl_approve_data(1_000),
    )];
    let d = authorize(&mut context, &admin, &extra, &ixs);
    assert_custom_error(
        execute_deferred(&mut context, &admin, d, &extra, &ixs),
        ERR_TOKEN_AUTHORITY_CHANGED,
        "Approve",
    );
    assert_eq!(token_account_delegate(&context.svm, acc), None);
}

/// An Admin still spends through the deferred path.
#[test]
fn d_admin_deferred_transfer_lands() {
    let mut context = setup_test();
    let admin = passkey_admin(&mut context);
    let recipient = Pubkey::new_unique();
    let extra = vec![
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new(recipient, false),
    ];
    let ixs = vec![(
        D_FIRST_EXTRA,
        vec![D_IDX_VAULT, D_FIRST_EXTRA + 1],
        system_transfer_data(400_000_000),
    )];
    let d = authorize(&mut context, &admin, &extra, &ixs);
    if let Err(failed) = execute_deferred(&mut context, &admin, d, &extra, &ixs) {
        panic!("{:?}\n{}", failed.err, failed.meta.pretty_logs());
    }
    assert_eq!(context.svm.get_balance(&recipient), Some(400_000_000));
}

/// An Owner keeps full power through the deferred path.
#[test]
fn d_owner_deferred_assign_lands() {
    let mut context = setup_test();
    let owner = passkey_owner(&mut context);
    let attacker = Pubkey::new_unique();
    let (extra, ixs) = deferred_assign(attacker);
    let d = authorize(&mut context, &owner, &extra, &ixs);
    if let Err(failed) = execute_deferred(&mut context, &owner, d, &extra, &ixs) {
        panic!("{:?}\n{}", failed.err, failed.meta.pretty_logs());
    }
    assert_eq!(
        context.svm.get_account(&owner.vault).unwrap().owner,
        attacker
    );
}

/// A DeferredExec written before `flags` existed holds zero there. Even one an
/// Owner authorized is then guarded: an authorization pending across the
/// upgrade can lose power, never gain it.
#[test]
fn d_an_authorization_without_the_owner_flag_is_guarded() {
    let mut context = setup_test();
    let owner = passkey_owner(&mut context);
    let (extra, ixs) = deferred_assign(Pubkey::new_unique());
    let d = authorize(&mut context, &owner, &extra, &ixs);
    assert_eq!(deferred_flags(&context, d), DEFERRED_FLAG_OWNER);

    let mut account = context.svm.get_account(&d).unwrap();
    account.data[DEFERRED_FLAGS_OFFSET] = 0;
    context.svm.set_account(d, account).unwrap();

    assert_custom_error(
        execute_deferred(&mut context, &owner, d, &extra, &ixs),
        ERR_VAULT_OWNER_CHANGED,
        "pre-upgrade DeferredExec",
    );
    assert_eq!(
        context.svm.get_account(&owner.vault).unwrap().owner,
        solana_sdk::system_program::id()
    );
}
