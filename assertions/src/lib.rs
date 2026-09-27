#![allow(unexpected_cfgs)]
#[cfg(target_os = "solana")]
use pinocchio::syscalls::sol_memcmp_;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
};
use pinocchio_pubkey::declare_id;

// LazorKit Program ID — chosen at build time by exactly one cluster feature.
// A binary compiled for one ID malfunctions at any other: every internal
// `crate::ID` check fails, and the entrypoint refuses outright (M-2).
//
// v2 lives at its own addresses. The v1 deployments keep theirs, and the only
// thing ever deployed there again is a *sunset* binary: the handful of
// instructions a retired v1 wallet still needs to leave (see `SUNSET`). This is
// how Solana protocols ship a breaking major — Squads v3/v4, Jupiter v4/v6,
// Token/Token-2022 all run side by side — rather than freezing every user's
// funds on one flag day.
//
//   feature          id                                             runs
//   mainnet          LAZORKIT_V2_MAINNET_ID                         v2
//   devnet           57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv   v2
//   staging          HQ584adp8ub2FzrTx1fdNmXmrL5yuyVndafPB3x4NYG3   v2
//   mainnet-v1       LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi    sunset
//   devnet-v1        4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS   sunset
//   rehearsal        3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA   v2
//   rehearsal-v1     3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA   sunset
//
// The v1 ids can only be built as sunset binaries. There is no feature that
// puts full v2 at a v1 address, so a slip of the flag cannot recreate the
// flag day this layout exists to avoid.

#[cfg(feature = "mainnet")]
declare_id!("LAZORKIT_V2_MAINNET_ID");

#[cfg(feature = "devnet")]
declare_id!("57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv");

#[cfg(feature = "staging")]
declare_id!("HQ584adp8ub2FzrTx1fdNmXmrL5yuyVndafPB3x4NYG3");

#[cfg(feature = "mainnet-v1")]
declare_id!("LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi");

#[cfg(feature = "devnet-v1")]
declare_id!("4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS");

#[cfg(any(feature = "rehearsal", feature = "rehearsal-v1"))]
declare_id!("3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA");

/// How many cluster features this build enabled. Exactly one is legal: none
/// leaves `ID` undeclared, and two would pin two addresses at once.
const CLUSTER_FEATURES: usize = cfg!(feature = "mainnet") as usize
    + cfg!(feature = "devnet") as usize
    + cfg!(feature = "staging") as usize
    + cfg!(feature = "mainnet-v1") as usize
    + cfg!(feature = "devnet-v1") as usize
    + cfg!(feature = "rehearsal") as usize
    + cfg!(feature = "rehearsal-v1") as usize;

const _: () = assert!(
    CLUSTER_FEATURES == 1,
    "LazorKit: pick exactly one cluster feature — mainnet | devnet | staging | \
     mainnet-v1 | devnet-v1 | rehearsal | rehearsal-v1"
);

/// The only key allowed to run `InitializeProtocol` (see the program's
/// `state::protocol_config`). It lives here, in the same cluster arms as the
/// program id, so no feature spelling can pair the mainnet id with the
/// committed devnet test key. The arms are positive and exhaustive over the
/// cluster features: with none of them the build fails, it does not default.
#[cfg(any(feature = "mainnet", feature = "mainnet-v1"))]
pub const PROTOCOL_INIT_AUTHORITY: Pubkey =
    pinocchio_pubkey::pubkey!("4fZM6RPRLkeW8T5dDctZjWaqidFDACyW41Kqztj7uL5V");

/// Every test cluster — devnet, staging, the rehearsal slot and their sunset
/// twins — reuses the committed devnet test authority
/// (`keys/devnet-init-authority.json`). None of them carries value.
#[cfg(any(
    feature = "devnet",
    feature = "staging",
    feature = "devnet-v1",
    feature = "rehearsal",
    feature = "rehearsal-v1"
))]
pub const PROTOCOL_INIT_AUTHORITY: Pubkey =
    pinocchio_pubkey::pubkey!("9AmBA2C7VwtoQXXowpqBsLC4azNXm81BCSXZNiQM6BsW");

/// True in the binary that replaces a retired v1 deployment.
///
/// A sunset binary accepts exactly the instructions a v1 wallet needs in order
/// to leave, and refuses everything else — no new wallets, no Execute, no fee
/// layer. What remains is reachable by the owner alone (`MigrateWallet`), by
/// the original payer (`ReclaimDeferred`), or by anyone once there is nothing
/// left to protect (`CloseExpiredSession`).
pub const SUNSET: bool = cfg!(any(
    feature = "mainnet-v1",
    feature = "devnet-v1",
    feature = "rehearsal-v1"
));

// Pin the property that matters rather than the spelling of `SUNSET`: every v1
// id builds as a sunset binary. If a refactor drops one from the list above,
// this fails to compile instead of shipping full v2 at a v1 address.
#[cfg(any(
    feature = "mainnet-v1",
    feature = "devnet-v1",
    feature = "rehearsal-v1"
))]
const _: () = assert!(SUNSET, "LazorKit: a v1 id must build as a sunset binary");
#[cfg(any(
    feature = "mainnet",
    feature = "devnet",
    feature = "staging",
    feature = "rehearsal"
))]
const _: () = assert!(!SUNSET, "LazorKit: a v2 id must build as the full program");

#[allow(unused_imports)]
use std::mem::MaybeUninit;

#[inline(always)]
#[cfg(target_os = "solana")]
pub fn sol_assert_bytes_eq(left: &[u8], right: &[u8], len: usize) -> bool {
    unsafe {
        let mut result = MaybeUninit::<i32>::uninit();
        sol_memcmp_(
            left.as_ptr(),
            right.as_ptr(),
            len as u64,
            result.as_mut_ptr() as *mut i32,
        );
        result.assume_init() == 0
    }
}

#[cfg(not(target_os = "solana"))]
pub fn sol_assert_bytes_eq(left: &[u8], right: &[u8], len: usize) -> bool {
    left.len() >= len && right.len() >= len && left[..len] == right[..len]
}

macro_rules! sol_assert {
  ($func_name:ident, $($param:ident: $type:ty),* $(,)? | $check:expr) => {
      #[inline(always)]
      pub fn $func_name<E: Into<ProgramError>>($($param: $type,)* error: E) -> ProgramResult {
          if $check {
              Ok(())
          } else {
              Err(error.into())
          }
      }
  };
}

macro_rules! sol_assert_return {
  ($func_name:ident, $return_type:ty, $($param:ident: $type:ty),* $(,)? | $check:expr) => {
      #[inline(always)]
      pub fn $func_name<E: Into<ProgramError>>($($param: $type,)* error: E) -> Result<$return_type, ProgramError> {
          if $check.is_some() {
              Ok($check.unwrap())
          } else {
            //need this branch to avoid the msg when we run into
              Err(error.into())
          }
      }
  };
}

sol_assert_return!(check_any_pda, u8, seeds: &[&[u8]], target_key: &Pubkey, program_id: &Pubkey | {
  let (pda, bump) = find_program_address(seeds, program_id);
  if sol_assert_bytes_eq(pda.as_ref(), target_key.as_ref(), 32) {
    Some(bump)
  } else {
    None
  }
});

sol_assert!(check_zero_data, account: &AccountInfo |
  account.data_len() == 0
);
