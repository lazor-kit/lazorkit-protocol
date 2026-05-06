export * from './system.js';
// Low-level instruction builders (`create*Ix`, `appendProtocolFeeAccounts`,
// `ProtocolFeeAccounts` interface) are intentionally NOT re-exported here.
// dApp consumers should use the high-level `LazorKit` class methods
// which auto-resolve fee accounts on every fee-eligible path. Tests
// that exercise edge cases (custom counter values, replay scenarios,
// hash-mismatch attacks) import the builders directly from
// `./builders.js` (relative path); they're available within the
// monorepo for that purpose, but not surfaced to npm consumers.
//
// The discriminator + role + auth-type *constants* are still
// re-exported because they're useful for inspecting on-chain state.
export {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  ROLE_OWNER,
  ROLE_ADMIN,
  ROLE_SPENDER,
  DISC_CREATE_WALLET,
  DISC_ADD_AUTHORITY,
  DISC_REMOVE_AUTHORITY,
  DISC_TRANSFER_OWNERSHIP,
  DISC_EXECUTE,
  DISC_CREATE_SESSION,
  DISC_AUTHORIZE,
  DISC_EXECUTE_DEFERRED,
  DISC_RECLAIM_DEFERRED,
  DISC_REVOKE_SESSION,
  DISC_INITIALIZE_PROTOCOL,
  DISC_UPDATE_PROTOCOL,
  DISC_REGISTER_PAYER,
  DISC_WITHDRAW_TREASURY,
  DISC_INITIALIZE_TREASURY_SHARD,
  SECP256R1_PROGRAM_ADDRESS,
} from './builders.js';
