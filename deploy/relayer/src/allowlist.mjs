// What this relayer will sponsor. Mirrors `allowed_programs` in
// lazorkit-protocol/deploy/kora/kora.devnet.toml, plus the Address Lookup Table
// program (the hosted devnet Kora allows it too).
//
// Every instruction's program id must be in ALLOWED_PROGRAMS — top-level ones
// from the message, and inner (CPI) ones from a simulation of the transaction.
// The Secp256r1 precompile is listed explicitly: every v2 passkey action carries
// one and it gets no exemption.

export const LAZORKIT_V2_DEVNET = '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv';

export const SYSTEM_PROGRAM = '11111111111111111111111111111111';
export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
export const ALT_PROGRAM = 'AddressLookupTab1e1111111111111111111111111';
export const SECP256R1_PROGRAM = 'Secp256r1SigVerify1111111111111111111111111';

export const ALLOWED_PROGRAMS = new Map([
  [LAZORKIT_V2_DEVNET, 'LazorKit v2'],
  [SECP256R1_PROGRAM, 'Secp256r1'],
  [SYSTEM_PROGRAM, 'System'],
  [TOKEN_PROGRAM, 'Token'],
  [TOKEN_2022_PROGRAM, 'Token-2022'],
  [ATA_PROGRAM, 'ATA'],
  [COMPUTE_BUDGET_PROGRAM, 'ComputeBudget'],
  [ALT_PROGRAM, 'ALT'],
]);

// Kora's `require_one_of_programs`. On by default, as in kora.devnet.toml: the
// relayer refuses any transaction that does not call LazorKit v2 at the top
// level. --allow-plain lifts it (only the smoke test's plain transfer needs that).
export const REQUIRE_ONE_OF = [LAZORKIT_V2_DEVNET];

// Names for programs that are NOT allowed, so rejections and logs read well.
const KNOWN_OTHER = new Map([
  ['4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS', 'LazorKit v1 (not allowed)'],
  ['MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', 'Memo (not allowed)'],
  ['Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo', 'Memo v1 (not allowed)'],
  ['Ed25519SigVerify111111111111111111111111111', 'Ed25519 precompile (not allowed)'],
  ['KeccakSecp256k11111111111111111111111111111', 'Secp256k1 precompile (not allowed)'],
  ['BPFLoaderUpgradeab1e11111111111111111111111', 'BPF Upgradeable Loader (not allowed)'],
]);

export function programLabel(id) {
  return ALLOWED_PROGRAMS.get(id) ?? KNOWN_OTHER.get(id) ?? id;
}

// Genesis hashes, for the startup cluster check.
export const DEVNET_GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
export const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
