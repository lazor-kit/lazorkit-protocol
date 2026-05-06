/**
 * Solana system program / sysvar addresses.
 *
 * Kit does not re-export these constants the way @solana/web3.js v1
 * does (SystemProgram.programId, SYSVAR_RENT_PUBKEY, etc), so we
 * declare them here. The base58 strings are the canonical Solana
 * addresses; verified against @solana/web3.js v1's exports.
 */
import { address, type Address } from '@solana/kit';

/** Solana System Program. */
export const SYSTEM_PROGRAM_ADDRESS: Address = address(
  '11111111111111111111111111111111',
);

/** Sysvar that exposes the current transaction's instructions for introspection. */
export const SYSVAR_INSTRUCTIONS_ADDRESS: Address = address(
  'Sysvar1nstructions1111111111111111111111111',
);

/** Rent sysvar. */
export const SYSVAR_RENT_ADDRESS: Address = address(
  'SysvarRent111111111111111111111111111111111',
);

/** Native Secp256r1 verify precompile. */
export const SECP256R1_PROGRAM_ADDRESS: Address = address(
  'Secp256r1SigVerify1111111111111111111111111',
);

/** Ed25519 verify precompile. */
export const ED25519_PROGRAM_ADDRESS: Address = address(
  'Ed25519SigVerify111111111111111111111111111',
);

/** SPL Token program. */
export const TOKEN_PROGRAM_ADDRESS: Address = address(
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
);

/** SPL Token-2022 program. */
export const TOKEN_2022_PROGRAM_ADDRESS: Address = address(
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
);
