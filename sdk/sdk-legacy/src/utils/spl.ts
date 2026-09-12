import { Buffer } from 'buffer';
// Minimal SPL Token / Associated Token Account helpers. sdk-legacy depends only
// on @solana/web3.js, so the few things the migration flow needs from spl-token
// are derived by hand here rather than pulling the package in.

import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

export const TOKEN_PROGRAM_ID = new PublicKey(
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
);
export const TOKEN_2022_PROGRAM_ID = new PublicKey(
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
);
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey(
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
);

/** The associated token account for `(owner, mint)` under the given token program. */
export function getAssociatedTokenAddress(
  mint: PublicKey,
  owner: PublicKey,
  tokenProgram: PublicKey,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0];
}

/**
 * `CreateIdempotent` — creates the ATA if it does not already exist, and is a
 * no-op if it does. Idempotent so re-running a migration that partly completed
 * cannot fail here.
 */
export function createAssociatedTokenAccountIdempotentIx(params: {
  payer: PublicKey;
  ata: PublicKey;
  owner: PublicKey;
  mint: PublicKey;
  tokenProgram: PublicKey;
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.ata, isSigner: false, isWritable: true },
      { pubkey: params.owner, isSigner: false, isWritable: false },
      { pubkey: params.mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: params.tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]), // CreateIdempotent
  });
}

/** Is `owner` (bytes 32..64) of this token account equal to `expected`? */
export function tokenAccountOwner(data: Uint8Array): PublicKey {
  return new PublicKey(data.slice(32, 64));
}

/** Amount (u64 LE at bytes 64..72) of a token account. */
export function tokenAccountAmount(data: Uint8Array): bigint {
  const dv = new DataView(data.buffer, data.byteOffset + 64, 8);
  return dv.getBigUint64(0, true);
}

/** Mint (bytes 0..32) of a token account. */
export function tokenAccountMint(data: Uint8Array): PublicKey {
  return new PublicKey(data.slice(0, 32));
}
