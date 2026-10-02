import { type AccountMeta } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from './bytes';

export interface CompactInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

/**
 * Packs a list of compact instructions into the binary format expected
 * by LazorKit's Execute instruction.
 *
 * Format:
 *   [num_instructions: u8]
 *   for each instruction:
 *     [program_id_index: u8]
 *     [num_accounts: u8]
 *     [account_indexes: u8[]]
 *     [data_len: u16 LE]
 *     [data: u8[]]
 */
/**
 * Account index encoding.
 *
 * The high bit of an index byte opts that account into signer forwarding.
 * Forwarding used to be implicit — every outer signer became a signer of every
 * inner instruction referencing it, with nobody having said so — which let a
 * session limited to 0.001 SOL move 2 SOL out of the paymaster's wallet. Making
 * it a bit inside the compact bytes puts the request inside the signed payload
 * for a Secp256r1 authority, so the passkey holder signs the elevation.
 *
 * Costs one bit: indices are capped at 127.
 */
export const ACCOUNT_INDEX_MASK = 0x7f;
export const ACCOUNT_INDEX_FORWARD_SIGNER = 0x80;
export const MAX_ACCOUNT_INDEX = ACCOUNT_INDEX_MASK;

/** Encode an index plus its forward-signer request into one byte. */
export function encodeAccountIndex(index: number, forwardSigner: boolean): number {
  if (index < 0 || index > MAX_ACCOUNT_INDEX) {
    throw new Error(
      `account index ${index} exceeds the ${MAX_ACCOUNT_INDEX} ceiling imposed by the ` +
        `forward-signer flag bit; reduce the number of accounts in this transaction`,
    );
  }
  return forwardSigner ? index | ACCOUNT_INDEX_FORWARD_SIGNER : index;
}

/** Strip the flag bit back off an index byte. */
export function decodeAccountIndex(byte: number): { index: number; forwardSigner: boolean } {
  return {
    index: byte & ACCOUNT_INDEX_MASK,
    forwardSigner: (byte & ACCOUNT_INDEX_FORWARD_SIGNER) !== 0,
  };
}

/**
 * Privilege byte hashed after each account key.
 *
 * The *runtime* flags, not the requested ones: these are what authorise the
 * inner CPI, so they are what the signature must cover. Must match
 * `compact::account_flags` on-chain.
 */
export function accountFlags(isSigner: boolean, isWritable: boolean): number {
  return (isSigner ? 1 : 0) | (isWritable ? 2 : 0);
}

export function packCompactInstructions(instructions: CompactInstruction[]): Uint8Array {
  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([instructions.length]));

  for (const ix of instructions) {
    parts.push(new Uint8Array([ix.programIdIndex, ix.accountIndexes.length]));
    parts.push(new Uint8Array(ix.accountIndexes));
    const len = ix.data.length;
    parts.push(new Uint8Array([len & 0xff, (len >> 8) & 0xff]));
    parts.push(ix.data);
  }

  return concatBytes(parts);
}

/**
 * Computes the SHA-256 hash of all account pubkeys referenced by compact instructions.
 * Must match the on-chain `compute_accounts_hash`.
 */
export function computeAccountsHash(
  accountMetas: AccountMeta[],
  instructions: CompactInstruction[],
): Uint8Array {
  const parts: Uint8Array[] = [];
  const push = (meta: AccountMeta | undefined, what: string) => {
    if (!meta) {
      throw new Error(
        `compact ix references ${what} but only ${accountMetas.length} accounts were supplied`,
      );
    }
    parts.push(meta.pubkey.toBytes());
    parts.push(new Uint8Array([accountFlags(meta.isSigner, meta.isWritable)]));
  };
  for (const ix of instructions) {
    // Mask the forward-signer bit off the program-id index before lookup, matching
    // the on-chain preimage walk (compact.rs).
    push(
      accountMetas[decodeAccountIndex(ix.programIdIndex).index],
      `program_id_index ${ix.programIdIndex}`,
    );
    for (const byte of ix.accountIndexes) {
      const { index } = decodeAccountIndex(byte);
      push(accountMetas[index], `account_index ${index}`);
    }
  }
  const data = concatBytes(parts);
  return sha256(data);
}

/**
 * Computes the SHA-256 hash of packed compact instructions.
 * Used for deferred execution — the hash is signed in tx1 and verified in tx2.
 */
export function computeInstructionsHash(
  instructions: CompactInstruction[],
): Uint8Array {
  const packed = packCompactInstructions(instructions);
  return sha256(packed);
}

