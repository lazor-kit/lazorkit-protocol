/**
 * Compact-instruction packing + hash helpers (kit flavor).
 *
 * These match sdk-legacy/src/utils/packing.ts byte-for-byte. The packed
 * format is what LazorKit's Execute / ExecuteDeferred reads from
 * instruction data, and the hashes feed into the deferred-execution
 * signed payload.
 */
import { createHash } from 'node:crypto';
import {
  getAddressEncoder,
  type AccountMeta,
} from '@solana/kit';

const addressEncoder = getAddressEncoder();

export interface CompactInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

/**
 * Wire format produced (matches `validate_compact_instructions` on-chain):
 *   [num_instructions: u8]
 *   for each instruction:
 *     [program_id_index: u8] [num_accounts: u8]
 *     [account_indexes: u8[num_accounts]]
 *     [data_len: u16 LE] [data: u8[data_len]]
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

export function packCompactInstructions(
  instructions: ReadonlyArray<CompactInstruction>,
): Uint8Array {
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
 * SHA-256 of the concatenated 32-byte address bytes for every account
 * referenced by the compact instructions, in the order
 * `[program_id, ...account_addresses]` per instruction.
 *
 * Must match the on-chain `compute_accounts_hash`.
 */
function flagsOf(meta: AccountMeta): number {
  // kit encodes privilege as an AccountRole enum: bit 0 = writable, bit 1 = signer.
  const role = meta.role as number;
  return accountFlags((role & 0b10) !== 0, (role & 0b01) !== 0);
}

export function computeAccountsHash(
  accountMetas: ReadonlyArray<AccountMeta>,
  instructions: ReadonlyArray<CompactInstruction>,
): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const ix of instructions) {
    const program = accountMetas[ix.programIdIndex];
    if (!program) {
      throw new Error(
        `compact ix references program_id_index ${ix.programIdIndex} but only ${accountMetas.length} accounts were supplied`,
      );
    }
    parts.push(addressEncoder.encode(program.address) as Uint8Array);
    parts.push(new Uint8Array([flagsOf(program)]));
    for (const byte of ix.accountIndexes) {
      const { index } = decodeAccountIndex(byte);
      const a = accountMetas[index];
      if (!a) {
        throw new Error(
          `compact ix references account_index ${index} but only ${accountMetas.length} accounts were supplied`,
        );
      }
      parts.push(addressEncoder.encode(a.address) as Uint8Array);
      parts.push(new Uint8Array([flagsOf(a)]));
    }
  }
  const data = concatBytes(parts);
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * SHA-256 of the packed compact-instructions buffer. Used by deferred
 * execution: tx1 (Authorize) signs this hash; tx2 (ExecuteDeferred)
 * re-packs the instructions on-chain and the program verifies the
 * hash matches.
 */
export function computeInstructionsHash(
  instructions: ReadonlyArray<CompactInstruction>,
): Uint8Array {
  const packed = packCompactInstructions(instructions);
  return new Uint8Array(createHash('sha256').update(packed).digest());
}

function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Re-export so client modules can use the same helper without crossing
 * module boundaries.
 * @internal
 */
export { concatBytes };
