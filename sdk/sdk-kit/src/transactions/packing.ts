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
  type Address,
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
    for (const idx of ix.accountIndexes) {
      const a = accountMetas[idx];
      if (!a) {
        throw new Error(
          `compact ix references account_index ${idx} but only ${accountMetas.length} accounts were supplied`,
        );
      }
      parts.push(addressEncoder.encode(a.address) as Uint8Array);
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
