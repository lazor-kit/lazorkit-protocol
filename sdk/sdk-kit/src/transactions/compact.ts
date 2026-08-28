/**
 * Convert standard kit Instructions into LazorKit's compact format.
 *
 * Mirrors sdk-legacy/src/utils/compact.ts. The compact form:
 *   - Each Instruction's accounts (and program address) are replaced
 *     with indexes into a flat AccountMeta[] table.
 *   - The fixed prefix of that table is determined by the LazorKit
 *     instruction itself (e.g. for Execute: payer, wallet, authority,
 *     vault, [signer], …); everything else becomes "remainingAccounts"
 *     appended to the on-chain account list.
 *   - When the same address appears as account in multiple ixs with
 *     different signer/writable flags, the most-permissive flags win
 *     (mirrors the on-chain merge semantics).
 */
import { encodeAccountIndex } from './packing.js';
import { AccountRole, type AccountMeta, type Instruction, type Address } from '@solana/kit';
import type { CompactInstruction } from './packing.js';

interface MutableMeta {
  address: Address;
  isSigner: boolean;
  isWritable: boolean;
}

function roleFromFlags(isSigner: boolean, isWritable: boolean): AccountRole {
  if (isSigner) return isWritable ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER;
  return isWritable ? AccountRole.WRITABLE : AccountRole.READONLY;
}

function flagsFromRole(role: AccountRole): { isSigner: boolean; isWritable: boolean } {
  return {
    isSigner: role === AccountRole.READONLY_SIGNER || role === AccountRole.WRITABLE_SIGNER,
    isWritable: role === AccountRole.WRITABLE || role === AccountRole.WRITABLE_SIGNER,
  };
}

/**
 * Build the compact-instruction layout + remainingAccounts for a list
 * of user instructions, given the fixed prefix accounts.
 *
 * `fixedAccounts` are the addresses already in the LazorKit instruction's
 * native account layout. `userInstructions` are the inner instructions
 * to be CPI'd by the wallet.
 *
 * `payer` is passed explicitly rather than read off `fixedAccounts[0]`. The
 * program refuses to forward the fee payer's signature into any inner CPI —
 * that was the H-3 hole — and relying on position to identify it would be one
 * refactor away from silently marking the wrong account.
 */
export function buildCompactLayout(
  fixedAccounts: ReadonlyArray<Address>,
  userInstructions: ReadonlyArray<Instruction>,
  /// Required, not derived from `fixedAccounts[0]`: an inner instruction may
  /// legitimately declare the fee payer a signer, which is the H-3 attack shape.
  payer: Address,
): {
  compactInstructions: CompactInstruction[];
  remainingAccounts: AccountMeta[];
} {
  // Index map: address -> index in the full account layout.
  const indexMap = new Map<string, number>();
  for (let i = 0; i < fixedAccounts.length; i++) {
    indexMap.set(fixedAccounts[i]!, i);
  }

  // Insertion-ordered collection of new accounts (i.e. accounts not
  // already in `fixedAccounts`). Flags are merged most-permissive.
  const remainingMap = new Map<string, MutableMeta>();

  for (const ix of userInstructions) {
    // Inner instructions use the program address as a non-signer,
    // non-writable account in the table.
    if (!indexMap.has(ix.programAddress) && !remainingMap.has(ix.programAddress)) {
      remainingMap.set(ix.programAddress, {
        address: ix.programAddress,
        isSigner: false,
        isWritable: false,
      });
    }

    if (!ix.accounts) continue;

    for (const acc of ix.accounts) {
      const flags = flagsFromRole(acc.role);
      const key = acc.address;
      if (indexMap.has(key)) continue; // already in fixed prefix
      const existing = remainingMap.get(key);
      if (existing) {
        existing.isSigner = existing.isSigner || flags.isSigner;
        existing.isWritable = existing.isWritable || flags.isWritable;
      } else {
        remainingMap.set(key, {
          address: acc.address,
          isSigner: flags.isSigner,
          isWritable: flags.isWritable,
        });
      }
    }
  }

  // Assign indexes to remaining accounts (after fixed accounts).
  const remainingMutable = Array.from(remainingMap.values());
  let nextIndex = fixedAccounts.length;
  for (const acc of remainingMutable) {
    indexMap.set(acc.address, nextIndex++);
  }

  // Compact each user instruction.
  // Signer forwarding is opt-in on the wire. The intent is already here in
  // `acc.role`; it used to be discarded at exactly this point, which is why the
  // program had to infer it — and inferred it for every outer signer, including
  // the payer. The payer is never flagged: the program would refuse it anyway,
  // and a request it will always reject is a request worth not making.
  const compactInstructions: CompactInstruction[] = userInstructions.map((ix) => ({
    programIdIndex: encodeAccountIndex(indexMap.get(ix.programAddress)!, false),
    accountIndexes: (ix.accounts ?? []).map((a) =>
      encodeAccountIndex(
        indexMap.get(a.address)!,
        flagsFromRole(a.role).isSigner && a.address !== payer,
      ),
    ),
    data: ix.data ? new Uint8Array(ix.data) : new Uint8Array(0),
  }));

  // Convert MutableMeta back to kit AccountMeta with proper role enum.
  const remainingAccounts: AccountMeta[] = remainingMutable.map((m) => ({
    address: m.address,
    role: roleFromFlags(m.isSigner, m.isWritable),
  }));

  return { compactInstructions, remainingAccounts };
}
