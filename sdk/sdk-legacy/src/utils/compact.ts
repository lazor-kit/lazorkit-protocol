import { PublicKey, TransactionInstruction } from '@solana/web3.js';
import { encodeAccountIndex } from './packing';
import type { CompactInstruction } from './packing';

/**
 * Converts standard Solana TransactionInstructions into the compact format
 * expected by the Execute instruction. Automatically computes account indexes
 * and builds the remaining accounts list.
 *
 * @param fixedAccounts - Accounts already in the instruction layout
 *                        (e.g., payer, wallet, authority, vault, sysvar)
 * @param instructions  - Standard Solana TransactionInstructions to convert
 * @param payer         - Passed explicitly rather than read off
 *   `fixedAccounts[0]`. The program refuses to forward the fee payer's
 *   signature into any inner CPI — that was the H-3 hole — and relying on
 *   position to identify it would be one refactor away from marking the wrong
 *   account.
 */
export function buildCompactLayout(
  fixedAccounts: PublicKey[],
  instructions: TransactionInstruction[],
  /// Required, not derived from `fixedAccounts[0]`: an inner instruction may
  /// legitimately declare the fee payer a signer, which is the H-3 attack shape.
  payer: PublicKey,
): {
  compactInstructions: CompactInstruction[];
  remainingAccounts: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[];
} {
  // Index map: pubkey base58 -> index in the full account layout
  const indexMap = new Map<string, number>();
  for (let i = 0; i < fixedAccounts.length; i++) {
    indexMap.set(fixedAccounts[i].toBase58(), i);
  }

  // Collect remaining accounts (unique, preserving insertion order)
  const remainingMap = new Map<string, { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>();

  for (const ix of instructions) {
    // Program ID (never signer, never writable)
    const progKey = ix.programId.toBase58();
    if (!indexMap.has(progKey) && !remainingMap.has(progKey)) {
      remainingMap.set(progKey, { pubkey: ix.programId, isSigner: false, isWritable: false });
    }
    // Account keys
    for (const key of ix.keys) {
      const k = key.pubkey.toBase58();
      if (!indexMap.has(k)) {
        if (remainingMap.has(k)) {
          // Merge: most permissive flags win
          const existing = remainingMap.get(k)!;
          existing.isSigner = existing.isSigner || key.isSigner;
          existing.isWritable = existing.isWritable || key.isWritable;
        } else {
          remainingMap.set(k, { pubkey: key.pubkey, isSigner: key.isSigner, isWritable: key.isWritable });
        }
      }
    }
  }

  // Assign indexes to remaining accounts (after fixed accounts)
  const remainingAccounts = Array.from(remainingMap.values());
  let nextIndex = fixedAccounts.length;
  for (const acc of remainingAccounts) {
    indexMap.set(acc.pubkey.toBase58(), nextIndex++);
  }

  // Convert each instruction to compact format
  // Signer forwarding is opt-in on the wire. The intent is already here in
  // `k.isSigner`; it used to be discarded at exactly this point, which is why
  // the program had to infer it — and inferred it for every outer signer,
  // including the payer. The payer is never flagged: the program would refuse
  // it anyway, and a request it will always reject is worth not making.
  const payerKey = payer?.toBase58();
  const compactInstructions: CompactInstruction[] = instructions.map(ix => ({
    programIdIndex: encodeAccountIndex(indexMap.get(ix.programId.toBase58())!, false),
    accountIndexes: ix.keys.map(k =>
      encodeAccountIndex(
        indexMap.get(k.pubkey.toBase58())!,
        k.isSigner && k.pubkey.toBase58() !== payerKey,
      ),
    ),
    data: new Uint8Array(ix.data),
  }));

  return { compactInstructions, remainingAccounts };
}
