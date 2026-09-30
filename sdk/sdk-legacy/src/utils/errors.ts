/**
 * Error code map for LazorKit program errors.
 */
import type { Commitment } from '@solana/web3.js';

/** Map of error code → human-readable name */
export const ERROR_NAMES: Record<number, string> = {
  3001: 'InvalidAuthorityPayload',
  3002: 'PermissionDenied',
  3003: 'InvalidInstruction',
  3004: 'InvalidPubkey',
  3005: 'InvalidMessageHash',
  3006: 'SignatureReused',
  3007: 'InvalidSignatureAge',
  3008: 'InvalidSessionDuration',
  3009: 'SessionExpired',
  3010: 'AuthorityDoesNotSupportSession',
  3011: 'InvalidAuthenticationKind',
  3012: 'InvalidMessage',
  3013: 'SelfReentrancyNotAllowed',
  3014: 'DeferredAuthorizationExpired',
  3015: 'DeferredHashMismatch',
  3016: 'InvalidExpiryWindow',
  3017: 'UnauthorizedReclaim',
  3018: 'DeferredAuthorizationNotExpired',
  3019: 'InvalidSessionAccount',
  // Session action errors
  3020: 'ActionBufferInvalid',
  3021: 'ActionProgramNotWhitelisted',
  3022: 'ActionProgramBlacklisted',
  3023: 'ActionSolMaxPerTxExceeded',
  3024: 'ActionSolLimitExceeded',
  3025: 'ActionSolRecurringLimitExceeded',
  3026: 'ActionTokenLimitExceeded',
  3027: 'ActionTokenRecurringLimitExceeded',
  3028: 'ActionWhitelistBlacklistConflict',
  3029: 'ActionTokenMaxPerTxExceeded',
  // Session vault + token invariants (defense against System::Assign / SetAuthority escapes)
  3030: 'SessionVaultOwnerChanged',
  3031: 'SessionVaultDataLenChanged',
  3032: 'SessionTokenAuthorityChanged',
  // Rank and policy (v2)
  3033: 'DelegateRequiresPolicy',
  3034: 'PolicyBearingAuthorityCannotDelegate',
  3035: 'PolicyRankMismatch',
  // Protocol errors (Commercial binary only — foundation binary never emits these)
  4001: 'ProtocolAlreadyInitialized',
  4002: 'InvalidProtocolAdmin',
  4004: 'InvalidIntegratorRecord',
  4005: 'InsufficientFeeBalance',
  4006: 'IntegratorAlreadyRegistered',
  4007: 'InvalidTreasury',
  4008: 'FeeAccountsRequired',
  4009: 'ProtocolNotInitialized',
  4010: 'InvalidTreasuryShard',
  4011: 'InvalidFeeRecord',
  4013: 'AccountVersionMismatch',
  4014: 'FeeExceedsMaximum',
  4015: 'UnauthorizedInitializer',
  4016: 'NoPendingAdmin',
  4017: 'WrongProgramAddress',
};

/**
 * Look up error name from code.
 *
 * The code alone does not say which program raised it: a program that
 * `Execute` calls can fail with the same custom code (Anchor's account errors
 * use 3000–3017, so its `AccountNotMutable` is 3006 too). The first
 * `Program <id> failed: custom program error` log line names the program.
 * A landed failure, `{ InstructionError: [i, { Custom: N }] }` from
 * `confirmTransaction` or `getSignatureStatuses`, names only the top-level
 * instruction — the LazorKit one, whichever program inside it failed — so it
 * cannot be attributed without the logs (`getTransaction(signature)` →
 * `meta.logMessages`). Without them, do not report it as this name.
 */
export function errorFromCode(code: number): string | undefined {
  return ERROR_NAMES[code];
}

/**
 * Extracts the custom program error code from a Solana SendTransactionError.
 * Returns null if the error is not a custom program error. Whichever program
 * raised it: see {@link errorFromCode}.
 *
 * It reads the error's text only: `custom program error: 0x…` (a preflight
 * failure) or `Custom(N)`. A landed `TransactionError` object such as
 * `{ InstructionError: [1, { Custom: 3006 }] }` gives null, and its
 * `JSON.stringify` form (`"Custom":3006`) does not match either; that error
 * carries no program id anyway (see {@link errorFromCode}).
 */
export function extractErrorCode(err: unknown): number | null {
  const msg = String(err);
  const match = msg.match(/custom program error: 0x([0-9a-fA-F]+)/);
  if (match) return parseInt(match[1], 16);
  const match2 = msg.match(/Custom\((\d+)\)/);
  if (match2) return parseInt(match2[1], 10);
  return null;
}

/**
 * The RPC node never reached the `minContextSlot` a passkey challenge read
 * asked for, within the wait (see {@link Secp256r1Params.minContextSlot}).
 *
 * Thrown instead of signing: a node behind that slot may not have executed the
 * authority's previous transaction yet, and the counter it holds would already
 * be spent — the program rejects such a signature with SignatureReused (3006),
 * and the signature commits to the counter, so nothing can repair it after the
 * user has approved. Retry, or read from a node that has caught up.
 *
 * At `'finalized'` the floor is the slot being finalized, which happens about
 * 32 slots (13 s) after it is confirmed; the read waits up to 30 s for that
 * (10 s at the other commitments), and the message says so.
 */
export class MinContextSlotNotReachedError extends Error {
  /** The slot the read had to be answered at or after. */
  readonly minContextSlot: number;
  /** How long the reads were retried, in milliseconds. */
  readonly waitedMs: number;
  /** The commitment the read was made at, when known. */
  readonly commitment?: Commitment;

  constructor(params: {
    minContextSlot: number;
    waitedMs: number;
    what: string;
    commitment?: Commitment;
    cause?: unknown;
  }) {
    const { minContextSlot, waitedMs, what, commitment } = params;
    const finalized = commitment === 'finalized' || commitment === 'max' || commitment === 'root';
    super(
      finalized
        ? `Slot ${minContextSlot} is not finalized on the RPC node after ${waitedMs} ms ` +
            `(reading ${what} for a passkey challenge at 'finalized'). A slot is finalized ` +
            `about 32 slots (13 s) after it is confirmed. Wait for the previous transaction ` +
            `to be finalized before preparing, or read at 'confirmed' (the default) with the ` +
            `same minContextSlot. Reading older state instead would sign a counter that ` +
            `transaction may have spent: SignatureReused (3006).`
        : `RPC node has not reached slot ${minContextSlot}` +
            `${commitment ? ` at '${commitment}'` : ''} after ${waitedMs} ms ` +
            `(reading ${what} for a passkey challenge). The authority's previous ` +
            `transaction may not be visible there yet, and a challenge over the counter it ` +
            `holds would fail with SignatureReused (3006). Retry, or use an RPC endpoint that ` +
            `has caught up.`,
    );
    this.name = 'MinContextSlotNotReachedError';
    this.minContextSlot = minContextSlot;
    this.waitedMs = waitedMs;
    if (commitment !== undefined) this.commitment = commitment;
    if (params.cause !== undefined) (this as { cause?: unknown }).cause = params.cause;
  }
}
