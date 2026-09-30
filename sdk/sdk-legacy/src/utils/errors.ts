/**
 * Error code map for LazorKit program errors.
 */

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
 */
export function errorFromCode(code: number): string | undefined {
  return ERROR_NAMES[code];
}

/**
 * Extracts the custom program error code from a Solana SendTransactionError.
 * Returns null if the error is not a custom program error. Whichever program
 * raised it: see {@link errorFromCode}.
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
 */
export class MinContextSlotNotReachedError extends Error {
  /** The slot the read had to be answered at or after. */
  readonly minContextSlot: number;
  /** How long the reads were retried, in milliseconds. */
  readonly waitedMs: number;

  constructor(params: { minContextSlot: number; waitedMs: number; what: string; cause?: unknown }) {
    super(
      `RPC node has not reached slot ${params.minContextSlot} after ${params.waitedMs} ms ` +
        `(reading ${params.what} for a passkey challenge). The authority's previous ` +
        `transaction may not be visible there yet, and a challenge over the counter it ` +
        `holds would fail with SignatureReused (3006). Retry, or use an RPC endpoint that ` +
        `has caught up.`,
    );
    this.name = 'MinContextSlotNotReachedError';
    this.minContextSlot = params.minContextSlot;
    this.waitedMs = params.waitedMs;
    if (params.cause !== undefined) (this as { cause?: unknown }).cause = params.cause;
  }
}
