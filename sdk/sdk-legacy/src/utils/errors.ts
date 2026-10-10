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
  // Vault + token-account invariants for every signer but an Owner
  // (defense against System::Assign / SetAuthority escapes)
  3030: 'SessionVaultOwnerChanged',
  3031: 'SessionVaultDataLenChanged',
  3032: 'SessionTokenAuthorityChanged',
  // Rank and policy (v2)
  3033: 'DelegateRequiresPolicy',
  3034: 'PolicyBearingAuthorityCannotDelegate',
  3035: 'PolicyRankMismatch',
  3036: 'SessionNotExpired',
  // Assets a policy does not name (v2): SOL with no Sol* action, a mint with no Token* action
  3037: 'ActionUnlistedSolOutflow',
  3038: 'ActionUnlistedTokenOutflow',
  // Protocol errors (fees, the protocol config, and the deployment itself)
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
  4018: 'RetiredDeployment',
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
 * At `'finalized'` the floor is the slot being finalized. How long after its
 * confirmation that happens is the cluster's: 31 slots (16.5 s) on a local
 * test validator (Agave 4.2.2), none on devnet on 2026-09-30, where the
 * finalized slot was the confirmed one. The read waits up to 30 s for it
 * (10 s at the other commitments), and the message names both causes of a
 * timeout there: a slot not finalized yet, or a node that is behind.
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
            `(reading ${what} for a passkey challenge at 'finalized'). Either the cluster ` +
            `has not finalized it yet (how long that takes after confirmation depends on ` +
            `the cluster) or this node is behind. Wait for the previous transaction to be ` +
            `finalized before preparing, read at 'confirmed' (the default) with the same ` +
            `minContextSlot, or retry on an RPC endpoint that has caught up. Reading older ` +
            `state instead would sign a counter that transaction may have spent: ` +
            `SignatureReused (3006).`
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
