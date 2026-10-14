// Errors of typed approval requests. Each carries a stable `code` so the
// portal and both SDKs can map it without matching message text.

/** The codes a portal refuses a typed request with. */
export const APPROVAL_REFUSAL_CODES = [
  'typed-malformed',
  'typed-unsupported',
  'wrong-network',
  'challenge-mismatch',
  'request-invalid',
  'stale-counter',
  'chain-unavailable',
] as const;
export type ApprovalRefusalCode = (typeof APPROVAL_REFUSAL_CODES)[number];

/** A request that does not decode, or that names a version or kind this module does not know. */
export class ApprovalRequestError extends Error {
  readonly code: 'typed-malformed' | 'typed-unsupported';
  constructor(code: 'typed-malformed' | 'typed-unsupported', message: string) {
    super(message);
    this.name = 'ApprovalRequestError';
    this.code = code;
  }
}

/** The encoded request or the URL carrying it is over the cap. Never truncated. */
export class TypedRequestTooLargeError extends Error {
  readonly code = 'typed-request-too-large' as const;
  readonly length: number;
  readonly limit: number;
  constructor(length: number, limit: number, what: string) {
    super(`${what} is ${length} characters, over the ${limit}-character limit`);
    this.name = 'TypedRequestTooLargeError';
    this.length = length;
    this.limit = limit;
  }
}

/**
 * The portal's reply does not match the request the SDK prepared: the
 * passkey signed something else. Nothing may be sent.
 */
export class PortalReplyMismatchError extends Error {
  readonly code = 'portal-reply-mismatch' as const;
  readonly reason: string;
  constructor(reason: string) {
    super(`The portal's reply does not match this request (${reason}); nothing was sent`);
    this.name = 'PortalReplyMismatchError';
    this.reason = reason;
  }
}

/**
 * The portal refused with `stale-counter`: its view of the passkey's counter
 * was behind the request. Nothing was signed; a new request may succeed.
 */
export class RequestOutOfDateError extends Error {
  readonly code = 'stale-counter' as const;
  readonly retryable = true;
  constructor(message = 'The request is out of date; nothing was signed. Try again.') {
    super(message);
    this.name = 'RequestOutOfDateError';
  }
}

/** Which program error an invalid actions buffer meets on chain. */
export type ActionsProgramError = 'ActionBufferInvalid' | 'ActionWhitelistBlacklistConflict';

/** An actions buffer the program's `validate_actions_buffer` would refuse. */
export class ApprovalActionsError extends Error {
  readonly code = 'actions-invalid' as const;
  readonly programError: ActionsProgramError;
  constructor(programError: ActionsProgramError, message: string) {
    super(message);
    this.name = 'ApprovalActionsError';
    this.programError = programError;
  }
}

/**
 * A passkey transaction that would not fit in one transaction once signed.
 * Thrown before any passkey is asked, so no one approves what cannot be sent.
 */
export class TransactionTooLargeError extends Error {
  readonly code = 'transaction-too-large' as const;
  /** The estimated size, in bytes, with the assumed WebAuthn lengths. */
  readonly bytes: number;
  readonly limit: number;
  constructor(bytes: number, limit: number, what: string) {
    super(`${what} would be about ${bytes} bytes once signed, over the ${limit}-byte transaction limit`);
    this.name = 'TransactionTooLargeError';
    this.bytes = bytes;
    this.limit = limit;
  }
}
