// The typed approval request (envelope) v1: shape, strict validation, and the
// one canonical encoding.
//
// Wire form: base64url (no padding) of the request's canonical JSON — keys in
// the order below, no whitespace, every value in its single canonical
// spelling. A decoder accepts a string only if re-encoding what it read gives
// back the same string, so duplicate keys, reordered keys, extra spaces,
// `7.0` for 7, padded base64 and non-canonical base58 are all refused. Build
// requests with `encodeApprovalRequest` (or `approvalFragment`), never by hand.

import {
  APPROVAL_CLUSTERS,
  APPROVAL_FRAGMENT_PARAM,
  APPROVAL_FRAGMENT_PREFIX,
  APPROVAL_KINDS,
  APPROVAL_VERSION,
  MAX_APPROVAL_REQUEST_CHARS,
  MAX_APPROVAL_URL_CHARS,
  MAX_CREDENTIAL_ID_BYTES,
  type ApprovalCluster,
  type ApprovalKind,
} from './constants';
import {
  I64_MAX,
  U32_MAX,
  U64_MAX,
  asciiDecode,
  asciiEncode,
  base64urlDecode,
  base64urlEncode,
  decodeAddress,
  parseCanonicalDecimal,
} from './bytes';
import { ApprovalRequestError, TypedRequestTooLargeError } from './errors';

interface ApprovalRequestBase {
  v: 1;
  cluster: ApprovalCluster;
  /** The v2 program, base58. */
  programId: string;
  /** The wallet PDA, base58. */
  wallet: string;
  /** The signing passkey's authority PDA, base58. */
  authority: string;
  /** The WebAuthn credential id, base64url without padding, 1 to 1023 bytes. */
  credentialId: string;
  /** The fee payer (account 0, a signer), base58. */
  payer: string;
  /** The counter the SDK expects the passkey to sign: the stored counter + 1. */
  counter: number;
  /** The slot in the SDK's own challenge (the `message` it sent), decimal u64. */
  preparedSlot: string;
  /** Optional: the slot the SDK's reads were floored at. */
  minContextSlot?: number;
}

export interface CreateSessionRequest extends ApprovalRequestBase {
  kind: 'createSession';
  args: {
    /** The session's Ed25519 key, base58. */
    sessionKey: string;
    /** Unix seconds, decimal, below 2^63. */
    expiresAt: string;
    /** The exact actions buffer, base64url; '' for none. */
    actions: string;
  };
}

export interface RevokeSessionRequest extends ApprovalRequestBase {
  kind: 'revokeSession';
  args: {
    /** The session PDA to close, base58. */
    session: string;
    /** Where the session's rent goes, base58. */
    refund: string;
  };
}

export interface RemoveAuthorityRequest extends ApprovalRequestBase {
  kind: 'removeAuthority';
  args: {
    /** The authority PDA to remove, base58. */
    target: string;
    /** Where its rent goes, base58. */
    refund: string;
  };
}

export type ApprovalRequest = CreateSessionRequest | RevokeSessionRequest | RemoveAuthorityRequest;

const BASE_KEYS = [
  'v',
  'kind',
  'cluster',
  'programId',
  'wallet',
  'authority',
  'credentialId',
  'payer',
  'counter',
  'preparedSlot',
] as const;

const ARG_KEYS: Record<ApprovalKind, readonly string[]> = {
  createSession: ['sessionKey', 'expiresAt', 'actions'],
  revokeSession: ['session', 'refund'],
  removeAuthority: ['target', 'refund'],
};

function malformed(message: string): never {
  throw new ApprovalRequestError('typed-malformed', message);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function requireKeys(obj: Record<string, unknown>, required: readonly string[], optional: readonly string[], where: string): void {
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!required.includes(k) && !optional.includes(k)) malformed(`${where}: unknown key "${k}"`);
  }
  for (const k of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) malformed(`${where}: missing "${k}"`);
  }
}

function requireAddress(v: unknown, what: string): void {
  if (!decodeAddress(v)) malformed(`${what} is not a canonical base58 address`);
}

/**
 * Checks a request object field by field and returns it typed. Throws
 * `ApprovalRequestError`: `typed-unsupported` for an unknown `v` or `kind`,
 * `typed-malformed` for anything else. The actions bytes are checked for
 * encoding only here; whether the program accepts them is a property of the
 * request (`decodeActions`, `describeApproval`), not of its encoding.
 */
export function validateApprovalRequest(value: unknown): ApprovalRequest {
  if (!isPlainObject(value)) malformed('the request is not a JSON object');
  if (typeof value.v !== 'number') malformed('"v" is not a number');
  if (value.v !== APPROVAL_VERSION) {
    throw new ApprovalRequestError('typed-unsupported', `request version ${String(value.v)} is not supported`);
  }
  if (typeof value.kind !== 'string') malformed('"kind" is not a string');
  if (!(APPROVAL_KINDS as readonly string[]).includes(value.kind)) {
    throw new ApprovalRequestError('typed-unsupported', `request kind "${value.kind}" is not supported`);
  }
  const kind = value.kind as ApprovalKind;
  requireKeys(value, [...BASE_KEYS, 'args'], ['minContextSlot'], 'request');

  if (!(APPROVAL_CLUSTERS as readonly string[]).includes(value.cluster as string)) {
    malformed('"cluster" is not devnet or mainnet');
  }
  requireAddress(value.programId, 'programId');
  requireAddress(value.wallet, 'wallet');
  requireAddress(value.authority, 'authority');
  requireAddress(value.payer, 'payer');
  const cred = base64urlDecode(value.credentialId);
  if (!cred) malformed('credentialId is not canonical base64url');
  if (cred.length < 1 || cred.length > MAX_CREDENTIAL_ID_BYTES) {
    malformed(`credentialId is ${cred.length} bytes, not 1 to ${MAX_CREDENTIAL_ID_BYTES}`);
  }
  const counter = value.counter;
  if (typeof counter !== 'number' || !Number.isInteger(counter) || counter < 0 || counter > U32_MAX) {
    malformed('counter is not a u32');
  }
  if (parseCanonicalDecimal(value.preparedSlot, U64_MAX) === undefined) {
    malformed('preparedSlot is not a canonical decimal u64');
  }
  if (Object.prototype.hasOwnProperty.call(value, 'minContextSlot')) {
    const m = value.minContextSlot;
    if (typeof m !== 'number' || !Number.isSafeInteger(m) || m < 0) {
      malformed('minContextSlot is not a non-negative integer');
    }
  }

  const args = value.args;
  if (!isPlainObject(args)) malformed('"args" is not an object');
  requireKeys(args, ARG_KEYS[kind], [], 'args');
  switch (kind) {
    case 'createSession': {
      requireAddress(args.sessionKey, 'args.sessionKey');
      if (parseCanonicalDecimal(args.expiresAt, I64_MAX) === undefined) {
        malformed('args.expiresAt is not a canonical decimal below 2^63');
      }
      if (base64urlDecode(args.actions) === undefined) malformed('args.actions is not canonical base64url');
      break;
    }
    case 'revokeSession':
      requireAddress(args.session, 'args.session');
      requireAddress(args.refund, 'args.refund');
      break;
    case 'removeAuthority':
      requireAddress(args.target, 'args.target');
      requireAddress(args.refund, 'args.refund');
      break;
  }
  return value as unknown as ApprovalRequest;
}

/** The canonical JSON text of a request that has passed validation. */
function canonicalJson(req: ApprovalRequest): string {
  const s = JSON.stringify;
  let out =
    `{"v":${req.v},"kind":${s(req.kind)},"cluster":${s(req.cluster)},"programId":${s(req.programId)}` +
    `,"wallet":${s(req.wallet)},"authority":${s(req.authority)},"credentialId":${s(req.credentialId)}` +
    `,"payer":${s(req.payer)},"counter":${req.counter},"preparedSlot":${s(req.preparedSlot)}`;
  if (req.minContextSlot !== undefined) out += `,"minContextSlot":${req.minContextSlot}`;
  const args = req.args as unknown as Record<string, string>;
  out += `,"args":{${ARG_KEYS[req.kind].map((k) => `${s(k)}:${s(args[k])}`).join(',')}}}`;
  return out;
}

/** The request's canonical encoding: base64url of its canonical JSON. Throws on an invalid request. */
export function encodeApprovalRequest(req: ApprovalRequest): string {
  const valid = validateApprovalRequest(req);
  const bytes = asciiEncode(canonicalJson(valid));
  if (!bytes) malformed('the request has a non-ASCII value');
  return base64urlEncode(bytes);
}

/**
 * Decodes an encoded request. Refuses (`ApprovalRequestError`) anything over
 * the cap, anything that is not the canonical encoding of a valid request,
 * and unknown versions or kinds (`typed-unsupported`).
 */
export function decodeApprovalRequest(encoded: string): ApprovalRequest {
  if (typeof encoded !== 'string' || encoded.length === 0) malformed('the request is empty');
  if (encoded.length > MAX_APPROVAL_REQUEST_CHARS) {
    malformed(`the request is ${encoded.length} characters, over ${MAX_APPROVAL_REQUEST_CHARS}`);
  }
  const bytes = base64urlDecode(encoded);
  if (!bytes) malformed('the request is not canonical base64url');
  const text = asciiDecode(bytes);
  if (text === undefined) malformed('the request is not printable ASCII');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    malformed('the request is not JSON');
  }
  const req = validateApprovalRequest(parsed);
  if (canonicalJson(req) !== text) malformed('the request is not in its canonical form');
  return req;
}

/**
 * `#/?lk1=<encoded>` for a request. Throws `TypedRequestTooLargeError` when
 * the encoding is over `MAX_APPROVAL_REQUEST_CHARS`: a request is never
 * truncated.
 */
export function approvalFragment(req: ApprovalRequest): string {
  const encoded = encodeApprovalRequest(req);
  if (encoded.length > MAX_APPROVAL_REQUEST_CHARS) {
    throw new TypedRequestTooLargeError(encoded.length, MAX_APPROVAL_REQUEST_CHARS, 'The encoded request');
  }
  return APPROVAL_FRAGMENT_PREFIX + encoded;
}

/**
 * A portal URL with the request appended as its fragment. The URL must not
 * already have one. Throws `TypedRequestTooLargeError` when the encoding or
 * the whole URL is over its cap.
 */
export function withApprovalFragment(url: string, req: ApprovalRequest): string {
  if (url.includes('#')) throw new Error('the portal URL already has a fragment');
  const full = url + approvalFragment(req);
  if (full.length > MAX_APPROVAL_URL_CHARS) {
    throw new TypedRequestTooLargeError(full.length, MAX_APPROVAL_URL_CHARS, 'The portal URL');
  }
  return full;
}

/**
 * Reads the request a page's fragment (`location.hash`) carries. Returns null
 * when the fragment carries none (no `lk1`). Once `lk1` appears anywhere in
 * the fragment, the fragment must be exactly `#/?lk1=<encoded>` and decode;
 * otherwise this throws `ApprovalRequestError`, and the caller refuses
 * rather than falling back to an untyped screen.
 */
export function readApprovalFragment(hash: string): ApprovalRequest | null {
  if (!hash.includes(APPROVAL_FRAGMENT_PARAM)) return null;
  if (!hash.startsWith(APPROVAL_FRAGMENT_PREFIX)) malformed('the fragment is not #/?lk1=…');
  const encoded = hash.slice(APPROVAL_FRAGMENT_PREFIX.length);
  if (/[&#=?/]/.test(encoded)) malformed('the fragment carries more than one request');
  return decodeApprovalRequest(encoded);
}

/** The actions buffer a createSession request carries. */
export function requestActionsBytes(req: CreateSessionRequest): Uint8Array {
  const bytes = base64urlDecode(req.args.actions);
  if (!bytes) malformed('args.actions is not canonical base64url');
  return bytes;
}

/** The credential id bytes a request carries. */
export function requestCredentialId(req: ApprovalRequest): Uint8Array {
  const bytes = base64urlDecode(req.credentialId);
  if (!bytes) malformed('credentialId is not canonical base64url');
  return bytes;
}
