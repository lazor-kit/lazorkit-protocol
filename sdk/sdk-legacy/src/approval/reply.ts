// Both ends of a typed approval: the portal's check of the request against
// the query it arrived with, the `typed` block of its reply, and the SDK's
// check of that reply before anything is sent.

import { APPROVAL_KINDS, APPROVAL_KIND_CONSTANTS, APPROVAL_VERSION, type ApprovalKind } from './constants';
import {
  U32_MAX,
  U64_MAX,
  base64DecodeLenient,
  base64urlEncode,
  bytesEqual,
  parseCanonicalDecimal,
  utf8Decode,
} from './bytes';
import { approvalChallenge, preparedBinding, type ApprovalBinding } from './challenge';
import { requestCredentialId, type ApprovalRequest } from './envelope';
import { PortalReplyMismatchError } from './errors';
import { credentialIdHash, findAuthorityAddress } from './pda';

// ─── Portal: the request against its query (DESIGN §3.2 steps 2–3) ───

export type ApprovalQueryCheck =
  | { ok: true }
  | {
      ok: false;
      code: 'challenge-mismatch';
      reason: 'credential-id-mismatch' | 'authority-not-derived' | 'message-mismatch';
    };

/**
 * Checks a decoded request against the query parameters it arrived with: the
 * query `credentialId` (base64 or base64url) names the same bytes; the
 * envelope's `authority` is the PDA of that credential on that wallet; and the
 * query `message` (base64 or base64url) is the challenge the request gives at
 * `(preparedSlot, counter)`. Any failure is `challenge-mismatch`: the SDK and
 * the portal disagree about what is being signed, so nothing is shown.
 */
export function checkApprovalQuery(
  req: ApprovalRequest,
  query: { message: string | null | undefined; credentialId: string | null | undefined },
): ApprovalQueryCheck {
  const cred = requestCredentialId(req);
  const queryCred = base64DecodeLenient(query.credentialId ?? undefined);
  if (!queryCred || !bytesEqual(cred, queryCred)) {
    return { ok: false, code: 'challenge-mismatch', reason: 'credential-id-mismatch' };
  }
  if (findAuthorityAddress(req.wallet, credentialIdHash(cred), req.programId) !== req.authority) {
    return { ok: false, code: 'challenge-mismatch', reason: 'authority-not-derived' };
  }
  const message = base64DecodeLenient(query.message ?? undefined);
  if (!message || !bytesEqual(message, approvalChallenge(req, preparedBinding(req)))) {
    return { ok: false, code: 'challenge-mismatch', reason: 'message-mismatch' };
  }
  return { ok: true };
}

// ─── The `typed` block of a reply ───────────────────────────────────

/** What the portal signed with, returned beside the assertion. */
export interface TypedReply {
  v: 1;
  kind: ApprovalKind;
  /** Decimal u64. */
  slot: string;
  counter: number;
  sysvarIxIndex: number;
}

/** The `typed` block for a request signed at `binding` (portal side). */
export function typedReplyFor(req: ApprovalRequest, binding: ApprovalBinding): TypedReply {
  return {
    v: APPROVAL_VERSION,
    kind: req.kind,
    slot: binding.slot.toString(),
    counter: binding.counter,
    sysvarIxIndex: APPROVAL_KIND_CONSTANTS[req.kind].sysvarIxIndex,
  };
}

/** Redirect form of a `typed` block: `typedV`, `typedKind`, `typedSlot`, `typedCounter`, `typedSysvarIx`. */
export function typedReplyParams(reply: TypedReply): Record<string, string> {
  return {
    typedV: String(reply.v),
    typedKind: reply.kind,
    typedSlot: reply.slot,
    typedCounter: String(reply.counter),
    typedSysvarIx: String(reply.sysvarIxIndex),
  };
}

function shapeError(what: string): never {
  throw new PortalReplyMismatchError(`malformed typed reply: ${what}`);
}

/**
 * Reads the `typed` block of a postMessage reply. Undefined when the reply
 * has none (an older portal); throws `PortalReplyMismatchError` when it has
 * one of the wrong shape.
 */
export function parseTypedReply(value: unknown): TypedReply | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) shapeError('not an object');
  const o = value as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  if (keys !== 'counter,kind,slot,sysvarIxIndex,v') shapeError(`keys ${keys}`);
  if (o.v !== APPROVAL_VERSION) shapeError('version');
  if (typeof o.kind !== 'string' || !(APPROVAL_KINDS as readonly string[]).includes(o.kind)) shapeError('kind');
  if (parseCanonicalDecimal(o.slot, U64_MAX) === undefined) shapeError('slot');
  if (typeof o.counter !== 'number' || !Number.isInteger(o.counter) || o.counter < 0 || o.counter > U32_MAX) {
    shapeError('counter');
  }
  if (typeof o.sysvarIxIndex !== 'number' || !Number.isInteger(o.sysvarIxIndex)) shapeError('sysvarIxIndex');
  return o as unknown as TypedReply;
}

const SMALL_INT = /^(0|[1-9][0-9]{0,9})$/;

/**
 * Reads the `typed*` parameters of a redirect reply. Undefined when none is
 * present; throws `PortalReplyMismatchError` when only some are, or any is
 * malformed.
 */
export function parseTypedReplyParams(get: (name: string) => string | null | undefined): TypedReply | undefined {
  const names = ['typedV', 'typedKind', 'typedSlot', 'typedCounter', 'typedSysvarIx'];
  const values = names.map((n) => get(n));
  const present = values.filter((v) => v !== null && v !== undefined);
  if (present.length === 0) return undefined;
  if (present.length !== names.length) shapeError('some typed parameters are missing');
  const [v, kind, slot, counter, sysvarIx] = values as string[];
  if (v !== String(APPROVAL_VERSION)) shapeError('typedV');
  if (!SMALL_INT.test(counter) || !SMALL_INT.test(sysvarIx)) shapeError('typedCounter or typedSysvarIx');
  return parseTypedReply({ v: APPROVAL_VERSION, kind, slot, counter: Number(counter), sysvarIxIndex: Number(sysvarIx) });
}

// ─── SDK: the reply against its own request (DESIGN §2.3) ───────────

export interface VerifiedApprovalReply {
  /** The slot and counter to finalize with. */
  binding: ApprovalBinding;
  /** Whether the portal chose the binding (a typed reply). */
  typed: boolean;
  /** The challenge the passkey signed. */
  challenge: Uint8Array;
}

/**
 * Checks a portal reply against the request the SDK built, before anything
 * is sent:
 * 1. `clientDataJSON` is UTF-8 JSON with `type: "webauthn.get"`.
 * 2. With a `typed` block: its kind and sysvar index are the request's, its
 *    counter is at least the request's, and the challenge recomputed from the
 *    request at `(typed.slot, typed.counter)` is the one in clientDataJSON.
 * 3. Without one (an older portal): clientDataJSON's challenge is the SDK's
 *    own, at `(preparedSlot, counter)`.
 * Returns the binding to finalize with; throws `PortalReplyMismatchError`
 * otherwise.
 */
export function verifyApprovalReply(
  req: ApprovalRequest,
  reply: { clientDataJson: Uint8Array; typed?: TypedReply },
): VerifiedApprovalReply {
  const text = utf8Decode(reply.clientDataJson);
  if (text === undefined) throw new PortalReplyMismatchError('clientDataJSON is not UTF-8');
  let cdj: unknown;
  try {
    cdj = JSON.parse(text);
  } catch {
    throw new PortalReplyMismatchError('clientDataJSON is not JSON');
  }
  if (typeof cdj !== 'object' || cdj === null) throw new PortalReplyMismatchError('clientDataJSON is not an object');
  const { type, challenge } = cdj as { type?: unknown; challenge?: unknown };
  if (type !== 'webauthn.get') throw new PortalReplyMismatchError('clientDataJSON type is not webauthn.get');
  if (typeof challenge !== 'string') throw new PortalReplyMismatchError('clientDataJSON has no challenge');

  let binding: ApprovalBinding;
  let typed = false;
  if (reply.typed !== undefined) {
    const t = parseTypedReply(reply.typed);
    if (!t) throw new PortalReplyMismatchError('malformed typed reply');
    if (t.kind !== req.kind) throw new PortalReplyMismatchError(`typed kind ${t.kind} is not ${req.kind}`);
    if (t.sysvarIxIndex !== APPROVAL_KIND_CONSTANTS[req.kind].sysvarIxIndex) {
      throw new PortalReplyMismatchError('typed sysvarIxIndex');
    }
    if (t.counter < req.counter) {
      throw new PortalReplyMismatchError(`typed counter ${t.counter} is below the request's ${req.counter}`);
    }
    binding = { slot: BigInt(t.slot), counter: t.counter };
    typed = true;
  } else {
    binding = preparedBinding(req);
  }
  const expected = approvalChallenge(req, binding);
  if (challenge !== base64urlEncode(expected)) {
    throw new PortalReplyMismatchError('the signed challenge is not the one this request gives');
  }
  return { binding, typed, challenge: expected };
}
