// The passkey challenge of a typed request, computed exactly as the program
// recomputes it (program/src/auth/secp256r1/mod.rs):
//
//   SHA256( discriminator(1)
//         || slot_le8 || counter_le4 || sysvarIxIdx(1) || reserved(1)
//         || signed_payload
//         || payer(32) || wallet(32) || counter_le4 || program_id(32) )

import { sha256 } from '@noble/hashes/sha2';
import { APPROVAL_KIND_CONSTANTS, AUTH_PAYLOAD_RESERVED_BYTE } from './constants';
import {
  U32_MAX,
  U64_MAX,
  base64urlEncode,
  concat,
  decodeAddress,
  parseCanonicalDecimal,
  u16LE,
  u32LE,
  u64LE,
} from './bytes';
import { requestActionsBytes, type ApprovalRequest } from './envelope';
import { ApprovalRequestError } from './errors';

/** The slot and counter a challenge commits to. */
export interface ApprovalBinding {
  slot: bigint;
  counter: number;
}

function addr(value: string, what: string): Uint8Array {
  const bytes = decodeAddress(value);
  if (!bytes) throw new ApprovalRequestError('typed-malformed', `${what} is not a canonical base58 address`);
  return bytes;
}

function checkBinding(b: ApprovalBinding): void {
  if (typeof b.slot !== 'bigint' || b.slot < 0n || b.slot > U64_MAX) {
    throw new RangeError(`binding slot out of range: ${String(b.slot)}`);
  }
  if (!Number.isInteger(b.counter) || b.counter < 0 || b.counter > U32_MAX) {
    throw new RangeError(`binding counter out of range: ${String(b.counter)}`);
  }
}

/**
 * The bytes the program passes as `signed_payload` for this request:
 * - createSession: session_key(32) || expires_at_le8 || actions_len_le2 || actions || payer(32)
 * - revokeSession: session(32) || refund(32)
 * - removeAuthority: target(32) || refund(32)
 */
export function signedPayloadOf(req: ApprovalRequest): Uint8Array {
  switch (req.kind) {
    case 'createSession': {
      const actions = requestActionsBytes(req);
      const expiresAt = parseCanonicalDecimal(req.args.expiresAt, U64_MAX);
      if (expiresAt === undefined) throw new ApprovalRequestError('typed-malformed', 'args.expiresAt');
      return concat([
        addr(req.args.sessionKey, 'args.sessionKey'),
        u64LE(expiresAt),
        u16LE(actions.length),
        actions,
        addr(req.payer, 'payer'),
      ]);
    }
    case 'revokeSession':
      return concat([addr(req.args.session, 'args.session'), addr(req.args.refund, 'args.refund')]);
    case 'removeAuthority':
      return concat([addr(req.args.target, 'args.target'), addr(req.args.refund, 'args.refund')]);
  }
}

/** The 14-byte auth payload prefix: slot, counter, sysvar index, reserved byte. */
export function authPayloadPrefix(req: ApprovalRequest, binding: ApprovalBinding): Uint8Array {
  checkBinding(binding);
  const k = APPROVAL_KIND_CONSTANTS[req.kind];
  return concat([
    u64LE(binding.slot),
    u32LE(binding.counter),
    new Uint8Array([k.sysvarIxIndex, AUTH_PAYLOAD_RESERVED_BYTE]),
  ]);
}

/** The 32-byte challenge the passkey signs to approve `req` at `binding`. */
export function approvalChallenge(req: ApprovalRequest, binding: ApprovalBinding): Uint8Array {
  const k = APPROVAL_KIND_CONSTANTS[req.kind];
  return sha256(
    concat([
      new Uint8Array([k.discriminator]),
      authPayloadPrefix(req, binding),
      signedPayloadOf(req),
      addr(req.payer, 'payer'),
      addr(req.wallet, 'wallet'),
      u32LE(binding.counter),
      addr(req.programId, 'programId'),
    ]),
  );
}

/** `approvalChallenge` as WebAuthn's clientDataJSON spells it: base64url, no padding. */
export function approvalChallengeBase64url(req: ApprovalRequest, binding: ApprovalBinding): string {
  return base64urlEncode(approvalChallenge(req, binding));
}

/** The binding of the SDK's own challenge: `(preparedSlot, counter)`. */
export function preparedBinding(req: ApprovalRequest): ApprovalBinding {
  const slot = parseCanonicalDecimal(req.preparedSlot, U64_MAX);
  if (slot === undefined) throw new ApprovalRequestError('typed-malformed', 'preparedSlot');
  return { slot, counter: req.counter };
}
