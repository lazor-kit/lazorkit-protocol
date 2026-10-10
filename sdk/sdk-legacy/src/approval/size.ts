// The size of a passkey CreateSession transaction, known before it is signed.
//
// The program receives the WebAuthn authenticatorData and clientDataJSON
// whole, beside the precompile instruction that verifies the signature, so a
// passkey CreateSession has far less room for actions than the program's
// 2,048-byte cap on the buffer. What the SDK builds (finalizeCreateSession):
//
//   precompile:    16-byte header, signature(64), public key(33), padding(1),
//                  authenticatorData || SHA256(clientDataJSON)
//   CreateSession: disc(1), session_key(32), expires_at(8), actions_len(2),
//                  actions, auth payload (14-byte prefix, authenticatorData
//                  and clientDataJSON, each after a u16 length)
//
// with one signer (the payer) and nine accounts: payer, wallet, authority,
// session, System program, Rent and Instructions sysvars, the program and the
// secp256r1 precompile. The size is that of a v0 message without lookup
// tables, two bytes more than the legacy form, so it holds for both.

import {
  ASSUMED_AUTHENTICATOR_DATA_BYTES,
  ASSUMED_CLIENT_DATA_JSON_BYTES,
  MAX_ACTIONS_BUFFER_BYTES,
  MAX_TRANSACTION_BYTES,
} from './constants';

/** Bytes of a compact-u16 length prefix. */
function compactU16Bytes(n: number): number {
  return n < 0x80 ? 1 : n < 0x4000 ? 2 : 3;
}

/** The WebAuthn lengths to size with; each defaults to the module's assumption. */
export interface AssumedWebAuthnSizes {
  authenticatorDataBytes?: number;
  clientDataJsonBytes?: number;
}

/**
 * The serialized size, in bytes, of the transaction a passkey CreateSession
 * with `actionsBytes` bytes of actions becomes, as a v0 message without lookup
 * tables (a legacy message is two bytes smaller).
 */
export function createSessionTransactionBytes(actionsBytes: number, assumed: AssumedWebAuthnSizes = {}): number {
  const authData = assumed.authenticatorDataBytes ?? ASSUMED_AUTHENTICATOR_DATA_BYTES;
  const clientData = assumed.clientDataJsonBytes ?? ASSUMED_CLIENT_DATA_JSON_BYTES;
  const signers = 1;
  const accounts = 9;
  const precompileData = 16 + 64 + 33 + 1 + authData + 32;
  const createSessionAccounts = 7;
  const createSessionData = 1 + 32 + 8 + 2 + actionsBytes + 14 + 2 + authData + 2 + clientData;
  const message =
    1 + // v0 prefix
    3 + // header
    compactU16Bytes(accounts) + 32 * accounts +
    32 + // recent blockhash
    compactU16Bytes(2) +
    (1 + compactU16Bytes(0) + compactU16Bytes(precompileData) + precompileData) +
    (1 + compactU16Bytes(createSessionAccounts) + createSessionAccounts +
      compactU16Bytes(createSessionData) + createSessionData) +
    compactU16Bytes(0); // address table lookups
  return compactU16Bytes(signers) + 64 * signers + message;
}

/** Whether a passkey CreateSession with `actionsBytes` bytes of actions fits one transaction. */
export function createSessionFits(actionsBytes: number, assumed: AssumedWebAuthnSizes = {}): boolean {
  return createSessionTransactionBytes(actionsBytes, assumed) <= MAX_TRANSACTION_BYTES;
}

/** The most bytes of actions a passkey CreateSession carries, with the assumed WebAuthn lengths. */
export const MAX_PASSKEY_SESSION_ACTIONS_BYTES: number = (() => {
  let n = MAX_ACTIONS_BUFFER_BYTES;
  while (n > 0 && !createSessionFits(n)) n--;
  return n;
})();
