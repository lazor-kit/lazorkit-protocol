/**
 * `@lazorkit/sdk-legacy/approval` — typed approval requests, v1.
 *
 * What a passkey approves, in a form both ends can check: the SDK builds a
 * request (`prepareCreateSession(...).request` and the others), carries it to
 * the portal in the URL fragment (`withApprovalFragment`), the portal reads
 * it (`readApprovalFragment`), checks it against its query
 * (`checkApprovalQuery`) and the chain (`approvalReadPlan`,
 * `describeApproval`), signs `approvalChallenge(request, { slot, counter })`
 * with the slot and counter it reads at Approve, and replies with
 * `typedReplyFor(...)`; the SDK checks the reply (`verifyApprovalReply`) and
 * finalizes with the binding it returns.
 *
 * The challenge recipe is the program's (program/src/auth/secp256r1/mod.rs),
 * tested against it in this repository. This entry point imports only
 * `@noble/hashes` and `@noble/curves`: no `@solana/web3.js`, no `buffer`.
 */
export * from './constants';
export * from './errors';
export {
  base58Encode,
  base64urlEncode,
  base64urlDecode,
  base64DecodeLenient,
  decodeAddress,
} from './bytes';
export * from './pda';
export * from './actions';
export * from './envelope';
export * from './challenge';
export * from './reply';
export * from './accounts';
export * from './describe';
export * from './size';
