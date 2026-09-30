import { address, getBase64Decoder, getBase64Encoder } from '@solana/kit';
/**
 * Shared input/output types for the LazorKit kit-flavored SDK.
 *
 * Mirrors sdk/sdk-legacy/src/utils/types.ts in spirit. Uses kit's
 * Address brand (a base58 string) instead of v1 PublicKey; the rest
 * of the public surface is unchanged.
 */
import type { AccountMeta, Address, Commitment, Slot } from '@solana/kit';
import type { Secp256r1Signer, WebAuthnResponse } from './secp256r1/index.js';

// ─── CreateWallet owner types ────────────────────────────────────────

export interface CreateWalletEd25519 {
  type: 'ed25519';
  publicKey: Address;
}

export interface CreateWalletSecp256r1 {
  type: 'secp256r1';
  credentialIdHash: Uint8Array;
  compressedPubkey: Uint8Array;
  rpId: string;
}

export type CreateWalletOwner = CreateWalletEd25519 | CreateWalletSecp256r1;

// ─── Signer configs ──────────────────────────────────────────────────

/**
 * Ed25519 signer config — the dApp produces a tx-level Ed25519
 * signature with the corresponding keypair. The on-chain program
 * authenticates the signer by reading the tx's signers list.
 */
export interface Ed25519SignerConfig {
  type: 'ed25519';
  publicKey: Address;
  /** Pre-derived authority PDA (auto-derived from publicKey if omitted). */
  authorityPda?: Address;
}

/**
 * Secp256r1 (passkey / WebAuthn) signer config. The signer callback
 * runs the WebAuthn `navigator.credentials.get()` flow on the user's
 * device and returns the raw response; the SDK never touches private
 * key material.
 */
export interface Secp256r1SignerConfig {
  type: 'secp256r1';
  signer: Secp256r1Signer;
  /** Pre-derived authority PDA (auto-derived from credentialIdHash if omitted). */
  authorityPda?: Address;
  /** Override slot (auto-fetched if omitted). */
  slotOverride?: bigint;
  /** See {@link Secp256r1Params.minContextSlot}. */
  minContextSlot?: Slot;
  /** See {@link Secp256r1Params.commitment}. */
  commitment?: Commitment;
}

/** Session key signer (for execute-as-session). */
export interface SessionSignerConfig {
  type: 'session';
  sessionPda: Address;
  sessionKeyPubkey: Address;
}

/** Signer union for admin operations. */
export type AdminSigner = Ed25519SignerConfig | Secp256r1SignerConfig;

/** Signer union for execute (admins + sessions). */
export type ExecuteSigner =
  | Ed25519SignerConfig
  | Secp256r1SignerConfig
  | SessionSignerConfig;

// ─── Helper constructors ─────────────────────────────────────────────

export function ed25519(
  publicKey: Address,
  authorityPda?: Address,
): Ed25519SignerConfig {
  return { type: 'ed25519', publicKey, authorityPda };
}

export function secp256r1(
  signer: Secp256r1Signer,
  opts?: {
    authorityPda?: Address;
    slotOverride?: bigint;
    minContextSlot?: Slot;
    commitment?: Commitment;
  },
): Secp256r1SignerConfig {
  return { type: 'secp256r1', signer, ...opts };
}

export function session(
  sessionPda: Address,
  sessionKeyPubkey: Address,
): SessionSignerConfig {
  return { type: 'session', sessionPda, sessionKeyPubkey };
}

// ─── Secp256r1 prepare-only params ───────────────────────────────────

/**
 * Identity bag for the prepare* methods (no signer callback).
 *
 * **One passkey flow per authority at a time.** The challenge signs the
 * authority's counter + 1, read when the flow is prepared. Two flows for one
 * authority that overlap — two prepares before the first transaction lands,
 * two tabs or devices using one passkey, an app and a wallet — read the same
 * counter and both sign counter + 1; whichever lands second fails with
 * SignatureReused (3006), and no `minContextSlot` helps, because neither has
 * landed when the other reads. Run prepare → sign → send → confirm for one
 * authority one after another, passing the previous transaction's slot as
 * `minContextSlot`. The SDK keeps no per-authority state and does not queue
 * flows for you (README: "Two passkey transactions in a row").
 */
export interface Secp256r1Params {
  credentialIdHash: Uint8Array;
  /** Compressed public key (33 bytes). Auto-fetched from on-chain authority if omitted. */
  publicKeyBytes?: Uint8Array;
  /** Pre-derived authority PDA. */
  authorityPda?: Address;
  /** Override slot (skip the network slot read). */
  slotOverride?: bigint;
  /**
   * Read the authority's counter, its key and the slot from a node that has
   * processed at least this slot. Pass the slot the authority's previous
   * transaction landed in (`getSignatureStatuses(...).value[0].slot`, once it
   * is confirmed) when this challenge follows it: a read made before a node has
   * executed that transaction returns the counter it is about to use, and the
   * signature fails on chain with SignatureReused (3006). The signature commits
   * to the counter, so this cannot be repaired after the user has signed.
   *
   * While the node answers that it has not reached the slot (-32016), the reads
   * are retried with a short backoff for up to 10 s (30 s at `'finalized'`),
   * then the prepare call throws `MinContextSlotNotReachedError`. If one of
   * the reads fails for another reason, the call rejects with that error and
   * the other reads stop at once.
   */
  minContextSlot?: Slot;
  /**
   * Commitment for those reads. Default `'confirmed'`. `'finalized'` with a
   * `minContextSlot` waits for that slot to be finalized: about 32 slots
   * (13 s) after it was confirmed.
   */
  commitment?: Commitment;
}

// ─── Deferred execution payload ──────────────────────────────────────

/**
 * The state Authorize (tx 1) hands off to ExecuteDeferred (tx 2).
 * Pre-computed so tx 2 doesn't have to re-run the compact-layout pass.
 */
export interface DeferredPayload {
  walletPda: Address;
  deferredExecPda: Address;
  compactInstructions: {
    programIdIndex: number;
    accountIndexes: number[];
    data: Uint8Array;
  }[];
  remainingAccounts: AccountMeta[];
  /** Who the accounts hash expects to send TX2 (`prepareAuthorize`'s
   *  `executor`). Absent on payloads written before it was recorded. */
  executor?: Address;
  /** The Authorize payer: the refund destination the program requires. */
  refundDestination?: Address;
}

/** JSON-serializable form of DeferredPayload (for HTTP / WebSocket transport). */
/**
 * Wire version of the serialized deferred payload.
 *
 * `accountIndexes` crosses a transaction boundary — tx1 authorizes, tx2
 * executes, often in a different process at a different SDK version — and since
 * v2 those bytes carry the forward-signer flag in their high bit. A v1 payload
 * replayed through a v2 client would mean something different, and the failure
 * would surface as an unexplained instructions-hash mismatch rather than as a
 * version error. So the version is explicit and mismatches are refused.
 */
export const DEFERRED_PAYLOAD_VERSION = 2;

export interface DeferredPayloadJson {
  /** See DEFERRED_PAYLOAD_VERSION. Absent on payloads written before v2. */
  version?: number;
  walletPda: string;
  deferredExecPda: string;
  compactInstructions: {
    programIdIndex: number;
    accountIndexes: number[];
    data: string; // base64
  }[];
  remainingAccounts: {
    address: string;
    role: number;
  }[];
  executor?: string;
  refundDestination?: string;
}

const base64Encoder = getBase64Encoder();
const base64Decoder = getBase64Decoder();

export function serializeDeferredPayload(p: DeferredPayload): string {
  const json: DeferredPayloadJson = {
    version: DEFERRED_PAYLOAD_VERSION,
    walletPda: p.walletPda,
    deferredExecPda: p.deferredExecPda,
    compactInstructions: p.compactInstructions.map((ix) => ({
      programIdIndex: ix.programIdIndex,
      accountIndexes: ix.accountIndexes,
      data: base64Decoder.decode(ix.data),
    })),
    remainingAccounts: p.remainingAccounts.map((a) => ({
      address: a.address,
      role: a.role,
    })),
    executor: p.executor,
    refundDestination: p.refundDestination,
  };
  return JSON.stringify(json);
}

export function deserializeDeferredPayload(serialized: string): DeferredPayload {
  const json = JSON.parse(serialized) as DeferredPayloadJson;
  if (
    typeof json !== 'object' ||
    json === null ||
    typeof json.walletPda !== 'string' ||
    typeof json.deferredExecPda !== 'string' ||
    !Array.isArray(json.compactInstructions) ||
    !Array.isArray(json.remainingAccounts) ||
    (json.executor !== undefined && typeof json.executor !== 'string') ||
    (json.refundDestination !== undefined && typeof json.refundDestination !== 'string')
  ) {
    throw new Error('Invalid DeferredPayload JSON shape');
  }
  if (json.version !== DEFERRED_PAYLOAD_VERSION) {
    throw new Error(
      `DeferredPayload is version ${json.version ?? 1}, this SDK writes and reads ` +
        `version ${DEFERRED_PAYLOAD_VERSION}. Account index bytes changed meaning ` +
        `between them; re-authorize rather than replaying this payload.`,
    );
  }
  return {
    walletPda: json.walletPda as Address,
    deferredExecPda: json.deferredExecPda as Address,
    compactInstructions: json.compactInstructions.map((ix) => ({
      programIdIndex: ix.programIdIndex,
      accountIndexes: ix.accountIndexes,
      data: new Uint8Array(base64Encoder.encode(ix.data)),
    })),
    remainingAccounts: json.remainingAccounts.map((a) => ({
      address: a.address as Address,
      role: a.role,
    })),
    executor: json.executor !== undefined ? address(json.executor) : undefined,
    refundDestination:
      json.refundDestination !== undefined ? address(json.refundDestination) : undefined,
  };
}

// ─── Re-export from secp256r1 module ─────────────────────────────────

export type { WebAuthnResponse };
