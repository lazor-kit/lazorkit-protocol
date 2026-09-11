import { Buffer } from 'buffer';
import { PublicKey } from '@solana/web3.js';
import type { Secp256r1Signer } from './secp256r1';

// ─── CreateWallet owner types ────────────────────────────────────────

export interface CreateWalletEd25519 {
  type: 'ed25519';
  publicKey: PublicKey;
}

export interface CreateWalletSecp256r1 {
  type: 'secp256r1';
  credentialIdHash: Uint8Array;
  compressedPubkey: Uint8Array;
  rpId: string;
}

/** Owner union for createWallet() */
export type CreateWalletOwner = CreateWalletEd25519 | CreateWalletSecp256r1;

// ─── Discriminated union signer types ─────────────────────────────────

/** Ed25519 signer — the Keypair signs at transaction level */
export interface Ed25519SignerConfig {
  type: 'ed25519';
  publicKey: PublicKey;
  /** Pre-derived authority PDA (auto-derived from publicKey if omitted) */
  authorityPda?: PublicKey;
}

/**
 * Secp256r1 (passkey / WebAuthn) signer.
 *
 * LazorKit supports a single auth mode for Secp256r1: raw clientDataJSON from
 * a real browser authenticator. For programmatic/bot signing, use Ed25519
 * authorities instead.
 */
export interface Secp256r1SignerConfig {
  type: 'secp256r1';
  signer: Secp256r1Signer;
  /** Pre-derived authority PDA (auto-derived from credentialIdHash if omitted) */
  authorityPda?: PublicKey;
  /** Override slot (auto-fetched from connection if omitted) */
  slotOverride?: bigint;
}

/** Session key signer */
export interface SessionSignerConfig {
  type: 'session';
  sessionPda: PublicKey;
  sessionKeyPubkey: PublicKey;
}

/** Signer union for admin operations (authority/ownership/session management) */
export type AdminSigner = Ed25519SignerConfig | Secp256r1SignerConfig;

/** Signer union for execute operations (includes session keys) */
export type ExecuteSigner = Ed25519SignerConfig | Secp256r1SignerConfig | SessionSignerConfig;

/** Pre-computed data from authorize() needed by executeDeferredFromPayload() */
export interface DeferredPayload {
  walletPda: PublicKey;
  deferredExecPda: PublicKey;
  compactInstructions: { programIdIndex: number; accountIndexes: number[]; data: Uint8Array }[];
  remainingAccounts: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[];
}

/** Wire-serializable form of a `DeferredPayload` (all fields are plain JSON types). */
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
  walletPda: string;        // base58
  deferredExecPda: string;  // base58
  compactInstructions: {
    programIdIndex: number;
    accountIndexes: number[];
    data: string;           // base64
  }[];
  remainingAccounts: {
    pubkey: string;         // base58
    isSigner: boolean;
    isWritable: boolean;
  }[];
}

/**
 * Serializes a `DeferredPayload` into a JSON string safe to send over the wire
 * (HTTP, WebSocket, store-and-forward). Pair with `deserializeDeferredPayload()`
 * on the receiving end.
 */
export function serializeDeferredPayload(payload: DeferredPayload): string {
  const json: DeferredPayloadJson = {
    version: DEFERRED_PAYLOAD_VERSION,
    walletPda: payload.walletPda.toBase58(),
    deferredExecPda: payload.deferredExecPda.toBase58(),
    compactInstructions: payload.compactInstructions.map((ix) => ({
      programIdIndex: ix.programIdIndex,
      accountIndexes: ix.accountIndexes,
      data: Buffer.from(ix.data).toString('base64'),
    })),
    remainingAccounts: payload.remainingAccounts.map((a) => ({
      pubkey: a.pubkey.toBase58(),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
  };
  return JSON.stringify(json);
}

/**
 * Reconstructs a `DeferredPayload` from a string produced by `serializeDeferredPayload()`.
 * Throws if the input is malformed.
 */
export function deserializeDeferredPayload(serialized: string): DeferredPayload {
  const json = JSON.parse(serialized) as DeferredPayloadJson;
  if (
    typeof json !== 'object' ||
    json === null ||
    typeof json.walletPda !== 'string' ||
    typeof json.deferredExecPda !== 'string' ||
    !Array.isArray(json.compactInstructions) ||
    !Array.isArray(json.remainingAccounts)
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
    walletPda: new PublicKey(json.walletPda),
    deferredExecPda: new PublicKey(json.deferredExecPda),
    compactInstructions: json.compactInstructions.map((ix) => ({
      programIdIndex: ix.programIdIndex,
      accountIndexes: ix.accountIndexes,
      data: new Uint8Array(Buffer.from(ix.data, 'base64')),
    })),
    remainingAccounts: json.remainingAccounts.map((a) => ({
      pubkey: new PublicKey(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
  };
}

// ─── Secp256r1 prepare/finalize types ────────────────────────────────

/** Secp256r1 identity for prepare methods (no signer callback needed) */
export interface Secp256r1Params {
  /** SHA256 of the credential ID (32 bytes) — used as PDA seed */
  credentialIdHash: Uint8Array;
  /** Compressed public key (33 bytes). Auto-fetched from the on-chain authority account if omitted. */
  publicKeyBytes?: Uint8Array;
  /** Pre-derived authority PDA (auto-derived from credentialIdHash if omitted) */
  authorityPda?: PublicKey;
  /** Override slot (auto-fetched from connection if omitted) */
  slotOverride?: bigint;
}

/** Raw WebAuthn authenticator response — what the browser gives back */
export { type WebAuthnResponse } from './signing';

// ─── Helper constructors ──────────────────────────────────────────────

export function ed25519(publicKey: PublicKey, authorityPda?: PublicKey): Ed25519SignerConfig {
  return { type: 'ed25519', publicKey, authorityPda };
}

export function secp256r1(
  signer: Secp256r1Signer,
  opts?: { authorityPda?: PublicKey; slotOverride?: bigint },
): Secp256r1SignerConfig {
  return { type: 'secp256r1', signer, ...opts };
}

export function session(sessionPda: PublicKey, sessionKeyPubkey: PublicKey): SessionSignerConfig {
  return { type: 'session', sessionPda, sessionKeyPubkey };
}
