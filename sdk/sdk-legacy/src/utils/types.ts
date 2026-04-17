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
 * Defaults to Mode 1 (raw clientDataJSON) which works with all real browser authenticators.
 * Set `rawMode: false` to use Mode 0 (on-chain reconstruction) for programmatic/bot signing.
 */
export interface Secp256r1SignerConfig {
  type: 'secp256r1';
  signer: Secp256r1Signer;
  /** Pre-derived authority PDA (auto-derived from credentialIdHash if omitted) */
  authorityPda?: PublicKey;
  /** Override slot (auto-fetched from connection if omitted) */
  slotOverride?: bigint;
  /** WebAuthn mode. Defaults to true (raw clientDataJSON). Set false for programmatic signing. */
  rawMode?: boolean;
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

// ─── Secp256r1 prepare/finalize types ────────────────────────────────

/** Secp256r1 identity for prepare methods (no signer callback needed) */
export interface Secp256r1Params {
  /** SHA256 of the credential ID (32 bytes) — used as PDA seed */
  credentialIdHash: Uint8Array;
  /** Compressed public key (33 bytes) */
  publicKeyBytes: Uint8Array;
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
  opts?: { authorityPda?: PublicKey; slotOverride?: bigint; rawMode?: boolean },
): Secp256r1SignerConfig {
  return { type: 'secp256r1', signer, ...opts };
}

export function session(sessionPda: PublicKey, sessionKeyPubkey: PublicKey): SessionSignerConfig {
  return { type: 'session', sessionPda, sessionKeyPubkey };
}
