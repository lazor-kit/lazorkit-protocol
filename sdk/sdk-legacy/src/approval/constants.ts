// Constants of typed approval requests, v1.

/** Envelope version this module reads and writes. */
export const APPROVAL_VERSION = 1 as const;

/** The operations a v1 typed request can describe. */
export const APPROVAL_KINDS = ['createSession', 'revokeSession', 'removeAuthority'] as const;
export type ApprovalKind = (typeof APPROVAL_KINDS)[number];

/** Clusters a typed request can name. */
export const APPROVAL_CLUSTERS = ['devnet', 'mainnet'] as const;
export type ApprovalCluster = (typeof APPROVAL_CLUSTERS)[number];

/** The v2 program on each cluster (same values as the package's PROGRAM_ADDRESS_*). */
export const APPROVAL_PROGRAM_ADDRESSES: Readonly<Record<ApprovalCluster, string>> = {
  devnet: '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv',
  mainnet: 'LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8',
};

/**
 * Per kind: the instruction discriminator the program hashes first, and the
 * index of the Instructions sysvar in the instruction's account list, which
 * the auth payload carries and the challenge hashes. Both are fixed by the
 * program and the SDK's builders, never taken from a request.
 */
export const APPROVAL_KIND_CONSTANTS: Readonly<
  Record<ApprovalKind, { discriminator: number; sysvarIxIndex: number }>
> = {
  createSession: { discriminator: 5, sysvarIxIndex: 6 },
  revokeSession: { discriminator: 9, sysvarIxIndex: 5 },
  removeAuthority: { discriminator: 2, sysvarIxIndex: 5 },
};

/** The auth payload's reserved byte, hashed into every challenge. */
export const AUTH_PAYLOAD_RESERVED_BYTE = 0x80;

/** The fragment parameter that carries an encoded request. */
export const APPROVAL_FRAGMENT_PARAM = 'lk1';

/**
 * What precedes the encoded request in a portal URL: `#/?lk1=`. The `/` keeps
 * a HashRouter portal on its root route.
 */
export const APPROVAL_FRAGMENT_PREFIX = `#/?${APPROVAL_FRAGMENT_PARAM}=`;

/** Longest encoded request (the fragment's value), in characters. */
export const MAX_APPROVAL_REQUEST_CHARS = 8192;

/** Longest portal URL that carries a request, in characters. */
export const MAX_APPROVAL_URL_CHARS = 16384;

/** Longest WebAuthn credential id a request carries, in bytes. */
export const MAX_CREDENTIAL_ID_BYTES = 1023;

/** A session may last at most this long after the cluster clock (program: MAX_SESSION_SECONDS). */
export const APPROVAL_MAX_SESSION_SECONDS = 2_592_000n;

/** A passkey signature is accepted for fewer than this many slots after the slot it names. */
export const MAX_SIGNATURE_AGE_SLOTS = 150n;

/** The program's cap on a CreateSession actions buffer, in bytes. */
export const MAX_ACTIONS_BUFFER_BYTES = 2048;

/** At most this many actions in one buffer. */
export const MAX_ACTIONS = 16;

/** The largest transaction a cluster accepts, serialized, in bytes (PACKET_DATA_SIZE). */
export const MAX_TRANSACTION_BYTES = 1232;

/**
 * The authenticatorData length assumed when sizing a passkey transaction
 * before it is signed: rpIdHash, flags and signCount, an assertion with no
 * extensions (the portal requests none).
 */
export const ASSUMED_AUTHENTICATOR_DATA_BYTES = 37;

/**
 * The clientDataJSON length assumed when sizing a passkey transaction before
 * it is signed. The program receives clientDataJSON whole, and its length is
 * known only after signing: type, the 43-character challenge, origin and
 * crossOrigin, plus what browsers may add (a cross-origin frame's topOrigin,
 * Chrome's occasional `other_keys_can_be_added_here` member). 320 bytes covers
 * all of them with origins of about 40 characters each.
 */
export const ASSUMED_CLIENT_DATA_JSON_BYTES = 320;

/** 2020-01-01 in Unix seconds: below this, a stored expiry is a slot written before time-based expiry. */
export const MIN_UNIX_SECONDS = 1_577_836_800n;

/** A `minContextSlot` this far beyond the current slot is malformed. */
export const MAX_MIN_CONTEXT_SLOT_LEAD = 1000;

/** Program and sysvar addresses the reads involve. */
export const SPL_TOKEN_PROGRAM_ADDRESS = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const SPL_TOKEN_2022_PROGRAM_ADDRESS = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const CLOCK_SYSVAR_ADDRESS = 'SysvarC1ock11111111111111111111111111111111';

/** PDA seeds (program/src/seeds.rs). */
export const SEED_AUTHORITY = 'lk2:authority';
export const SEED_SESSION = 'lk2:session';
export const SEED_VAULT = 'lk2:vault';

/** Account discriminators and layout version (program/src/state/mod.rs). */
export const DISC_WALLET_ACCOUNT = 0x21;
export const DISC_AUTHORITY_ACCOUNT = 0x22;
export const DISC_SESSION_ACCOUNT = 0x23;
export const ACCOUNT_LAYOUT_VERSION = 1;

/**
 * Program features a portal configures per cluster and confirms against the
 * deployed binary. Binary-dependent conclusions are drawn only from these.
 */
export const APPROVAL_FEATURES = [
  'wallet-bound-challenge',
  'd13',
  'nonowner-invariants',
  'time-expiry',
] as const;
export type ApprovalFeature = (typeof APPROVAL_FEATURES)[number];
