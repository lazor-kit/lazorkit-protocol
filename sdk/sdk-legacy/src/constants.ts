import { PublicKey } from '@solana/web3.js';

/**
 * LazorKit Smart Wallet program addresses.
 *
 * Two on-chain binaries are built from this codebase:
 *   - **commercial** (`lazorkit-protocol`): with admin + protocol-fee surface.
 *   - **foundation** (`program-v2`): no admin, no fees. Built from a sibling
 *     repo that tracks the wallet/session/auth code without the fee module.
 *
 * **Mainnet shares ONE program ID between both binaries.** During the
 * foundation contract period, the foundation binary occupies that slot;
 * after contract end, the upgrade authority swaps in the commercial binary.
 * dApp integrators keep using the same mainnet program ID throughout — only
 * the on-chain behavior changes (no fee charged before swap, fee charged
 * after).
 *
 * **Devnet uses two distinct IDs** — one for each binary — so both can run
 * side-by-side for testing without conflict.
 *
 * The SDK is flavor-blind by design: it always builds "commercial-shape"
 * transactions (with the four trailing fee accounts on fee-eligible
 * instructions). The foundation binary tolerates the extra accounts as
 * unused remaining accounts and charges no fee; the commercial binary
 * detects the pattern and transfers the fee. Same SDK code works for both.
 */

/**
 * Protocol v2 program address on mainnet.
 *
 * v2 lives at its own program id, as every breaking Solana major does (Squads
 * v3/v4, Jupiter v4/v6, Token/Token-2022). The v1 deployment keeps its address
 * — see {@link PROGRAM_ADDRESS_MAINNET_V1} — and runs a sunset binary once v1
 * is retired, serving only the way out.
 */
export const PROGRAM_ADDRESS_MAINNET =
  'LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8';

/** Protocol v2 program address on devnet. */
export const PROGRAM_ADDRESS_DEVNET =
  '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv';

/**
 * The original (v1) mainnet deployment. Wallets created before v2 live here,
 * and migrate out with `migrateV1Wallet`, which executes against this id and
 * delivers to a v2 vault at {@link PROGRAM_ADDRESS_MAINNET}.
 */
export const PROGRAM_ADDRESS_MAINNET_V1 =
  'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi';

/** The original (v1) devnet deployment. */
export const PROGRAM_ADDRESS_DEVNET_V1 =
  '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS';

/**
 * Foundation-binary devnet program address (program-v2). Pass this
 * explicitly to `LazorKitClient` when targeting a program-v2 devnet
 * deployment — the URL-based auto-inference defaults to the commercial
 * devnet ID.
 */
export const PROGRAM_ADDRESS_FOUNDATION_DEVNET =
  'FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao';

/** Protocol v2 program ID on mainnet. */
export const PROGRAM_ID_MAINNET = new PublicKey(PROGRAM_ADDRESS_MAINNET);

/** Protocol v2 program ID on devnet (default for devnet RPC URLs). */
export const PROGRAM_ID_DEVNET = new PublicKey(PROGRAM_ADDRESS_DEVNET);

/** The v1 mainnet deployment — where pre-v2 wallets live. */
export const PROGRAM_ID_MAINNET_V1 = new PublicKey(PROGRAM_ADDRESS_MAINNET_V1);

/** The v1 devnet deployment. */
export const PROGRAM_ID_DEVNET_V1 = new PublicKey(PROGRAM_ADDRESS_DEVNET_V1);

/**
 * The v1 deployment that pairs with a v2 program id: where that cluster's
 * pre-v2 wallets live, and where their migration executes.
 *
 * Any other id — staging, a rehearsal slot, a local validator — maps to
 * itself, which is the in-place layout those environments use.
 */
export function legacyProgramIdFor(programId: PublicKey): PublicKey {
  if (programId.equals(PROGRAM_ID_MAINNET)) {
    return PROGRAM_ID_MAINNET_V1;
  }
  if (programId.equals(PROGRAM_ID_DEVNET)) return PROGRAM_ID_DEVNET_V1;
  return programId;
}

/** Foundation-binary devnet program ID (program-v2 devnet). */
export const PROGRAM_ID_FOUNDATION_DEVNET = new PublicKey(
  PROGRAM_ADDRESS_FOUNDATION_DEVNET,
);

// ─── Account discriminators ───────────────────────────────────────────────
//
// Byte 0 of every program-owned account. The high nibble is the protocol major
// version, the low nibble the account type, so a v1 account (1..7) fails the
// first byte check on every v2 read path — which is what makes v2 free of
// migration code. Byte-identical with program/src/state/mod.rs.
export const ACCOUNT_DISCRIMINATOR = {
  WALLET: 0x21,
  AUTHORITY: 0x22,
  SESSION: 0x23,
  DEFERRED_EXEC: 0x24,
  PROTOCOL_CONFIG: 0x25,
  FEE_RECORD: 0x26,
  TREASURY_SHARD: 0x27,
} as const;

/** Account layout revision within the current protocol version. */
export const CURRENT_ACCOUNT_VERSION = 1;

/** Protocol major version. Mirrors PROTOCOL_VERSION in program/src/state/mod.rs. */
export const PROTOCOL_VERSION = 2;
