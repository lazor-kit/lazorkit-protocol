import { address, type Address } from '@solana/kit';

/**
 * LazorKit Smart Wallet program addresses (Solana Kit / web3.js v2 SDK).
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
 * Mainnet program address (vanity). Slot is shared between the commercial
 * and foundation binaries — see file-level docs.
 */
export const PROGRAM_ADDRESS_MAINNET =
  'LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi';

/** Commercial-binary devnet program address (lazorkit-protocol). */
export const PROGRAM_ADDRESS_DEVNET =
  '4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS';

/**
 * Foundation-binary devnet program address (program-v2). Pass this
 * explicitly when targeting a program-v2 devnet deployment — the URL-based
 * auto-inference defaults to the commercial devnet ID.
 */
export const PROGRAM_ADDRESS_FOUNDATION_DEVNET =
  'FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao';

/** Mainnet program address as an Address. */
export const PROGRAM_ID_MAINNET: Address = address(PROGRAM_ADDRESS_MAINNET);

/** Commercial-binary devnet program address as an Address. */
export const PROGRAM_ID_DEVNET: Address = address(PROGRAM_ADDRESS_DEVNET);

/** Foundation-binary devnet program address as an Address. */
export const PROGRAM_ID_FOUNDATION_DEVNET: Address = address(
  PROGRAM_ADDRESS_FOUNDATION_DEVNET,
);
