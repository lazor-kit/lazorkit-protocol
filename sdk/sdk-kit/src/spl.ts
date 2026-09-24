// Minimal SPL Token / Associated Token Account helpers.
//
// The migration path is the only thing in this SDK that touches token accounts,
// and it needs four things: the two token program addresses, an ATA address,
// an idempotent create instruction, and enough of the token-account layout to
// read a mint and an amount. That is small enough to derive by hand rather
// than take on a dependency.
import {
  AccountRole,
  address,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
  type Instruction,
} from '@solana/kit';

import { SYSTEM_PROGRAM_ADDRESS } from './instructions/system.js';

export const ASSOCIATED_TOKEN_PROGRAM_ADDRESS = address(
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
);

const addressEncoder = getAddressEncoder();
const addressDecoder = getAddressDecoder();

/** The associated token account for `(owner, mint)` under the given token program. */
export async function getAssociatedTokenAddress(
  mint: Address,
  owner: Address,
  tokenProgram: Address,
): Promise<Address> {
  const [ata] = await getProgramDerivedAddress({
    programAddress: ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
    seeds: [
      addressEncoder.encode(owner),
      addressEncoder.encode(tokenProgram),
      addressEncoder.encode(mint),
    ],
  });
  return ata;
}

/**
 * `CreateIdempotent` — creates the account if it is missing and does nothing if
 * it already exists. Idempotent on purpose: a migration that half-completed can
 * be re-run without failing here.
 */
export function createAssociatedTokenAccountIdempotentIx(params: {
  payer: Address;
  ata: Address;
  owner: Address;
  mint: Address;
  tokenProgram: Address;
}): Instruction {
  return {
    programAddress: ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: params.payer, role: AccountRole.WRITABLE_SIGNER },
      { address: params.ata, role: AccountRole.WRITABLE },
      { address: params.owner, role: AccountRole.READONLY },
      { address: params.mint, role: AccountRole.READONLY },
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: params.tokenProgram, role: AccountRole.READONLY },
    ],
    data: new Uint8Array([1]),
  };
}

/** Mint of a token account: bytes 0..32. */
export function tokenAccountMint(data: Uint8Array): Address {
  return addressDecoder.decode(data.slice(0, 32));
}

/** Owner of a token account: bytes 32..64. */
export function tokenAccountOwner(data: Uint8Array): Address {
  return addressDecoder.decode(data.slice(32, 64));
}

/** Amount of a token account: u64 LE at bytes 64..72. */
export function tokenAccountAmount(data: Uint8Array): bigint {
  return new DataView(data.buffer, data.byteOffset + 64, 8).getBigUint64(0, true);
}
