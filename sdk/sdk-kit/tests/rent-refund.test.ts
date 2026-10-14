// Closing an authority or a session refunds its rent to the account that paid
// it. From layout revision 2 both record that account, and the program
// refuses any other destination (RefundDestinationMismatch, 3039). The client
// reads the account being closed and fills the recorded payer in; asked for
// another destination it refuses before building anything. An account from
// before revision 2 records none and closes where the caller says, as before.

import { describe, expect, it } from 'vitest';
import { address, getAddressEncoder, type Address } from '@solana/kit';
import {
  LazorKit,
  PROGRAM_ID_DEVNET,
  RefundDestinationMismatchError,
  ed25519,
} from '../src/index.js';

const PAYER = address('11111111111111111111111111111112');
const SPONSOR = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
const OWNER = address('So11111111111111111111111111111111111111112');
const SESSION = address('SysvarRent111111111111111111111111111111111');
const TARGET = address('SysvarC1ock11111111111111111111111111111111');
const OWNER_PDA = address('Sysvar1nstructions1111111111111111111111111');
const WALLET = address('Stake11111111111111111111111111111111111111');

const enc = getAddressEncoder();

function sessionBytes(version: number): Uint8Array {
  const d = new Uint8Array(version === 2 ? 112 : 80);
  d[0] = 0x23;
  d[2] = version;
  d.set(enc.encode(WALLET), 8);
  if (version === 2) d.set(enc.encode(SPONSOR), 80);
  return d;
}

function authorityBytes(version: number): Uint8Array {
  const d = new Uint8Array(version === 2 ? 112 : 80);
  d[0] = 0x22;
  d[1] = 0; // Ed25519
  d[4] = version;
  d.set(enc.encode(WALLET), 16);
  if (version === 2) d.set(enc.encode(SPONSOR), 80);
  return d;
}

/** An RPC that knows `accounts` and nothing else. */
function rpcWith(accounts: Record<string, Uint8Array>) {
  return {
    getAccountInfo: (key: Address) => ({
      send: async () => {
        const data = accounts[key];
        return {
          value: data ? { data: [Buffer.from(data).toString('base64'), 'base64'] } : null,
        };
      },
    }),
  };
}

/** The refund destination: index 4 of RevokeSession / RemoveAuthority / TransferOwnership, 2 of CloseExpiredSession. */
function refundOf(ix: { accounts?: readonly { address: Address }[] }, index = 4): Address {
  return ix.accounts![index].address;
}

describe('rent refunds', () => {
  for (const version of [1, 2]) {
    const expected = version === 2 ? SPONSOR : PAYER;
    it(`revokeSession, revision ${version}: refunds to ${version === 2 ? 'the recorded payer' : 'payer, as before'}`, async () => {
      const lk = new LazorKit(rpcWith({ [SESSION]: sessionBytes(version) }) as never, PROGRAM_ID_DEVNET);
      const { instructions } = await lk.revokeSession({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        sessionPda: SESSION,
      });
      expect(refundOf(instructions[0])).toBe(expected);
    });

    it(`removeAuthority, revision ${version}`, async () => {
      const lk = new LazorKit(rpcWith({ [TARGET]: authorityBytes(version) }) as never, PROGRAM_ID_DEVNET);
      const { instructions } = await lk.removeAuthority({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        targetAuthorityPda: TARGET,
      });
      expect(refundOf(instructions[0])).toBe(expected);
    });

    it(`transferOwnership, revision ${version}: the replaced Owner's payer`, async () => {
      const lk = new LazorKit(rpcWith({ [OWNER_PDA]: authorityBytes(version) }) as never, PROGRAM_ID_DEVNET);
      const { instructions } = await lk.transferOwnership({
        payer: PAYER,
        walletPda: WALLET,
        ownerSigner: ed25519(OWNER, OWNER_PDA),
        newOwner: { type: 'ed25519', publicKey: SPONSOR },
      });
      expect(refundOf(instructions[0])).toBe(expected);
    });

    it(`closeExpiredSession, revision ${version}: ${version === 2 ? 'the recorded payer' : 'the caller'}`, async () => {
      const lk = new LazorKit(rpcWith({ [SESSION]: sessionBytes(version) }) as never, PROGRAM_ID_DEVNET);
      const { instructions } = await lk.closeExpiredSession({ caller: PAYER, sessionPda: SESSION });
      expect(refundOf(instructions[0], 2)).toBe(version === 2 ? SPONSOR : PAYER);
    });
  }

  it('another destination than the recorded payer is refused before anything is built', async () => {
    const lk = new LazorKit(
      rpcWith({ [SESSION]: sessionBytes(2), [TARGET]: authorityBytes(2) }) as never,
      PROGRAM_ID_DEVNET,
    );
    await expect(
      lk.revokeSession({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        sessionPda: SESSION,
        refundDestination: OWNER,
      }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);
    await expect(
      lk.removeAuthority({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        targetAuthorityPda: TARGET,
        refundDestination: PAYER,
      }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);
    await expect(
      lk.closeExpiredSession({ caller: PAYER, sessionPda: SESSION, refundDestination: PAYER }),
    ).rejects.toThrow(/3039/);
    // Naming the recorded payer is fine.
    const { instructions } = await lk.revokeSession({
      payer: PAYER,
      walletPda: WALLET,
      adminSigner: ed25519(OWNER, OWNER_PDA),
      sessionPda: SESSION,
      refundDestination: SPONSOR,
    });
    expect(refundOf(instructions[0])).toBe(SPONSOR);
  });

  it('a revision-1 account closes where the caller says', async () => {
    const lk = new LazorKit(rpcWith({ [SESSION]: sessionBytes(1) }) as never, PROGRAM_ID_DEVNET);
    const { instructions } = await lk.revokeSession({
      payer: PAYER,
      walletPda: WALLET,
      adminSigner: ed25519(OWNER, OWNER_PDA),
      sessionPda: SESSION,
      refundDestination: OWNER,
    });
    expect(refundOf(instructions[0])).toBe(OWNER);
  });
});
