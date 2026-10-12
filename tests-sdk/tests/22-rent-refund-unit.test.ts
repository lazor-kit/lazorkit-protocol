/**
 * Closing an authority or a session refunds its rent to the account that paid
 * it. From layout revision 2 both record that account, and the program refuses
 * any other destination (RefundDestinationMismatch, 3039). The client reads the
 * account being closed and fills the recorded payer in; asked for another
 * destination it refuses before building anything. An account from before
 * revision 2 records none and closes where the caller says, as before.
 *
 * Mirrors sdk/sdk-kit/tests/rent-refund.test.ts. No validator.
 */
import { describe, expect, it } from 'vitest';
import { Keypair, PublicKey, type TransactionInstruction } from '@solana/web3.js';
import {
  LazorKitClient,
  RefundDestinationMismatchError,
  PROGRAM_ID_DEVNET,
  ed25519,
  recordedRentPayer,
} from '../../sdk/sdk-legacy/src';
import { contextual } from './contextReads';

const PAYER = Keypair.generate().publicKey;
const SPONSOR = Keypair.generate().publicKey;
const OWNER = Keypair.generate().publicKey;
const OWNER_PDA = Keypair.generate().publicKey;
const SESSION = Keypair.generate().publicKey;
const TARGET = Keypair.generate().publicKey;
const WALLET = Keypair.generate().publicKey;

function sessionBytes(version: number): Buffer {
  const d = Buffer.alloc(version === 2 ? 112 : 80);
  d[0] = 0x23;
  d[2] = version;
  WALLET.toBuffer().copy(d, 8);
  if (version === 2) SPONSOR.toBuffer().copy(d, 80);
  return d;
}

function authorityBytes(version: number): Buffer {
  const d = Buffer.alloc(version === 2 ? 112 : 80);
  d[0] = 0x22;
  d[1] = 0; // Ed25519
  d[4] = version;
  WALLET.toBuffer().copy(d, 16);
  if (version === 2) SPONSOR.toBuffer().copy(d, 80);
  return d;
}

function clientWith(accounts: [PublicKey, Buffer][]): LazorKitClient {
  const connection = contextual({
    getAccountInfo: async (key: PublicKey) => {
      const hit = accounts.find(([k]) => k.equals(key));
      return hit ? { data: hit[1], owner: PROGRAM_ID_DEVNET, lamports: 1, executable: false } : null;
    },
  });
  return new LazorKitClient(connection, PROGRAM_ID_DEVNET);
}

/** RevokeSession / RemoveAuthority / TransferOwnership: index 4; CloseExpiredSession: 2. */
const refundOf = (ix: TransactionInstruction, index = 4) => ix.keys[index].pubkey;

describe('rent refunds (sdk-legacy)', () => {
  it('recordedRentPayer reads revision 2 and nothing else', () => {
    expect(recordedRentPayer(sessionBytes(2))?.equals(SPONSOR)).toBe(true);
    expect(recordedRentPayer(authorityBytes(2))?.equals(SPONSOR)).toBe(true);
    expect(recordedRentPayer(sessionBytes(1))).toBeNull();
    expect(recordedRentPayer(authorityBytes(1))).toBeNull();
  });

  for (const version of [1, 2]) {
    const expected = version === 2 ? SPONSOR : PAYER;
    it(`revokeSession, revision ${version}`, async () => {
      const client = clientWith([[SESSION, sessionBytes(version)]]);
      const { instructions } = await client.revokeSession({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        sessionPda: SESSION,
      });
      expect(refundOf(instructions[0]).equals(expected)).toBe(true);
    });

    it(`removeAuthority, revision ${version}`, async () => {
      const client = clientWith([[TARGET, authorityBytes(version)]]);
      const { instructions } = await client.removeAuthority({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        targetAuthorityPda: TARGET,
      });
      expect(refundOf(instructions[0]).equals(expected)).toBe(true);
    });

    it(`transferOwnership, revision ${version}`, async () => {
      const client = clientWith([[OWNER_PDA, authorityBytes(version)]]);
      const { instructions } = await client.transferOwnership({
        payer: PAYER,
        walletPda: WALLET,
        ownerSigner: ed25519(OWNER, OWNER_PDA),
        newOwner: { type: 'ed25519', publicKey: SPONSOR },
      });
      expect(refundOf(instructions[0]).equals(expected)).toBe(true);
    });

    it(`closeExpiredSession, revision ${version}`, async () => {
      const client = clientWith([[SESSION, sessionBytes(version)]]);
      const { instructions } = await client.closeExpiredSession({ caller: PAYER, sessionPda: SESSION });
      expect(refundOf(instructions[0], 2).equals(version === 2 ? SPONSOR : PAYER)).toBe(true);
    });
  }

  it('another destination than the recorded payer is refused before anything is built', async () => {
    const client = clientWith([
      [SESSION, sessionBytes(2)],
      [TARGET, authorityBytes(2)],
    ]);
    await expect(
      client.revokeSession({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        sessionPda: SESSION,
        refundDestination: OWNER,
      }),
    ).rejects.toBeInstanceOf(RefundDestinationMismatchError);
    await expect(
      client.removeAuthority({
        payer: PAYER,
        walletPda: WALLET,
        adminSigner: ed25519(OWNER, OWNER_PDA),
        targetAuthorityPda: TARGET,
        refundDestination: PAYER,
      }),
    ).rejects.toThrow(/3039/);
    const { instructions } = await client.revokeSession({
      payer: PAYER,
      walletPda: WALLET,
      adminSigner: ed25519(OWNER, OWNER_PDA),
      sessionPda: SESSION,
      refundDestination: SPONSOR,
    });
    expect(refundOf(instructions[0]).equals(SPONSOR)).toBe(true);
  });

  it('a revision-1 account closes where the caller says', async () => {
    const client = clientWith([[SESSION, sessionBytes(1)]]);
    const { instructions } = await client.revokeSession({
      payer: PAYER,
      walletPda: WALLET,
      adminSigner: ed25519(OWNER, OWNER_PDA),
      sessionPda: SESSION,
      refundDestination: OWNER,
    });
    expect(refundOf(instructions[0]).equals(OWNER)).toBe(true);
  });
});
