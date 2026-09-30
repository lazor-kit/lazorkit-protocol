/**
 * The reads a passkey challenge is built from: the authority's counter, its
 * key and the slot. Pure unit tests, no validator.
 *
 * The challenge signs `counter + 1`. Read before a node has executed the
 * authority's previous transaction, the counter is the one that transaction
 * is about to use, and the signature fails with SignatureReused (3006) — on
 * devnet, three back-to-back passkey sends out of three. The fix is a floor:
 * `minContextSlot` (the slot the previous transaction landed in) and a
 * commitment, default 'confirmed'. These pin that every method that builds a
 * passkey challenge passes both to all three reads, that a node behind the
 * floor (-32016) is waited for, and that the wait ends in a clear error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  Keypair,
  PublicKey,
  SolanaJSONRPCError,
  SystemProgram,
  type AccountInfo,
  type Connection,
} from '@solana/web3.js';

import {
  LazorKitClient,
  MinContextSlotNotReachedError,
  PROGRAM_ID_DEVNET,
  ROLE_ADMIN,
  readAuthorityCounter,
  secp256r1,
  type Secp256r1Signer,
} from '../../sdk/sdk-legacy/src';
import { contextual } from './contextReads';

const PROGRAM_ID = PROGRAM_ID_DEVNET;
const COUNTER = 41;

/** A Secp256r1 authority account: counter at 8, key at 80. */
function authorityAccount(): AccountInfo<Buffer> {
  const data = Buffer.alloc(113 + 16);
  data[0] = 0x22; // v2 Authority
  data[1] = 1; // Secp256r1
  data.writeUInt32LE(COUNTER, 8);
  data[80] = 0x02;
  return { data, owner: PROGRAM_ID, executable: false, lamports: 1, rentEpoch: 0 };
}

/** -32016 as web3.js 1.x raises it from `getAccountInfoAndContext`/`getSlot`. */
function notReached(what = 'failed to get info about account'): SolanaJSONRPCError {
  return new SolanaJSONRPCError(
    { code: -32016, message: 'Minimum context slot has not been reached', data: { contextSlot: 99 } },
    what,
  );
}

type Read = { method: 'account' | 'slot'; key?: string; config: unknown };

/**
 * A node that answers every authority read with `authorityAccount()`, the
 * slot with 1000, and nothing else (no protocol config, no wallet). Records
 * the config of each authority and slot read.
 */
function recordingConnection(authorityPda: () => PublicKey | undefined) {
  const reads: Read[] = [];
  const connection = contextual({
    getAccountInfo: async (key: PublicKey, config?: unknown) => {
      const authority = authorityPda();
      if (authority && key.equals(authority)) {
        reads.push({ method: 'account', key: key.toBase58(), config });
        return authorityAccount();
      }
      return null;
    },
    getSlot: async (config?: unknown) => {
      reads.push({ method: 'slot', config });
      return 1_000;
    },
    getMultipleAccountsInfo: async (keys: PublicKey[]) => keys.map(() => null),
  });
  return { connection, reads };
}

/** Stops each high-level call at the prompt: the reads are done by then. */
class Prompted extends Error {}
function signerThatStops(credentialIdHash: Uint8Array): Secp256r1Signer {
  return {
    publicKeyBytes: Uint8Array.from([0x02, ...new Uint8Array(32).fill(7)]),
    credentialIdHash,
    rpId: 'portal.lazor.sh',
    sign: async () => {
      throw new Prompted('prompted');
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('challenge reads — options reach every read', () => {
  const payer = Keypair.generate().publicKey;
  const walletPda = Keypair.generate().publicKey;
  const credentialIdHash = new Uint8Array(32).fill(0xa7);
  const floor = { minContextSlot: 5_000, commitment: 'processed' as const };

  it('prepareExecute reads the key, the slot and the counter at the given floor and commitment', async () => {
    let authority: PublicKey | undefined;
    const { connection, reads } = recordingConnection(() => authority);
    const client = new LazorKitClient(connection, PROGRAM_ID);
    authority = client.findAuthority(walletPda, credentialIdHash)[0];

    const prepared = await client.prepareExecute({
      payer,
      walletPda,
      secp256r1: { credentialIdHash, ...floor },
      instructions: [],
    });

    // Key and counter from the authority, the slot from getSlot: all three held to it.
    expect(reads).toHaveLength(3);
    for (const r of reads) expect(r.config).toEqual(floor);
    expect(reads.filter((r) => r.method === 'account')).toHaveLength(2);
    expect(prepared.challenge).toHaveLength(32);
  });

  it("defaults to 'confirmed' with no floor on a Connection built without a commitment", async () => {
    let authority: PublicKey | undefined;
    const { connection, reads } = recordingConnection(() => authority);
    const client = new LazorKitClient(connection, PROGRAM_ID);
    authority = client.findAuthority(walletPda, credentialIdHash)[0];

    await client.prepareExecute({ payer, walletPda, secp256r1: { credentialIdHash }, instructions: [] });

    expect(reads).toHaveLength(3);
    for (const r of reads) expect(r.config).toEqual({ commitment: 'confirmed' });
  });

  // Never staler than the Connection: 1.2.0 read at the Connection's own
  // commitment, and a 'processed' Connection confirms its sends at processed.
  // A 'confirmed' read right after holds the counter the previous transaction
  // used (3006 on chain), or no authority at all right after createWallet.
  // A 'finalized' Connection (or none: the RPC's default is finalized) is read
  // at 'confirmed', seconds fresher.
  for (const [own, expected] of [
    ['processed', 'processed'],
    ['recent', 'processed'],
    ['confirmed', 'confirmed'],
    ['finalized', 'confirmed'],
  ] as const) {
    it(`on a Connection at '${own}', the default reads are at '${expected}'`, async () => {
      let authority: PublicKey | undefined;
      const { connection, reads } = recordingConnection(() => authority);
      Object.assign(connection, { commitment: own });
      expect(connection.commitment).toBe(own);
      const client = new LazorKitClient(connection, PROGRAM_ID);
      authority = client.findAuthority(walletPda, credentialIdHash)[0];

      await client.prepareExecute({ payer, walletPda, secp256r1: { credentialIdHash }, instructions: [] });
      expect(await client.readCounter(authority)).toBe(COUNTER);
      expect(await readAuthorityCounter(connection, authority)).toBe(COUNTER);

      expect(reads).toHaveLength(5);
      for (const r of reads) expect(r.config).toEqual({ commitment: expected });
    });
  }

  it("an explicit commitment wins over a 'processed' Connection's", async () => {
    let authority: PublicKey | undefined;
    const { connection, reads } = recordingConnection(() => authority);
    Object.assign(connection, { commitment: 'processed' });
    const client = new LazorKitClient(connection, PROGRAM_ID);
    authority = client.findAuthority(walletPda, credentialIdHash)[0];

    await client.prepareExecute({
      payer,
      walletPda,
      secp256r1: { credentialIdHash, commitment: 'confirmed', minContextSlot: 7 },
      instructions: [],
    });

    expect(reads).toHaveLength(3);
    for (const r of reads) expect(r.config).toEqual({ commitment: 'confirmed', minContextSlot: 7 });
  });

  it('readCounter takes the same options', async () => {
    let authority: PublicKey | undefined;
    const { connection, reads } = recordingConnection(() => authority);
    const client = new LazorKitClient(connection, PROGRAM_ID);
    authority = client.findAuthority(walletPda, credentialIdHash)[0];

    expect(await client.readCounter(authority, floor)).toBe(COUNTER);
    expect(await client.readCounter(authority)).toBe(COUNTER);
    expect(reads.map((r) => r.config)).toEqual([floor, { commitment: 'confirmed' }]);
  });

  // Every high-level method that signs with a passkey, from a signer config
  // built with `secp256r1(signer, { minContextSlot, commitment })`.
  const highLevel: [string, (c: LazorKitClient, signer: ReturnType<typeof secp256r1>) => Promise<unknown>][] = [
    ['execute', (c, signer) =>
      c.execute({ payer, walletPda, signer, instructions: [SystemProgram.transfer({ fromPubkey: payer, toPubkey: payer, lamports: 1 })] })],
    ['transferSol', (c, signer) =>
      c.transferSol({ payer, walletPda, signer, recipient: Keypair.generate().publicKey, lamports: 1n })],
    ['authorize', (c, signer) => c.authorize({ payer, walletPda, signer, instructions: [] })],
    ['addAuthority', (c, signer) =>
      c.addAuthority({
        payer,
        walletPda,
        adminSigner: signer,
        newAuthority: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
        role: ROLE_ADMIN,
      })],
    ['removeAuthority', (c, signer) =>
      c.removeAuthority({ payer, walletPda, adminSigner: signer, targetAuthorityPda: Keypair.generate().publicKey })],
    ['transferOwnership', (c, signer) =>
      c.transferOwnership({
        payer,
        walletPda,
        ownerSigner: signer,
        newOwner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
      })],
    ['createSession', (c, signer) =>
      c.createSession({
        payer,
        walletPda,
        adminSigner: signer,
        sessionKey: Keypair.generate().publicKey,
        expiresAt: 10_000n,
        unrestricted: true,
      })],
    ['revokeSession', (c, signer) =>
      c.revokeSession({ payer, walletPda, adminSigner: signer, sessionPda: Keypair.generate().publicKey })],
  ];

  for (const [name, call] of highLevel) {
    it(`${name}: the signer config's floor and commitment reach the counter and slot reads`, async () => {
      let authority: PublicKey | undefined;
      const { connection, reads } = recordingConnection(() => authority);
      const client = new LazorKitClient(connection, PROGRAM_ID);
      authority = client.findAuthority(walletPda, credentialIdHash)[0];

      const signer = secp256r1(signerThatStops(credentialIdHash), floor);
      await expect(call(client, signer)).rejects.toBeInstanceOf(Prompted);

      // The signer carries its key, so only the counter and the slot are read.
      expect(reads.map((r) => r.method).sort()).toEqual(['account', 'slot']);
      for (const r of reads) expect(r.config).toEqual(floor);
    });
  }
});

describe('challenge reads — a node behind the floor', () => {
  const authorityPda = Keypair.generate().publicKey;

  it('retries -32016 with a short backoff, then reads the counter', async () => {
    let calls = 0;
    const connection = {
      getAccountInfoAndContext: async () => {
        calls++;
        if (calls < 3) throw notReached();
        return { context: { slot: 5_000 }, value: authorityAccount() };
      },
    } as unknown as Connection;

    const started = Date.now();
    expect(await readAuthorityCounter(connection, authorityPda, { minContextSlot: 5_000 })).toBe(COUNTER);
    expect(calls).toBe(3);
    // 100 ms, then 200 ms.
    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
  });

  it('also knows -32016 by its message, as web3.js getAccountInfo rethrows it without the code', async () => {
    let calls = 0;
    const connection = {
      getAccountInfoAndContext: async () => {
        calls++;
        if (calls === 1) throw new Error(`failed to get info about account x: ${notReached()}`);
        return { context: { slot: 5_000 }, value: authorityAccount() };
      },
    } as unknown as Connection;

    expect(await readAuthorityCounter(connection, authorityPda, { minContextSlot: 5_000 })).toBe(COUNTER);
    expect(calls).toBe(2);
  });

  it('retries the slot read the same way inside prepare*', async () => {
    let slotCalls = 0;
    const walletPda = Keypair.generate().publicKey;
    const credentialIdHash = new Uint8Array(32).fill(0x3c);
    let authority: PublicKey | undefined;
    const connection = contextual({
      getAccountInfo: async (key: PublicKey) => (authority && key.equals(authority) ? authorityAccount() : null),
      getSlot: async () => {
        slotCalls++;
        if (slotCalls === 1) throw notReached('failed to get slot');
        return 5_001;
      },
    });
    const client = new LazorKitClient(connection, PROGRAM_ID);
    authority = client.findAuthority(walletPda, credentialIdHash)[0];

    const prepared = await client.prepareRevokeSession({
      payer: Keypair.generate().publicKey,
      walletPda,
      secp256r1: { credentialIdHash, minContextSlot: 5_000 },
      sessionPda: Keypair.generate().publicKey,
    });
    expect(slotCalls).toBe(2);
    expect(prepared.challenge).toHaveLength(32);
  });

  it('gives up after about 10 s with MinContextSlotNotReachedError, never reading older state', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const connection = {
      getAccountInfoAndContext: async () => {
        calls++;
        throw notReached();
      },
    } as unknown as Connection;

    const read = readAuthorityCounter(connection, authorityPda, { minContextSlot: 5_000 });
    const outcome = read.then(
      () => null,
      (e: unknown) => e,
    );
    await vi.advanceTimersByTimeAsync(20_000);
    const error = await outcome;

    expect(error).toBeInstanceOf(MinContextSlotNotReachedError);
    const e = error as MinContextSlotNotReachedError;
    expect(e.minContextSlot).toBe(5_000);
    expect(e.waitedMs).toBeGreaterThan(8_000);
    expect(e.waitedMs).toBeLessThanOrEqual(10_000);
    expect(e.message).toContain('slot 5000');
    expect(e.message).toContain(`the counter of ${authorityPda.toBase58()}`);
    expect(e.message).toContain('SignatureReused (3006)');
    expect((e as { cause?: unknown }).cause).toBeInstanceOf(SolanaJSONRPCError);
    // Backoff 100 ms, 200 ms, … 1 s, then 1 s: well under a hundred calls.
    expect(calls).toBeGreaterThan(5);
    expect(calls).toBeLessThan(20);
  });

  it('does not retry any other error', async () => {
    let calls = 0;
    const connection = {
      getAccountInfoAndContext: async () => {
        calls++;
        throw new SolanaJSONRPCError({ code: -32005, message: 'Node is unhealthy' }, 'failed');
      },
    } as unknown as Connection;

    await expect(readAuthorityCounter(connection, authorityPda, { minContextSlot: 5_000 })).rejects.toThrow(
      'Node is unhealthy',
    );
    expect(calls).toBe(1);
  });

  it('does not retry -32016 when no floor was asked for', async () => {
    let calls = 0;
    const connection = {
      getAccountInfoAndContext: async () => {
        calls++;
        throw notReached();
      },
    } as unknown as Connection;

    await expect(readAuthorityCounter(connection, authorityPda)).rejects.toBeInstanceOf(SolanaJSONRPCError);
    expect(calls).toBe(1);
  });
});
