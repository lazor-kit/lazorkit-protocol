// The reads a passkey challenge is built from: the authority's counter, its
// key and the slot. Mirrors tests-sdk/tests/18-counter-read-unit.test.ts for
// sdk-legacy, so the two SDKs behave the same.
//
// The challenge signs `counter + 1`. Read before a node has executed the
// authority's previous transaction, the counter is the one that transaction is
// about to use, and the signature fails with SignatureReused (3006). The fix
// is a floor — `minContextSlot`, the slot the previous transaction landed in —
// and a commitment, default 'confirmed', on all three reads; a node behind the
// floor (-32016) is waited for, and the wait ends in a clear error.

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NODE_UNHEALTHY,
  SolanaError,
  address,
  type Address,
} from '@solana/kit';
import {
  LazorKit,
  MinContextSlotNotReachedError,
  PROGRAM_ID_DEVNET,
  ROLE_ADMIN,
  readAuthorityCounter,
  secp256r1,
  type Secp256r1Signer,
} from '../src/index.js';

const PAYER = address('11111111111111111111111111111112');
const COUNTER = 41;
const floor = { minContextSlot: 5_000n, commitment: 'processed' as const };

/** A v2 Secp256r1 authority account, base64: counter at 8, key at 80. */
function authorityAccount(): { data: [string, 'base64'] } {
  const data = Buffer.alloc(113 + 16);
  data[0] = 0x22; // v2 Authority
  data[1] = 1; // Secp256r1
  data.writeUInt32LE(COUNTER, 8);
  data[80] = 0x02;
  return { data: [data.toString('base64'), 'base64'] };
}

function notReached(): SolanaError {
  return new SolanaError(SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, {
    contextSlot: 99n,
  });
}

type Read = { method: 'account' | 'slot'; config: Record<string, unknown> | undefined };

/**
 * A node that answers the authority with `authorityAccount()`, the slot with
 * 1000, and every other account with nothing. Records the config of each
 * authority and slot read, minus the encoding.
 */
function recordingRpc(authorityPda: () => Address | undefined) {
  const reads: Read[] = [];
  const rpc = {
    getAccountInfo: (key: Address, config?: Record<string, unknown>) => ({
      send: async () => {
        if (key !== authorityPda()) return { value: null };
        const { encoding: _encoding, ...rest } = config ?? {};
        reads.push({ method: 'account', config: rest });
        return { value: authorityAccount() };
      },
    }),
    getSlot: (config?: Record<string, unknown>) => ({
      send: async () => {
        reads.push({ method: 'slot', config });
        return 1_000n;
      },
    }),
  };
  return { rpc, reads };
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
  const credentialIdHash = new Uint8Array(32).fill(0xa7);

  async function setup() {
    let authority: Address | undefined;
    const { rpc, reads } = recordingRpc(() => authority);
    const lk = new LazorKit(rpc as never, PROGRAM_ID_DEVNET);
    const [walletPda] = await lk.findWallet(new Uint8Array(32).fill(0x51));
    authority = (await lk.findAuthority(walletPda, credentialIdHash))[0];
    return { lk, reads, walletPda, authority };
  }

  it('prepareExecute reads the key, the slot and the counter at the given floor and commitment', async () => {
    const { lk, reads, walletPda } = await setup();
    const prepared = await lk.prepareExecute({
      payer: PAYER,
      walletPda,
      secp256r1: { credentialIdHash, ...floor },
      instructions: [],
    });

    expect(reads).toHaveLength(3);
    for (const r of reads) expect(r.config).toEqual(floor);
    expect(reads.filter((r) => r.method === 'account')).toHaveLength(2);
    expect(prepared.challenge).toHaveLength(32);
  });

  it("defaults to 'confirmed' with no floor", async () => {
    const { lk, reads, walletPda } = await setup();
    await lk.prepareExecute({ payer: PAYER, walletPda, secp256r1: { credentialIdHash }, instructions: [] });

    expect(reads).toHaveLength(3);
    for (const r of reads) expect(r.config).toEqual({ commitment: 'confirmed' });
  });

  it('readCounter takes the same options', async () => {
    const { lk, reads, authority } = await setup();
    expect(await lk.readCounter(authority, floor)).toBe(COUNTER);
    expect(await lk.readCounter(authority)).toBe(COUNTER);
    expect(reads.map((r) => r.config)).toEqual([floor, { commitment: 'confirmed' }]);
  });

  const other = address('So11111111111111111111111111111111111111112');
  const highLevel: [string, (lk: LazorKit, walletPda: Address, signer: ReturnType<typeof secp256r1>) => Promise<unknown>][] = [
    ['execute', (lk, walletPda, signer) => lk.execute({ payer: PAYER, walletPda, signer, instructions: [] })],
    ['authorize', (lk, walletPda, signer) => lk.authorize({ payer: PAYER, walletPda, signer, instructions: [] })],
    ['addAuthority', (lk, walletPda, signer) =>
      lk.addAuthority({
        payer: PAYER,
        walletPda,
        adminSigner: signer,
        newAuthority: { type: 'ed25519', publicKey: other },
        role: ROLE_ADMIN,
      })],
    ['removeAuthority', (lk, walletPda, signer) =>
      lk.removeAuthority({ payer: PAYER, walletPda, adminSigner: signer, targetAuthorityPda: other })],
    ['transferOwnership', (lk, walletPda, signer) =>
      lk.transferOwnership({
        payer: PAYER,
        walletPda,
        ownerSigner: signer,
        newOwner: { type: 'ed25519', publicKey: other },
      })],
    ['createSession', (lk, walletPda, signer) =>
      lk.createSession({
        payer: PAYER,
        walletPda,
        adminSigner: signer,
        sessionKey: other,
        expiresAt: 10_000n,
        unrestricted: true,
      })],
    ['revokeSession', (lk, walletPda, signer) =>
      lk.revokeSession({ payer: PAYER, walletPda, adminSigner: signer, sessionPda: other })],
  ];

  for (const [name, call] of highLevel) {
    it(`${name}: the signer config's floor and commitment reach the counter and slot reads`, async () => {
      const { lk, reads, walletPda } = await setup();
      const signer = secp256r1(signerThatStops(credentialIdHash), floor);
      await expect(call(lk, walletPda, signer)).rejects.toBeInstanceOf(Prompted);

      // The signer carries its key, so only the counter and the slot are read.
      expect(reads.map((r) => r.method).sort()).toEqual(['account', 'slot']);
      for (const r of reads) expect(r.config).toEqual(floor);
    });
  }
});

describe('challenge reads — a node behind the floor', () => {
  const authorityPda = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');

  function rpcThat(answer: (call: number) => unknown) {
    let calls = 0;
    const rpc = {
      getAccountInfo: () => ({
        send: async () => {
          calls++;
          return answer(calls);
        },
      }),
    };
    return { rpc: rpc as never, calls: () => calls };
  }

  it('retries -32016 with a short backoff, then reads the counter', async () => {
    const { rpc, calls } = rpcThat((n) => {
      if (n < 3) throw notReached();
      return { value: authorityAccount() };
    });
    const started = Date.now();
    expect(await readAuthorityCounter(rpc, authorityPda, { minContextSlot: 5_000n })).toBe(COUNTER);
    expect(calls()).toBe(3);
    // 100 ms, then 200 ms.
    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
  });

  it('retries the slot read the same way inside prepare*', async () => {
    const lk0 = new LazorKit({} as never, PROGRAM_ID_DEVNET);
    const credentialIdHash = new Uint8Array(32).fill(0x3c);
    const [walletPda] = await lk0.findWallet(new Uint8Array(32).fill(0x52));
    const [authority] = await lk0.findAuthority(walletPda, credentialIdHash);
    let slotCalls = 0;
    const rpc = {
      getAccountInfo: (key: Address) => ({
        send: async () => ({ value: key === authority ? authorityAccount() : null }),
      }),
      getSlot: () => ({
        send: async () => {
          slotCalls++;
          if (slotCalls === 1) throw notReached();
          return 5_001n;
        },
      }),
    };
    const prepared = await new LazorKit(rpc as never, PROGRAM_ID_DEVNET).prepareRevokeSession({
      payer: PAYER,
      walletPda,
      secp256r1: { credentialIdHash, minContextSlot: 5_000n },
      sessionPda: authorityPda,
    });
    expect(slotCalls).toBe(2);
    expect(prepared.challenge).toHaveLength(32);
  });

  it('gives up after about 10 s with MinContextSlotNotReachedError, never reading older state', async () => {
    vi.useFakeTimers();
    const { rpc, calls } = rpcThat(() => {
      throw notReached();
    });
    const outcome = readAuthorityCounter(rpc, authorityPda, { minContextSlot: 5_000n }).then(
      () => null,
      (e: unknown) => e,
    );
    await vi.advanceTimersByTimeAsync(20_000);
    const error = await outcome;

    expect(error).toBeInstanceOf(MinContextSlotNotReachedError);
    const e = error as MinContextSlotNotReachedError;
    expect(e.minContextSlot).toBe(5_000n);
    expect(e.waitedMs).toBeGreaterThan(8_000);
    expect(e.waitedMs).toBeLessThanOrEqual(10_000);
    expect(e.message).toContain('slot 5000');
    expect(e.message).toContain(`the counter of ${authorityPda}`);
    expect(e.message).toContain('SignatureReused (3006)');
    expect(e.cause).toBeInstanceOf(SolanaError);
    expect(calls()).toBeGreaterThan(5);
    expect(calls()).toBeLessThan(20);
  });

  it('does not retry any other error', async () => {
    const { rpc, calls } = rpcThat(() => {
      throw new SolanaError(SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NODE_UNHEALTHY, {});
    });
    await expect(readAuthorityCounter(rpc, authorityPda, { minContextSlot: 5_000n })).rejects.toBeInstanceOf(
      SolanaError,
    );
    expect(calls()).toBe(1);
  });

  it('does not retry -32016 when no floor was asked for', async () => {
    const { rpc, calls } = rpcThat(() => {
      throw notReached();
    });
    await expect(readAuthorityCounter(rpc, authorityPda)).rejects.toBeInstanceOf(SolanaError);
    expect(calls()).toBe(1);
  });
});
