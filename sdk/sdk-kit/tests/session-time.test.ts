// Session expiry and policy time are Unix seconds (protocol v2, time-based
// expiry): what createSession accepts, and the cluster clock it is read from.

import { describe, it, expect } from 'vitest';
import { address, getBase64Decoder, type Address } from '@solana/kit';
import {
  Actions,
  LazorKit,
  MAX_SESSION_SECONDS,
  PROGRAM_ID_DEVNET,
  ed25519,
} from '../src/index.js';

const PAYER = address('11111111111111111111111111111112');
const WALLET = address('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
const OWNER = address('So11111111111111111111111111111111111111112');
const SESSION_KEY = address('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const OWNER_AUTHORITY = address('Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo');

/** 2026-10-04 in Unix seconds. */
const NOW = 1_791_072_000n;
/** Devnet's slot that day: what an expiry held before time-based expiry. */
const DEVNET_SLOT = 507_081_509n;

// createSession with an Ed25519 admin builds its instruction without a read.
const noRpc = new Proxy(
  {},
  {
    get() {
      throw new Error('no RPC in these tests');
    },
  },
);

function create(expiresAt: bigint, actions = [Actions.solLimit(1_000_000n)]) {
  return new LazorKit(noRpc as never, PROGRAM_ID_DEVNET).createSession({
    payer: PAYER,
    walletPda: WALLET,
    adminSigner: ed25519(OWNER, OWNER_AUTHORITY),
    sessionKey: SESSION_KEY,
    expiresAt,
    actions,
  });
}

describe('createSession takes Unix seconds', () => {
  it('builds a session expiring an hour from the cluster clock', async () => {
    const { instructions } = await create(NOW + 3_600n);
    // [disc 5][session_key 32][expires_at u64 LE]…
    const data = instructions[0]!.data!;
    expect(new DataView(data.buffer, data.byteOffset).getBigUint64(33, true)).toBe(NOW + 3_600n);
  });

  it('refuses a slot where a time belongs, before any read or prompt', async () => {
    await expect(create(DEVNET_SLOT + 9_000n)).rejects.toThrow(/not a Unix time in seconds/);
  });

  it("refuses an action's expiry that is a slot, and a recurring window of zero", async () => {
    await expect(create(NOW + 3_600n, [Actions.solLimit(1n, DEVNET_SLOT + 216_000n)])).rejects.toThrow(
      /action's expiresAt .* not a Unix time/,
    );
    await expect(
      create(NOW + 3_600n, [Actions.solRecurringLimit({ limit: 1n, windowSeconds: 0n })]),
    ).rejects.toThrow(/windowSeconds > 0/);
    // 0 is "no expiry of its own", not a slot.
    await expect(create(NOW + 3_600n, [Actions.solLimit(1n, 0n)])).resolves.toBeDefined();
  });

  it('caps a session at 30 days, as the program does', () => {
    expect(MAX_SESSION_SECONDS).toBe(2_592_000n);
  });
});

describe('getClusterTime', () => {
  it("reads the slot and the Unix time from the Clock sysvar, as the program sees them", async () => {
    const clock = new Uint8Array(40);
    const view = new DataView(clock.buffer);
    view.setBigUint64(0, DEVNET_SLOT, true);
    view.setBigInt64(8, NOW - 86_400n, true); // epoch start, not what is read
    view.setBigInt64(32, NOW, true);
    let asked: Address | undefined;
    const rpc = {
      getAccountInfo: (key: Address) => ({
        send: async () => {
          asked = key;
          return { value: { data: [getBase64Decoder().decode(clock), 'base64'] } };
        },
      }),
    };
    const lk = new LazorKit(rpc as never, PROGRAM_ID_DEVNET);
    expect(await lk.getClusterTime()).toEqual({ slot: DEVNET_SLOT, unixTimestamp: NOW });
    expect(asked).toBe('SysvarC1ock11111111111111111111111111111111');
  });
});
