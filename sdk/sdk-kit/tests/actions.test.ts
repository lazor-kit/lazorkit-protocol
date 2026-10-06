// Action codec parity test against sdk-legacy.
//
// Both SDKs must produce byte-identical action buffers — the on-chain
// reader (validate_actions_buffer in program/src/state/action.rs) walks
// the bytes linearly and is sensitive to layout. Any drift here means
// either the kit SDK or the legacy SDK is producing wallet-bricking
// session permissions on-chain.

import { describe, it, expect } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import {
  Actions as LegacyActions,
  serializeActions as legacySerializeActions,
  SessionActionType as LegacyType,
  type SessionAction as LegacySessionAction,
} from '../../sdk-legacy/src/utils/actions.js';
import {
  Actions,
  serializeActions,
  SessionActionType,
} from '../src/codecs/actions.js';
import { address, type Address } from '@solana/kit';

const MINT_BASE58 = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // USDC
const PROGRAM_BASE58 = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'; // Jupiter
const MINT_KIT: Address = address(MINT_BASE58);
const PROGRAM_KIT: Address = address(PROGRAM_BASE58);
const MINT_PK = new PublicKey(MINT_BASE58);
const PROGRAM_PK = new PublicKey(PROGRAM_BASE58);

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('Action type IDs match the program', () => {
  it('discriminators match sdk-legacy enum', () => {
    expect(SessionActionType.SolLimit).toBe(LegacyType.SolLimit);
    expect(SessionActionType.SolRecurringLimit).toBe(
      LegacyType.SolRecurringLimit,
    );
    expect(SessionActionType.SolMaxPerTx).toBe(LegacyType.SolMaxPerTx);
    expect(SessionActionType.TokenLimit).toBe(LegacyType.TokenLimit);
    expect(SessionActionType.TokenRecurringLimit).toBe(
      LegacyType.TokenRecurringLimit,
    );
    expect(SessionActionType.TokenMaxPerTx).toBe(LegacyType.TokenMaxPerTx);
    expect(SessionActionType.ProgramWhitelist).toBe(
      LegacyType.ProgramWhitelist,
    );
    expect(SessionActionType.ProgramBlacklist).toBe(
      LegacyType.ProgramBlacklist,
    );
  });
});

describe('serializeActions byte-parity with sdk-legacy', () => {
  it('empty array produces 0 bytes', () => {
    expect(serializeActions([]).length).toBe(0);
    expect(legacySerializeActions([]).length).toBe(0);
  });

  it('SolLimit', () => {
    const expiresAt = 1_700_000_000n;
    const kit = serializeActions([Actions.solLimit(5_000_000n, expiresAt)]);
    const legacy = legacySerializeActions([
      LegacyActions.solLimit(5_000_000n, expiresAt),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // Header (11) + data (8) = 19 bytes
    expect(kit.length).toBe(19);
  });

  it('SolRecurringLimit', () => {
    const kit = serializeActions([
      Actions.solRecurringLimit({ limit: 1_000_000_000n, windowSeconds: 86_400n }),
    ]);
    const legacy = legacySerializeActions([
      LegacyActions.solRecurringLimit({
        limit: 1_000_000_000n,
        windowSeconds: 86_400n,
      }),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // Header (11) + data (32) = 43 bytes
    expect(kit.length).toBe(43);
  });

  it('SolMaxPerTx', () => {
    const kit = serializeActions([Actions.solMaxPerTx(500_000_000n)]);
    const legacy = legacySerializeActions([
      LegacyActions.solMaxPerTx(500_000_000n),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    expect(kit.length).toBe(19);
  });

  it('TokenLimit', () => {
    const kit = serializeActions([
      Actions.tokenLimit({ mint: MINT_KIT, remaining: 1_000_000_000n }),
    ]);
    const legacy = legacySerializeActions([
      LegacyActions.tokenLimit({ mint: MINT_PK, remaining: 1_000_000_000n }),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // Header (11) + data (40) = 51 bytes
    expect(kit.length).toBe(51);
  });

  it('TokenRecurringLimit', () => {
    const kit = serializeActions([
      Actions.tokenRecurringLimit({
        mint: MINT_KIT,
        limit: 1_000_000n,
        windowSeconds: 100n,
      }),
    ]);
    const legacy = legacySerializeActions([
      LegacyActions.tokenRecurringLimit({
        mint: MINT_PK,
        limit: 1_000_000n,
        windowSeconds: 100n,
      }),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // Header (11) + data (64) = 75 bytes
    expect(kit.length).toBe(75);
  });

  it('TokenMaxPerTx', () => {
    const kit = serializeActions([
      Actions.tokenMaxPerTx({ mint: MINT_KIT, max: 500n }),
    ]);
    const legacy = legacySerializeActions([
      LegacyActions.tokenMaxPerTx({ mint: MINT_PK, max: 500n }),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    expect(kit.length).toBe(51);
  });

  it('ProgramWhitelist', () => {
    const kit = serializeActions([Actions.programWhitelist(PROGRAM_KIT)]);
    const legacy = legacySerializeActions([
      LegacyActions.programWhitelist(PROGRAM_PK),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // Header (11) + data (32) = 43 bytes
    expect(kit.length).toBe(43);
  });

  it('ProgramBlacklist', () => {
    const kit = serializeActions([Actions.programBlacklist(PROGRAM_KIT)]);
    const legacy = legacySerializeActions([
      LegacyActions.programBlacklist(PROGRAM_PK),
    ]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    expect(kit.length).toBe(43);
  });

  it('mixed actions in one buffer', () => {
    const expires = 1_700_000_000n;
    const kit = serializeActions([
      Actions.solRecurringLimit({
        limit: 1_000_000_000n,
        windowSeconds: 86_400n,
        expiresAt: expires,
      }),
      Actions.programWhitelist(PROGRAM_KIT, expires),
      Actions.solMaxPerTx(500_000_000n, expires),
    ]);
    const legacy = legacySerializeActions([
      LegacyActions.solRecurringLimit({
        limit: 1_000_000_000n,
        windowSeconds: 86_400n,
        expiresAt: expires,
      }),
      LegacyActions.programWhitelist(PROGRAM_PK, expires),
      LegacyActions.solMaxPerTx(500_000_000n, expires),
    ] as LegacySessionAction[]);
    expect(bytesEqual(kit, legacy)).toBe(true);
    // 43 + 43 + 19 = 105
    expect(kit.length).toBe(105);
  });

  it('expiresAt unset becomes 0 in header', () => {
    const kit = serializeActions([Actions.solMaxPerTx(1n)]);
    // header: type=3 | data_len=8 LE | expires_at=0 LE | data=1 LE
    expect(kit[0]).toBe(3); // type
    expect(kit[1]).toBe(8); // data_len lo
    expect(kit[2]).toBe(0); // data_len hi
    // bytes 3..11 = expires_at (all zero)
    for (let i = 3; i < 11; i++) expect(kit[i]).toBe(0);
  });
});

// Every policy is built here: a session's, and a Delegate's passed to
// AddAuthority as bytes. An action expiry that is a slot would be stored as a
// time long past, which lifts a blacklist entry at once.
describe('serializeActions refuses times that are not seconds, in both SDKs', () => {
  /** Devnet's slot on 2026-10-04: what an expiry held before time-based expiry. */
  const SLOT = 507_081_509n;

  it("refuses an action's expiresAt that is a slot", () => {
    expect(() => serializeActions([Actions.programBlacklist(PROGRAM_KIT, SLOT + 216_000n)])).toThrow(
      /action's expiresAt .* not a Unix time/,
    );
    expect(() =>
      legacySerializeActions([LegacyActions.programBlacklist(PROGRAM_PK, SLOT + 216_000n)]),
    ).toThrow(/action's expiresAt .* not a Unix time/);
    expect(() =>
      serializeActions([Actions.tokenLimit({ mint: MINT_KIT, remaining: 1n, expiresAt: SLOT })]),
    ).toThrow(/not a Unix time/);
    expect(() =>
      legacySerializeActions([LegacyActions.tokenLimit({ mint: MINT_PK, remaining: 1n, expiresAt: SLOT })]),
    ).toThrow(/not a Unix time/);
  });

  it('refuses a recurring window of zero', () => {
    expect(() =>
      serializeActions([Actions.tokenRecurringLimit({ mint: MINT_KIT, limit: 1n, windowSeconds: 0n })]),
    ).toThrow(/windowSeconds > 0/);
    expect(() =>
      legacySerializeActions([
        LegacyActions.tokenRecurringLimit({ mint: MINT_PK, limit: 1n, windowSeconds: 0n }),
      ]),
    ).toThrow(/windowSeconds > 0/);
  });

  it('takes 0 as no expiry of its own, and a time in seconds', () => {
    const at = 1_791_072_000n + 86_400n;
    expect(
      bytesEqual(
        serializeActions([Actions.programBlacklist(PROGRAM_KIT, at), Actions.solLimit(1n, 0n)]),
        legacySerializeActions([LegacyActions.programBlacklist(PROGRAM_PK, at), LegacyActions.solLimit(1n, 0n)]),
      ),
    ).toBe(true);
  });
});
