// Parity + invariant tests for the compact wire format.
//
// `compact.ts` and `packing.ts` were the only mirrored pair with no parity test
// at all, and they are exactly the two files the forward-signer flag and the
// privilege binding changed. Everything they produce is hashed on-chain, so a
// divergence between the two SDKs — or between an SDK and the program — surfaces
// as an unexplained signature failure rather than as a format error.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { describe, it, expect } from 'vitest';
import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import { address, AccountRole, type Address, type Instruction } from '@solana/kit';

import {
  ACCOUNT_INDEX_FORWARD_SIGNER,
  MAX_ACCOUNT_INDEX,
  accountFlags,
  buildCompactLayout as buildKit,
  computeAccountsHash as hashKit,
  decodeAccountIndex,
  encodeAccountIndex,
  packCompactInstructions as packKit,
} from '../src/index.js';

import {
  buildCompactLayout as buildLegacy,
  computeAccountsHash as hashLegacy,
  packCompactInstructions as packLegacy,
} from '../../sdk-legacy/src/utils/index';

// Fixed keys so both SDKs see identical input.
const KEYS = [
  '11111111111111111111111111111112',
  '11111111111111111111111111111113',
  '11111111111111111111111111111114',
  '11111111111111111111111111111115',
  '11111111111111111111111111111116',
].map((s) => new PublicKey(s));

const PAYER = KEYS[0]!;
const WALLET = KEYS[1]!;
const VAULT = KEYS[2]!;
const DEST = KEYS[3]!;
const COSIGNER = KEYS[4]!;

const toKitAddress = (k: PublicKey): Address => address(k.toBase58());

// ─── index byte encoding ─────────────────────────────────────────────────

describe('account index encoding', () => {
  it('round-trips index and flag', () => {
    for (const index of [0, 1, 63, 127]) {
      for (const forwardSigner of [false, true]) {
        const byte = encodeAccountIndex(index, forwardSigner);
        expect(decodeAccountIndex(byte)).toEqual({ index, forwardSigner });
      }
    }
  });

  it('sets exactly the high bit for a forward request', () => {
    expect(encodeAccountIndex(5, false)).toBe(5);
    expect(encodeAccountIndex(5, true)).toBe(5 | ACCOUNT_INDEX_FORWARD_SIGNER);
  });

  // The flag bit halves the addressable range. Failing loudly here is the point:
  // silently masking would point the instruction at a different account.
  it('refuses an index past the ceiling the flag bit imposes', () => {
    expect(() => encodeAccountIndex(MAX_ACCOUNT_INDEX + 1, false)).toThrow(/ceiling/);
    expect(() => encodeAccountIndex(255, false)).toThrow(/ceiling/);
    expect(() => encodeAccountIndex(-1, false)).toThrow(/ceiling/);
  });

  it('encodes privilege the same way the program does', () => {
    expect(accountFlags(false, false)).toBe(0b00);
    expect(accountFlags(true, false)).toBe(0b01);
    expect(accountFlags(false, true)).toBe(0b10);
    expect(accountFlags(true, true)).toBe(0b11);
  });
});

// ─── cross-SDK parity ────────────────────────────────────────────────────

describe('compact layout parity with sdk-legacy', () => {
  const legacyIx = new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [
      { pubkey: VAULT, isSigner: false, isWritable: true },
      { pubkey: DEST, isSigner: false, isWritable: true },
      { pubkey: COSIGNER, isSigner: true, isWritable: false },
    ],
    data: Buffer.from([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
  });

  const kitIx: Instruction = {
    programAddress: toKitAddress(SystemProgram.programId),
    accounts: [
      { address: toKitAddress(VAULT), role: AccountRole.WRITABLE },
      { address: toKitAddress(DEST), role: AccountRole.WRITABLE },
      { address: toKitAddress(COSIGNER), role: AccountRole.READONLY_SIGNER },
    ],
    data: new Uint8Array([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
  };

  const fixedLegacy = [PAYER, WALLET, VAULT];
  const fixedKit = fixedLegacy.map(toKitAddress);

  it('produces identical index bytes', () => {
    const a = buildLegacy(fixedLegacy, [legacyIx], PAYER);
    const b = buildKit(fixedKit, [kitIx], toKitAddress(PAYER));
    expect(b.compactInstructions[0]!.accountIndexes).toEqual(
      a.compactInstructions[0]!.accountIndexes,
    );
    expect(b.compactInstructions[0]!.programIdIndex).toBe(
      a.compactInstructions[0]!.programIdIndex,
    );
  });

  it('produces identical packed bytes', () => {
    const a = packLegacy(buildLegacy(fixedLegacy, [legacyIx], PAYER).compactInstructions);
    const b = packKit(buildKit(fixedKit, [kitIx], toKitAddress(PAYER)).compactInstructions);
    expect(Array.from(b)).toEqual(Array.from(a));
  });

  it('produces identical accounts hashes', () => {
    const la = buildLegacy(fixedLegacy, [legacyIx], PAYER);
    const ka = buildKit(fixedKit, [kitIx], toKitAddress(PAYER));

    const legacyMetas = [
      { pubkey: PAYER, isSigner: true, isWritable: true },
      { pubkey: WALLET, isSigner: false, isWritable: false },
      { pubkey: VAULT, isSigner: false, isWritable: true },
      ...la.remainingAccounts,
    ];
    const kitMetas = [
      { address: toKitAddress(PAYER), role: AccountRole.WRITABLE_SIGNER },
      { address: toKitAddress(WALLET), role: AccountRole.READONLY },
      { address: toKitAddress(VAULT), role: AccountRole.WRITABLE },
      ...ka.remainingAccounts,
    ];

    expect(Array.from(hashKit(kitMetas, ka.compactInstructions))).toEqual(
      Array.from(hashLegacy(legacyMetas, la.compactInstructions)),
    );
  });
});

// ─── forwarding intent ───────────────────────────────────────────────────

describe('forward-signer flag', () => {
  const build = (keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[]) =>
    buildLegacy(
      [PAYER, WALLET, VAULT],
      [
        new TransactionInstruction({
          programId: SystemProgram.programId,
          keys,
          data: Buffer.alloc(0),
        }),
      ],
      PAYER,
    ).compactInstructions[0]!.accountIndexes.map(decodeAccountIndex);

  it('flags a signer the inner instruction asked for', () => {
    const [cosigner] = build([{ pubkey: COSIGNER, isSigner: true, isWritable: false }]);
    expect(cosigner!.forwardSigner).toBe(true);
  });

  it('does not flag a non-signer', () => {
    const [dest] = build([{ pubkey: DEST, isSigner: false, isWritable: true }]);
    expect(dest!.forwardSigner).toBe(false);
  });

  // The program refuses to forward the payer regardless, so asking is pointless
  // — and asking for something that will always be refused is worth not doing.
  it('never flags the fee payer, even when the instruction declares it a signer', () => {
    const [payer] = build([{ pubkey: PAYER, isSigner: true, isWritable: true }]);
    expect(payer!.forwardSigner).toBe(false);
    expect(payer!.index).toBe(0);
  });

  it('never flags the program id', () => {
    const layout = buildLegacy(
      [PAYER, WALLET, VAULT],
      [
        new TransactionInstruction({
          programId: SystemProgram.programId,
          keys: [],
          data: Buffer.alloc(0),
        }),
      ],
      PAYER,
    );
    expect(
      decodeAccountIndex(layout.compactInstructions[0]!.programIdIndex).forwardSigner,
    ).toBe(false);
  });
});

// ─── privilege binding ───────────────────────────────────────────────────

describe('accounts hash binds privilege, not just identity', () => {
  const ix = new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [{ pubkey: DEST, isSigner: false, isWritable: true }],
    data: Buffer.alloc(0),
  });
  const layout = buildLegacy([PAYER, WALLET, VAULT], [ix], PAYER);
  // The System Program lands in `remainingAccounts` ahead of DEST, so the full
  // meta list is the fixed prefix followed by both — building it by hand is how
  // the indices drift.
  const metas = (destWritable: boolean, destSigner = false) => [
    { pubkey: PAYER, isSigner: true, isWritable: true },
    { pubkey: WALLET, isSigner: false, isWritable: false },
    { pubkey: VAULT, isSigner: false, isWritable: true },
    ...layout.remainingAccounts.map((m) =>
      m.pubkey.equals(DEST)
        ? { pubkey: DEST, isSigner: destSigner, isWritable: destWritable }
        : m,
    ),
  ];

  it('changes when a referenced account becomes writable', () => {
    const a = hashLegacy(metas(true), layout.compactInstructions);
    const b = hashLegacy(metas(false), layout.compactInstructions);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('changes when a referenced account gains a signature', () => {
    const a = hashLegacy(metas(true, false), layout.compactInstructions);
    const b = hashLegacy(metas(true, true), layout.compactInstructions);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('is stable for identical input', () => {
    const a = hashLegacy(metas(true), layout.compactInstructions);
    const b = hashLegacy(metas(true), layout.compactInstructions);
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});

// ─── golden vectors ──────────────────────────────────────────────────────

// The same file `program/src/compact.rs` asserts against. It is generated by a
// third implementation, so neither side is its own oracle — and a stale SDK
// build fails here instead of as an unexplained InvalidMessageHash against a
// validator, which is exactly how this format's last divergence surfaced.
type Vector = {
  name: string;
  accounts: { address: string; isSigner: boolean; isWritable: boolean }[];
  compactInstructions: { programIdIndex: number; accountIndexes: number[] }[];
  preimageHex: string;
  hashHex: string;
};

const VECTORS: { vectors: Vector[] } = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../test-vectors/accounts-hash.json', import.meta.url)),
    'utf8',
  ),
);

describe('accounts-hash golden vectors', () => {
  it('has vectors to check', () => {
    expect(VECTORS.vectors.length).toBeGreaterThan(0);
  });

  for (const vector of VECTORS.vectors) {
    it(`matches: ${vector.name}`, () => {
      const metas = vector.accounts.map((a) => ({
        pubkey: new PublicKey(a.address),
        isSigner: a.isSigner,
        isWritable: a.isWritable,
      }));
      const ixs = vector.compactInstructions.map((ix) => ({
        programIdIndex: ix.programIdIndex,
        accountIndexes: ix.accountIndexes,
        data: Buffer.alloc(0),
      }));

      // Rebuild the preimage the same way the program walks it, so a mismatch
      // says which byte moved rather than only that the digest changed.
      const parts: Buffer[] = [];
      for (const ix of ixs) {
        for (const byte of [ix.programIdIndex, ...ix.accountIndexes]) {
          const meta = metas[decodeAccountIndex(byte).index]!;
          parts.push(meta.pubkey.toBuffer());
          parts.push(Buffer.from([accountFlags(meta.isSigner, meta.isWritable)]));
        }
      }
      const preimage = Buffer.concat(parts);
      expect(preimage.toString('hex')).toBe(vector.preimageHex);
      expect(createHash('sha256').update(preimage).digest('hex')).toBe(vector.hashHex);

      // And the shipped implementation agrees with that walk.
      expect(Buffer.from(hashLegacy(metas, ixs)).toString('hex')).toBe(vector.hashHex);
      expect(
        Buffer.from(
          hashKit(
            vector.accounts.map((a) => ({
              address: toKitAddress(new PublicKey(a.address)),
              role: a.isWritable
                ? a.isSigner
                  ? AccountRole.WRITABLE_SIGNER
                  : AccountRole.WRITABLE
                : a.isSigner
                  ? AccountRole.READONLY_SIGNER
                  : AccountRole.READONLY,
            })),
            ixs,
          ),
        ).toString('hex'),
      ).toBe(vector.hashHex);
    });
  }
});
