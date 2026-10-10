/**
 * Shared fixtures for the typed approval request tests (20-*, 21-*): a seeded
 * random source, valid-by-construction action buffers, and the reference
 * challenge written straight from the program.
 */
import { createHash } from 'crypto';
import { parseActions, serializeActions, type SessionAction } from '../../sdk/sdk-legacy/src';
import { MIN_UNIX_SECONDS } from '../../sdk/sdk-legacy/src/approval';

// ─── Seeded randomness ─────────────────────────────────────────────

/** sfc32: small, fast, seedable; good enough to draw test cases. */
export class Rng {
  private a: number;
  private b: number;
  private c: number;
  private d: number;
  constructor(seed: number) {
    this.a = 0x9e3779b9;
    this.b = 0x243f6a88;
    this.c = 0xb7e15162;
    this.d = seed >>> 0;
    for (let i = 0; i < 16; i++) this.u32();
  }
  u32(): number {
    const t = (((this.a + this.b) | 0) + this.d) | 0;
    this.d = (this.d + 1) | 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) | 0;
    this.c = (this.c << 21) | (this.c >>> 11);
    this.c = (this.c + t) | 0;
    return t >>> 0;
  }
  int(maxExclusive: number): number {
    return Math.floor((this.u32() / 0x1_0000_0000) * maxExclusive);
  }
  bool(p = 0.5): boolean {
    return this.u32() / 0x1_0000_0000 < p;
  }
  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = this.u32() & 0xff;
    return out;
  }
  u64(): bigint {
    return (BigInt(this.u32()) << 32n) | BigInt(this.u32());
  }
  /** A u64 biased towards edges: 0, 1, max, and powers of two. */
  edgyU64(): bigint {
    switch (this.int(6)) {
      case 0:
        return 0n;
      case 1:
        return (1n << 64n) - 1n;
      case 2:
        return 1n << BigInt(this.int(64));
      default:
        return this.u64();
    }
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)];
  }
}

// ─── Action buffers, valid by construction ─────────────────────────

const HEADER = 11;
const SIZES: Record<number, number> = { 1: 8, 2: 32, 3: 8, 4: 40, 5: 64, 6: 40, 10: 32, 11: 32 };

function u64(buf: Uint8Array, off: number, v: bigint) {
  for (let i = 0; i < 8; i++) buf[off + i] = Number((v >> BigInt(8 * i)) & 0xffn);
}

/** One raw action: [type][len u16][expires_at u64][data]. */
export function rawAction(type: number, expiresAt: bigint, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER + data.length);
  out[0] = type;
  out[1] = data.length & 0xff;
  out[2] = data.length >> 8;
  u64(out, 3, expiresAt);
  out.set(data, HEADER);
  return out;
}

function data(type: number, rng: Rng, mint?: Uint8Array): Uint8Array {
  const d = new Uint8Array(SIZES[type]);
  switch (type) {
    case 1:
    case 3:
      u64(d, 0, rng.edgyU64());
      break;
    case 2:
      u64(d, 0, rng.edgyU64());
      u64(d, 16, 1n + (rng.u64() % ((1n << 63n) - 1n)));
      break;
    case 4:
    case 6:
      d.set(mint!, 0);
      u64(d, 32, rng.edgyU64());
      break;
    case 5:
      d.set(mint!, 0);
      u64(d, 32, rng.edgyU64());
      u64(d, 48, 1n + (rng.u64() % ((1n << 63n) - 1n)));
      break;
    case 10:
    case 11:
      d.set(rng.bytes(32), 0);
      break;
  }
  return d;
}

/**
 * A random buffer the program's validate_actions_buffer accepts: 0 to 16
 * actions over all eight types, at most one of each Sol type, unique mints
 * per Token type, never a whitelist with a blacklist, recurring windows > 0
 * and zero counters, any expiry.
 */
export function randomValidActions(rng: Rng, maxActions = 16): Uint8Array {
  const n = rng.int(maxActions + 1);
  const programType = rng.bool() ? 10 : 11;
  const mintPool = Array.from({ length: 1 + rng.int(6) }, () => rng.bytes(32));
  const usedSol = new Set<number>();
  const usedMint: Record<number, Set<string>> = { 4: new Set(), 5: new Set(), 6: new Set() };
  const parts: Uint8Array[] = [];
  let guard = 0;
  while (parts.length < n && guard++ < 200) {
    const type = rng.pick([1, 2, 3, 4, 5, 6, programType]);
    const expiresAt = rng.bool(0.5) ? 0n : rng.edgyU64();
    if (type <= 3) {
      if (usedSol.has(type)) continue;
      usedSol.add(type);
      parts.push(rawAction(type, expiresAt, data(type, rng)));
    } else if (type <= 6) {
      const mint = rng.bool(0.7) ? rng.pick(mintPool) : rng.bytes(32);
      const key = Buffer.from(mint).toString('hex');
      if (usedMint[type].has(key)) continue;
      usedMint[type].add(key);
      parts.push(rawAction(type, expiresAt, data(type, rng, mint)));
    } else {
      parts.push(rawAction(type, expiresAt, data(type, rng)));
    }
  }
  return Uint8Array.from(Buffer.concat(parts));
}

/**
 * A random action list the SDK can express (expiries 0 or real times), and
 * the buffer `serializeActions` writes for it.
 */
export function sdkActions(rng: Rng): { actions: SessionAction[]; buffer: Uint8Array } {
  const actions = parseActions(randomValidActions(rng)).map((a): SessionAction => {
    const expiresAt = a.expiresAt === 0n ? undefined : MIN_UNIX_SECONDS + (a.expiresAt % 4_000_000_000n);
    switch (a.type) {
      case 1: return { type: 1, remaining: a.limit!, expiresAt };
      case 2: return { type: 2, limit: a.limit!, windowSeconds: a.windowSeconds!, expiresAt };
      case 3: return { type: 3, max: a.limit!, expiresAt };
      case 4: return { type: 4, mint: a.mint!, remaining: a.limit!, expiresAt };
      case 5: return { type: 5, mint: a.mint!, limit: a.limit!, windowSeconds: a.windowSeconds!, expiresAt };
      case 6: return { type: 6, mint: a.mint!, max: a.limit!, expiresAt };
      case 10: return { type: 10, programId: a.programId!, expiresAt };
      default: return { type: 11, programId: a.programId!, expiresAt };
    }
  });
  return { actions, buffer: serializeActions(actions) };
}

// ─── The reference challenge ───────────────────────────────────────

/**
 * The challenge exactly as program/src/auth/secp256r1/mod.rs hashes it
 * (lines 126-166): discriminator, the 14-byte auth payload prefix (slot,
 * counter, sysvar index, reserved 0x80), the signed payload, payer, wallet
 * (the authority's header field), the expected counter, the program id.
 */
export function referenceChallenge(c: {
  discriminator: number;
  slot: bigint;
  counter: number;
  sysvarIxIndex: number;
  signedPayload: Uint8Array;
  payer: Uint8Array;
  wallet: Uint8Array;
  programId: Uint8Array;
}): Buffer {
  const prefix = Buffer.alloc(14);
  prefix.writeBigUInt64LE(c.slot, 0);
  prefix.writeUInt32LE(c.counter, 8);
  prefix[12] = c.sysvarIxIndex;
  prefix[13] = 0x80;
  const counter = Buffer.alloc(4);
  counter.writeUInt32LE(c.counter);
  return createHash('sha256')
    .update(Buffer.from([c.discriminator]))
    .update(prefix)
    .update(c.signedPayload)
    .update(c.payer)
    .update(c.wallet)
    .update(counter)
    .update(c.programId)
    .digest();
}

/** CreateSession's signed payload (create.rs:233-276): instruction args through the actions, then the payer. */
export function referenceCreateSessionPayload(
  sessionKey: Uint8Array,
  expiresAt: bigint,
  actions: Uint8Array,
  payer: Uint8Array,
): Buffer {
  const head = Buffer.alloc(42);
  Buffer.from(sessionKey).copy(head, 0);
  head.writeBigUInt64LE(expiresAt, 32);
  head.writeUInt16LE(actions.length, 40);
  return Buffer.concat([head, actions, payer]);
}

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
