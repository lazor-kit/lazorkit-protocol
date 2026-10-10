// Byte, base58, base64url and integer helpers for the approval module.
//
// This module is bundled on its own by the portal and by React Native, so it
// uses neither `buffer` nor `@solana/web3.js` nor TextEncoder/TextDecoder:
// everything here is plain Uint8Array and bigint.

/** Byte-wise equality. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Concatenates byte arrays into one. */
export function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ─── Integers ────────────────────────────────────────────────────────

export const U64_MAX = (1n << 64n) - 1n;
export const I64_MAX = (1n << 63n) - 1n;
export const U32_MAX = 0xffffffff;

export function u64LE(value: bigint): Uint8Array {
  if (value < 0n || value > U64_MAX) throw new RangeError(`u64 out of range: ${value}`);
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function u32LE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new RangeError(`u32 out of range: ${value}`);
  }
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
}

export function u16LE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`u16 out of range: ${value}`);
  }
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
}

export function readU64LE(buf: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[offset + i]);
  return v;
}

export function readI64LE(buf: Uint8Array, offset: number): bigint {
  const v = readU64LE(buf, offset);
  return v > I64_MAX ? v - (1n << 64n) : v;
}

export function readU32LE(buf: Uint8Array, offset: number): number {
  return (buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24)) >>> 0;
}

export function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * Parses a canonical decimal string (no sign, no leading zeros, no spaces) in
 * [0, max]. Returns undefined for anything else.
 */
export function parseCanonicalDecimal(value: unknown, max: bigint): bigint | undefined {
  if (typeof value !== 'string' || value.length > 20 || !DECIMAL.test(value)) return undefined;
  const n = BigInt(value);
  return n <= max ? n : undefined;
}

// ─── base58 ──────────────────────────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX = new Map<string, number>();
for (let i = 0; i < B58.length; i++) B58_INDEX.set(B58[i], i);

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // Base-58 digits, little-endian.
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

/** Decodes base58; undefined on any character outside the alphabet. */
export function base58Decode(value: string): Uint8Array | undefined {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === '1') zeros++;
  const bytes: number[] = []; // little-endian
  for (let i = zeros; i < value.length; i++) {
    const d = B58_INDEX.get(value[i]);
    if (d === undefined) return undefined;
    let carry = d;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i];
  return out;
}

/**
 * A 32-byte address from its canonical base58 form, or undefined: wrong
 * alphabet, wrong length, or a spelling that does not re-encode to itself.
 */
export function decodeAddress(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string' || value.length < 32 || value.length > 44) return undefined;
  const bytes = base58Decode(value);
  if (!bytes || bytes.length !== 32) return undefined;
  return base58Encode(bytes) === value ? bytes : undefined;
}

// ─── base64 / base64url ──────────────────────────────────────────────

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX = new Map<string, number>();
for (let i = 0; i < B64URL.length; i++) B64URL_INDEX.set(B64URL[i], i);

/** base64url without padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
  }
  return out;
}

function decodeB64Chars(value: string): Uint8Array | undefined {
  if (value.length % 4 === 1) return undefined;
  const out = new Uint8Array(Math.floor((value.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < value.length; i++) {
    const d = B64URL_INDEX.get(value[i]);
    if (d === undefined) return undefined;
    acc = ((acc << 6) | d) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

/**
 * Strict base64url (no padding): only the url alphabet, and only the spelling
 * that re-encodes to itself (unused trailing bits zero). Undefined otherwise.
 */
export function base64urlDecode(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string') return undefined;
  const bytes = decodeB64Chars(value);
  if (!bytes) return undefined;
  return base64urlEncode(bytes) === value ? bytes : undefined;
}

/**
 * Lenient base64 for values another component wrote, such as a query
 * parameter: standard or url alphabet, padding optional. Undefined when it is
 * neither.
 */
export function base64DecodeLenient(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string') return undefined;
  let v = value.replace(/=+$/, '');
  if (/[+/]/.test(v) && /[-_]/.test(v)) return undefined;
  v = v.replace(/\+/g, '-').replace(/\//g, '_');
  return decodeB64Chars(v);
}

// ─── Text ────────────────────────────────────────────────────────────

/** Printable ASCII (0x20..0x7e) to bytes; undefined if any other character. */
export function asciiEncode(value: string): Uint8Array | undefined {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return undefined;
    out[i] = c;
  }
  return out;
}

/** Bytes to a string when every byte is printable ASCII; undefined otherwise. */
export function asciiDecode(bytes: Uint8Array): string | undefined {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c < 0x20 || c > 0x7e) return undefined;
    out += String.fromCharCode(c);
  }
  return out;
}

/** Strict UTF-8 decode (no overlongs, no surrogates); undefined on bad input. */
export function utf8Decode(bytes: Uint8Array): string | undefined {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i];
    let cp: number;
    let n: number;
    if (b0 < 0x80) {
      cp = b0;
      n = 0;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      cp = b0 & 0x1f;
      n = 1;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      cp = b0 & 0x0f;
      n = 2;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      cp = b0 & 0x07;
      n = 3;
    } else {
      return undefined;
    }
    if (i + n >= bytes.length) return undefined;
    for (let k = 1; k <= n; k++) {
      const b = bytes[i + k];
      if (b === undefined || (b & 0xc0) !== 0x80) return undefined;
      cp = (cp << 6) | (b & 0x3f);
    }
    if (
      (n === 2 && cp < 0x800) ||
      (n === 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
      (cp >= 0xd800 && cp <= 0xdfff)
    ) {
      return undefined;
    }
    out += String.fromCodePoint(cp);
    i += n + 1;
  }
  return out;
}
