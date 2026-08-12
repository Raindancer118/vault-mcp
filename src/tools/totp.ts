/**
 * RFC 4226 (HOTP) / RFC 6238 (TOTP) implementation, used as a second, independent
 * secret ("something else you have locally") for committed project vaults — see
 * project-vault.ts. The TOTP *seed* (not the rotating 6-digit code) is what's mixed
 * into key derivation, since the rotating code can't gate a persistent ciphertext
 * without making it undecryptable 30 seconds later. The rotating code is still fully
 * RFC-compliant so the same seed can optionally be scanned into a normal
 * authenticator app for a human to cross-check independently.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** RFC 4226 HOTP over a raw (already-decoded) secret and a counter value. */
export function hotpCode(secret: Buffer, counter: bigint, digits = 6): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(counter);
  const hmac = createHmac('sha1', secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 10 ** digits).padStart(digits, '0');
}

export interface TotpTimeOpts {
  /** Unix time in seconds. Defaults to now. */
  atTimeSec?: number;
  /** Step size in seconds. Default 30 (the RFC 6238 default). */
  stepSec?: number;
  digits?: number;
}

export function currentTotpCode(secretBase32: string, opts: TotpTimeOpts = {}): string {
  const step = opts.stepSec ?? 30;
  const t = opts.atTimeSec ?? Date.now() / 1000;
  const counter = BigInt(Math.floor(t / step));
  return hotpCode(base32Decode(secretBase32), counter, opts.digits ?? 6);
}

export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function totpUri(secretBase32: string, accountLabel: string, issuer = 'vault-mcp'): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountLabel)}`;
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/** Verifies a 6-digit code against `secretBase32`, tolerating ±`window` steps of clock drift. */
export function verifyTotpToken(secretBase32: string, token: string, opts: TotpTimeOpts & { window?: number } = {}): boolean {
  const clean = (token ?? '').trim();
  if (!/^\d{6}$/.test(clean)) return false;

  const step = opts.stepSec ?? 30;
  const t = opts.atTimeSec ?? Date.now() / 1000;
  const window = opts.window ?? 1;

  for (let w = -window; w <= window; w++) {
    const candidate = currentTotpCode(secretBase32, { atTimeSec: t + w * step, stepSec: step });
    if (timingSafeEqualStr(candidate, clean)) return true;
  }
  return false;
}
