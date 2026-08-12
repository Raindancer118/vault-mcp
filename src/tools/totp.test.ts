import { describe, it, expect } from 'vitest';
import { base32Encode, base32Decode, generateTotpSecret, totpUri, currentTotpCode, verifyTotpToken, hotpCode } from './totp.js';

// RFC 6238 Appendix B test vectors — SHA1, secret ASCII "12345678901234567890", 8-digit codes.
const RFC6238_SECRET_ASCII = '12345678901234567890';
const RFC6238_VECTORS: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('base32Encode / base32Decode', () => {
  it('round-trips arbitrary bytes', () => {
    const buf = Buffer.from([0, 1, 2, 253, 254, 255, 42, 7]);
    expect(base32Decode(base32Encode(buf))).toEqual(buf);
  });

  it('encodes the RFC 6238 test secret to its known base32 form', () => {
    expect(base32Encode(Buffer.from(RFC6238_SECRET_ASCII, 'ascii'))).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  });

  it('decodes lowercase and hyphenated/spaced input', () => {
    const canonical = base32Encode(Buffer.from('hello world!'));
    const messy = canonical.toLowerCase().replace(/(.{4})/g, '$1-');
    expect(base32Decode(messy)).toEqual(base32Decode(canonical));
  });
});

describe('hotpCode — RFC 4226 / 6238 vectors', () => {
  const secret = Buffer.from(RFC6238_SECRET_ASCII, 'ascii');

  for (const [timeSec, expected] of RFC6238_VECTORS) {
    it(`matches the official 8-digit vector for T=${timeSec}`, () => {
      const counter = BigInt(Math.floor(timeSec / 30));
      expect(hotpCode(secret, counter, 8)).toBe(expected);
    });
  }
});

describe('currentTotpCode / verifyTotpToken', () => {
  const secretBase32 = base32Encode(Buffer.from(RFC6238_SECRET_ASCII, 'ascii'));

  it('produces the 6-digit suffix of the known 8-digit vector', () => {
    const code = currentTotpCode(secretBase32, { atTimeSec: 59 });
    expect(code).toBe('287082'); // last 6 digits of 94287082
  });

  it('verifies a freshly generated code against its own secret', () => {
    const secret = generateTotpSecret();
    const code = currentTotpCode(secret);
    expect(verifyTotpToken(secret, code)).toBe(true);
  });

  it('rejects a code generated from a different secret', () => {
    const secretA = generateTotpSecret();
    const secretB = generateTotpSecret();
    const code = currentTotpCode(secretA);
    expect(verifyTotpToken(secretB, code)).toBe(false);
  });

  it('accepts a code from one step in the past (clock drift tolerance)', () => {
    const secret = generateTotpSecret();
    const code = currentTotpCode(secret, { atTimeSec: 1000 });
    expect(verifyTotpToken(secret, code, { atTimeSec: 1029 })).toBe(true); // still within the same/adjacent 30s step
  });

  it('rejects garbage input without throwing', () => {
    const secret = generateTotpSecret();
    expect(verifyTotpToken(secret, 'not-a-code')).toBe(false);
    expect(verifyTotpToken(secret, '')).toBe(false);
  });
});

describe('generateTotpSecret', () => {
  it('produces a valid, decodable base32 secret of sufficient length', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(base32Decode(secret).length).toBeGreaterThanOrEqual(20);
  });

  it('produces different secrets on each call', () => {
    expect(generateTotpSecret()).not.toBe(generateTotpSecret());
  });
});

describe('totpUri', () => {
  it('builds a valid otpauth:// URI containing the secret, label, and issuer', () => {
    const secret = generateTotpSecret();
    const uri = totpUri(secret, 'my-project', 'vault-mcp');
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain('vault-mcp');
    expect(uri).toContain('my-project');
  });
});
