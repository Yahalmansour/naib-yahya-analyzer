import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt) as (password: string, salt: string, keylen: number) => Promise<Buffer>;
export const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

export function makeToken(userId: number, secret: string, now = Date.now()): string {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: now + TOKEN_TTL_MS })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

export type TokenResult = { ok: true; userId: number } | { ok: false; error: string };

export function verifyToken(authorization: string | null, secret: string, now = Date.now()): TokenResult {
  const header = authorization || '';
  const token = header.slice(0, 7).toLowerCase() === 'bearer ' ? header.slice(7).trim() : '';
  if (token.length > 2048) return { ok: false, error: 'رمز الدخول غير صالح.' };
  if (!token) return { ok: false, error: 'يجب تسجيل الدخول أولاً.' };
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return { ok: false, error: 'رمز الدخول غير صالح.' };
  const expected = crypto.createHmac('sha256', secret).update(payload).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return { ok: false, error: 'رمز الدخول غير صالح.' };
  }
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!Number.isInteger(decoded.sub) || !(decoded.exp >= now)) {
      return { ok: false, error: 'انتهت صلاحية تسجيل الدخول.' };
    }
    return { ok: true, userId: decoded.sub };
  } catch {
    return { ok: false, error: 'رمز الدخول غير صالح.' };
  }
}

// Same scrypt parameters as the original Express app, so existing password hashes stay valid if migrated.
export async function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = await scrypt(password, salt, 64);
  return { salt, passwordHash: hash.toString('hex') };
}

export async function verifyPassword(password: string, user?: { salt: string; password_hash: string }) {
  const salt = user?.salt || crypto.randomBytes(16).toString('hex');
  const actual = await scrypt(password, salt, 64);
  const expected = user ? Buffer.from(user.password_hash, 'hex') : Buffer.alloc(64);
  return Boolean(user) && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function safeEqualString(provided: unknown, expected: string): boolean {
  const a = typeof provided === 'string' ? Buffer.from(provided) : Buffer.alloc(0);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
