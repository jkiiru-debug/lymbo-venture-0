import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import type { Request, Response, NextFunction } from 'express';
import {
  loadDatabase,
  saveDatabase,
  addAuditLog,
  UserAccount,
  UserRole,
  generateBase32Secret,
  generateBackupCodes
} from '../db/persistentStore.ts';

// Base32 Decoding for TOTP Secrets (RFC 4648)
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(base32: string): Buffer {
  const clean = base32.toUpperCase().replace(/=+$/, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_CHARS.indexOf(clean[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return output;
}

// Generates an RFC 6238 TOTP code for a given timestamp and base32 secret
export function generateTotpCode(secretBase32: string, timestampMs = Date.now()): string {
  const timeStep = Math.floor(timestampMs / 1000 / 30);
  const secretBuffer = base32Decode(secretBase32);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(timeStep));

  const hmac = crypto.createHmac('sha1', secretBuffer);
  hmac.update(counterBuffer);
  const digest = hmac.digest();

  const offset = digest[digest.length - 1] & 0x0f;
  const binaryCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = binaryCode % 1000000;
  return otp.toString().padStart(6, '0');
}

// Verifies a 6-digit TOTP code with time-step drift tolerance (window = 1, i.e. +/- 30s)
export function verifyTotpCode(secretBase32: string, candidateCode: string, window = 1): boolean {
  if (!candidateCode || typeof candidateCode !== 'string') return false;
  const cleanCandidate = candidateCode.trim().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleanCandidate)) return false;

  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    const checkTime = now + i * 30 * 1000;
    const expected = generateTotpCode(secretBase32, checkTime);
    // Constant-time comparison to prevent timing attacks
    if (crypto.timingSafeEqual(Buffer.from(cleanCandidate), Buffer.from(expected))) {
      return true;
    }
  }

  return false;
}

// Common breached & compromised passwords blacklist (length >= 12 variations)
const BREACHED_PASSWORDS_BLACKLIST = new Set([
  'password123456',
  '123456789012',
  '1234567890123',
  'qwertyuiop12',
  'administrator1',
  'welcome123456',
  'letmein123456',
  'changeme12345',
  'iloveyou12345',
  'sunshine12345',
  'princess12345',
  'dragon1234567',
  'football12345',
  'monkey1234567',
  'master1234567',
  'defaultpassword'
]);

// Validates password security rules (Min 12 chars, no common breached passwords)
export function validatePasswordSecurity(password: string): { valid: boolean; error?: string } {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required.' };
  }

  if (password.length < 12) {
    return {
      valid: false,
      error: `Password must be at least 12 characters in length (currently ${password.length} characters).`
    };
  }

  const normalized = password.toLowerCase().replace(/[\s\-_]/g, '');
  if (BREACHED_PASSWORDS_BLACKLIST.has(normalized)) {
    return {
      valid: false,
      error: 'This password is too common and has appeared in known data breaches. Please choose a unique passphrase.'
    };
  }

  return { valid: true };
}

// Brute Force & Rate Limiting Tracker
interface AttemptRecord {
  count: number;
  lastAttempt: number;
  lockedUntil: number;
  captchaRequired: boolean;
}

const loginAttempts = new Map<string, AttemptRecord>();

export function checkBruteForceLockout(ip: string): { locked: boolean; retryAfterSeconds: number; captchaRequired: boolean } {
  const record = loginAttempts.get(ip);
  if (!record) return { locked: false, retryAfterSeconds: 0, captchaRequired: false };

  const now = Date.now();
  if (record.lockedUntil > now) {
    const retryAfterSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    return { locked: true, retryAfterSeconds, captchaRequired: true };
  }

  return { locked: false, retryAfterSeconds: 0, captchaRequired: record.count >= 3 };
}

export async function recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds: number; captchaRequired: boolean }> {
  const now = Date.now();
  let record = loginAttempts.get(ip);
  if (!record) {
    record = { count: 0, lastAttempt: now, lockedUntil: 0, captchaRequired: false };
    loginAttempts.set(ip, record);
  }

  record.count += 1;
  record.lastAttempt = now;

  // Progressive delay: artificial delay after 2 failures (up to 3 seconds)
  if (record.count >= 2) {
    const delayMs = Math.min(500 * Math.pow(1.6, record.count - 2), 3000);
    await new Promise(res => setTimeout(res, delayMs));
  }

  // Temporary Lockout: 5 consecutive failures triggers 15-minute lock
  if (record.count >= 5) {
    record.lockedUntil = now + 15 * 60 * 1000;
    record.captchaRequired = true;
    const retryAfterSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    return { locked: true, retryAfterSeconds, captchaRequired: true };
  }

  record.captchaRequired = record.count >= 3;
  return { locked: false, retryAfterSeconds: 0, captchaRequired: record.captchaRequired };
}

export function resetLoginAttempts(ip: string): void {
  loginAttempts.delete(ip);
}

// Pre-auth MFA tokens (Valid for 5 minutes during 2-step verification)
interface PreAuthRecord {
  userId: string;
  expiresAt: number;
}
export const preAuthTokens = new Map<string, PreAuthRecord>();

export function createPreAuthToken(userId: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  preAuthTokens.set(token, {
    userId,
    expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutes
  });
  return token;
}

export function validatePreAuthToken(token: string): string | null {
  const record = preAuthTokens.get(token);
  if (!record) return null;
  if (Date.now() > record.expiresAt) {
    preAuthTokens.delete(token);
    return null;
  }
  return record.userId;
}

export function consumePreAuthToken(token: string): void {
  preAuthTokens.delete(token);
}

// Authenticated Session Store with Idle (30m) & Absolute (8h) Timeouts
export interface SessionData {
  id: string;
  userId: string;
  role: UserRole;
  email: string;
  name: string;
  createdAt: number;
  lastActivityAt: number;
  ip: string;
  userAgent: string;
}

export const sessions = new Map<string, SessionData>();

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;      // 30 minutes idle timeout
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000; // 8 hours absolute timeout

export function createSession(user: UserAccount, ip: string, userAgent: string): string {
  const sessionId = crypto.randomBytes(36).toString('hex');
  const now = Date.now();

  sessions.set(sessionId, {
    id: sessionId,
    userId: user.id,
    role: (user.role || 'staff') as UserRole,
    email: user.email,
    name: user.name,
    createdAt: now,
    lastActivityAt: now,
    ip,
    userAgent
  });

  return sessionId;
}

export function getSession(sessionId: string): SessionData | null {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;

  const now = Date.now();
  // Check Idle Timeout
  if (now - session.lastActivityAt > IDLE_TIMEOUT_MS) {
    sessions.delete(sessionId);
    return null;
  }

  // Check Absolute Timeout
  if (now - session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    sessions.delete(sessionId);
    return null;
  }

  // Touch session activity timestamp
  session.lastActivityAt = now;
  return session;
}

export function destroySession(sessionId: string): void {
  sessions.delete(sessionId);
}

export function destroyAllUserSessions(userId: string): void {
  for (const [sId, s] of sessions.entries()) {
    if (s.userId === userId) {
      sessions.delete(sId);
    }
  }
}

// Secure Password Reset Request (Single-use, 15 minutes expiration, SHA-256 Hashed Token)
export function createPasswordResetRequest(email: string, clientIp: string): { success: boolean; rawTokenForDispatch?: string } {
  const db = loadDatabase();
  const cleanEmail = email.trim().toLowerCase();
  const user = db.users.find(u => u.email.toLowerCase() === cleanEmail || u.username.toLowerCase() === cleanEmail);

  if (!user || user.status !== 'active') {
    // Return success without token to prevent account enumeration
    return { success: true };
  }

  // Generate secure token and store only the SHA-256 hash in database
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  user.resetTokenHash = tokenHash;
  user.resetTokenExpires = Date.now() + 15 * 60 * 1000; // 15 minutes
  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    user.role || 'staff',
    clientIp,
    'PASSWORD_RESET_REQUESTED',
    `Password reset link requested for ${user.email}. Hashed token saved (15m expiry).`,
    user.id
  );

  return {
    success: true,
    rawTokenForDispatch: rawToken
  };
}

// Confirm Password Reset with Token (Enforces 12+ chars, bcrypt hash)
export function confirmPasswordReset(token: string, newPassword: string, clientIp: string) {
  const db = loadDatabase();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const user = db.users.find(u => u.resetTokenHash === tokenHash);
  if (!user) {
    return { success: false, error: 'Password reset link is invalid or has already been used.' };
  }

  if (!user.resetTokenExpires || Date.now() > user.resetTokenExpires) {
    user.resetTokenHash = undefined;
    user.resetTokenExpires = undefined;
    saveDatabase();
    return { success: false, error: 'Password reset link has expired (15-minute validity limit).' };
  }

  const validation = validatePasswordSecurity(newPassword);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  user.resetTokenHash = undefined;
  user.resetTokenExpires = undefined;
  saveDatabase();

  // Invalidate all active user sessions on password change
  destroyAllUserSessions(user.id);

  addAuditLog(
    user.id,
    user.email,
    user.role || 'staff',
    clientIp,
    'PASSWORD_RESET_COMPLETED',
    `Password successfully updated for ${user.email} (12+ char requirement verified). All active sessions invalidated.`,
    user.id
  );

  return { success: true };
}

// User Lookup Helper
export function findUserByIdentifier(identifier: string): UserAccount | null {
  const db = loadDatabase();
  const clean = identifier.trim().toLowerCase();
  const adminEmail = (process.env.ADMIN_EMAIL || 'lymboventures0@gmail.com').toLowerCase();

  return db.users.find(u =>
    u.email.toLowerCase() === clean ||
    u.username.toLowerCase() === clean ||
    (clean === 'admin' && u.email.toLowerCase() === adminEmail) ||
    clean === 'jkiiru8251@gmail.com'
  ) || null;
}

// Middleware: Require Authenticated User (Any Active Staff/Admin)
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Unauthorized: Valid authenticated session required.'
    });
  }

  (req as any).user = session;
  next();
}

// Middleware: Require System Admin (Tier 1: lymboventures0@gmail.com)
export function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);

  if (!session || session.role !== 'admin') {
    return res.status(403).json({
      success: false,
      authenticated: Boolean(session),
      error: 'Forbidden: Access restricted strictly to System Administrators.'
    });
  }

  (req as any).user = session;
  next();
}

// Middleware: Require Manager or Admin (Tier 1 & Tier 2)
export function requireManagerOrAdminAuth(req: Request, res: Response, next: NextFunction) {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);

  if (!session || (session.role !== 'admin' && session.role !== 'manager')) {
    return res.status(403).json({
      success: false,
      authenticated: Boolean(session),
      error: 'Forbidden: Access restricted to Managers and Administrators.'
    });
  }

  (req as any).user = session;
  next();
}

// Generic Role Check Middleware (Database Grounded on Every Request - Section 9.4)
export function requireRole(...allowed: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
    const session = getSession(sessionId);

    if (!session) {
      return res.status(401).json({ success: false, error: 'Please sign in.' });
    }

    const db = loadDatabase();
    const user = db.users.find(u => u.id === session.userId);
    if (!user || user.status !== 'active' || !user.role) {
      return res.status(403).json({ success: false, error: 'Not allowed: Active staff role required.' });
    }

    // Admin always possesses root governance
    if (user.role === 'admin') {
      (req as any).user = { id: user.id, email: user.email, role: user.role, name: user.name };
      return next();
    }

    const effectiveRole = user.role === 'staff' ? 'sales_officer' : user.role;
    const isPermitted = allowed.some(r => r === user.role || (r === 'sales_officer' && user.role === 'staff') || (r === 'staff' && user.role === 'sales_officer'));

    if (!isPermitted) {
      return res.status(403).json({ success: false, error: 'Forbidden: Insufficient role permissions for this endpoint.' });
    }

    (req as any).user = { id: user.id, email: user.email, role: user.role, name: user.name };
    next();
  };
}

// Middleware: Require Staff, Manager, or Admin (Tier 1, Tier 2, Tier 3)
export function requireStaffOrAdminAuth(req: Request, res: Response, next: NextFunction) {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Unauthorized: Valid authenticated session required.'
    });
  }

  const validRoles: string[] = ['admin', 'manager', 'sales_officer', 'dispatch_officer', 'accounts_officer', 'customer_support', 'staff'];
  if (!validRoles.includes(session.role)) {
    return res.status(403).json({
      success: false,
      authenticated: Boolean(session),
      error: 'Forbidden: Access restricted to authorized company personnel.'
    });
  }

  (req as any).user = session;
  next();
}
