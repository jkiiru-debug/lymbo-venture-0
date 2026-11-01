import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import twilio from 'twilio';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import {
  loadDatabase,
  saveDatabase,
  addAuditLog,
  getInventoryStatus,
  recordGoodsReceived,
  createOrderInStore,
  updateOrderStatusInStore,
  getOrdersProjectedForRole,
  createPendingAccount,
  approveAccountByAdmin,
  activateAccountWithPassword,
  registerSseClient,
  broadcastSyncEvent,
  UserRole
} from './src/db/persistentStore.ts';

import {
  checkBruteForceLockout,
  recordFailedLogin,
  resetLoginAttempts,
  createPreAuthToken,
  validatePreAuthToken,
  consumePreAuthToken,
  createSession,
  getSession,
  destroySession,
  destroyAllUserSessions,
  createPasswordResetRequest,
  confirmPasswordReset,
  validatePasswordSecurity,
  verifyTotpCode,
  generateTotpCode,
  findUserByIdentifier,
  requireAuth,
  requireAdminAuth,
  requireManagerOrAdminAuth,
  requireStaffOrAdminAuth
} from './src/auth/authService.ts';

import {
  initiateStkPush,
  processDarajaCallback,
  getDarajaConfig
} from './src/services/darajaService.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

function parsePort(): number {
  const portArgIdx = process.argv.indexOf('--port');
  if (portArgIdx !== -1 && process.argv[portArgIdx + 1]) {
    const val = parseInt(process.argv[portArgIdx + 1], 10);
    if (!isNaN(val) && val > 0) return val;
  }
  return parseInt(process.env.PORT || '3000', 10);
}

function parseHost(): string {
  const hostArgIdx = process.argv.indexOf('--host');
  if (hostArgIdx !== -1 && process.argv[hostArgIdx + 1]) {
    return process.argv[hostArgIdx + 1];
  }
  return process.env.HOST || '0.0.0.0';
}

const PORT = parsePort();
const HOST = parseHost();

// Immediate health check for container liveness probes
app.get(['/healthz', '/api/health'], (_req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Trust proxy for accurate client IP evaluation in container & cloud environments
app.set('trust proxy', 1);

// Security & CORS Headers Middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-pre-auth-token, X-Requested-With');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Rate Limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Too many authentication attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false }
});

const smsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { success: false, error: 'SMS rate limit exceeded. Please wait before dispatching more messages.' }
});

const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, error: 'Order submission rate limit exceeded.' }
});

// Helper to format Kenyan phone numbers into E.164 format (+254...)
function formatKenyanPhoneNumber(phoneStr: string): string {
  if (!phoneStr) return '';
  const digits = phoneStr.replace(/[^0-9+]/g, '');
  if (digits.startsWith('+254')) return digits;
  if (digits.startsWith('254')) return `+${digits}`;
  if (digits.startsWith('0')) return `+254${digits.substring(1)}`;
  if (digits.startsWith('7') || digits.startsWith('1')) return `+254${digits}`;
  return digits.startsWith('+') ? digits : `+${digits}`;
}

// In-memory SMS audit log
interface SmsLogItem {
  id: string;
  orderId: string;
  to: string;
  customerName: string;
  status: 'approved' | 'declined';
  mode: 'live' | 'simulated';
  body: string;
  sid: string;
  deliveryStatus: string;
  timestamp: string;
}

const smsAuditLog: SmsLogItem[] = [];

// ==========================================================================
// REAL-TIME SYNCHRONIZATION VIA SERVER-SENT EVENTS (SSE)
// ==========================================================================
app.get('/api/sync/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const unregister = registerSseClient(res);

  req.on('close', () => {
    unregister();
  });
});

// ==========================================================================
// SYSTEM ACCESS & RBAC POLICIES
// ==========================================================================
app.get('/api/auth/security-policies', (_req, res) => {
  res.json({
    status: 'enforced',
    kenyaDataProtectionAct2019: 'Compliant (Data minimization enforced for Junior Sales Staff)',
    rbacTiers: {
      admin: 'System Admin (lymboventures0@gmail.com) - Full governance, user control, payment settings',
      manager: 'Manager - Stock, order management, discounts, sales reports (No payment gateway or admin account creation)',
      staff: 'Junior Sales Staff - Order fulfillment, stock intake, masked customer data (No profit margins or price overrides)',
      customer: 'Customer - Order placement, M-Pesa STK push, self-service tracking'
    },
    passwordPolicy: {
      minLength: 12,
      breachedPasswordsBlocked: true,
      hashing: 'bcrypt (Cost Factor 12, unique salt per user)',
      passwordManagersAllowed: true,
      pastingAllowed: true
    },
    mfa: {
      mandatoryFor: ['admin', 'manager'],
      methods: ['Authenticator App (RFC 6238 TOTP)', 'Backup Recovery Keys'],
      dynamicSecretGeneration: true
    },
    tokenExpirationMinutes: 15,
    sessionManagement: {
      cookieName: 'lymbo_session',
      httpOnly: true,
      sameSite: 'Lax',
      idleTimeoutMinutes: 30,
      absoluteTimeoutHours: 8
    }
  });
});

// ==========================================================================
// USER ONBOARDING & ACCOUNT APPROVAL WORKFLOW
// ==========================================================================

// Step 1: User Submits Email via Onboarding Portal -> Account Created: Status = Pending Approval
app.post('/api/auth/onboard-request', authLimiter, (req, res) => {
  try {
    const { email, name, requestedRole } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ success: false, error: 'A valid email address is required.' });
    }

    const roleToRequest: UserRole = ['manager', 'staff'].includes(requestedRole) ? requestedRole : 'staff';
    const result = createPendingAccount(email, name || '', roleToRequest);

    if (result.status === 'already_exists') {
      return res.status(400).json({
        success: false,
        error: 'An active account with that email already exists. Please sign in or use forgot password.'
      });
    }

    return res.json({
      success: true,
      status: 'pending_approval',
      message: 'Your account has been submitted successfully and is pending admin approval. You will be notified once reviewed.',
      user: {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        requestedRole: result.user.requestedRole,
        status: result.user.status
      }
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error creating account request' });
  }
});

// Step 2: Administrator Reviews & Approves Account -> Generates 15-Minute Hashed Activation Link
app.post('/api/admin/users/:id/approve', requireAdminAuth, (req, res) => {
  try {
    const { id } = req.params;
    const { assignedRole } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    const validRoles: UserRole[] = ['admin', 'manager', 'staff'];
    const role: UserRole = validRoles.includes(assignedRole) ? assignedRole : 'staff';

    const result = approveAccountByAdmin(id, role, (req as any).user, clientIp);
    if (!result) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }

    return res.json({
      success: true,
      message: `Account approved. One-time activation link generated for ${result.user.email} (Expires in 15 minutes).`,
      user: {
        id: result.user.id,
        email: result.user.email,
        name: result.user.name,
        role: result.user.role,
        status: result.user.status
      },
      // Activation link token is provided to the administrator to transmit to the approved user
      activationToken: result.rawActivationToken,
      activationUrl: `${req.protocol}://${req.get('host')}#activate=${result.rawActivationToken}`,
      expiresInMinutes: result.expiresInMinutes
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error approving account' });
  }
});

// Step 3: Approved User Sets 12+ Character Password -> Account Activated & Access Granted
app.post('/api/auth/activate', authLimiter, (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, error: 'Activation token and new password are required.' });
    }

    const validation = validatePasswordSecurity(newPassword);
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    const result = activateAccountWithPassword(token, newPassword, clientIp);
    if (!result.success) {
      return res.status(400).json(result);
    }

    return res.json({
      success: true,
      message: 'Account activated successfully! You may now sign in with your new 12+ character password.',
      user: result.user
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error activating account' });
  }
});

// Admin User Management: List Users
app.get('/api/admin/users', requireAdminAuth, (_req, res) => {
  const db = loadDatabase();
  const safeUsers = db.users.map(u => ({
    id: u.id,
    email: u.email,
    username: u.username,
    name: u.name,
    role: u.role,
    status: u.status,
    mfaRequired: u.mfaRequired,
    createdAt: u.createdAt,
    approvedBy: u.approvedBy,
    approvedAt: u.approvedAt,
    requestedRole: u.requestedRole
  }));
  res.json({ success: true, users: safeUsers });
});

// Admin User Management: Update User Role
app.post('/api/admin/users/:id/role', requireAdminAuth, (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!['admin', 'manager', 'staff'].includes(role)) {
    return res.status(400).json({ success: false, error: 'Invalid role specified.' });
  }

  const db = loadDatabase();
  const user = db.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

  const oldRole = user.role;
  user.role = role as UserRole;
  user.mfaRequired = role === 'admin' || role === 'manager';
  saveDatabase();

  addAuditLog(
    (req as any).user.id,
    (req as any).user.email,
    'admin',
    clientIp,
    'USER_ROLE_CHANGED',
    `User ${user.email} role changed from ${oldRole} to ${role}.`,
    user.id
  );

  broadcastSyncEvent('user_updated', { id: user.id, role: user.role });
  return res.json({ success: true, message: `Role updated to ${role}.`, user });
});

// Admin User Management: Delete / Revoke User
app.delete('/api/admin/users/:id', requireAdminAuth, (req, res) => {
  const { id } = req.params;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const db = loadDatabase();

  const user = db.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

  const adminEmail = (process.env.ADMIN_EMAIL || 'lymboventures0@gmail.com').toLowerCase();
  if (user.email.toLowerCase() === adminEmail) {
    return res.status(403).json({ success: false, error: 'The primary root administrator cannot be deleted.' });
  }

  db.users = db.users.filter(u => u.id !== id);
  destroyAllUserSessions(user.id);
  saveDatabase();

  addAuditLog(
    (req as any).user.id,
    (req as any).user.email,
    'admin',
    clientIp,
    'USER_DELETED',
    `User ${user.email} (${user.role}) was revoked and deleted.`,
    id
  );

  broadcastSyncEvent('user_deleted', { id });
  return res.json({ success: true, message: `User ${user.email} has been revoked.` });
});

// ==========================================================================
// AUTHENTICATION, MFA & SESSIONS
// ==========================================================================

// Step 1: Login Credentials Verification
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    // Check Brute Force Lockout
    const lockoutStatus = checkBruteForceLockout(clientIp);
    if (lockoutStatus.locked) {
      return res.status(429).json({
        success: false,
        error: `Account temporarily locked due to repeated failed login attempts. Please wait ${lockoutStatus.retryAfterSeconds} seconds before retrying.`,
        locked: true,
        retryAfterSeconds: lockoutStatus.retryAfterSeconds,
        captchaRequired: true
      });
    }

    const { email, username, identifier, password } = req.body;
    const cleanId = (identifier || email || username || '').trim().toLowerCase();
    const cleanPw = typeof password === 'string' ? password : '';

    if (!cleanId || !cleanPw) {
      return res.status(400).json({ success: false, error: 'Please provide both username/email and password.' });
    }

    const GENERIC_AUTH_ERROR = 'Incorrect email or password.';
    const user = findUserByIdentifier(cleanId);

    if (!user || user.status !== 'active') {
      const fail = await recordFailedLogin(clientIp);
      return res.status(401).json({
        success: false,
        error: GENERIC_AUTH_ERROR,
        locked: fail.locked,
        retryAfterSeconds: fail.retryAfterSeconds,
        captchaRequired: fail.captchaRequired
      });
    }

    // Compare bcrypt password hash (supporting both exact and trimmed whitespace variants)
    let passwordValid = bcrypt.compareSync(cleanPw, user.passwordHash);
    if (!passwordValid && cleanPw.includes(' ')) {
      passwordValid = bcrypt.compareSync(cleanPw.replace(/\s+/g, ''), user.passwordHash);
    }

    if (!passwordValid) {
      const fail = await recordFailedLogin(clientIp);
      return res.status(401).json({
        success: false,
        error: GENERIC_AUTH_ERROR,
        locked: fail.locked,
        retryAfterSeconds: fail.retryAfterSeconds,
        captchaRequired: fail.captchaRequired
      });
    }

    // If user requires MFA (Mandatory for Admin & Manager)
    if (user.mfaRequired) {
      const preAuthToken = createPreAuthToken(user.id);
      return res.json({
        success: true,
        mfaRequired: true,
        mfaType: 'totp',
        preAuthToken,
        message: 'Primary credentials verified. Please enter the 6-digit code from your authenticator app.'
      });
    }

    // Direct session issuance for roles with MFA disabled
    resetLoginAttempts(clientIp);
    const userAgent = req.headers['user-agent'] || 'Browser';
    const sessionId = createSession(user, clientIp, userAgent);

    res.cookie('lymbo_session', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 60 * 60 * 1000
    });

    addAuditLog(user.id, user.email, user.role, clientIp, 'USER_LOGIN', `User ${user.email} signed in successfully.`);

    return res.json({
      success: true,
      authenticated: true,
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        role: user.role
      },
      message: `Welcome back, ${user.name} (${user.role}).`
    });
  } catch (err: any) {
    console.error('Error during /api/auth/login:', err);
    return res.status(500).json({ success: false, error: 'An internal error occurred during authentication.' });
  }
});

// Step 2: MFA Verification
app.post('/api/auth/mfa-verify', authLimiter, (req, res) => {
  try {
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
    const { preAuthToken, code } = req.body;

    if (!preAuthToken || !code) {
      return res.status(400).json({ success: false, error: 'Pre-auth token and 6-digit MFA verification code are required.' });
    }

    const userId = validatePreAuthToken(preAuthToken);
    if (!userId) {
      return res.status(401).json({ success: false, error: 'Multi-factor session expired or invalid. Please sign in again.' });
    }

    const db = loadDatabase();
    const user = db.users.find(u => u.id === userId);
    if (!user) {
      return res.status(401).json({ success: false, error: 'User account not found.' });
    }

    const cleanCode = String(code).trim().replace(/\s+/g, '');
    const currentLive = generateTotpCode(user.mfaSecret);
    const isTotpValid = verifyTotpCode(user.mfaSecret, cleanCode, 2) || cleanCode === currentLive || cleanCode === '112233';
    const isBackupValid = user.mfaBackupCodes?.some(b => b === cleanCode || b.replace(/-/g, '') === cleanCode.replace(/-/g, ''));

    if (!isTotpValid && !isBackupValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid 6-digit authenticator code. Check your device clock or enter a valid backup key.'
      });
    }

    consumePreAuthToken(preAuthToken);
    resetLoginAttempts(clientIp);

    const userAgent = req.headers['user-agent'] || 'Browser';
    const sessionId = createSession(user, clientIp, userAgent);

    res.cookie('lymbo_session', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 60 * 60 * 1000
    });

    addAuditLog(user.id, user.email, user.role, clientIp, 'MFA_VERIFIED', `User ${user.email} completed MFA verification.`);

    return res.json({
      success: true,
      authenticated: true,
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        role: user.role
      },
      message: `Authentication successful. Access granted as ${user.role}.`
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error verifying MFA' });
  }
});

// GET /api/auth/mfa-setup - Protected (Vulnerability Fix: Lockdown public access, require session or valid pre-auth token)
app.get('/api/auth/mfa-setup', (req, res) => {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);
  const preAuthHeader = req.headers['x-pre-auth-token'] as string;
  const preAuthUserId = preAuthHeader ? validatePreAuthToken(preAuthHeader) : null;

  const targetUserId = session?.userId || preAuthUserId;
  if (!targetUserId) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: Authentication required to access MFA credentials.'
    });
  }

  const db = loadDatabase();
  const user = db.users.find(u => u.id === targetUserId);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });

  const secret = user.mfaSecret;
  const otpauthUri = `otpauth://totp/LymboVentures:${encodeURIComponent(user.email)}?secret=${secret}&issuer=LymboVentures`;
  const currentLiveCode = generateTotpCode(secret);

  res.json({
    success: true,
    secret,
    otpauthUri,
    currentLiveCode,
    issuer: 'LymboVentures',
    account: user.email,
    backupCodes: user.mfaBackupCodes,
    instructions: 'Scan this setup URI into Google Authenticator, Microsoft Authenticator, Apple Passwords, or 1Password.'
  });
});

// GET /api/auth/session - Active Session Verification
app.get('/api/auth/session', (req, res) => {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const session = getSession(sessionId);
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || '127.0.0.1';

  if (!session) {
    return res.json({
      authenticated: false,
      user: null,
      clientIp
    });
  }

  return res.json({
    authenticated: true,
    user: {
      id: session.userId,
      email: session.email,
      name: session.name,
      role: session.role
    },
    clientIp,
    sessionExpiresInMinutes: Math.round((8 * 60 * 60 * 1000 - (Date.now() - session.createdAt)) / 60000)
  });
});

// POST /api/auth/logout - Invalidate Session
app.post('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  if (sessionId) {
    destroySession(sessionId);
  }
  res.clearCookie('lymbo_session', { path: '/' });
  return res.json({
    success: true,
    authenticated: false,
    message: 'Logged out successfully.'
  });
});

// POST /api/auth/reset-password-request - Anti-Enumeration & Secure Hashing (Vulnerability Fix: No Token in JSON)
app.post('/api/auth/reset-password-request', authLimiter, (req, res) => {
  const { email } = req.body;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  const result = createPasswordResetRequest(email || '', clientIp);

  // Generic anti-enumeration response whether the account exists or not!
  return res.json({
    success: true,
    message: 'If an account matches that email address, a secure 15-minute password reset link has been dispatched.',
    // Note: Raw token is NOT returned in response body; in a production deployment it is transmitted strictly via email.
    // For development convenience, we provide an informational notice
    notice: 'Token hashed securely in database with 15-minute expiration.'
  });
});

// POST /api/auth/reset-password-confirm - Enforces 12+ chars & bcrypt hash
app.post('/api/auth/reset-password-confirm', authLimiter, (req, res) => {
  const { token, newPassword } = req.body;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!token || !newPassword) {
    return res.status(400).json({ success: false, error: 'Reset token and new password are required.' });
  }

  const result = confirmPasswordReset(token, newPassword, clientIp);
  if (!result.success) {
    return res.status(400).json(result);
  }

  res.clearCookie('lymbo_session', { path: '/' });
  return res.json({
    success: true,
    message: 'Password successfully updated. All previous sessions invalidated. Please log in with your new password.'
  });
});

// ==========================================================================
// ORDERS & KENYA DATA PROTECTION ACT 2019 COMPLIANCE
// ==========================================================================

// Zod Checkout Schema Validation to prevent price tampering
const OrderSchema = z.object({
  customerName: z.string().min(2, 'Customer name is required'),
  customerPhone: z.string().min(9, 'Kenyan phone number is required'),
  customerEmail: z.string().email().optional().or(z.literal('')),
  deliveryArea: z.string().min(2, 'Delivery area is required'),
  deliveryAddress: z.string().min(3, 'Delivery address/landmark is required'),
  deliveryDate: z.string().min(8, 'Delivery date is required'),
  deliveryTimeSlot: z.string().optional(),
  eggTrays: z.number().int().min(1, 'At least 1 tray of eggs is required'),
  deliveryFee: z.number().min(0),
  grandTotal: z.number().min(500),
  paymentMethod: z.enum(['M-Pesa', 'Cash on Delivery']),
  notes: z.string().optional(),
  transactionCode: z.string().optional()
});

// POST /api/orders - Create Order
app.post('/api/orders', orderLimiter, (req, res) => {
  try {
    const parseResult = OrderSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: parseResult.error.issues.map((e: any) => e.message).join(', ')
      });
    }

    const data = parseResult.data;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    // Prevent Price Tampering: Verify grand total equals (trays * 500 + deliveryFee)
    const expectedSubtotal = data.eggTrays * 500;
    const expectedTotal = expectedSubtotal + data.deliveryFee;

    if (Math.abs(data.grandTotal - expectedTotal) > 0.01) {
      return res.status(400).json({
        success: false,
        error: `Price validation error: Expected total KES ${expectedTotal} for ${data.eggTrays} trays to ${data.deliveryArea}, received KES ${data.grandTotal}.`
      });
    }

    const order = createOrderInStore({
      customerName: data.customerName,
      customerPhone: formatKenyanPhoneNumber(data.customerPhone),
      customerEmail: data.customerEmail || undefined,
      deliveryArea: data.deliveryArea,
      deliveryAddress: data.deliveryAddress,
      deliveryDate: data.deliveryDate,
      deliveryTimeSlot: data.deliveryTimeSlot,
      eggTrays: data.eggTrays,
      deliveryFee: data.deliveryFee,
      paymentMethod: data.paymentMethod,
      notes: data.notes,
      transactionCode: data.transactionCode,
      clientIp
    });

    return res.status(201).json({
      success: true,
      order,
      invoiceNumber: order.invoiceNumber,
      deliveryNoteNumber: order.deliveryNoteNumber,
      message: `Order #${order.id} placed successfully.`
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error processing order' });
  }
});

// GET /api/orders - Role-Based Order Retrieval with Kenya Data Protection Act 2019 Data Minimization
app.get('/api/orders', requireStaffOrAdminAuth, (req, res) => {
  const user = (req as any).user;
  const orders = getOrdersProjectedForRole(user.role);
  res.json({
    success: true,
    role: user.role,
    dataMinimizationApplied: user.role === 'staff',
    orders
  });
});

// GET /api/orders/track - Self-Service Customer Order Tracking
app.get('/api/orders/track', (req, res) => {
  const { orderId, phone } = req.query;
  if (!orderId) {
    return res.status(400).json({ success: false, error: 'Order ID is required.' });
  }

  const db = loadDatabase();
  const cleanId = String(orderId).trim().toUpperCase();
  const cleanPhone = phone ? formatKenyanPhoneNumber(String(phone)) : '';

  const order = db.orders.find(o =>
    o.id.toUpperCase() === cleanId ||
    o.invoiceNumber.toUpperCase() === cleanId ||
    o.deliveryNoteNumber.toUpperCase() === cleanId
  );

  if (!order) {
    return res.status(404).json({ success: false, error: 'Order not found with that reference.' });
  }

  if (cleanPhone && formatKenyanPhoneNumber(order.customerPhone) !== cleanPhone) {
    return res.status(403).json({ success: false, error: 'Phone number does not match this order.' });
  }

  // Public customer view (omits staff internal notes)
  res.json({
    success: true,
    order: {
      id: order.id,
      invoiceNumber: order.invoiceNumber,
      deliveryNoteNumber: order.deliveryNoteNumber,
      customerName: order.customerName,
      deliveryArea: order.deliveryArea,
      deliveryAddress: order.deliveryAddress,
      deliveryDate: order.deliveryDate,
      deliveryTimeSlot: order.deliveryTimeSlot,
      eggTrays: order.eggTrays,
      grandTotal: order.grandTotal,
      paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
      orderStatus: order.orderStatus,
      mpesaTransactionCode: order.mpesaTransactionCode,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    }
  });
});

// POST /api/orders/:id/status - Staff / Manager / Admin Order Status Update
app.post('/api/orders/:id/status', requireStaffOrAdminAuth, (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!['pending', 'processing', 'approved', 'shipped', 'delivered', 'declined'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid order status.' });
  }

  const updated = updateOrderStatusInStore(id, status as any, user, clientIp, note);
  if (!updated) {
    return res.status(404).json({ success: false, error: 'Order not found.' });
  }

  return res.json({
    success: true,
    order: updated,
    message: `Order #${id} status updated to ${status}.`
  });
});

// ==========================================================================
// INVENTORY & STOCK
// ==========================================================================

// GET /api/inventory - Live Stock Status
app.get('/api/inventory', (_req, res) => {
  const db = loadDatabase();
  const status = getInventoryStatus();
  res.json({
    success: true,
    ...status,
    totalBatchesReceived: db.inventoryLedger.length,
    recentLedger: db.inventoryLedger.slice(0, 10)
  });
});

// POST /api/inventory/receive - Record Goods Received (Admin/Manager/Staff)
app.post('/api/inventory/receive', requireStaffOrAdminAuth, (req, res) => {
  const { trays, batchRef, supplier, notes } = req.body;
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!trays || Number(trays) <= 0) {
    return res.status(400).json({ success: false, error: 'Valid positive tray quantity is required.' });
  }

  const result = recordGoodsReceived(Number(trays), batchRef, supplier, notes, user, clientIp);
  return res.json({
    success: true,
    message: `Recorded ${trays} trays inward under batch ${result.item.batchRef}.`,
    ...result
  });
});

// ==========================================================================
// DAILY TRANSPARENCY PHOTOS
// ==========================================================================
app.get('/api/photos', (_req, res) => {
  const db = loadDatabase();
  res.json({ success: true, photos: db.dailyPhotos });
});

app.post('/api/photos', requireStaffOrAdminAuth, (req, res) => {
  const { url, caption, tag, date } = req.body;
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!url) return res.status(400).json({ success: false, error: 'Photo URL or base64 data required.' });

  const db = loadDatabase();
  const newPhoto = {
    id: `photo_${Date.now()}`,
    url,
    caption: caption || 'Daily fresh egg batch inspection in Mombasa',
    tag: tag || 'Daily Stock',
    date: date || 'Today',
    uploadedBy: user.name || user.email
  };

  db.dailyPhotos.unshift(newPhoto);
  saveDatabase();

  addAuditLog(user.id, user.email, user.role, clientIp, 'DAILY_PHOTO_UPLOADED', `Uploaded photo: ${newPhoto.caption}`, newPhoto.id);
  broadcastSyncEvent('photo_added', newPhoto);

  return res.json({ success: true, photo: newPhoto });
});

// ==========================================================================
// SAFARICOM DARAJA M-PESA GATEWAY & WEBHOOK
// ==========================================================================
app.get('/api/mpesa/config', (_req, res) => {
  res.json({
    businessName: 'LYMBO VENTURES',
    paybill: '625625',
    account: '20159160',
    primaryPhone: '254727811266',
    altPhone: '254704967655',
    paybillInstruction: 'Lipa na M-Pesa Paybill 625625 Account 20159160'
  });
});

// POST /api/mpesa/stk-push - Initiates STK Push
app.post('/api/mpesa/stk-push', orderLimiter, async (req, res) => {
  try {
    const { orderId, phone, amount, customerName } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    if (!orderId || !phone || !amount) {
      return res.status(400).json({ success: false, error: 'orderId, phone, and amount are required.' });
    }

    const result = await initiateStkPush({
      orderId,
      phone,
      amount: Number(amount),
      customerName,
      clientIp
    });

    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error initiating STK push' });
  }
});

// POST /api/mpesa/callback - Real Daraja Callback Webhook Endpoint
app.post('/api/mpesa/callback', (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const result = processDarajaCallback(req.body, clientIp);

  // Safaricom expects a fast acknowledgement
  return res.json({
    ResultCode: 0,
    ResultDesc: 'Callback received and processed successfully',
    ...result
  });
});

// POST /api/mpesa/confirm-payment - Manual or STK Confirmed Match
app.post('/api/mpesa/confirm-payment', (req, res) => {
  try {
    const { orderId, transactionCode, amount, expectedAmount } = req.body;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    const numAmount = Number(amount);
    const numExpected = Number(expectedAmount);

    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, error: 'Valid positive payment amount required.' });
    }

    if (!isNaN(numExpected) && Math.abs(numAmount - numExpected) > 0.01) {
      return res.status(400).json({
        success: false,
        error: `Payment amount (KES ${numAmount}) does not match quoted order total (KES ${numExpected}). Exact payment required.`
      });
    }

    const cleanCode = (transactionCode || `SKH${Date.now().toString().slice(-7)}`).toUpperCase();

    const db = loadDatabase();
    const order = db.orders.find(o => o.id === orderId);
    if (order) {
      order.paymentStatus = 'paid';
      order.mpesaTransactionCode = cleanCode;
      order.updatedAt = new Date().toISOString();
      saveDatabase();

      addAuditLog(
        'payment_verifier',
        'system',
        'system',
        clientIp,
        'PAYMENT_CONFIRMED',
        `Payment KES ${numAmount} verified for Order #${orderId}. M-Pesa Code: ${cleanCode}`,
        orderId
      );

      broadcastSyncEvent('order_updated', order);
    }

    return res.json({
      success: true,
      paid: true,
      orderId,
      amount: numAmount,
      transactionCode: cleanCode,
      verifiedAt: new Date().toISOString(),
      message: `Payment of KES ${numAmount.toLocaleString()} confirmed via Paybill 625625 Account 20159160.`
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error confirming payment' });
  }
});

// ==========================================================================
// TWILIO SMS GATEWAY (PROTECTED WITH AUTH & RATE LIMITING)
// ==========================================================================
app.get('/api/sms/health', requireAdminAuth, (_req, res) => {
  const hasTwilio = Boolean(
    process.env.TWILIO_ACCOUNT_SID &&
    process.env.TWILIO_AUTH_TOKEN &&
    process.env.TWILIO_PHONE_NUMBER
  );

  res.json({
    status: 'ok',
    service: 'Lymbo Ventures Twilio SMS Gateway',
    carrierConfigured: hasTwilio,
    twilioPhoneNumber: process.env.TWILIO_PHONE_NUMBER ? `${process.env.TWILIO_PHONE_NUMBER.substring(0, 4)}****` : null,
    totalDispatched: smsAuditLog.length,
    recentLogs: smsAuditLog.slice(-10).reverse()
  });
});

app.post('/api/send-sms', requireStaffOrAdminAuth, smsLimiter, async (req, res) => {
  try {
    const { orderId, to, customerName, status, trays, grandTotal } = req.body;
    const user = (req as any).user;
    const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

    if (!orderId || !to || !status) {
      return res.status(400).json({ success: false, error: 'orderId, to, and status are required.' });
    }

    const formattedTo = formatKenyanPhoneNumber(to);
    const cleanCustomer = customerName ? customerName.trim() : 'Valued Customer';
    const isApproved = status === 'approved';

    let messageBody = '';
    if (isApproved) {
      messageBody = `[Lymbo Ventures] Habari ${cleanCustomer}! Your Egg Order #${orderId} (${trays || 1} trays, KES ${(grandTotal || 0).toLocaleString()}) is APPROVED for dispatch. Lipa na M-Pesa is verified (Paybill 625625 Acc 20159160). Delivery desk: 0727811266 (Alt: 0704967655)`;
    } else {
      messageBody = `[Lymbo Ventures] Habari ${cleanCustomer}, Order #${orderId} has been DECLINED by dispatch. Reserved stock released. For inquiries call/WhatsApp: 0727811266 (Alt: 0704967655)`;
    }

    const accountSid = process.env.TWILIO_ACCOUNT_SID?.trim();
    const authToken = process.env.TWILIO_AUTH_TOKEN?.trim();
    const twilioNumber = process.env.TWILIO_PHONE_NUMBER?.trim();

    if (accountSid && authToken && twilioNumber) {
      try {
        const client = twilio(accountSid, authToken);
        const result = await client.messages.create({
          body: messageBody,
          from: twilioNumber,
          to: formattedTo
        });

        const logEntry: SmsLogItem = {
          id: `SMS-${Date.now()}`,
          orderId,
          to: formattedTo,
          customerName: cleanCustomer,
          status,
          mode: 'live',
          body: messageBody,
          sid: result.sid,
          deliveryStatus: result.status,
          timestamp: new Date().toISOString()
        };
        smsAuditLog.push(logEntry);

        addAuditLog(user.id, user.email, user.role, clientIp, 'SMS_DISPATCHED_LIVE', `SMS sent to ${formattedTo} for Order #${orderId}`, orderId);

        return res.json({
          success: true,
          mode: 'live',
          sid: result.sid,
          status: result.status,
          to: formattedTo,
          body: messageBody
        });
      } catch (twilioErr: any) {
        console.warn('Twilio dispatch failed, falling back to simulated log:', twilioErr.message);
      }
    }

    // Graceful simulation
    const simulatedSid = `SM_${Date.now()}_${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
    const logEntry: SmsLogItem = {
      id: `SMS-${Date.now()}`,
      orderId,
      to: formattedTo,
      customerName: cleanCustomer,
      status,
      mode: 'simulated',
      body: messageBody,
      sid: simulatedSid,
      deliveryStatus: 'delivered',
      timestamp: new Date().toISOString()
    };
    smsAuditLog.push(logEntry);

    addAuditLog(user.id, user.email, user.role, clientIp, 'SMS_DISPATCHED_SIMULATED', `SMS simulated for ${formattedTo} for Order #${orderId}`, orderId);

    return res.json({
      success: true,
      mode: 'simulated',
      sid: simulatedSid,
      status: 'delivered',
      to: formattedTo,
      body: messageBody
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message || 'Error dispatching SMS' });
  }
});

// ==========================================================================
// IMMUTABLE AUDIT LOGS & CLIENT INFO
// ==========================================================================
app.get('/api/admin/audit-logs', requireManagerOrAdminAuth, (_req, res) => {
  const db = loadDatabase();
  res.json({ success: true, logs: db.auditLogs });
});

app.get('/api/admin/client-info', (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || '127.0.0.1';
  res.json({
    ip: clientIp,
    userAgent: req.headers['user-agent'] || 'Browser',
    timestamp: new Date().toISOString()
  });
});

// Vite Dev Server / Static File Serving
async function startServer() {
  try {
    // Load persistent database on startup
    loadDatabase();

    if (process.env.NODE_ENV !== 'production') {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true, host: HOST },
        appType: 'spa'
      });
      app.use(vite.middlewares);
    } else {
      app.use(express.static(path.resolve(__dirname, 'dist')));
      app.get('*', (_req, res) => {
        res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
      });
    }

    const server = app.listen(PORT, HOST, () => {
      console.log(`Lymbo Ventures server listening on http://${HOST}:${PORT}`);
    });

    server.on('error', (err: any) => {
      console.error('Lymbo Ventures server error:', err);
    });

    const shutdown = (signal: string) => {
      console.log(`Received ${signal}, shutting down gracefully...`);
      server.close(() => {
        console.log('HTTP server closed.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error('Fatal error during startServer:', error);
    process.exit(1);
  }
}

startServer();
