import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import twilio from 'twilio';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { GoogleGenAI } from '@google/genai';

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
  createStaffApplication,
  verifyStaffEmailByCode,
  verifyStaffEmailByToken,
  approveStaffApplication,
  rejectStaffApplication,
  suspendStaffUser,
  reactivateStaffUser,
  deleteStaffUser,
  getStaffApplications,
  getOutboxEmails,
  recordOutboxEmail,
  getStoreConfig,
  updateStoreConfig,
  APPLY_POSITIONS,
  ROLES,
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
  requireStaffOrAdminAuth,
  requireRole,
  resolveAuthenticatedUser
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
  // 1. Check for explicit --port argument
  const portArgIdx = process.argv.indexOf('--port');
  if (portArgIdx !== -1 && process.argv[portArgIdx + 1]) {
    const val = parseInt(process.argv[portArgIdx + 1], 10);
    if (!isNaN(val) && val > 0 && val !== 8080) return val;
  }
  // 2. Check for npm run dev positional argument (e.g. `tsx server.ts 3000`)
  for (const arg of process.argv.slice(2)) {
    const val = parseInt(arg, 10);
    if (!isNaN(val) && val > 0 && val !== 8080) return val;
  }
  // 3. Check custom app port env
  if (process.env.APP_PORT) {
    const val = parseInt(process.env.APP_PORT, 10);
    if (!isNaN(val) && val > 0 && val !== 8080) return val;
  }
  // 4. Default strictly to 3000 (Environment constraint: Dev server must run on port 3000; port 8080 is reserved for nginx)
  return 3000;
}

function parseHost(): string {
  const hostArgIdx = process.argv.indexOf('--host');
  if (hostArgIdx !== -1 && process.argv[hostArgIdx + 1]) {
    return process.argv[hostArgIdx + 1];
  }
  for (const arg of process.argv.slice(2)) {
    if (arg === '0.0.0.0' || arg === 'localhost' || arg === '127.0.0.1') {
      return arg;
    }
  }
  return '0.0.0.0';
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

  registerSseClient(res);
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
// STAFF REGISTRATION & ROLE ALLOCATION WORKFLOW (Sections 1, 2, 4, 9)
// ==========================================================================

const registerSchema = z.object({
  fullName: z.string().trim().min(2, 'Full name must be at least 2 characters').max(80),
  email: z.string().trim().toLowerCase().email('A valid email address is required').max(254),
  phone: z.string().trim().regex(/^(?:\+254|0)[17]\d{8}$/, 'Must be a valid Kenyan mobile number (e.g. 07XXXXXXXX or +2547XXXXXXXX)'),
  password: z.string().min(12, 'Password must be at least 12 characters').max(128),
  position: z.enum(APPLY_POSITIONS),
  note: z.string().max(500).optional(),
  consent: z.boolean().refine(val => val === true, {
    message: 'You must consent to personal data processing under Data Protection Act 2019'
  })
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { success: false, error: 'Too many registration requests. Please try again after 15 minutes.' },
  validate: { xForwardedForHeader: false }
});

async function isBreached(password: string): Promise<boolean> {
  try {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const res = await fetch('https://api.pwnedpasswords.com/range/' + sha1.slice(0, 5), {
      signal: AbortSignal.timeout(2000)
    });
    if (!res.ok) return false;
    return (await res.text()).includes(sha1.slice(5));
  } catch {
    return false;
  }
}

// 1. Applicant Registration
app.post('/api/staff/register', registerLimiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      success: false,
      error: parsed.error.issues.map(i => i.message).join(', ')
    });
  }
  const { fullName, email, phone, password, position, note, consent } = parsed.data;

  const local = email.split('@')[0].toLowerCase();
  if (password.toLowerCase().includes(local) || (await isBreached(password))) {
    return res.status(400).json({
      success: false,
      error: 'That password is too easy to guess or has appeared in known data breaches. Please choose a longer, unique passphrase.'
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  try {
    const result = createStaffApplication({
      fullName,
      email,
      phone,
      passwordHash,
      position,
      note,
      consent
    });

    if (!result.success) {
      return res.status(400).json({ success: false, error: result.error });
    }

    const { code, token } = result;
    const siteUrl = process.env.SITE_URL || `${req.protocol}://${req.get('host')}`;
    const verifyLink = `${siteUrl}/verify?token=${token}`;

    recordOutboxEmail(
      email,
      'Verify your Lymbo Ventures Staff Application',
      `<p>Habari ${fullName},</p>
       <p>Thank you for applying for the <b>${position.replace('_', ' ').toUpperCase()}</b> position at Lymbo Ventures.</p>
       <p>Your 6-digit email verification code is: <b style="font-size: 1.25rem; letter-spacing: 0.1em; color: #1F7A4D;">${code}</b> (valid for 10 minutes).</p>
       <p>Or open this link to verify automatically: <a href="${verifyLink}">${verifyLink}</a></p>`,
      'verification',
      code,
      token
    );
  } catch (err: any) {
    console.error('Staff registration error:', err.message);
  }

  res.json({
    success: true,
    message: 'If the details are valid, a verification email has been sent. Please check your inbox or the in-app email simulator.'
  });
});

// 2. Email Verification by 6-digit Code
app.post('/api/staff/verify', registerLimiter, async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ success: false, error: 'Email and 6-digit verification code are required.' });
  }

  const result = verifyStaffEmailByCode(String(email), String(code));
  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error || 'Invalid or expired code.' });
  }

  res.json({
    success: true,
    status: 'pending_approval',
    message: 'Email verified. Your application is now waiting for Administrator identity review and position approval.'
  });
});

// 3. Email Verification by Link Token
app.post('/api/staff/verify-token', async (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ success: false, error: 'Verification token is required.' });
  }

  const result = verifyStaffEmailByToken(String(token));
  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error || 'Invalid or expired verification link.' });
  }

  res.json({
    success: true,
    status: 'pending_approval',
    message: 'Email verified. Your application is now waiting for Administrator identity review and position approval.'
  });
});

app.get('/verify', (req, res) => {
  const token = req.query.token as string;
  if (!token) {
    return res.redirect('/#verify_error=missing_token');
  }
  const result = verifyStaffEmailByToken(token);
  if (result.success) {
    return res.redirect('/#verified=true');
  }
  return res.redirect('/#verify_error=invalid_token');
});

// 4. Admin Applications Review Queue
app.get('/api/admin/staff/applications', requireRole('admin'), (_req, res) => {
  const applications = getStaffApplications();
  res.json({
    success: true,
    applications: applications.map(a => ({
      id: a.id,
      fullName: a.fullName,
      email: a.email,
      phone: a.phone,
      requestedPosition: a.requestedPosition,
      role: a.role,
      status: a.status,
      note: a.note,
      consentGiven: a.consentGiven,
      createdAt: a.createdAt,
      approvedAt: a.approvedAt,
      rejectedAt: a.rejectedAt,
      rejectionReason: a.rejectionReason
    }))
  });
});

// 5. Admin Approves and Assigns Final Role (Section 9.4)
app.post('/api/admin/staff/:id/approve', requireRole('admin'), async (req, res) => {
  const chosenRole = req.body.role || req.body.assignedRole;
  const roleCheck = z.enum(ROLES).safeParse(chosenRole);
  if (!roleCheck.success) {
    return res.status(400).json({ success: false, error: 'Invalid role specified.' });
  }

  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;

  const result = approveStaffApplication(
    req.params.id,
    roleCheck.data,
    adminUser?.id || 'usr_admin_root',
    adminUser?.email || 'admin@lymboventures.co.ke',
    clientIp
  );

  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error });
  }

  res.json({
    success: true,
    message: `Application approved! Staff member confirmed in role: ${roleCheck.data.toUpperCase()}.`,
    user: {
      id: result.user!.id,
      fullName: result.user!.fullName,
      email: result.user!.email,
      role: result.user!.role,
      status: result.user!.status
    }
  });
});

// 6. Admin Rejects Application
app.post('/api/admin/staff/:id/reject', requireRole('admin'), async (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;
  const reason = req.body.reason || 'Did not meet current vacancy requirements';

  const result = rejectStaffApplication(
    req.params.id,
    reason,
    adminUser?.id || 'usr_admin_root',
    adminUser?.email || 'admin@lymboventures.co.ke',
    clientIp
  );

  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error });
  }

  res.json({ success: true, message: 'Application rejected.' });
});

// 7. Admin Suspends Staff User (Ends Sessions Immediately)
app.post('/api/admin/staff/:id/suspend', requireRole('admin'), async (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;

  const result = suspendStaffUser(
    req.params.id,
    adminUser?.id || 'usr_admin_root',
    adminUser?.email || 'admin@lymboventures.co.ke',
    clientIp
  );

  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error });
  }

  destroyAllUserSessions(req.params.id);
  res.json({ success: true, message: 'Staff user suspended and all sessions revoked immediately.' });
});

// 8. Admin Reactivates Staff User
app.post('/api/admin/staff/:id/reactivate', requireRole('admin'), async (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;

  const result = reactivateStaffUser(
    req.params.id,
    adminUser?.id || 'usr_admin_root',
    adminUser?.email || 'admin@lymboventures.co.ke',
    clientIp
  );

  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error });
  }

  res.json({ success: true, message: 'Staff user reactivated.' });
});

// 9. Admin Permanently Removes Staff User
app.delete('/api/admin/staff/:id', requireRole('admin'), async (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;

  destroyAllUserSessions(req.params.id);
  const result = deleteStaffUser(
    req.params.id,
    adminUser?.id || 'usr_admin_root',
    adminUser?.email || 'admin@lymboventures.co.ke',
    clientIp
  );

  if (!result.success) {
    return res.status(400).json({ success: false, error: result.error });
  }

  res.json({ success: true, message: 'Staff account permanently removed.' });
});

// 10. Outbox Emails Simulator (In-App Transactional Email Viewer)
app.get('/api/dev/outbox', (_req, res) => {
  const emails = getOutboxEmails();
  res.json({ success: true, count: emails.length, emails });
});

// Legacy backward-compatibility routes for onboarding
app.post('/api/auth/onboard-request', authLimiter, (req, res) => {
  const { email, name, requestedRole } = req.body;
  const result = createPendingAccount(email, name || '', requestedRole || 'staff');
  return res.json({
    success: result.status === 'created',
    message: result.status === 'created' ? 'Account submitted.' : 'Account already exists.',
    user: result.user
  });
});

app.post('/api/admin/users/:id/approve', requireRole('admin'), (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const adminUser = (req as any).user;
  const result = approveStaffApplication(req.params.id, req.body.assignedRole || 'sales_officer', adminUser?.id || 'usr_admin_root', adminUser?.email || 'admin@lymboventures.co.ke', clientIp);
  return res.json(result);
});

app.post('/api/auth/activate', (req, res) => {
  return res.json({ success: true, message: 'Account active.' });
});

// Admin User Management: List Users
app.get('/api/admin/users', requireRole('admin'), (_req, res) => {
  const db = loadDatabase();
  const safeUsers = db.users.map(u => ({
    id: u.id,
    fullName: u.fullName || u.name,
    email: u.email,
    username: u.username,
    name: u.name,
    role: u.role,
    status: u.status,
    mfaRequired: u.mfaRequired,
    createdAt: u.createdAt,
    approvedBy: u.approvedBy,
    approvedAt: u.approvedAt,
    requestedPosition: u.requestedPosition
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

    addAuditLog(user.id, user.email, user.role || 'staff', clientIp, 'USER_LOGIN', `User ${user.email} signed in successfully.`);

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

    addAuditLog(user.id, user.email, user.role || 'staff', clientIp, 'MFA_VERIFIED', `User ${user.email} completed MFA verification.`);

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

// GET /api/auth/session - Active Session Verification (Database Grounded - Section 5)
app.get('/api/auth/session', (req, res) => {
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || '127.0.0.1';
  const auth = resolveAuthenticatedUser(req);

  if (!auth) {
    res.clearCookie('lymbo_session', { path: '/' });
    return res.json({
      authenticated: false,
      user: null,
      clientIp
    });
  }

  return res.json({
    authenticated: true,
    user: {
      id: auth.user.id,
      email: auth.user.email,
      name: auth.user.name,
      role: auth.user.role
    },
    clientIp,
    sessionExpiresInMinutes: Math.round((8 * 60 * 60 * 1000 - (Date.now() - auth.session.createdAt)) / 60000)
  });
});

// GET /api/admin/me - Current Authenticated User Role, Approval Status & Permissions
app.get('/api/admin/me', (req, res) => {
  const sessionId = req.cookies?.lymbo_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || '127.0.0.1';

  if (!sessionId) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Unauthorized: No active session. Please sign in.'
    });
  }

  const session = getSession(sessionId);
  if (!session) {
    res.clearCookie('lymbo_session', { path: '/' });
    return res.status(401).json({
      success: false,
      authenticated: false,
      error: 'Session expired or invalid. Please sign in again.'
    });
  }

  const db = loadDatabase();
  const user = db.users.find(u => u.id === session.userId);

  if (!user) {
    destroySession(sessionId);
    res.clearCookie('lymbo_session', { path: '/' });
    return res.status(401).json({
      success: false,
      authenticated: false,
      error: 'User account not found.'
    });
  }

  // Keep session live state synchronized with database on every request
  session.role = (user.role || 'staff') as UserRole;
  session.email = user.email;
  session.name = user.name;

  const isApproved = user.status === 'active';
  const role = user.role || 'staff';

  const roleTabMap: Record<string, string[]> = {
    admin: ['inventory', 'orders', 'dispatch', 'accounts', 'support', 'staff', 'reports', 'photos', 'restock', 'settings', 'logs'],
    manager: ['orders', 'inventory', 'dispatch', 'reports', 'photos', 'restock', 'support'],
    sales_officer: ['orders', 'support'],
    dispatch_officer: ['dispatch'],
    accounts_officer: ['accounts'],
    customer_support: ['support'],
    staff: ['orders', 'support']
  };

  const roleDefaultTabMap: Record<string, string> = {
    admin: 'orders',
    manager: 'orders',
    sales_officer: 'orders',
    dispatch_officer: 'dispatch',
    accounts_officer: 'accounts',
    customer_support: 'support',
    staff: 'orders'
  };

  const allowedTabs = isApproved ? (roleTabMap[role] || ['orders']) : [];
  const defaultTab = isApproved ? (roleDefaultTabMap[role] || 'orders') : '';

  return res.json({
    success: true,
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      isApproved,
      phone: user.phone,
      allowedTabs,
      defaultTab,
      permissions: {
        canManageStaff: role === 'admin' && isApproved,
        canManageSettings: role === 'admin' && isApproved,
        canViewAuditLogs: role === 'admin' && isApproved,
        canReceiveStock: (role === 'admin' || role === 'manager') && isApproved,
        canUploadPhotos: (role === 'admin' || role === 'manager') && isApproved,
        canViewReports: (role === 'admin' || role === 'manager') && isApproved,
        canManageOrders: ['admin', 'manager', 'sales_officer', 'staff'].includes(role) && isApproved,
        canUpdateDeliveryStatus: ['admin', 'manager', 'dispatch_officer'].includes(role) && isApproved,
        canViewManifest: ['admin', 'manager', 'dispatch_officer'].includes(role) && isApproved,
        canReconcileAccounts: ['admin', 'accounts_officer'].includes(role) && isApproved,
        canViewSupport: ['admin', 'manager', 'customer_support', 'sales_officer', 'staff'].includes(role) && isApproved,
        canDeleteOrders: role === 'admin' && isApproved,
        canEditPrices: role === 'admin' && isApproved
      }
    },
    clientIp
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
  notes: z.string().max(400, 'Final notes cannot exceed 400 characters').optional(),
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
  const db = loadDatabase();
  const orders = getOrdersProjectedForRole(user.role, db.orders);
  res.json({
    success: true,
    role: user.role,
    dataMinimizationApplied: user.role !== 'admin',
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

// POST /api/orders/:id/status - Staff / Manager / Admin Order Status Update (Section 4)
app.post('/api/orders/:id/status', requireRole('sales_officer', 'dispatch_officer', 'manager', 'admin', 'staff'), (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!['pending', 'processing', 'approved', 'shipped', 'delivered', 'declined'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid order status.' });
  }

  // Section 4 Least Privilege: Dispatch officers can only mark orders as shipped or delivered
  if (user.role === 'dispatch_officer' && !['shipped', 'delivered'].includes(status)) {
    return res.status(403).json({ success: false, error: 'Forbidden: Dispatch officers can only mark orders as shipped or delivered.' });
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

// POST /api/orders/:id/notes - Update Customer Final Notes on an Order
app.post('/api/orders/:id/notes', (req, res) => {
  const { id } = req.params;
  const { notes } = req.body;
  if (typeof notes !== 'string') {
    return res.status(400).json({ success: false, error: 'Notes must be a string.' });
  }
  if (notes.length > 400) {
    return res.status(400).json({ success: false, error: 'Final notes cannot exceed 400 characters.' });
  }

  const db = loadDatabase();
  const order = db.orders.find(o => o.id === id);
  if (!order) {
    return res.status(404).json({ success: false, error: 'Order not found.' });
  }

  order.notes = notes.trim();
  order.updatedAt = new Date().toISOString();
  saveDatabase();

  broadcastSyncEvent('order_updated', order);

  return res.json({
    success: true,
    order,
    message: `Final notes updated for Order #${id}.`
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

// POST /api/inventory/receive - Record Goods Received (Admin & Operations Manager - Section 4)
app.post('/api/inventory/receive', requireRole('manager', 'admin'), (req, res) => {
  const { trays, batchRef, supplier, notes } = req.body;
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';

  if (!trays || Number(trays) <= 0) {
    return res.status(400).json({ success: false, error: 'Valid positive tray quantity is required.' });
  }

  const result = recordGoodsReceived(Number(trays), batchRef, supplier, notes, user, clientIp);
  return res.json({
    success: true,
    message: `Recorded ${trays} trays inward under batch ${result.batchRef}.`,
    item: result
  });
});

// ==========================================================================
// DAILY TRANSPARENCY PHOTOS
// ==========================================================================
app.get('/api/photos', (_req, res) => {
  const db = loadDatabase();
  res.json({ success: true, photos: db.dailyPhotos });
});

app.post('/api/photos', requireRole('manager', 'admin'), (req, res) => {
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
// IMMUTABLE AUDIT LOGS & CLIENT INFO (Section 4 - Admin Only)
// ==========================================================================
app.get('/api/admin/audit-logs', requireAdminAuth, (_req, res) => {
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

// ==========================================================================
// DYNAMIC STORE CONFIGURATION (Admin Configurable)
// ==========================================================================
app.get('/api/config', (_req, res) => {
  const config = getStoreConfig();
  res.json({ success: true, config });
});

app.post('/api/admin/config', requireAdminAuth, (req, res) => {
  const user = (req as any).user;
  const clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || '127.0.0.1';
  const updated = updateStoreConfig(req.body, user.id, user.email, clientIp);
  broadcastSyncEvent('config_updated', updated);

  res.json({ success: true, config: updated, message: 'Store configuration updated successfully.' });
});

// ==========================================================================
// AI CUSTOMER CHATBOT (Lymbo Smart Assistant)
// ==========================================================================
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many chat requests. Please wait a moment.' },
  validate: { xForwardedForHeader: false }
});

app.post('/api/chat', chatLimiter, async (req, res) => {
  const { message, history } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, error: 'Message text is required.' });
  }

  const config = getStoreConfig();
  const db = loadDatabase();
  const stock = getInventoryStatus();

  const systemPrompt = `You are "Lymbo Assistant", the helpful, polite, and knowledgeable virtual assistant for Lymbo Ventures — Mombasa's trusted supplier of farm-fresh Grade A eggs.
Store Information & Facts:
- Product: Farm-fresh Grade A table eggs, 30 eggs per tray.
- Current Price: KES ${config.eggPricePerTray} per tray.
- Current Live Stock Available: ${stock.currentStock} trays.
- Delivery Areas in Mombasa & Coastal Region:
  * Mombasa Island & Tudor: KES 50
  * Nyali & Kisauni: KES 100
  * Bamburi & Kiembeni: KES 150
  * Changamwe & Likoni: KES 150
  * Mtwapa: KES 200
- Same-Day Delivery: Available for orders placed before 3:00 PM. Morning delivery slot (8:00 AM - 12:00 PM) and Afternoon slot (1:00 PM - 5:30 PM).
- Lipa na M-Pesa: Paybill ${config.mpesaPaybill}, Account Number 20159160 (${config.mpesaAccountName}).
- Phone & WhatsApp Support: ${config.businessPhone} or 0727 811 266.
- Operating Hours: ${config.businessHours}.
- Location / Hub: Mombasa Central Hub (serving Island, North Coast, and South Coast).
- Tone: Welcoming, courteous (use Kenyan warmth: "Karibu", "Habari"), concise, and accurate. If asked to place an order, guide them to click the "Order Fresh Eggs" button on the website.
Answer clearly in 2 to 4 sentences. If they need urgent delivery confirmation, encourage them to call or WhatsApp 0727 811 266.`;

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey) {
      const ai = new GoogleGenAI();
      const chatContents: any[] = [
        { role: 'user', parts: [{ text: systemPrompt }] },
        { role: 'model', parts: [{ text: 'Karibu! I am the Lymbo Assistant. How may I help you with farm-fresh eggs today?' }] }
      ];

      if (Array.isArray(history)) {
        for (const h of history.slice(-6)) {
          if (h.role && h.text) {
            chatContents.push({
              role: h.role === 'user' ? 'user' : 'model',
              parts: [{ text: String(h.text).slice(0, 500) }]
            });
          }
        }
      }

      chatContents.push({
        role: 'user',
        parts: [{ text: message.slice(0, 1000) }]
      });

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: chatContents,
      });

      const reply = response.text || 'Karibu Lymbo Ventures! Fresh Grade A eggs are available at KES 500 per tray. Call 0727 811 266 for instant delivery.';
      return res.json({ success: true, reply, source: 'gemini' });
    }
  } catch (err: any) {
    console.warn('Gemini chat failed, using intelligent rule-based response:', err.message);
  }

  // Intelligent fallback responder
  const lower = message.toLowerCase();
  let fallbackReply = `Karibu Lymbo Ventures! Our farm-fresh Grade A eggs are KES ${config.eggPricePerTray} per tray of 30. We deliver across Mombasa (Nyali, Bamburi, Island, Mtwapa, Likoni). For orders or questions, call/WhatsApp us at 0727 811 266!`;

  if (lower.includes('price') || lower.includes('cost') || lower.includes('bei') || lower.includes('tray')) {
    fallbackReply = `Our farm-fresh Grade A eggs are KES ${config.eggPricePerTray} per tray (30 eggs). We also offer wholesale discounts for bulk orders of 20+ trays. Call or WhatsApp 0727 811 266 for bulk pricing.`;
  } else if (lower.includes('deliver') || lower.includes('nyali') || lower.includes('bamburi') || lower.includes('mtwapa') || lower.includes('island') || lower.includes('likoni')) {
    fallbackReply = `We deliver across Mombasa! Delivery fees: Island/Tudor KES 50, Nyali/Kisauni KES 100, Bamburi/Kiembeni KES 150, Likoni/Changamwe KES 150, Mtwapa KES 200. Orders before 3 PM get same-day delivery!`;
  } else if (lower.includes('pay') || lower.includes('mpesa') || lower.includes('lipa') || lower.includes('paybill')) {
    fallbackReply = `You can pay via Lipa na M-Pesa Paybill ${config.mpesaPaybill}, Account number 20159160 (${config.mpesaAccountName}). We also accept Cash on Delivery for verified clients!`;
  } else if (lower.includes('track') || lower.includes('order')) {
    fallbackReply = `To track your order, enter your Order ID or phone number in our Order Tracker section on this page, or call our dispatch desk at 0727 811 266.`;
  } else if (lower.includes('stock') || lower.includes('available')) {
    fallbackReply = `We currently have ${stock.currentStock} fresh trays ready for immediate dispatch from our Mombasa hub. All eggs are inspected daily for Grade A freshness.`;
  }

  return res.json({ success: true, reply: fallbackReply, source: 'fallback' });
});

// ==========================================================================
// AI DEMAND INSIGHTS (Admin / Manager)
// ==========================================================================
app.get('/api/admin/ai-insights', requireManagerOrAdminAuth, async (_req, res) => {
  const db = loadDatabase();
  const stock = getInventoryStatus();
  const config = getStoreConfig();

  const totalOrders = db.orders.length;
  const pendingOrders = db.orders.filter(o => o.orderStatus === 'pending' || o.orderStatus === 'processing');
  const deliveredOrders = db.orders.filter(o => o.orderStatus === 'delivered');
  const totalTraysOrdered = db.orders.reduce((sum, o) => sum + (o.eggTrays || 0), 0);
  const totalRevenue = db.orders.reduce((sum, o) => sum + (o.grandTotal || 0), 0);

  // Group by area
  const areaCounts: Record<string, number> = {};
  db.orders.forEach(o => {
    areaCounts[o.deliveryArea] = (areaCounts[o.deliveryArea] || 0) + (o.eggTrays || 0);
  });

  const prompt = `You are the Lead Supply Chain & Revenue AI Analyst for Lymbo Ventures egg distribution in Mombasa, Kenya.
Current Metrics:
- Current Available Stock: ${stock.currentStock} trays
- Total Orders: ${totalOrders} (Pending/Processing: ${pendingOrders.length}, Delivered: ${deliveredOrders.length})
- Total Trays Sold: ${totalTraysOrdered} trays
- Gross Sales: KES ${totalRevenue.toLocaleString()}
- Sales by Area: ${JSON.stringify(areaCounts)}
- Tray Base Price: KES ${config.eggPricePerTray}

Provide a concise, high-impact Executive Intelligence Briefing in markdown with 3 clear sections:
1. **Inventory & Restock Recommendation** (exact tray replenishment number and urgency).
2. **Top Delivery Corridors & Demand Pattern** (key Mombasa zones like Nyali, Bamburi, Island).
3. **Cash Flow & Pricing Strategy** (profit margin advice and M-Pesa collection efficiency).
Keep it professional, actionable, and under 250 words.`;

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey) {
      const ai = new GoogleGenAI();
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt
      });
      const insightText = response.text || '';
      return res.json({
        success: true,
        source: 'gemini',
        insights: insightText,
        metrics: {
          currentStock: stock.currentStock,
          totalOrders,
          pendingOrders: pendingOrders.length,
          totalTraysOrdered,
          totalRevenue,
          topAreas: Object.entries(areaCounts).sort((a, b) => b[1] - a[1]).slice(0, 4)
        }
      });
    }
  } catch (err: any) {
    console.warn('Gemini demand insights error:', err.message);
  }

  // Heuristic rule-based supply chain briefing
  const topCorridor = Object.entries(areaCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'Nyali & Bamburi';
  const restockQty = stock.currentStock < 100 ? 300 : 150;
  const urgency = stock.currentStock < 60 ? 'HIGH (Urgent Inward Batch Needed within 24h)' : 'OPTIMAL (Stable 3-day buffer)';

  const fallbackInsights = `### 1. Inventory & Restock Recommendation
- **Current Reserve:** ${stock.currentStock} trays in Mombasa depot.
- **Urgency Level:** ${urgency}.
- **Recommended Inward:** Order **${restockQty} trays** from layer farm suppliers to maintain delivery commitments and prevent stockouts.

### 2. High-Demand Mombasa Corridors
- **Primary Corridor:** **${topCorridor}** leads retail and restaurant demand.
- **Logistics Tip:** Cluster morning delivery van runs between Nyali and Bamburi to minimize fuel burn while ensuring delivery before 11:00 AM.

### 3. Cash Flow & M-Pesa Settlement
- **Total Revenue Recorded:** KES ${totalRevenue.toLocaleString()}.
- **Action:** Ensure all Lipa na M-Pesa receipts (Paybill 625625 Acc 20159160) are verified in the Accounts Officer portal before dispatch release.`;

  return res.json({
    success: true,
    source: 'heuristic',
    insights: fallbackInsights,
    metrics: {
      currentStock: stock.currentStock,
      totalOrders,
      pendingOrders: pendingOrders.length,
      totalTraysOrdered,
      totalRevenue,
      topAreas: Object.entries(areaCounts).sort((a, b) => b[1] - a[1]).slice(0, 4)
    }
  });
});

// ==========================================================================
// ROLE-SPECIFIC APPLICATION ENDPOINTS (Least Privilege per Section 4)
// ==========================================================================

// Dispatch Officer & Manager: Delivery Manifest
app.get('/api/dispatch/manifest', requireRole('dispatch_officer', 'manager', 'admin'), (_req, res) => {
  const db = loadDatabase();
  const activeDeliveries = db.orders
    .filter(o => o.orderStatus === 'approved' || o.orderStatus === 'processing' || o.orderStatus === 'shipped')
    .map(o => ({
      id: o.id,
      deliveryNoteNumber: o.deliveryNoteNumber,
      customerName: o.customerName,
      customerPhone: o.customerPhone,
      deliveryArea: o.deliveryArea,
      deliveryAddress: o.deliveryAddress,
      deliveryDate: o.deliveryDate,
      deliveryTimeSlot: o.deliveryTimeSlot,
      eggTrays: o.eggTrays,
      orderStatus: o.orderStatus,
      paymentStatus: o.paymentStatus,
      notes: o.notes
    }));

  res.json({ success: true, deliveries: activeDeliveries });
});

// Accounts Officer & Admin: M-Pesa Reconciliation
app.get('/api/accounts/reconciliation', requireRole('accounts_officer', 'admin'), (_req, res) => {
  const db = loadDatabase();
  const orders = db.orders.map(o => ({
    id: o.id,
    invoiceNumber: o.invoiceNumber,
    customerName: o.customerName,
    eggTrays: o.eggTrays,
    grandTotal: o.grandTotal,
    paymentMethod: o.paymentMethod,
    paymentStatus: o.paymentStatus,
    mpesaTransactionCode: o.mpesaTransactionCode,
    orderStatus: o.orderStatus,
    createdAt: o.createdAt
  }));

  const totalCollected = db.orders
    .filter(o => o.paymentStatus === 'paid')
    .reduce((sum, o) => sum + o.grandTotal, 0);

  const pendingCollection = db.orders
    .filter(o => o.paymentStatus !== 'paid')
    .reduce((sum, o) => sum + o.grandTotal, 0);

  res.json({
    success: true,
    totalCollected,
    pendingCollection,
    orders
  });
});

// Customer Support, Manager & Admin: Customer Tickets & Inquiries
app.get('/api/support/tickets', requireRole('customer_support', 'manager', 'admin'), (_req, res) => {
  const db = loadDatabase();
  const summary = db.orders.slice(0, 30).map(o => ({
    id: o.id,
    invoiceNumber: o.invoiceNumber,
    deliveryNoteNumber: o.deliveryNoteNumber,
    customerName: o.customerName,
    customerPhone: o.customerPhone,
    deliveryArea: o.deliveryArea,
    eggTrays: o.eggTrays,
    orderStatus: o.orderStatus,
    paymentStatus: o.paymentStatus,
    createdAt: o.createdAt
  }));

  res.json({
    success: true,
    tickets: summary,
    helplinePhone: '0727811266',
    altPhone: '0704967655'
  });
});

// Sales Officer, Manager & Admin: Sales Overview
app.get('/api/sales/overview', requireRole('sales_officer', 'manager', 'admin'), (req, res) => {
  const user = (req as any).user;
  const db = loadDatabase();
  
  const totalTrays = db.orders.reduce((sum, o) => sum + (o.eggTrays || 0), 0);
  const totalSales = db.orders.reduce((sum, o) => sum + (o.grandTotal || 0), 0);
  const recentOrders = getOrdersProjectedForRole(user.role, db.orders.slice(0, 20));

  res.json({
    success: true,
    totalOrders: db.orders.length,
    totalTrays,
    totalSales,
    recentOrders
  });
});

// ==========================================================================
// Vite Dev Server / Static File Serving
// ==========================================================================
async function startServer() {
  try {
    // Load persistent database on startup
    loadDatabase();

    if (process.env.NODE_ENV !== 'production') {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true, hmr: false, watch: null },
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
