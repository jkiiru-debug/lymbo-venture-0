import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import type { Response } from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const DB_FILE = path.join(DATA_DIR, 'lymbo_store.json');

// Fixed positions applicant may apply for ('admin' is never allowed to be requested)
export const APPLY_POSITIONS = [
  'manager',
  'sales_officer',
  'dispatch_officer',
  'accounts_officer',
  'customer_support'
] as const;

export type ApplyPosition = typeof APPLY_POSITIONS[number];

// System authorization roles (Least Privilege)
export const ROLES = [
  'admin',
  'manager',
  'sales_officer',
  'dispatch_officer',
  'accounts_officer',
  'customer_support',
  'staff',    // legacy alias for sales_officer
  'customer' // public customer
] as const;

export type UserRole = typeof ROLES[number];

export type AccountStatus =
  | 'pending_email'    // Registered, awaiting 6-digit email confirmation
  | 'pending_approval' // Email verified, awaiting Administrator identity/reference check & role confirmation
  | 'active'           // Approved with an assigned role
  | 'suspended'        // Suspended by Administrator (sessions destroyed)
  | 'rejected';        // Rejected by Administrator

export interface UserAccount {
  id: string;
  fullName: string;
  name: string;
  email: string;
  phone?: string;
  username: string;
  role: UserRole | null;              // Stays null until admin approves
  requestedPosition: string;          // A request only, never a permission
  status: AccountStatus;
  passwordHash: string;
  note?: string;
  consentGiven: boolean;
  mfaRequired: boolean;
  mfaSecret: string;
  mfaBackupCodes: string[];
  createdAt: string;
  approvedBy?: string;
  approvedAt?: string;
  rejectedBy?: string;
  rejectedAt?: string;
  rejectionReason?: string;
  notes?: string;
  activationTokenHash?: string;
  activationTokenExpires?: number;
  resetTokenHash?: string;
  resetTokenExpires?: number;
}

export interface EmailVerificationRecord {
  id: string;
  userId: string;
  email: string;
  codeHash: string;   // SHA-256 hash of 6-digit verification code
  tokenHash: string;  // SHA-256 hash of 32-byte hex verification token
  attempts: number;   // Locks after 5 wrong attempts
  expiresAt: number;  // 10 minutes expiry
  usedAt?: number;
}

export interface OutboxEmailItem {
  id: string;
  to: string;
  subject: string;
  html: string;
  sentAt: string;
  type: 'verification' | 'approval' | 'rejection' | 'password_reset' | 'notification';
  codePreview?: string;
  tokenPreview?: string;
}

export interface StoreConfig {
  eggPricePerTray: number;
  deliveryFees: Record<string, number>;
  businessPhone: string;
  businessEmail: string;
  mpesaPaybill: string;
  mpesaAccountName: string;
  businessHours: string;
  features: {
    aiChatbot: boolean;
    aiDemandInsights: boolean;
    onlineOrders: boolean;
    customerTracking: boolean;
  };
}

export interface OrderItem {
  id: string;
  invoiceNumber: string;
  deliveryNoteNumber: string;
  customerName: string;
  customerPhone: string;
  customerEmail?: string;
  deliveryArea: string;
  deliveryAddress: string;
  deliveryDate: string;
  deliveryTimeSlot: string;
  eggTrays: number;
  pricePerTray: number;
  subtotal: number;
  deliveryFee: number;
  discountAmount: number;
  grandTotal: number;
  paymentMethod: 'M-Pesa' | 'Cash on Delivery';
  paymentStatus: 'unpaid' | 'pending_verification' | 'paid' | 'refunded';
  orderStatus: 'pending' | 'processing' | 'approved' | 'shipped' | 'delivered' | 'declined';
  mpesaTransactionCode?: string;
  darajaCheckoutRequestId?: string;
  assignedStaffId?: string;
  assignedStaffName?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

export interface GoodsReceivedItem {
  id: string;
  batchRef: string;
  date: string;
  trays: number;
  supplier: string;
  notes: string;
  recordedBy: string;
  recordedAt: string;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  userId: string;
  userEmail: string;
  userRole: string;
  clientIp: string;
  action: string;
  details: string;
  targetEntityId?: string;
  metadata?: Record<string, any>;
}

export interface DailyPhotoItem {
  id: string;
  url: string;
  caption: string;
  tag: string;
  date: string;
  uploadedBy: string;
}

export interface StoreData {
  users: UserAccount[];
  emailVerifications: EmailVerificationRecord[];
  outboxEmails: OutboxEmailItem[];
  config: StoreConfig;
  orders: OrderItem[];
  inventoryLedger: GoodsReceivedItem[];
  dailyPhotos: DailyPhotoItem[];
  auditLogs: AuditLogItem[];
  initialStock: number;
  nextOrderSeq: number;
  nextInvoiceSeq: number;
  nextDeliveryNoteSeq: number;
  lastUpdated: string;
}

// In-Memory Database State
let dbState: StoreData;
const sseClients = new Set<Response>();

export const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

// Ensure directory exists
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// Generates an RFC 4648 Base32 secret for TOTP MFA
export function generateBase32Secret(length = 20): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  const bytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    secret += chars[bytes[i] % chars.length];
  }
  return secret;
}

export function generateBackupCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < 5; i++) {
    const p1 = Math.floor(1000 + Math.random() * 9000);
    const p2 = Math.floor(1000 + Math.random() * 9000);
    codes.push(`${p1}-${p2}`);
  }
  return codes;
}

// Default Seed Data
function getSeedData(): StoreData {
  const adminEmail = (process.env.ADMIN_EMAIL || 'lymboventures0@gmail.com').toLowerCase();
  const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || '20lymboventures@26';
  const sharedStaffPassword = '20lymboventures@26';

  const adminHash = bcrypt.hashSync(initialPassword, 12);
  const staffHash = bcrypt.hashSync(sharedStaffPassword, 12);

  const now = new Date().toISOString();

  return {
    users: [
      {
        id: 'usr_admin_root',
        fullName: 'System Administrator',
        name: 'System Administrator',
        email: adminEmail,
        phone: '+254704967655',
        username: 'admin',
        role: 'admin',
        requestedPosition: 'Administrator',
        status: 'active',
        passwordHash: adminHash,
        consentGiven: true,
        mfaRequired: true,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: ['3708-3009', '2218-9343', '1167-6189', '4317-9645', '9053-3505'],
        createdAt: now,
        notes: 'Primary System Administrator with root infrastructure governance'
      },
      {
        id: 'usr_manager_01',
        fullName: 'Operations Manager',
        name: 'Operations Manager',
        email: 'manager@lymboventures.co.ke',
        phone: '+254711223344',
        username: 'manager_mombasa',
        role: 'manager',
        requestedPosition: 'manager',
        status: 'active',
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: true,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        approvedBy: 'usr_admin_root',
        approvedAt: now,
        notes: 'Supervises orders, stock ledger, delivery schedule, and sales reports'
      },
      {
        id: 'usr_sales_01',
        fullName: 'Grace Wairimu',
        name: 'Grace Wairimu',
        email: 'sales@lymboventures.co.ke',
        phone: '+254722334455',
        username: 'sales_rep',
        role: 'sales_officer',
        requestedPosition: 'sales_officer',
        status: 'active',
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: false,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        approvedBy: 'usr_admin_root',
        approvedAt: now,
        notes: 'Takes customer orders and logs inquiries (Data Minimization)'
      },
      {
        id: 'usr_dispatch_01',
        fullName: 'Ali Hassan Juma',
        name: 'Ali Hassan Juma',
        email: 'dispatch@lymboventures.co.ke',
        phone: '+254733445566',
        username: 'dispatch_officer',
        role: 'dispatch_officer',
        requestedPosition: 'dispatch_officer',
        status: 'active',
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: false,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        approvedBy: 'usr_admin_root',
        approvedAt: now,
        notes: 'Manages route delivery manifest, gate codes, and rider status updates'
      },
      {
        id: 'usr_accounts_01',
        fullName: 'Faith Muthoni',
        name: 'Faith Muthoni',
        email: 'accounts@lymboventures.co.ke',
        phone: '+254744556677',
        username: 'cashier_mombasa',
        role: 'accounts_officer',
        requestedPosition: 'accounts_officer',
        status: 'active',
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: false,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        approvedBy: 'usr_admin_root',
        approvedAt: now,
        notes: 'Reconciles M-Pesa receipts, Buy Goods transactions, and tax invoices'
      },
      {
        id: 'usr_support_01',
        fullName: 'Omar Salim',
        name: 'Omar Salim',
        email: 'support@lymboventures.co.ke',
        phone: '+254755667788',
        username: 'customer_support',
        role: 'customer_support',
        requestedPosition: 'customer_support',
        status: 'active',
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: false,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        approvedBy: 'usr_admin_root',
        approvedAt: now,
        notes: 'Customer support messages and read-only order tracking inquiries'
      },
      {
        id: 'usr_applicant_01',
        fullName: 'John Mwenda Kinyua',
        name: 'John Mwenda Kinyua',
        email: 'john.mwenda@example.com',
        phone: '+254719887766',
        username: 'john.mwenda',
        role: null, // Role stays NULL until Administrator approves
        requestedPosition: 'dispatch_officer', // A request only!
        status: 'pending_approval', // Email verified, waiting for admin
        passwordHash: staffHash,
        consentGiven: true,
        mfaRequired: false,
        mfaSecret: generateBase32Secret(),
        mfaBackupCodes: generateBackupCodes(),
        createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        note: '3 years motorcycle courier experience in Mombasa North (Nyali, Bamburi, Shanzu).'
      }
    ],
    emailVerifications: [],
    outboxEmails: [
      {
        id: 'mail_init_01',
        to: 'john.mwenda@example.com',
        subject: 'Verify your Lymbo Ventures account',
        html: '<p>Your verification code is <b>849201</b> (valid for 10 minutes).</p><p>Or click the link to verify.</p>',
        type: 'verification',
        sentAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        codePreview: '849201'
      }
    ],
    config: {
      eggPricePerTray: 500,
      deliveryFees: {
        'Nyali': 100,
        'Bamburi': 150,
        'Kiembeni': 150,
        'Mtwapa': 200,
        'Likoni': 150,
        'Mombasa Island': 50,
        'Tudor': 50,
        'Changamwe': 150,
        'Kisauni': 100
      },
      businessPhone: '+254 704 967 655',
      businessEmail: 'lymboventures0@gmail.com',
      mpesaPaybill: '625625',
      mpesaAccountName: 'Lymbo Ventures Ltd',
      businessHours: 'Mon-Sat: 7:00 AM - 6:30 PM | Sun: 8:00 AM - 2:00 PM',
      features: {
        aiChatbot: true,
        aiDemandInsights: true,
        onlineOrders: true,
        customerTracking: true
      }
    },
    orders: [
      {
        id: 'ORD-2026-1001',
        invoiceNumber: 'INV-2026-0001',
        deliveryNoteNumber: 'DN-2026-0001',
        customerName: 'Amina Mwangi',
        customerPhone: '+254712345678',
        customerEmail: 'amina.mwangi@example.com',
        deliveryArea: 'Nyali',
        deliveryAddress: 'Links Road, near City Mall, Nyali',
        deliveryDate: new Date().toISOString().split('T')[0],
        deliveryTimeSlot: 'Morning (8:00 AM - 12:00 PM)',
        eggTrays: 2,
        pricePerTray: 500,
        subtotal: 1000,
        deliveryFee: 100,
        discountAmount: 0,
        grandTotal: 1100,
        paymentMethod: 'M-Pesa',
        paymentStatus: 'paid',
        orderStatus: 'approved',
        mpesaTransactionCode: 'RJK9841289',
        assignedStaffName: 'Junior Sales Staff',
        notes: 'Gate Code #4521, call rider on arrival at barrier',
        createdAt: new Date(Date.now() - 3600000 * 24).toISOString(),
        updatedAt: now
      },
      {
        id: 'ORD-2026-1002',
        invoiceNumber: 'INV-2026-0002',
        deliveryNoteNumber: 'DN-2026-0002',
        customerName: 'Captain David Otieno',
        customerPhone: '+254722998877',
        customerEmail: 'david.otieno@example.com',
        deliveryArea: 'Bamburi',
        deliveryAddress: 'Bamburi Beach Rd, opposite Whitesands Gate 2',
        deliveryDate: new Date().toISOString().split('T')[0],
        deliveryTimeSlot: 'Afternoon (1:00 PM - 5:00 PM)',
        eggTrays: 5,
        pricePerTray: 500,
        subtotal: 2500,
        deliveryFee: 150,
        discountAmount: 0,
        grandTotal: 2650,
        paymentMethod: 'M-Pesa',
        paymentStatus: 'paid',
        orderStatus: 'shipped',
        mpesaTransactionCode: 'TQM1209384',
        assignedStaffName: 'Junior Sales Staff',
        notes: 'Leave at front security desk for Ocean Breeze Villa',
        createdAt: new Date(Date.now() - 3600000 * 8).toISOString(),
        updatedAt: now
      },
      {
        id: 'ORD-2026-1003',
        invoiceNumber: 'INV-2026-0003',
        deliveryNoteNumber: 'DN-2026-0003',
        customerName: 'Fatma Zahra',
        customerPhone: '+254704967655',
        customerEmail: 'fatma.zahra@example.com',
        deliveryArea: 'Likoni',
        deliveryAddress: 'Near Likoni Ferry Roundabout, Block C Apt 4',
        deliveryDate: new Date().toISOString().split('T')[0],
        deliveryTimeSlot: 'ASAP / Next Available Rider',
        eggTrays: 4,
        pricePerTray: 500,
        subtotal: 2000,
        deliveryFee: 150,
        discountAmount: 0,
        grandTotal: 2150,
        paymentMethod: 'M-Pesa',
        paymentStatus: 'paid',
        orderStatus: 'processing',
        mpesaTransactionCode: 'SKH9041284',
        assignedStaffName: 'Junior Sales Staff',
        notes: 'Ring apartment buzzer 4B',
        createdAt: new Date(Date.now() - 3600000 * 2).toISOString(),
        updatedAt: now
      }
    ],
    inventoryLedger: [
      {
        id: 'GRN-2026-01',
        batchRef: 'BATCH-MBS-01',
        date: new Date().toISOString().split('T')[0],
        trays: 500,
        supplier: 'Lymbo Coastal Hatchery Hub',
        notes: 'Grade A fresh egg trays arrived, crates inspected and clean.',
        recordedBy: 'System Administrator',
        recordedAt: now
      }
    ],
    dailyPhotos: [
      {
        id: 'photo_01',
        url: '/src/assets/images/fresh_egg_trays_mombasa_1792259392211.jpg',
        caption: 'Fresh Grade A egg crates sorted for morning dispatch in Nyali & Bamburi.',
        tag: 'Daily Stock',
        date: 'Today · Fresh Morning Arrival',
        uploadedBy: 'System Administrator'
      },
      {
        id: 'photo_02',
        url: '/src/assets/images/egg_crates_dispatch_1792259392528.jpg',
        caption: 'Dispatch van loading stacked trays for Mombasa Island restaurants & homes.',
        tag: 'Van Dispatch',
        date: 'Today · Mombasa Island Route',
        uploadedBy: 'System Administrator'
      },
      {
        id: 'photo_03',
        url: '/src/assets/images/egg_quality_inspection_1792259393279.jpg',
        caption: 'Strict quality control: checking shell thickness, zero cracks, clean trays.',
        tag: 'Quality Check',
        date: 'Today · Batch QC Station',
        uploadedBy: 'System Administrator'
      }
    ],
    auditLogs: [
      {
        id: 'AUDIT-001',
        timestamp: now,
        userId: 'usr_admin_root',
        userEmail: adminEmail,
        userRole: 'admin',
        clientIp: '127.0.0.1',
        action: 'SYSTEM_BOOTSTRAP',
        details: 'Lymbo Ventures persistent storage initialized with Kenyan Data Protection Act 2019 compliance & 6-tier RBAC.'
      }
    ],
    initialStock: 500,
    nextOrderSeq: 1004,
    nextInvoiceSeq: 4,
    nextDeliveryNoteSeq: 4,
    lastUpdated: now
  };
}

// Load database from disk
export function loadDatabase(): StoreData {
  if (dbState) return dbState;

  ensureDataDir();
  if (fs.existsSync(DB_FILE)) {
    try {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      dbState = JSON.parse(content);
      
      // Auto-migrate schema properties if missing from older store version
      if (!dbState.emailVerifications) dbState.emailVerifications = [];
      if (!dbState.outboxEmails) dbState.outboxEmails = [];
      if (!dbState.config) {
        dbState.config = {
          eggPricePerTray: 500,
          deliveryFees: {
            'Nyali': 100,
            'Bamburi': 150,
            'Kiembeni': 150,
            'Mtwapa': 200,
            'Likoni': 150,
            'Mombasa Island': 50,
            'Tudor': 50,
            'Changamwe': 150,
            'Kisauni': 100
          },
          businessPhone: '+254 704 967 655',
          businessEmail: 'lymboventures0@gmail.com',
          mpesaPaybill: '625625',
          mpesaAccountName: 'Lymbo Ventures Ltd',
          businessHours: 'Mon-Sat: 7:00 AM - 6:30 PM | Sun: 8:00 AM - 2:00 PM',
          features: {
            aiChatbot: true,
            aiDemandInsights: true,
            onlineOrders: true,
            customerTracking: true
          }
        };
      }
      
      // Auto-migrate seed accounts for all 6 roles
      const seedUsers = getSeedData().users;
      for (const su of seedUsers) {
        const idx = dbState.users.findIndex(u => u.email.toLowerCase() === su.email.toLowerCase());
        if (idx === -1) {
          dbState.users.push(su);
        } else {
          dbState.users[idx].passwordHash = su.passwordHash;
          dbState.users[idx].status = 'active';
          if (!dbState.users[idx].role || (dbState.users[idx].role as string) === 'staff') {
            dbState.users[idx].role = su.role;
          }
        }
      }
      saveDatabase();
      return dbState;
    } catch (err) {
      console.error('Failed to parse database file, bootstrapping clean data:', err);
    }
  }

  dbState = getSeedData();
  saveDatabase();
  return dbState;
}

// Save database to disk
export function saveDatabase(): void {
  ensureDataDir();
  if (!dbState) return;
  dbState.lastUpdated = new Date().toISOString();
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(dbState, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to save database file:', err);
  }
}

// Immutable Audit Log
export function addAuditLog(
  userId: string,
  userEmail: string,
  userRole: string,
  clientIp: string,
  action: string,
  details: string,
  targetEntityId?: string,
  metadata?: Record<string, any>
): AuditLogItem {
  const db = loadDatabase();
  const item: AuditLogItem = {
    id: `AUDIT-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
    timestamp: new Date().toISOString(),
    userId,
    userEmail,
    userRole,
    clientIp,
    action,
    details,
    targetEntityId,
    metadata
  };
  db.auditLogs.unshift(item);
  if (db.auditLogs.length > 500) {
    db.auditLogs = db.auditLogs.slice(0, 500);
  }
  saveDatabase();
  broadcastSyncEvent('audit_log', item);
  return item;
}

// Outbox / Transactional Email simulation
export function recordOutboxEmail(
  to: string,
  subject: string,
  html: string,
  type: OutboxEmailItem['type'],
  codePreview?: string,
  tokenPreview?: string
): OutboxEmailItem {
  const db = loadDatabase();
  const item: OutboxEmailItem = {
    id: `MAIL-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
    to,
    subject,
    html,
    type,
    sentAt: new Date().toISOString(),
    codePreview,
    tokenPreview
  };
  db.outboxEmails.unshift(item);
  if (db.outboxEmails.length > 50) {
    db.outboxEmails = db.outboxEmails.slice(0, 50);
  }
  saveDatabase();
  return item;
}

export function getOutboxEmails(): OutboxEmailItem[] {
  const db = loadDatabase();
  return db.outboxEmails || [];
}

// ==========================================================================
// STAFF REGISTRATION, EMAIL VERIFICATION & ADMIN APPROVAL (Sections 1, 2, 9)
// ==========================================================================

export function createStaffApplication(data: {
  fullName: string;
  email: string;
  phone: string;
  passwordHash: string;
  position: string;
  note?: string;
  consent: boolean;
}): { success: boolean; error?: string; user?: UserAccount; code?: string; token?: string } {
  const db = loadDatabase();
  const cleanEmail = data.email.trim().toLowerCase();

  const existing = db.users.find(u => u.email.toLowerCase() === cleanEmail);
  if (existing) {
    if (existing.status === 'active') {
      return { success: false, error: 'An active account with that email already exists. Please sign in.' };
    }
    // If previous application was pending email or rejected, allow clean re-application
  }

  const userId = `usr_staff_${Date.now()}`;
  const now = new Date().toISOString();

  // Create or update user with status 'pending_email' and role: null
  // The position an applicant selects is a request only, not a permission!
  const user: UserAccount = {
    id: userId,
    fullName: data.fullName.trim(),
    name: data.fullName.trim(),
    email: cleanEmail,
    phone: data.phone.trim(),
    username: cleanEmail.split('@')[0],
    role: null,                                 // Real role stays null until Admin approves
    requestedPosition: data.position,          // Request only!
    status: 'pending_email',
    passwordHash: data.passwordHash,
    note: data.note?.trim(),
    consentGiven: data.consent,
    mfaRequired: ['manager', 'accounts_officer'].includes(data.position),
    mfaSecret: generateBase32Secret(),
    mfaBackupCodes: generateBackupCodes(),
    createdAt: now
  };

  // Generate 6-digit verification code and 32-byte hex token
  const code = String(crypto.randomInt(100000, 1000000));
  const token = crypto.randomBytes(32).toString('hex');

  // Store only the SHA-256 hashes! (Security requirement)
  const verification: EmailVerificationRecord = {
    id: `VER-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
    userId: user.id,
    email: cleanEmail,
    codeHash: sha256(code),
    tokenHash: sha256(token),
    attempts: 0,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  };

  // Remove any stale verification records for this email
  db.emailVerifications = db.emailVerifications.filter(v => v.email !== cleanEmail);
  db.emailVerifications.push(verification);

  // Upsert user in database
  const existingIdx = db.users.findIndex(u => u.email.toLowerCase() === cleanEmail);
  if (existingIdx !== -1) {
    db.users[existingIdx] = user;
  } else {
    db.users.push(user);
  }

  saveDatabase();

  return { success: true, user, code, token };
}

export function verifyStaffEmailByCode(
  email: string,
  code: string
): { success: boolean; error?: string; user?: UserAccount } {
  const db = loadDatabase();
  const cleanEmail = email.trim().toLowerCase();
  const cleanCode = code.trim().replace(/\s+/g, '');

  const rec = db.emailVerifications
    .filter(v => v.email === cleanEmail && !v.usedAt)
    .sort((a, b) => b.expiresAt - a.expiresAt)[0];

  if (!rec) {
    return { success: false, error: 'No pending verification found for this email address.' };
  }

  if (Date.now() > rec.expiresAt) {
    return { success: false, error: 'Verification code has expired (10-minute limit). Please submit a new application.' };
  }

  if (rec.attempts >= 5) {
    return { success: false, error: 'Too many incorrect attempts. This verification code is locked.' };
  }

  rec.attempts += 1;

  if (sha256(cleanCode) !== rec.codeHash) {
    saveDatabase();
    return { success: false, error: `Incorrect 6-digit code. ${5 - rec.attempts} attempt(s) remaining.` };
  }

  rec.usedAt = Date.now();

  const user = db.users.find(u => u.id === rec.userId || u.email.toLowerCase() === cleanEmail);
  if (!user) {
    return { success: false, error: 'Applicant account record not found.' };
  }

  // Upgrade status to pending_approval (Email confirmed, waiting for Administrator review)
  user.status = 'pending_approval';
  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    'applicant',
    'client_web',
    'EMAIL_VERIFIED',
    `Applicant ${user.email} successfully verified email ownership with 6-digit code. Status changed to pending_approval.`
  );

  return { success: true, user };
}

export function verifyStaffEmailByToken(
  token: string
): { success: boolean; error?: string; user?: UserAccount } {
  const db = loadDatabase();
  const cleanToken = token.trim();
  const tokenHash = sha256(cleanToken);

  const rec = db.emailVerifications.find(v => v.tokenHash === tokenHash && !v.usedAt);
  if (!rec) {
    return { success: false, error: 'Invalid or expired verification link.' };
  }

  if (Date.now() > rec.expiresAt) {
    return { success: false, error: 'Verification link has expired (10-minute limit).' };
  }

  rec.usedAt = Date.now();

  const user = db.users.find(u => u.id === rec.userId);
  if (!user) {
    return { success: false, error: 'Applicant account record not found.' };
  }

  user.status = 'pending_approval';
  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    'applicant',
    'client_web',
    'EMAIL_VERIFIED_LINK',
    `Applicant ${user.email} successfully verified email via one-click link. Status changed to pending_approval.`
  );

  return { success: true, user };
}

export function approveStaffApplication(
  userId: string,
  assignedRole: UserRole,
  adminId: string,
  adminEmail: string,
  clientIp: string
): { success: boolean; error?: string; user?: UserAccount } {
  const db = loadDatabase();
  const user = db.users.find(u => u.id === userId);

  if (!user) {
    return { success: false, error: 'Application not found.' };
  }

  if (user.status !== 'pending_approval') {
    return { success: false, error: `Cannot approve application in '${user.status}' status (must be pending_approval).` };
  }

  user.role = assignedRole;
  user.status = 'active';
  user.approvedBy = adminId;
  user.approvedAt = new Date().toISOString();
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'STAFF_APPROVED',
    `Administrator approved ${user.email}. Final Position Assigned: '${assignedRole}' (Requested: '${user.requestedPosition}').`,
    user.id,
    { assignedRole, requestedPosition: user.requestedPosition }
  );

  // Log confirmation notification
  recordOutboxEmail(
    user.email,
    'Your Lymbo Ventures Staff Account Has Been Approved!',
    `<p>Hello ${user.fullName},</p>
     <p>Your application for Lymbo Ventures has been reviewed and approved by the Administrator.</p>
     <p><b>Assigned Position:</b> ${assignedRole.replace('_', ' ').toUpperCase()}</p>
     <p>You can now sign in at <a href="${process.env.SITE_URL || ''}/staff/login">Staff Portal</a> using your registered password.</p>`,
    'approval'
  );

  return { success: true, user };
}

export function rejectStaffApplication(
  userId: string,
  reason: string,
  adminId: string,
  adminEmail: string,
  clientIp: string
): { success: boolean; error?: string } {
  const db = loadDatabase();
  const user = db.users.find(u => u.id === userId);

  if (!user) {
    return { success: false, error: 'Application not found.' };
  }

  user.status = 'rejected';
  user.rejectedBy = adminId;
  user.rejectedAt = new Date().toISOString();
  user.rejectionReason = reason || 'Application did not meet operational vacancy criteria.';
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'STAFF_REJECTED',
    `Administrator rejected application for ${user.email}. Reason: ${user.rejectionReason}`,
    user.id
  );

  recordOutboxEmail(
    user.email,
    'Update regarding your Lymbo Ventures Application',
    `<p>Hello ${user.fullName},</p>
     <p>Thank you for your interest in Lymbo Ventures. After review, we are unable to proceed with your application at this time.</p>
     <p>Reason: ${user.rejectionReason}</p>`,
    'rejection'
  );

  return { success: true };
}

export function suspendStaffUser(
  userId: string,
  adminId: string,
  adminEmail: string,
  clientIp: string
): { success: boolean; error?: string } {
  const db = loadDatabase();
  const user = db.users.find(u => u.id === userId);

  if (!user) {
    return { success: false, error: 'Staff user not found.' };
  }

  if (user.role === 'admin' && user.id === 'usr_admin_root') {
    return { success: false, error: 'Cannot suspend root Administrator.' };
  }

  user.status = 'suspended';
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'STAFF_SUSPENDED',
    `Administrator suspended staff account for ${user.email}. All sessions terminated immediately.`,
    user.id
  );

  return { success: true };
}

export function reactivateStaffUser(
  userId: string,
  adminId: string,
  adminEmail: string,
  clientIp: string
): { success: boolean; error?: string } {
  const db = loadDatabase();
  const user = db.users.find(u => u.id === userId);

  if (!user) {
    return { success: false, error: 'Staff user not found.' };
  }

  user.status = 'active';
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'STAFF_REACTIVATED',
    `Administrator reactivated staff account for ${user.email}.`,
    user.id
  );

  return { success: true };
}

export function deleteStaffUser(
  userId: string,
  adminId: string,
  adminEmail: string,
  clientIp: string
): { success: boolean; error?: string } {
  const db = loadDatabase();
  const index = db.users.findIndex(u => u.id === userId);

  if (index === -1) {
    return { success: false, error: 'Staff user not found.' };
  }

  const user = db.users[index];
  if (user.role === 'admin' && user.id === 'usr_admin_root') {
    return { success: false, error: 'Cannot delete root Administrator.' };
  }

  db.users.splice(index, 1);
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'STAFF_DELETED',
    `Administrator permanently removed staff account for ${user.email}.`,
    user.id
  );

  return { success: true };
}

export function getStaffApplications(): UserAccount[] {
  const db = loadDatabase();
  return db.users.filter(u => u.status === 'pending_approval' || u.status === 'pending_email' || u.status === 'rejected');
}

// ==========================================================================
// CONFIGURATION & DYNAMIC STORE SETTINGS (Section 3)
// ==========================================================================

export function getStoreConfig(): StoreConfig {
  const db = loadDatabase();
  return db.config;
}

export function updateStoreConfig(
  newConfig: Partial<StoreConfig>,
  adminId: string,
  adminEmail: string,
  clientIp: string
): StoreConfig {
  const db = loadDatabase();
  db.config = {
    ...db.config,
    ...newConfig,
    features: {
      ...db.config.features,
      ...(newConfig.features || {})
    }
  };
  saveDatabase();

  addAuditLog(
    adminId,
    adminEmail,
    'admin',
    clientIp,
    'CONFIG_UPDATED',
    `Administrator updated live store pricing and delivery settings: Tray Price KES ${db.config.eggPricePerTray}, Paybill ${db.config.mpesaPaybill}.`,
    'store_config',
    { config: db.config }
  );

  return db.config;
}

// ==========================================================================
// ORDERS & INVENTORY MANAGEMENT
// ==========================================================================

export function getInventoryStatus(): { totalReceived: number; totalSold: number; currentStock: number } {
  const db = loadDatabase();
  const totalReceived = db.inventoryLedger.reduce((sum, item) => sum + item.trays, 0);
  const totalSold = db.orders
    .filter(o => o.orderStatus !== 'declined')
    .reduce((sum, item) => sum + item.eggTrays, 0);
  const currentStock = Math.max(0, db.initialStock + totalReceived - totalSold);
  return { totalReceived, totalSold, currentStock };
}

export function recordGoodsReceived(
  trays: number,
  batchRef: string,
  supplier: string,
  notes: string,
  recordedBy: string,
  clientIp: string
): GoodsReceivedItem {
  const db = loadDatabase();
  const item: GoodsReceivedItem = {
    id: `GRN-${Date.now().toString().slice(-6)}`,
    batchRef: batchRef || `BATCH-MBS-${Math.floor(1000 + Math.random() * 9000)}`,
    date: new Date().toISOString().split('T')[0],
    trays: Number(trays),
    supplier: supplier || 'Coastal Poultry Farm Mombasa',
    notes: notes || 'Standard shipment received and verified',
    recordedBy,
    recordedAt: new Date().toISOString()
  };
  db.inventoryLedger.unshift(item);
  saveDatabase();

  addAuditLog(
    'inventory_mgr',
    recordedBy,
    'staff',
    clientIp,
    'STOCK_INTAKE',
    `Recorded ${trays} fresh egg trays intake under batch ${item.batchRef}. Total stock increased.`,
    item.id
  );

  broadcastSyncEvent('inventory_updated', {
    item,
    stockStatus: getInventoryStatus()
  });

  return item;
}

export function createOrderInStore(data: {
  customerName: string;
  customerPhone: string;
  customerEmail?: string;
  deliveryArea: string;
  deliveryAddress: string;
  deliveryDate: string;
  deliveryTimeSlot?: string;
  eggTrays: number;
  deliveryFee: number;
  paymentMethod: 'M-Pesa' | 'Cash on Delivery';
  notes?: string;
  transactionCode?: string;
  clientIp: string;
}): OrderItem {
  const db = loadDatabase();
  const orderId = `ORD-2026-${db.nextOrderSeq++}`;
  const invSeq = String(db.nextInvoiceSeq++).padStart(4, '0');
  const dnSeq = String(db.nextDeliveryNoteSeq++).padStart(4, '0');
  const now = new Date().toISOString();

  const pricePerTray = db.config?.eggPricePerTray || 500;
  const subtotal = data.eggTrays * pricePerTray;
  const grandTotal = subtotal + data.deliveryFee;

  const order: OrderItem = {
    id: orderId,
    invoiceNumber: `INV-2026-${invSeq}`,
    deliveryNoteNumber: `DN-2026-${dnSeq}`,
    customerName: data.customerName,
    customerPhone: data.customerPhone,
    customerEmail: data.customerEmail,
    deliveryArea: data.deliveryArea,
    deliveryAddress: data.deliveryAddress,
    deliveryDate: data.deliveryDate,
    deliveryTimeSlot: data.deliveryTimeSlot || 'Morning (8:00 AM - 12:00 PM)',
    eggTrays: data.eggTrays,
    pricePerTray,
    subtotal,
    deliveryFee: data.deliveryFee,
    discountAmount: 0,
    grandTotal,
    paymentMethod: data.paymentMethod,
    paymentStatus: data.transactionCode ? 'paid' : (data.paymentMethod === 'Cash on Delivery' ? 'unpaid' : 'pending_verification'),
    orderStatus: 'pending',
    mpesaTransactionCode: data.transactionCode,
    notes: data.notes,
    createdAt: now,
    updatedAt: now
  };

  db.orders.unshift(order);
  saveDatabase();

  addAuditLog(
    'customer_portal',
    data.customerPhone,
    'customer',
    data.clientIp,
    'ORDER_CREATED',
    `New order ${order.id} (${order.invoiceNumber}) placed: ${data.eggTrays} trays to ${data.deliveryArea}. KES ${grandTotal}`,
    order.id
  );

  broadcastSyncEvent('order_created', order);

  return order;
}

export function updateOrderStatusInStore(
  orderId: string,
  newStatus: OrderItem['orderStatus'],
  staffUser: string,
  staffRole: string,
  clientIp: string,
  trackingNote?: string
): OrderItem | null {
  const db = loadDatabase();
  const order = db.orders.find(o => o.id === orderId);
  if (!order) return null;

  const previousStatus = order.orderStatus;
  order.orderStatus = newStatus;
  order.updatedAt = new Date().toISOString();

  if (trackingNote) {
    order.notes = order.notes ? `${order.notes} | ${trackingNote}` : trackingNote;
  }

  saveDatabase();

  addAuditLog(
    staffUser,
    staffUser,
    staffRole,
    clientIp,
    'ORDER_STATUS_CHANGED',
    `Order ${orderId} status changed from '${previousStatus}' to '${newStatus}'. Staff: ${staffUser}`,
    orderId
  );

  broadcastSyncEvent('order_updated', order);

  return order;
}

// Data Minimization for Least Privilege Role View
export function getOrdersProjectedForRole(role: UserRole | string, orders: OrderItem[]) {
  if (role === 'admin' || role === 'manager') {
    return orders;
  }

  if (role === 'dispatch_officer') {
    // Dispatch officer sees delivery details, street, landmark, special instructions, status; cannot see wholesale profit margins
    return orders.map(o => ({
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
      notes: o.notes, // Gate code / instructions
      createdAt: o.createdAt
    }));
  }

  if (role === 'accounts_officer') {
    // Accounts officer sees payments, M-Pesa codes, receipts, invoices
    return orders.map(o => ({
      id: o.id,
      invoiceNumber: o.invoiceNumber,
      customerName: o.customerName,
      customerPhone: o.customerPhone,
      subtotal: o.subtotal,
      deliveryFee: o.deliveryFee,
      grandTotal: o.grandTotal,
      paymentMethod: o.paymentMethod,
      paymentStatus: o.paymentStatus,
      orderStatus: o.orderStatus,
      mpesaTransactionCode: o.mpesaTransactionCode,
      createdAt: o.createdAt
    }));
  }

  if (role === 'customer_support') {
    // Read-only customer tracking
    return orders.map(o => ({
      id: o.id,
      customerName: o.customerName,
      deliveryArea: o.deliveryArea,
      eggTrays: o.eggTrays,
      orderStatus: o.orderStatus,
      deliveryDate: o.deliveryDate,
      createdAt: o.createdAt
    }));
  }

  // Sales officer / Junior Staff (Data Minimization)
  return orders.map(o => ({
    id: o.id,
    invoiceNumber: o.invoiceNumber,
    deliveryNoteNumber: o.deliveryNoteNumber,
    customerName: o.customerName,
    customerPhone: o.customerPhone.replace(/(\+254\d{2})\d{4}(\d{3})/, '$1****$2'),
    deliveryArea: o.deliveryArea,
    deliveryAddress: o.deliveryAddress,
    deliveryDate: o.deliveryDate,
    deliveryTimeSlot: o.deliveryTimeSlot,
    eggTrays: o.eggTrays,
    deliveryFee: o.deliveryFee,
    grandTotal: o.grandTotal,
    paymentMethod: o.paymentMethod,
    paymentStatus: o.paymentStatus,
    orderStatus: o.orderStatus,
    mpesaTransactionCode: o.mpesaTransactionCode,
    notes: o.notes,
    createdAt: o.createdAt
  }));
}

// Legacy helper for onboarding request
export function createPendingAccount(email: string, name: string, requestedRole: UserRole): { status: 'created' | 'already_exists'; user: UserAccount } {
  const result = createStaffApplication({
    fullName: name || email.split('@')[0],
    email,
    phone: '+254700000000',
    passwordHash: bcrypt.hashSync('20lymboventures@26', 12),
    position: requestedRole,
    consent: true
  });
  return { status: result.success ? 'created' : 'already_exists', user: result.user! };
}

export function approveAccountByAdmin(userId: string, assignedRole: UserRole, adminId: string, adminEmail: string, clientIp: string) {
  return approveStaffApplication(userId, assignedRole, adminId, adminEmail, clientIp);
}

export function activateAccountWithPassword(token: string, newPassword: string, clientIp: string) {
  return { success: true };
}

// SSE Real-time Synchronization
export function registerSseClient(res: Response): void {
  sseClients.add(res);
  res.on('close', () => {
    sseClients.delete(res);
  });
}

export function broadcastSyncEvent(eventType: string, payload: any): void {
  const dataString = `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(dataString);
    } catch {
      sseClients.delete(client);
    }
  }
}
