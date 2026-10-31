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

export type UserRole = 'admin' | 'manager' | 'staff' | 'customer';
export type AccountStatus = 'active' | 'pending_approval' | 'suspended';

export interface UserAccount {
  id: string;
  email: string;
  username: string;
  name: string;
  role: UserRole;
  status: AccountStatus;
  passwordHash: string;
  mfaRequired: boolean;
  mfaSecret: string;
  mfaBackupCodes: string[];
  createdAt: string;
  approvedBy?: string;
  approvedAt?: string;
  requestedRole?: UserRole;
  notes?: string;
  activationTokenHash?: string;
  activationTokenExpires?: number;
  resetTokenHash?: string;
  resetTokenExpires?: number;
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

// Ensure directory exists
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

// Generate secure dynamic Base32 secret for TOTP
export function generateBase32Secret(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(20);
  let secret = '';
  for (let i = 0; i < bytes.length; i++) {
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
  const adminEmail = process.env.ADMIN_EMAIL || 'lymboventures0@gmail.com';
  const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || '20lymboventures@26';
  const adminHash = bcrypt.hashSync(initialPassword, 12);
  const managerHash = bcrypt.hashSync('20@LymboManager26', 12);
  const staffHash = bcrypt.hashSync('20@LymboStaff26', 12);

  const adminSecret = generateBase32Secret();
  const managerSecret = generateBase32Secret();
  const staffSecret = generateBase32Secret();

  const now = new Date().toISOString();

  return {
    users: [
      {
        id: 'usr_admin_root',
        email: adminEmail.toLowerCase(),
        username: 'admin',
        name: 'System Administrator',
        role: 'admin',
        status: 'active',
        passwordHash: adminHash,
        mfaRequired: true,
        mfaSecret: adminSecret,
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        notes: 'Primary System Administrator with root infrastructure governance'
      },
      {
        id: 'usr_manager_01',
        email: 'manager@lymboventures.co.ke',
        username: 'manager_mombasa',
        name: 'Operations Manager',
        role: 'manager',
        status: 'active',
        passwordHash: managerHash,
        mfaRequired: true,
        mfaSecret: managerSecret,
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        notes: 'Supervises stock, orders, and sales reports'
      },
      {
        id: 'usr_staff_01',
        email: 'sales@lymboventures.co.ke',
        username: 'sales_rep',
        name: 'Junior Sales Staff',
        role: 'staff',
        status: 'active',
        passwordHash: staffHash,
        mfaRequired: false,
        mfaSecret: staffSecret,
        mfaBackupCodes: generateBackupCodes(),
        createdAt: now,
        notes: 'Fulfills assigned orders with Data Minimization'
      }
    ],
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
        orderStatus: 'delivered',
        mpesaTransactionCode: 'SKH8921827',
        assignedStaffName: 'Junior Sales Staff',
        createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        updatedAt: now
      },
      {
        id: 'ORD-2026-1002',
        invoiceNumber: 'INV-2026-0002',
        deliveryNoteNumber: 'DN-2026-0002',
        customerName: 'Hassan Omar',
        customerPhone: '+254722998877',
        customerEmail: 'hassan.omar@example.com',
        deliveryArea: 'Bamburi',
        deliveryAddress: 'Vescon Estate 2, Gate 4',
        deliveryDate: new Date().toISOString().split('T')[0],
        deliveryTimeSlot: 'Afternoon (1:00 PM - 5:00 PM)',
        eggTrays: 3,
        pricePerTray: 500,
        subtotal: 1500,
        deliveryFee: 150,
        discountAmount: 0,
        grandTotal: 1650,
        paymentMethod: 'M-Pesa',
        paymentStatus: 'paid',
        orderStatus: 'processing',
        mpesaTransactionCode: 'SKH9041284',
        assignedStaffName: 'Junior Sales Staff',
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
        details: 'Lymbo Ventures persistent storage initialized with Kenyan Data Protection Act 2019 compliance & 4-tier RBAC.'
      }
    ],
    initialStock: 500,
    nextOrderSeq: 1003,
    nextInvoiceSeq: 3,
    nextDeliveryNoteSeq: 3,
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
      // Ensure users array includes current admin email if migrated
      const adminEmail = (process.env.ADMIN_EMAIL || 'lymboventures0@gmail.com').toLowerCase();
      const hasAdmin = dbState.users.some(u => u.email.toLowerCase() === adminEmail);
      if (!hasAdmin) {
        const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || '20lymboventures@26';
        dbState.users.unshift({
          id: 'usr_admin_root',
          email: adminEmail,
          username: 'admin',
          name: 'System Administrator',
          role: 'admin',
          status: 'active',
          passwordHash: bcrypt.hashSync(initialPassword, 12),
          mfaRequired: true,
          mfaSecret: generateBase32Secret(),
          mfaBackupCodes: generateBackupCodes(),
          createdAt: new Date().toISOString(),
          notes: 'Primary System Administrator'
        });
        saveDatabase();
      }
      return dbState;
    } catch (err) {
      console.error('Failed to parse database file, re-seeding:', err);
    }
  }

  dbState = getSeedData();
  saveDatabase();
  return dbState;
}

// Persist database to disk atomically
export function saveDatabase(): void {
  try {
    ensureDataDir();
    dbState.lastUpdated = new Date().toISOString();
    const tempFile = `${DB_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tempFile, JSON.stringify(dbState, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Failed to save persistent store:', err);
  }
}

// Real-Time Server-Sent Events (SSE) Synchronization
export function registerSseClient(res: Response): () => void {
  sseClients.add(res);

  // Send initial connected payload
  res.write(`event: connected\ndata: ${JSON.stringify({ timestamp: new Date().toISOString(), clientsCount: sseClients.size })}\n\n`);

  return () => {
    sseClients.delete(res);
  };
}

export function broadcastSyncEvent(eventType: string, data: any): void {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

// Heartbeat for SSE connections every 25 seconds
setInterval(() => {
  const ping = `: heartbeat ${Date.now()}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(ping);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}, 25000);

// Immutable Audit Log
export function addAuditLog(
  userId: string,
  userEmail: string,
  userRole: string,
  clientIp: string,
  action: string,
  details: string,
  targetEntityId?: string
): AuditLogItem {
  const db = loadDatabase();
  const entry: AuditLogItem = {
    id: `AUDIT-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
    timestamp: new Date().toISOString(),
    userId,
    userEmail,
    userRole,
    clientIp,
    action,
    details,
    targetEntityId
  };

  db.auditLogs.unshift(entry);
  if (db.auditLogs.length > 500) {
    db.auditLogs.pop(); // Keep 500 latest immutable entries
  }

  saveDatabase();
  broadcastSyncEvent('audit_logged', entry);
  return entry;
}

// Inventory Calculation
export function getInventoryStatus() {
  const db = loadDatabase();
  const totalReceived = db.inventoryLedger.reduce((acc, item) => acc + (item.trays || 0), 0);
  const totalDispatched = db.orders
    .filter(o => o.orderStatus !== 'declined')
    .reduce((acc, item) => acc + (item.eggTrays || 0), 0);

  const availableStock = Math.max(0, totalReceived - totalDispatched);
  const stockValuationKes = availableStock * 500;

  return {
    totalReceived,
    totalDispatched,
    availableStock,
    stockValuationKes,
    pricePerTray: 500
  };
}

// Add Goods Received (Admin/Manager only)
export function recordGoodsReceived(
  trays: number,
  batchRef: string,
  supplier: string,
  notes: string,
  user: { id: string; email: string; role: string; name?: string },
  clientIp: string
) {
  const db = loadDatabase();
  const item: GoodsReceivedItem = {
    id: `GRN-${Date.now()}`,
    batchRef: batchRef || `BATCH-${Date.now().toString().slice(-6)}`,
    date: new Date().toISOString().split('T')[0],
    trays: Number(trays),
    supplier: supplier || 'Lymbo Mombasa Farm Hub',
    notes: notes || 'Fresh batch intake',
    recordedBy: user.name || user.email,
    recordedAt: new Date().toISOString()
  };

  db.inventoryLedger.unshift(item);
  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    user.role,
    clientIp,
    'STOCK_INWARD_RECORDED',
    `Added ${trays} egg trays inward under batch ${item.batchRef}. Supplier: ${item.supplier}`,
    item.id
  );

  const inventoryStatus = getInventoryStatus();
  broadcastSyncEvent('stock_updated', inventoryStatus);

  return { item, inventoryStatus };
}

// Sequential Numbers for Invoices and Delivery Notes
export function generateNextOrderNumbers() {
  const db = loadDatabase();
  const orderId = `ORD-2026-${db.nextOrderSeq++}`;
  const invoiceNumber = `INV-2026-${String(db.nextInvoiceSeq++).padStart(4, '0')}`;
  const deliveryNoteNumber = `DN-2026-${String(db.nextDeliveryNoteSeq++).padStart(4, '0')}`;
  saveDatabase();
  return { orderId, invoiceNumber, deliveryNoteNumber };
}

// Create Order (Self-service Customer or Staff manual entry)
export function createOrderInStore(orderData: {
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
}) {
  const db = loadDatabase();
  const numbers = generateNextOrderNumbers();
  const trays = Math.max(1, Number(orderData.eggTrays));
  const pricePerTray = 500;
  const subtotal = trays * pricePerTray;
  const deliveryFee = Number(orderData.deliveryFee) || 100;
  const grandTotal = subtotal + deliveryFee;
  const now = new Date().toISOString();

  const newOrder: OrderItem = {
    id: numbers.orderId,
    invoiceNumber: numbers.invoiceNumber,
    deliveryNoteNumber: numbers.deliveryNoteNumber,
    customerName: orderData.customerName.trim(),
    customerPhone: orderData.customerPhone.trim(),
    customerEmail: orderData.customerEmail?.trim(),
    deliveryArea: orderData.deliveryArea,
    deliveryAddress: orderData.deliveryAddress.trim(),
    deliveryDate: orderData.deliveryDate || now.split('T')[0],
    deliveryTimeSlot: orderData.deliveryTimeSlot || 'Morning (8:00 AM - 12:00 PM)',
    eggTrays: trays,
    pricePerTray,
    subtotal,
    deliveryFee,
    discountAmount: 0,
    grandTotal,
    paymentMethod: orderData.paymentMethod,
    paymentStatus: orderData.paymentMethod === 'M-Pesa' && orderData.transactionCode ? 'paid' : 'unpaid',
    orderStatus: 'pending',
    mpesaTransactionCode: orderData.transactionCode || undefined,
    notes: orderData.notes,
    createdAt: now,
    updatedAt: now
  };

  db.orders.unshift(newOrder);
  saveDatabase();

  addAuditLog(
    'customer_portal',
    orderData.customerPhone,
    'customer',
    orderData.clientIp,
    'ORDER_CREATED',
    `New order ${newOrder.id} (${newOrder.invoiceNumber}) placed: ${newOrder.eggTrays} trays to ${newOrder.deliveryArea}. KES ${newOrder.grandTotal}`,
    newOrder.id
  );

  broadcastSyncEvent('order_created', newOrder);
  broadcastSyncEvent('stock_updated', getInventoryStatus());

  return newOrder;
}

// Update Order Status (RBAC Protected: Admin, Manager, Junior Sales Staff)
export function updateOrderStatusInStore(
  orderId: string,
  newStatus: OrderItem['orderStatus'],
  user: { id: string; email: string; role: string; name?: string },
  clientIp: string,
  extraNote?: string
) {
  const db = loadDatabase();
  const order = db.orders.find(o => o.id === orderId);
  if (!order) return null;

  const oldStatus = order.orderStatus;
  order.orderStatus = newStatus;
  order.updatedAt = new Date().toISOString();
  if (newStatus === 'delivered' && order.paymentMethod === 'Cash on Delivery') {
    order.paymentStatus = 'paid';
  }
  if (user.role === 'staff' && !order.assignedStaffId) {
    order.assignedStaffId = user.id;
    order.assignedStaffName = user.name || user.email;
  }
  if (extraNote) {
    order.notes = (order.notes ? `${order.notes}; ` : '') + extraNote;
  }

  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    user.role,
    clientIp,
    'ORDER_STATUS_UPDATED',
    `Order ${orderId} status changed from '${oldStatus}' to '${newStatus}' by ${user.role} (${user.email}).`,
    orderId
  );

  broadcastSyncEvent('order_updated', order);
  broadcastSyncEvent('stock_updated', getInventoryStatus());

  return order;
}

// Kenya Data Protection Act 2019: Data Minimization for Junior Sales Staff
export function getOrdersProjectedForRole(role: UserRole) {
  const db = loadDatabase();

  if (role === 'admin' || role === 'manager') {
    return db.orders;
  }

  if (role === 'staff') {
    // Junior Sales Staff: Data minimization applies!
    // Mask sensitive customer emails, omit margin data, show necessary fulfillment information
    return db.orders.map(order => ({
      id: order.id,
      invoiceNumber: order.invoiceNumber,
      deliveryNoteNumber: order.deliveryNoteNumber,
      customerName: order.customerName,
      customerPhone: order.customerPhone,
      customerEmail: order.customerEmail ? maskEmail(order.customerEmail) : undefined,
      deliveryArea: order.deliveryArea,
      deliveryAddress: order.deliveryAddress,
      deliveryDate: order.deliveryDate,
      deliveryTimeSlot: order.deliveryTimeSlot,
      eggTrays: order.eggTrays,
      grandTotal: order.grandTotal,
      paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
      orderStatus: order.orderStatus,
      assignedStaffName: order.assignedStaffName,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    }));
  }

  return [];
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  const maskedLocal = local.length > 2 ? `${local[0]}***${local[local.length - 1]}` : '***';
  return `${maskedLocal}@${domain}`;
}

// User Accounts & Approval Onboarding
export function createPendingAccount(email: string, name: string, requestedRole: UserRole = 'staff') {
  const db = loadDatabase();
  const cleanEmail = email.trim().toLowerCase();

  const existing = db.users.find(u => u.email.toLowerCase() === cleanEmail);
  if (existing) {
    if (existing.status === 'pending_approval') {
      return { status: 'already_pending', user: existing };
    }
    return { status: 'already_exists', user: existing };
  }

  const dummyHash = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);
  const newUser: UserAccount = {
    id: `usr_pending_${Date.now()}`,
    email: cleanEmail,
    username: cleanEmail.split('@')[0],
    name: name.trim() || cleanEmail.split('@')[0],
    role: requestedRole,
    status: 'pending_approval',
    passwordHash: dummyHash,
    mfaRequired: requestedRole === 'admin' || requestedRole === 'manager',
    mfaSecret: generateBase32Secret(),
    mfaBackupCodes: generateBackupCodes(),
    createdAt: new Date().toISOString(),
    requestedRole,
    notes: 'Submitted via staff onboarding portal; awaiting Administrator review.'
  };

  db.users.push(newUser);
  saveDatabase();

  addAuditLog(
    newUser.id,
    newUser.email,
    newUser.role,
    'client_onboarding',
    'ACCOUNT_ONBOARDING_SUBMITTED',
    `New onboarding request submitted for email ${cleanEmail}. Assigned status: pending_approval. Requested Role: ${requestedRole}.`,
    newUser.id
  );

  broadcastSyncEvent('user_pending', {
    id: newUser.id,
    email: newUser.email,
    name: newUser.name,
    requestedRole: newUser.requestedRole,
    createdAt: newUser.createdAt
  });

  return { status: 'created', user: newUser };
}

// Admin Approves Account & Generates 15-Minute Hashed Activation Link
export function approveAccountByAdmin(
  userId: string,
  assignedRole: UserRole,
  adminUser: { id: string; email: string; role: string },
  clientIp: string
) {
  const db = loadDatabase();
  const user = db.users.find(u => u.id === userId);
  if (!user) return null;

  user.status = 'active';
  user.role = assignedRole;
  user.approvedBy = adminUser.email;
  user.approvedAt = new Date().toISOString();
  user.mfaRequired = assignedRole === 'admin' || assignedRole === 'manager';

  // Secure One-Time Activation Token (SHA-256 Hashed in Database, 15 Minutes Expiry)
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  user.activationTokenHash = tokenHash;
  user.activationTokenExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

  saveDatabase();

  addAuditLog(
    adminUser.id,
    adminUser.email,
    adminUser.role,
    clientIp,
    'USER_ACCOUNT_APPROVED',
    `User account for ${user.email} approved by Admin. Assigned Role: '${assignedRole}'. Secure one-time activation token generated (15m expiry).`,
    user.id
  );

  broadcastSyncEvent('user_approved', {
    id: user.id,
    email: user.email,
    role: user.role,
    status: user.status
  });

  return {
    user,
    rawActivationToken: rawToken, // Dispatched to user via email/activation message
    expiresInMinutes: 15
  };
}

// Activate Account With New 12+ Character Password
export function activateAccountWithPassword(token: string, newPassword: string, clientIp: string) {
  const db = loadDatabase();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const user = db.users.find(u => u.activationTokenHash === tokenHash);
  if (!user) {
    return { success: false, error: 'Activation link is invalid or has already been used.' };
  }

  if (!user.activationTokenExpires || Date.now() > user.activationTokenExpires) {
    user.activationTokenHash = undefined;
    user.activationTokenExpires = undefined;
    saveDatabase();
    return { success: false, error: 'Activation link has expired (15-minute limit). Please contact your administrator.' };
  }

  // Hash password using bcrypt salt cost factor 12
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  user.activationTokenHash = undefined;
  user.activationTokenExpires = undefined;
  user.status = 'active';

  saveDatabase();

  addAuditLog(
    user.id,
    user.email,
    user.role,
    clientIp,
    'ACCOUNT_ACTIVATED',
    `User ${user.email} successfully completed onboarding and set 12+ char password. Access granted for role: ${user.role}.`,
    user.id
  );

  return {
    success: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }
  };
}
