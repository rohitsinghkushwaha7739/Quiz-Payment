/**
 * PadhaQ backend — ₹49 / 12-month Pro, account-gated Razorpay payments.
 *
 * /api/create-order: server-priced order for signed-in user
 * /api/verify-payment: signature + Razorpay order/amount/captured status
 * /api/razorpay/webhook: optional signed payment.captured safety net
 * /api/admin/payments: admin-key-protected, verified payment ledger
 *
 * Configure secrets in Render Environment (not the public Blogger XML).
 * See README-SETUP.md for deployment and persistent storage requirements.
 */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.join(__dirname, 'config.json');
// Mount a persistent disk here on Render (or use a durable database).
// Files inside a normal free web-service filesystem can disappear on deploy/restart.
const DATA_DIR = process.env.PADHAQ_DATA_DIR || path.join(__dirname, 'data');
const PAYMENTS_PATH = path.join(DATA_DIR, 'payments.json');

// One server-authoritative price and term. Never accept a client's amount/expiry.
const PLANS = Object.freeze({
  '49': Object.freeze({ label: '1 Year', months: 12, amount: 49 }),
});

// ---------- config + storage helpers ----------
function loadConfig() {
  let fileCfg = {};
  try { fileCfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) || {}; } catch (e) { /* no config yet */ }
  return {
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || fileCfg.razorpayKeyId || '',
    razorpayKeySecret: process.env.RAZORPAY_KEY_SECRET || fileCfg.razorpayKeySecret || '',
    geminiApiKey: process.env.GEMINI_API_KEY || fileCfg.geminiApiKey || '',
    // Never put this in the public Blogger XML or a public GitHub repository.
    adminKey: process.env.PADHAQ_ADMIN_KEY || process.env.ADMIN_KEY || '',
    webhookSecret: process.env.RAZORPAY_WEBHOOK_SECRET || '',
  };
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) {
    if (e.code === 'ENOENT') return fallback;
    throw e; // A corrupt database must NOT silently turn into an empty one.
  }
}
function saveJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } finally {
    try { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); } catch (_) { /* cleanup */ }
  }
}
function loadPayments() {
  const records = readJson(PAYMENTS_PATH, []);
  if (!Array.isArray(records)) throw new Error('payments.json must be an array');
  return records;
}
function savePayments(list) { saveJson(PAYMENTS_PATH, list); }

function liveSetupError(cfg) {
  if (!/^rzp_live_/.test(cfg.razorpayKeyId)) return '';
  if (!process.env.PADHAQ_DATA_DIR) return 'Live payment ke liye mounted persistent disk aur PADHAQ_DATA_DIR set karein.';
  if (!cfg.adminKey || cfg.adminKey.length < 16) return 'Live payment ke liye 16+ character PADHAQ_ADMIN_KEY set karein.';
  if (!cfg.webhookSecret || cfg.webhookSecret.length < 16) return 'Live payment ke liye RAZORPAY_WEBHOOK_SECRET set karein aur webhook configure karein.';
  return '';
}

// CORS: taaki Blogger (blogspot.com) ya koi bhi domain se bhi payment server
// ko safely call kiya ja sake (GET/POST).
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Optional safety net: Razorpay calls this even if a paying customer closes
// the browser before the Checkout success handler can call /api/verify-payment.
// Configure a webhook for payment.captured and set RAZORPAY_WEBHOOK_SECRET.
// The HMAC must use the RAW body bytes (before express.json middleware).
app.post('/api/razorpay/webhook', express.raw({ type: 'application/json', limit: '128kb' }), async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.webhookSecret || cfg.webhookSecret.length < 16) {
    return res.status(503).json({ ok: false, error: 'Webhook secret not configured.' });
  }
  const signature = String(req.get('X-Razorpay-Signature') || '');
  if (!Buffer.isBuffer(req.body) || !/^[a-fA-F0-9]{64}$/.test(signature)) {
    return res.status(400).json({ ok: false, error: 'Invalid webhook payload/signature.' });
  }
  const expected = crypto.createHmac('sha256', cfg.webhookSecret).update(req.body).digest('hex');
  if (!sameSecret(expected, signature.toLowerCase())) {
    return res.status(401).json({ ok: false, error: 'Invalid webhook signature.' });
  }
  let event;
  try { event = JSON.parse(req.body.toString('utf8')); }
  catch (e) { return res.status(400).json({ ok: false, error: 'Invalid JSON.' }); }
  if (event.event !== 'payment.captured') return res.json({ ok: true, ignored: true });
  const entity = event.payload && event.payload.payment && event.payload.payment.entity;
  const orderId = String((entity && entity.order_id) || '');
  const paymentId = String((entity && entity.id) || '');
  if (!/^order_[a-zA-Z0-9]+$/.test(orderId) || !/^pay_[a-zA-Z0-9]+$/.test(paymentId)) {
    return res.status(400).json({ ok: false, error: 'Payment IDs missing.' });
  }
  try {
    const [order, payment] = await Promise.all([
      getRazorpayEntity(cfg, 'orders', orderId),
      getRazorpayEntity(cfg, 'payments', paymentId),
    ]);
    const notes = order.notes || {};
    const plan = PLANS['49'];
    const db = loadDB();
    const phone = String(notes.phone || '');
    const user = findUserByMobile(db, phone);
    if (!user || String(notes.username) !== String(user.username) ||
        String(notes.plan) !== '49' || String(notes.planMonths) !== '12' ||
        order.id !== orderId || !String(order.receipt || '').startsWith('padhaq_') ||
        Number(order.amount) !== plan.amount * 100 || order.currency !== 'INR' ||
        payment.id !== paymentId || payment.order_id !== orderId ||
        Number(payment.amount) !== plan.amount * 100 || payment.currency !== 'INR' ||
        payment.status !== 'captured') {
      // An invalid order should not be silently credited to somebody else.
      console.warn('Ignored webhook: order/payment not annual or account mismatch', orderId);
      return res.status(409).json({ ok: false, error: 'Order/account mismatch.' });
    }
    if (verifyingUsers.has(user.username)) {
      return res.status(503).json({ ok: false, error: 'Processing; retry webhook.' });
    }
    verifyingUsers.add(user.username);
    try {
      // Re-read after any network delay. In this process, writes below are sync.
      const currentDb = loadDB();
      const currentUser = findUserByMobile(currentDb, phone);
      if (!currentUser || currentUser.username !== user.username) {
        return res.status(409).json({ ok: false, error: 'Account changed.' });
      }
      const list = loadPayments();
      const prior = list.find(p => p.razorpay_payment_id === paymentId || p.razorpay_order_id === orderId);
      if (prior) {
        if (prior.razorpay_payment_id !== paymentId || prior.razorpay_order_id !== orderId ||
            prior.username !== user.username || prior.phone !== phone ||
            prior.planLabel !== plan.label || !prior.expiresAt) {
          return res.status(409).json({ ok: false, error: 'Payment already claimed by another account/plan.' });
        }
        activateUserFromRecord(currentUser, prior, currentDb);
        return res.json({ ok: true, duplicate: true });
      }
      const activatedAt = Date.now();
      const periodStart = Math.max(activatedAt, Number(currentUser.premium && currentUser.premium.expiresAt) || 0);
      const record = {
        razorpay_order_id: orderId, razorpay_payment_id: paymentId,
        plan: '49', planLabel: plan.label, amount: plan.amount, currency: 'INR',
        phone, whatsapp: phone, username: currentUser.username, name: currentUser.name,
        activatedAt, expiresAt: oneCalendarYearFrom(periodStart),
        verifiedAt: new Date(activatedAt).toISOString(),
      };
      list.unshift(record);
      savePayments(list);
      activateUserFromRecord(currentUser, record, currentDb);
      return res.json({ ok: true });
    } finally {
      verifyingUsers.delete(user.username);
    }
  } catch (e) {
    console.error('Webhook processing error:', e.message);
    return res.status(503).json({ ok: false, error: 'Webhook not saved; retry.' });
  }
});

app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- routes ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: '49-year-v2', ts: Date.now() });
});

// App ko batata hai ki keys set hain ya nahi (UI warning ke liye)
app.get('/api/app-config', (req, res) => {
  const cfg = loadConfig();
  res.json({
    geminiApiKey: cfg.geminiApiKey || '',
    razorpayReady: !!(cfg.razorpayKeyId && cfg.razorpayKeySecret && !liveSetupError(cfg)),
    setupMessage: liveSetupError(cfg),
    demoOtpEnabled: !/^rzp_live_/.test(cfg.razorpayKeyId),
    razorpayKeyId: /^rzp_(test|live)_/.test(cfg.razorpayKeyId) ? cfg.razorpayKeyId : '',
  });
});

// Only server-generated and server-verified orders can activate Pro.
function sameSecret(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function oneCalendarYearFrom(ms) {
  const end = new Date(ms);
  end.setUTCFullYear(end.getUTCFullYear() + 1);
  return end.getTime();
}
function activateUserFromRecord(user, record, db) {
  // Retrying an older payment must never shorten a later renewal.
  if (user.premium && Number(user.premium.expiresAt) >= Number(record.expiresAt)) return;
  user.premium = {
    plan: record.plan,
    planLabel: record.planLabel,
    paymentId: record.razorpay_payment_id,
    activatedAt: record.activatedAt,
    expiresAt: record.expiresAt,
  };
  saveDB(db);
}
function verifiedResponse(record, user, duplicate = false) {
  return {
    verified: true, duplicate,
    paymentId: record.razorpay_payment_id,
    planLabel: record.planLabel,
    expiresAt: record.expiresAt,
    user: publicUser(user),
  };
}
async function getRazorpayEntity(cfg, kind, id) {
  const r = await fetch('https://api.razorpay.com/v1/' + kind + '/' + encodeURIComponent(id), {
    headers: {
      Authorization: 'Basic ' + Buffer.from(cfg.razorpayKeyId + ':' + cfg.razorpayKeySecret).toString('base64'),
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error('Razorpay ' + kind + ' lookup failed (' + r.status + ')');
  return r.json();
}

// Order creation: backend chooses ₹49 / 12 months; a valid login is required.
app.post('/api/create-order', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.razorpayKeyId || !cfg.razorpayKeySecret) {
    return res.status(503).json({ error: 'Razorpay keys server par setup nahi hain.' });
  }
  if (liveSetupError(cfg)) return res.status(503).json({ error: liveSetupError(cfg) });
  const b = req.body || {};
  const planKey = String(b.plan || '');
  const plan = PLANS[planKey];
  if (!plan) return res.status(400).json({ error: 'Sirf ₹49 / 1 Year plan available hai.' });
  let user;
  try { user = findUserByToken(loadDB(), b.token); }
  catch (e) { return res.status(500).json({ error: 'Account database load nahi hua.' }); }
  if (!user) return res.status(401).json({ error: 'Pehle login karein.' });

  try {
    const r = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + Buffer.from(cfg.razorpayKeyId + ':' + cfg.razorpayKeySecret).toString('base64'),
      },
      body: JSON.stringify({
        amount: plan.amount * 100, // Razorpay requires INR paise
        currency: 'INR',
        receipt: 'padhaq_' + crypto.randomBytes(12).toString('hex'),
        notes: {
          plan: planKey, planMonths: String(plan.months),
          phone: user.mobile, username: user.username,
        },
      }),
      signal: AbortSignal.timeout(15000),
    });
    const order = await r.json();
    if (!r.ok || !order.id || Number(order.amount) !== plan.amount * 100 || order.currency !== 'INR') {
      return res.status(502).json({ error: 'Razorpay ne ₹49 ka valid order nahi banaya.' });
    }
    res.json({
      orderId: order.id,
      amount: plan.amount, // rupees, for the existing Blogger checkout code
      planMonths: plan.months,
      currency: 'INR',
      keyId: cfg.razorpayKeyId,
      planLabel: plan.label,
    });
  } catch (e) {
    console.error('Razorpay order error:', e.message);
    res.status(502).json({ error: 'Payment server ya Razorpay abhi available nahi hai.' });
  }
});

// Verify checkout signature AND Razorpay's captured payment, amount, order
// and server-created user/plan notes. Never trust plan/phone/expiry from JS.
// File-based storage is safe for one server process. Use a transaction-capable
// database when running multiple instances.
const verifyingUsers = new Set();
app.post('/api/verify-payment', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.razorpayKeyId || !cfg.razorpayKeySecret) {
    return res.status(503).json({ verified: false, error: 'Razorpay keys server par setup nahi hain.' });
  }
  const b = req.body || {};
  const orderId = String(b.razorpay_order_id || '');
  const paymentId = String(b.razorpay_payment_id || '');
  const signature = String(b.razorpay_signature || '');
  if (!/^order_[a-zA-Z0-9]+$/.test(orderId) || !/^pay_[a-zA-Z0-9]+$/.test(paymentId) ||
      !/^[a-fA-F0-9]{64}$/.test(signature)) {
    return res.status(400).json({ verified: false, error: 'Valid payment details missing.' });
  }
  let db, user;
  try { db = loadDB(); user = findUserByToken(db, b.token); }
  catch (e) { return res.status(500).json({ verified: false, error: 'Account database load nahi hua.' }); }
  if (!user) return res.status(401).json({ verified: false, error: 'Login required for payment verification.' });

  const expected = crypto.createHmac('sha256', cfg.razorpayKeySecret)
    .update(orderId + '|' + paymentId).digest('hex');
  if (!sameSecret(expected, signature.toLowerCase())) {
    return res.status(400).json({ verified: false, error: 'Signature mismatch — payment verify nahi hui.' });
  }
  if (verifyingUsers.has(user.username)) {
    return res.status(409).json({ verified: false, error: 'Verification chal rahi hai. Kuch der baad dobara try karein.' });
  }
  const usernameForLock = user.username;
  verifyingUsers.add(usernameForLock);
  try {
    const payments = loadPayments();
    const old = payments.find(p => p.razorpay_payment_id === paymentId || p.razorpay_order_id === orderId);
    if (old) {
      // Do not turn old 1-month or somebody else's payment into a new 1-year subscription.
      if (old.razorpay_payment_id !== paymentId || old.razorpay_order_id !== orderId ||
          old.username !== user.username || old.phone !== user.mobile ||
          old.plan !== '49' || old.planLabel !== PLANS['49'].label || !old.expiresAt) {
        return res.status(409).json({ verified: false, error: 'Payment already used, or belongs to a legacy/other account.' });
      }
      if (user.premium && user.premium.paymentId !== paymentId &&
          Number(user.premium.expiresAt) >= Number(old.expiresAt)) {
        return res.status(409).json({ verified: false, error: 'Purana payment pehle use ho chuka hai.' });
      }
      activateUserFromRecord(user, old, db);
      return res.json(verifiedResponse(old, user, true));
    }

    const [order, payment] = await Promise.all([
      getRazorpayEntity(cfg, 'orders', orderId),
      getRazorpayEntity(cfg, 'payments', paymentId),
    ]);
    // Refresh state after network I/O so profile/credits/other payments aren't overwritten.
    db = loadDB();
    user = findUserByToken(db, b.token);
    if (!user) return res.status(401).json({ verified: false, error: 'Session expire ho gaya.' });
    const currentPayments = loadPayments();
    if (currentPayments.some(p => p.razorpay_payment_id === paymentId || p.razorpay_order_id === orderId)) {
      return res.status(409).json({ verified: false, error: 'Order pehle verify ho chuka hai. Page refresh karke dobara check karein.' });
    }
    const plan = PLANS['49'];
    const notes = order.notes || {};
    if (order.id !== orderId || !String(order.receipt || '').startsWith('padhaq_') ||
        Number(order.amount) !== plan.amount * 100 || order.currency !== 'INR' ||
        String(notes.plan) !== '49' || String(notes.planMonths) !== '12' ||
        String(notes.phone) !== String(user.mobile) || String(notes.username) !== String(user.username) ||
        payment.id !== paymentId || payment.order_id !== orderId ||
        Number(payment.amount) !== plan.amount * 100 || payment.currency !== 'INR' ||
        payment.status !== 'captured') {
      return res.status(409).json({ verified: false, error: 'Payment/order amount, captured status, plan ya account match nahi hua.' });
    }

    const activatedAt = Date.now();
    // Renewals extend from the existing expiry, rather than discarding paid days.
    const periodStart = Math.max(activatedAt, Number(user.premium && user.premium.expiresAt) || 0);
    const expiresAt = oneCalendarYearFrom(periodStart);
    const record = {
      razorpay_order_id: orderId,
      razorpay_payment_id: paymentId,
      plan: '49', planLabel: plan.label,
      amount: plan.amount, currency: 'INR',
      phone: user.mobile, whatsapp: user.mobile,
      username: user.username, name: user.name,
      activatedAt, expiresAt, verifiedAt: new Date(activatedAt).toISOString(),
    };
    // Save payment first; if a later user-db write fails, retry repairs the
    // account from this durable record without ever giving a second year.
    currentPayments.unshift(record);
    savePayments(currentPayments);
    activateUserFromRecord(user, record, db);
    return res.json(verifiedResponse(record, user));
  } catch (e) {
    console.error('Razorpay verification error:', e.message);
    return res.status(502).json({ verified: false, error: 'Payment verify/save nahi hua. Payment ID sambhal kar admin se sampark karein.' });
  } finally {
    verifyingUsers.delete(usernameForLock);
  }
});

// Admin panel: verified transactions only. Never return signature or secrets.
app.post('/api/admin/payments', (req, res) => {
  const cfg = loadConfig();
  if (!cfg.adminKey || cfg.adminKey.length < 16) {
    return res.status(503).json({ ok: false, error: 'Render me PADHAQ_ADMIN_KEY (16+ characters) set karein.' });
  }
  if (!sameSecret(cfg.adminKey, (req.body || {}).adminKey)) {
    return res.status(403).json({ ok: false, error: 'Wrong admin key.' });
  }
  try {
    const db = loadDB();
    const rows = loadPayments().map(p => {
      const mobile = String(p.phone || p.whatsapp || '');
      const owner = findUserByMobile(db, mobile);
      const legacyPrice = { '49': 49, '199': 199, '299': 299 }[String(p.plan)];
      const amount = Number.isFinite(Number(p.amount)) ? Number(p.amount) : (legacyPrice || 0);
      return {
        verifiedAt: p.verifiedAt || '',
        name: p.name || (owner && owner.name) || '-',
        whatsapp: mobile,
        phone: mobile,
        plan: p.plan || '',
        planLabel: p.planLabel || 'Legacy plan',
        amount,
        razorpay_payment_id: p.razorpay_payment_id || '',
        razorpay_order_id: p.razorpay_order_id || '',
        expiresAt: p.expiresAt || null,
      };
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, count: rows.length,
      totalAmount: rows.reduce((sum, p) => sum + p.amount, 0), rows });
  } catch (e) {
    console.error('Admin data error:', e.message);
    res.status(500).json({ ok: false, error: 'Payment records load nahi hue.' });
  }
});

// ================================================================
//  ACCOUNTS: Username+Password + Mobile OTP (server-side REAL)
//  - data/users.json: { users: {username: {...}}, mobileToUser: {mobile: username} }
//  - PREMIUM + FREE CREDITS server par — login karte hi account se wapas
//  - password + OTP hashed; sessions tokenHash se
//  - PRODUCTION SMS: sendOtpSms() me MSG91/Twilio/Fast2SMS lagayein
// ================================================================
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const otpStore = new Map(); // phone -> { hash, exp, attempts, count, windowExp, name }

function loadDB() {
  const db = readJson(USERS_PATH, { users: {}, mobileToUser: {} });
  if (!db || typeof db.users !== 'object' || !db.users ||
      typeof db.mobileToUser !== 'object' || !db.mobileToUser) {
    throw new Error('users.json has an invalid format');
  }
  return db;
}
function saveDB(db) { saveJson(USERS_PATH, db); }
function sha256(s, salt) { return crypto.createHash('sha256').update(String(salt || '') + String(s)).digest('hex'); }

function findUserByToken(db, token) {
  if (!token) return null;
  const th = sha256(token, 'tok');
  return Object.values(db.users).find(u => (u.tokens && u.tokens[th]) || u.tokenHash === th) || null;
}
function findUserByMobile(db, mobile) {
  const un = db.mobileToUser[mobile];
  return un ? db.users[un] : null;
}
function publicUser(u) {
  return {
    username: u.username, name: u.name, mobile: u.mobile, avatar: u.avatar || '\u{1F4DA}',
    premium: u.premium || null,
    freeUsed: u.freeUsed || 0,
  };
}
function premiumActive(u) {
  return !!(u && u.premium && u.premium.expiresAt && u.premium.expiresAt > Date.now());
}
function issueToken(u) {
  const token = crypto.randomBytes(24).toString('hex');
  const th = sha256(token, 'tok');
  u.tokens = u.tokens || {};
  u.tokens[th] = Date.now();
  // max 5 devices — purane sessions hatao
  const entries = Object.entries(u.tokens).sort((a, b) => a[1] - b[1]);
  while (entries.length > 5) { delete u.tokens[entries.shift()[0]]; }
  u.lastLogin = new Date().toISOString();
  return token;
}

function sendOtpSms(phone, code) {
  // PRODUCTION: yahan real SMS gateway call karein (MSG91 / Twilio / Fast2SMS).
  // Abhi demo mode: OTP response me 'demoOtp' milta hai.
  return { demoOtp: code };
}

// ---------- Register: username + password + name + mobile ----------
app.post('/api/register', (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').trim().toLowerCase();
  const password = String(b.password || '');
  const name = String(b.name || '').trim().slice(0, 30);
  const mobile = String(b.mobile || '').replace(/\D/g, '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ ok: false, error: 'Username: 3-20 me letter/digit/underscore (a-z, 0-9, _).' });
  if (password.length < 6) return res.status(400).json({ ok: false, error: 'Password kam se kam 6 akshar ka rakhein.' });
  if (name.length < 2) return res.status(400).json({ ok: false, error: 'Naam likhna zaroori hai.' });
  if (!/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ ok: false, error: 'Valid 10-digit Indian mobile number daalein.' });

  const db = loadDB();
  if (db.users[username]) return res.status(409).json({ ok: false, error: 'Yeh username pehle se hai — koi aur chunein.' });
  if (db.mobileToUser[mobile]) return res.status(409).json({ ok: false, error: 'Is mobile se account pehle se hai — Login karein (Username-Password ya Mobile OTP).' });

  const salt = crypto.randomBytes(8).toString('hex');
  const u = {
    username, name, mobile,
    passwordHash: sha256(password, salt), salt,
    avatar: '\u{1F4DA}', premium: null, freeUsed: 0,
    createdAt: new Date().toISOString(),
  };
  const token = issueToken(u);
  db.users[username] = u;
  db.mobileToUser[mobile] = username;
  saveDB(db);
  res.json({ ok: true, token, user: publicUser(u) });
});

// ---------- Login: username + password ----------
app.post('/api/login', (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').trim().toLowerCase();
  const password = String(b.password || '');
  const db = loadDB();
  const u = db.users[username];
  if (!u || !u.passwordHash || sha256(password, u.salt) !== u.passwordHash) {
    return res.status(401).json({ ok: false, error: 'Username ya password galat hai.' });
  }
  const token = issueToken(u);
  saveDB(db);
  res.json({ ok: true, token, user: publicUser(u) });
});

// ---------- Mobile + OTP ----------
app.post('/api/send-otp', (req, res) => {
  // The existing OTP is shown in the response itself. Allow it for test mode
  // only: in live mode it would let anyone take over a paid mobile account.
  if (/^rzp_live_/.test(loadConfig().razorpayKeyId)) {
    return res.status(503).json({ ok: false,
      error: 'Live payments me demo OTP band hai. Username-Password se login karein; OTP ke liye real SMS gateway setup karein.' });
  }
  const b = req.body || {};
  const phone = String(b.phone || '').replace(/\D/g, '');
  const name = String(b.name || '').trim().slice(0, 30);
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ ok: false, error: 'Valid 10-digit Indian mobile number daalein.' });
  if (name.length < 2) return res.status(400).json({ ok: false, error: 'Naam likhna zaroori hai (kam se kam 2 akshar).' });

  const now = Date.now();
  let rec = otpStore.get(phone);
  if (rec && rec.windowExp > now && rec.count >= 5) {
    return res.status(429).json({ ok: false, error: 'Bahut zyada OTP requests. 10 minute baad try karein.' });
  }
  if (!rec || rec.windowExp <= now) rec = { count: 0, windowExp: now + 10 * 60 * 1000 };
  rec.count++;
  const code = String(Math.floor(100000 + Math.random() * 900000));
  rec.hash = sha256(code, 'otp');
  rec.exp = now + 5 * 60 * 1000;
  rec.attempts = 0;
  rec.name = name;
  otpStore.set(phone, rec);
  const sms = sendOtpSms(phone, code);
  res.json({ ok: true, demoOtp: sms.demoOtp });
});

app.post('/api/verify-otp', (req, res) => {
  if (/^rzp_live_/.test(loadConfig().razorpayKeyId)) {
    return res.status(503).json({ ok: false, error: 'Live mode me demo OTP band hai; Username-Password se login karein.' });
  }
  const b = req.body || {};
  const phone = String(b.phone || '').replace(/\D/g, '');
  const otp = String(b.otp || '').replace(/\D/g, '');
  const rec = otpStore.get(phone);
  if (!rec) return res.status(400).json({ ok: false, error: 'Pehle OTP bhejein.' });
  if (Date.now() > rec.exp) { otpStore.delete(phone); return res.status(400).json({ ok: false, error: 'OTP expire ho gaya. Naya OTP bhejein.' }); }
  rec.attempts++;
  if (rec.attempts > 5) { otpStore.delete(phone); return res.status(429).json({ ok: false, error: 'Bahut zyada galat attempts. Naya OTP bhejein.' }); }
  if (sha256(otp, 'otp') !== rec.hash) return res.status(400).json({ ok: false, error: 'Galat OTP. Dobara try karein.' });
  otpStore.delete(phone);

  const db = loadDB();
  let u = findUserByMobile(db, phone);
  if (!u) {
    let username = phone;
    let n = 1;
    while (db.users[username]) { username = phone + '_' + n; n++; }
    u = { username, name: rec.name || 'Student', mobile: phone, passwordHash: '', salt: '', avatar: '\u{1F4DA}', premium: null, freeUsed: 0, createdAt: new Date().toISOString() };
    db.users[username] = u;
    db.mobileToUser[phone] = username;
  } else if (rec.name) {
    u.name = rec.name;
  }
  const token = issueToken(u);
  saveDB(db);
  res.json({ ok: true, token, user: publicUser(u) });
});

// ---------- Session: /api/me (login ke baad premium + credits wapas) ----------
app.post('/api/me', (req, res) => {
  const b = req.body || {};
  const db = loadDB();
  const u = findUserByToken(db, b.token);
  if (!u) return res.status(401).json({ ok: false, error: 'Session expire ho gaya. Dobara login karein.' });
  res.json({ ok: true, user: publicUser(u) });
});

// ---------- Profile save (token required) ----------
app.post('/api/save-profile', (req, res) => {
  const b = req.body || {};
  const db = loadDB();
  const u = findUserByToken(db, b.token);
  if (!u) return res.status(401).json({ ok: false, error: 'Login valid nahi hai. Dobara login karein.' });
  if (typeof b.name === 'string' && b.name.trim().length >= 2) u.name = b.name.trim().slice(0, 30);
  if (typeof b.avatar === 'string' && b.avatar.length <= 8) u.avatar = b.avatar;
  saveDB(db);
  res.json({ ok: true, user: publicUser(u) });
});

// ---------- Free credit gate (quiz se pehle — server-side STRICT) ----------
app.post('/api/use-credit', (req, res) => {
  const b = req.body || {};
  const db = loadDB();
  const u = findUserByToken(db, b.token);
  if (!u) return res.status(401).json({ ok: false, error: 'Quiz ke liye login zaroori hai.' });
  if (premiumActive(u)) return res.json({ ok: true, unlimited: true, user: publicUser(u) });
  const used = u.freeUsed || 0;
  if (used >= 3) {
    return res.status(402).json({ ok: false, reason: 'no_credits', error: 'Aapke 3 free tests poore ho gaye. Unlimited ke liye Premium lein.', user: publicUser(u) });
  }
  u.freeUsed = used + 1;
  saveDB(db);
  res.json({ ok: true, remaining: 3 - u.freeUsed, user: publicUser(u) });
});

// ---------- start ----------
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('PadhaQ server running on port ' + PORT);
    const cfg = loadConfig();
    console.log('Razorpay ready: ' + (!!(cfg.razorpayKeyId && cfg.razorpayKeySecret)));
    console.log('Gemini key set: ' + (!!cfg.geminiApiKey));
  });
}

module.exports = app;
