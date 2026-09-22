/**
 * AI Quiz Notes — Payment + Config Server
 *
 * Kya karta hai:
 *  1. App serve karta hai (public/index.html)
 *  2. /api/create-order    -> Razorpay order banata hai
 *  3. /api/verify-payment  -> SERVER-SIDE HMAC signature verify karta hai
 *     (yahi wahi step hai jahan koi bhi fake UTR / fake signature kabhi pass nahi hota)
 *  4. /api/app-config      -> Gemini key + Razorpay status app ko bhejta hai
 *
 * Keys: quiz-app/config.json me daalein (ya environment variables me).
 *   config.json:  { "razorpayKeyId": "rzp_test_...", "razorpayKeySecret": "...", "geminiApiKey": "AIza..." }
 *   env:          RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, GEMINI_API_KEY
 */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.join(__dirname, 'config.json');
const DATA_DIR = path.join(__dirname, 'data');
const PAYMENTS_PATH = path.join(DATA_DIR, 'payments.json');

const PLANS = {
  '49':  { label: '1 Month',  months: 1,  amount: 49 },
  '199': { label: '6 Months', months: 6,  amount: 199 },
  '299': { label: '1 Year',   months: 12, amount: 299 },
};

// ---------- config + storage helpers ----------
function loadConfig() {
  let fileCfg = {};
  try { fileCfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) || {}; } catch (e) { /* no config yet */ }
  return {
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || fileCfg.razorpayKeyId || '',
    razorpayKeySecret: process.env.RAZORPAY_KEY_SECRET || fileCfg.razorpayKeySecret || '',
    geminiApiKey: process.env.GEMINI_API_KEY || fileCfg.geminiApiKey || '',
    adminKey: process.env.ADMIN_KEY || fileCfg.adminKey || 'PadhaQ@Rohit',
  };
}

function loadPayments() {
  try { return JSON.parse(fs.readFileSync(PAYMENTS_PATH, 'utf8')) || []; } catch (e) { return []; }
}
function savePayments(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(PAYMENTS_PATH, JSON.stringify(list, null, 2));
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

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- routes ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// App ko batata hai ki keys set hain ya nahi (UI warning ke liye)
app.get('/api/app-config', (req, res) => {
  const cfg = loadConfig();
  res.json({
    geminiApiKey: cfg.geminiApiKey || '',
    razorpayReady: !!(cfg.razorpayKeyId && cfg.razorpayKeySecret),
    razorpayKeyId: /^rzp_(test|live)_/.test(cfg.razorpayKeyId) ? cfg.razorpayKeyId : '',
  });
});

// Step 1: Razorpay order banao (amount hamesha SERVER side fix hota hai)
app.post('/api/create-order', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.razorpayKeyId || !cfg.razorpayKeySecret) {
    return res.status(503).json({ error: 'Setup pending: config.json me Razorpay keys add karein.' });
  }
  const plan = PLANS[String((req.body || {}).plan || '49')];
  if (!plan) return res.status(400).json({ error: 'Invalid plan' });
  const phone = String((req.body || {}).phone || '').replace(/\D/g, '');

  try {
    const r = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(cfg.razorpayKeyId + ':' + cfg.razorpayKeySecret).toString('base64'),
      },
      body: JSON.stringify({
        amount: plan.amount * 100, // paise
        currency: 'INR',
        receipt: 'quiz_' + Date.now(),
        notes: { plan: plan.label, phone },
      }),
    });
    const data = await r.json();
    if (!r.ok || !data.id) {
      return res.status(502).json({ error: 'Razorpay order create nahi hua', detail: data });
    }
    res.json({
      orderId: data.id,
      amount: plan.amount,
      currency: 'INR',
      keyId: cfg.razorpayKeyId,
      planLabel: plan.label,
    });
  } catch (e) {
    res.status(500).json({ error: 'Order creation error: ' + e.message });
  }
});

// Step 2: SERVER-SIDE verification (yahi asli "payment check" hai)
// Razorpay signature = HMAC-SHA256(order_id + "|" + payment_id, key_secret)
// Fake UTR / ghar se bana signature yahan KABHI accept nahi hota.
app.post('/api/verify-payment', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.razorpayKeySecret) {
    return res.status(503).json({ error: 'Setup pending: Razorpay key_secret missing.' });
  }
  const b = req.body || {};
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = b;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ verified: false, error: 'Payment details missing' });
  }

  const expected = crypto
    .createHmac('sha256', cfg.razorpayKeySecret)
    .update(razorpay_order_id + '|' + razorpay_payment_id)
    .digest('hex');

  let ok = false;
  try {
    ok = crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(String(razorpay_signature), 'hex'));
  } catch (e) { ok = false; }

  if (!ok) {
    return res.json({ verified: false, error: 'Signature mismatch — payment verify NAHI hui.' });
  }

  // Idempotency: same payment dobara submit ho toh dobara entry mat banao
  const payments = loadPayments();
  if (payments.some(p => p.razorpay_payment_id === razorpay_payment_id)) {
    return res.json({ verified: true, duplicate: true, paymentId: razorpay_payment_id });
  }

  const planKey = String(b.plan || '');

  // Razorpay se ASLI payment details fetch (UTR, method, VPA, contact) — admin panel ke liye
  let payDetails = { utr: '', method: '', vpa: '', payerContact: '', payerEmail: '' };
  try {
    const pr = await fetch('https://api.razorpay.com/v1/payments/' + encodeURIComponent(razorpay_payment_id), {
      headers: { Authorization: 'Basic ' + Buffer.from(cfg.razorpayKeyId + ':' + cfg.razorpayKeySecret).toString('base64') },
    });
    if (pr.ok) {
      const pj = await pr.json();
      payDetails = {
        utr: (pj.acquirer_data && (pj.acquirer_data.bank_transaction_id || pj.acquirer_data.rrn)) || '',
        method: pj.method || '',
        vpa: pj.vpa || '',
        payerContact: pj.contact || '',
        payerEmail: pj.email || '',
      };
    }
  } catch (e) { /* network issue — details baad me mil jayengi */ }

  const record = {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    plan: planKey,
    planLabel: (PLANS[planKey] || {}).label || '',
    amount: Number(planKey) || 0,
    phone: String(b.phone || '').replace(/\D/g, ''),
    name: String(b.name || ''),
    username: String(b.username || ''),
    whatsapp: String(b.phone || '').replace(/\D/g, ''),
    utr: payDetails.utr,
    method: payDetails.method,
    vpa: payDetails.vpa,
    payerContact: payDetails.payerContact,
    payerEmail: payDetails.payerEmail,
    verifiedAt: new Date().toISOString(),
  };
  payments.unshift(record);
  savePayments(payments);

  // PREMIUM account (username/mobile) se bandho — login karte hi wapas milega
  const db = loadDB();
  const pu = findUserByMobile(db, String(b.phone || '').replace(/\D/g, ''));
  const months = PLAN_MONTHS[planKey] || 1;
  const expMs = Date.now() + Math.round(months * 30.44 * 24 * 3600 * 1000);
  if (pu) {
    pu.premium = {
      plan: planKey,
      planLabel: (PLANS[planKey] || {}).label || '',
      paymentId: razorpay_payment_id,
      activatedAt: Date.now(),
      expiresAt: expMs,
    };
    pu.payments = pu.payments || [];
    pu.payments.unshift(record);
    saveDB(db);
  }

  res.json({ verified: true, paymentId: razorpay_payment_id, planLabel: (PLANS[planKey] || {}).label || '', expiresAt: expMs, user: pu ? publicUser(pu) : null });
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
const PLAN_MONTHS = { '49': 1, '199': 6, '299': 12 };

function loadDB() {
  try {
    const db = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
    if (db && db.users) return db;
  } catch (e) { /* no db yet */ }
  return { users: {}, mobileToUser: {} };
}
function saveDB(db) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_PATH, JSON.stringify(db, null, 2));
}
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

// ---------- ADMIN: payments list (naam, WhatsApp, UTR, Payment ID) ----------
app.post('/api/admin/payments', (req, res) => {
  const cfg = loadConfig();
  const key = String((req.body || {}).adminKey || '');
  const want = String(cfg.adminKey || 'PadhaQ@Rohit');
  let okKey = false;
  try { okKey = key.length === want.length && crypto.timingSafeEqual(Buffer.from(key), Buffer.from(want)); } catch (e) { okKey = false; }
  if (!okKey) return res.status(401).json({ ok: false, error: 'Admin key galat hai.' });

  const db = loadDB();
  const rows = [];
  Object.values(db.users).forEach(u => (u.payments || []).forEach(p => rows.push({
    ...p,
    name: p.name || u.name, username: p.username || u.username,
    whatsapp: p.whatsapp || u.mobile, phone: p.phone || u.mobile,
  })));
  const seen = new Set(rows.map(r => r.razorpay_payment_id));
  loadPayments().forEach(p => { if (!seen.has(p.razorpay_payment_id)) rows.push(p); });
  rows.sort((a, b) => String(b.verifiedAt || '').localeCompare(String(a.verifiedAt || '')));
  const totalAmount = rows.reduce((s, r) => s + (Number(r.amount) || 0), 0);
  res.json({ ok: true, rows, count: rows.length, totalAmount });
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
