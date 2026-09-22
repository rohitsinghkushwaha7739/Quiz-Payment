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
app.post('/api/verify-payment', (req, res) => {
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
  payments.unshift({
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    plan: planKey,
    planLabel: (PLANS[planKey] || {}).label || '',
    phone: String(b.phone || '').replace(/\D/g, ''),
    verifiedAt: new Date().toISOString(),
  });
  savePayments(payments);

  res.json({ verified: true, paymentId: razorpay_payment_id, planLabel: (PLANS[planKey] || {}).label || '' });
});

// ---------- start ----------
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('AI Quiz server running on port ' + PORT);
    const cfg = loadConfig();
    console.log('Razorpay ready: ' + (!!(cfg.razorpayKeyId && cfg.razorpayKeySecret)));
    console.log('Gemini key set: ' + (!!cfg.geminiApiKey));
  });
}

module.exports = app;
