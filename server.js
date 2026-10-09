'use strict';
/* =====================================================================
   PayX backend  (Node 18+, Express, Firebase Realtime Database via Admin SDK)
   - FamApi key lives ONLY in env (FAMAPI_KEY), never in the browser
   - All order creation / verification / crediting / webhooks happen here
   - Serves public/index.html (merchant + checkout) and public/admin.html (/admin)
   ===================================================================== */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const { promisify } = require('util');
const admin = require('firebase-admin');
const scrypt = promisify(crypto.scrypt);

/* ---------- ENV ---------- */
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.FIREBASE_DB_URL || 'https://getway-2ed8b-default-rtdb.firebaseio.com';
const FAM_KEY = process.env.FAMAPI_KEY || '';
const FAM_BASE = (process.env.FAMAPI_BASE || 'https://famapi-orcin.vercel.app').replace(/\/$/, '');
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

if (TOKEN_SECRET.length < 16) { console.error('FATAL: set TOKEN_SECRET env var (16+ random characters).'); process.exit(1); }
if (!FAM_KEY) console.warn('WARNING: FAMAPI_KEY is not set. Payments cannot be created.');

function loadServiceAccount() {
  const raw = (process.env.FIREBASE_SERVICE_ACCOUNT || '').trim();
  if (!raw) { console.error('FATAL: set FIREBASE_SERVICE_ACCOUNT env var (service account JSON, or its base64).'); process.exit(1); }
  try { return JSON.parse(raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8')); }
  catch (e) { console.error('FATAL: FIREBASE_SERVICE_ACCOUNT is not valid JSON/base64.'); process.exit(1); }
}
admin.initializeApp({ credential: admin.credential.cert(loadServiceAccount()), databaseURL: DB_URL });
const db = admin.database();

const DEFAULTS = {
  siteName: 'PayX', tagline: "India's Fastest and Secured Platform",
  feePercent: 2, minAmount: 1, maxAmount: 100000, expiryMin: 15,
  support: 'https://t.me/ShivamXoffical01', maintenance: false, paymentUpiId: ''
};

/* ---------- small utils ---------- */
const r2 = n => Math.round(n * 100) / 100;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const rid = (p, n) => p + Array.from(crypto.randomBytes(n), b => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 32]).join('');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const ok = (res, data = {}) => res.json({ success: true, ...data });
const fail = (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } });
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const ORDER_ID = /^PX[A-Z0-9]{6,24}$/;

let cfgCache = null, cfgAt = 0;
async function getCfg(force) {
  if (!force && cfgCache && Date.now() - cfgAt < 10000) return cfgCache;
  const s = (await db.ref('settings/config').get()).val() || {};
  cfgCache = { ...DEFAULTS, ...s }; delete cfgCache.famKey; delete cfgCache.famBase; cfgAt = Date.now();
  return cfgCache;
}

/* ---------- passwords & tokens ---------- */
async function hashPw(pw) { const salt = crypto.randomBytes(16).toString('hex'); const h = (await scrypt(pw, salt, 64)).toString('hex'); return `scrypt$${salt}$${h}`; }
async function checkPw(pw, stored, legacySeed) {
  if (!stored) return false;
  if (stored.startsWith('scrypt$')) { const [, salt, h] = stored.split('$'); return safeEq((await scrypt(pw, salt, 64)).toString('hex'), h); }
  return safeEq(sha256(pw + ':' + legacySeed), stored); // old SHA-256 format
}
const b64 = s => Buffer.from(s).toString('base64url');
function signToken(payload, ttlMs) {
  const body = b64(JSON.stringify({ ...payload, exp: Date.now() + ttlMs }));
  return body + '.' + crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
}
function readToken(t) {
  if (!t || typeof t !== 'string') return null;
  const [body, sig] = t.split('.'); if (!body || !sig) return null;
  if (!safeEq(sig, crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url'))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}
const bearer = req => (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

/* ---------- rate limit ---------- */
const hits = new Map();
const limit = (name, max, winMs) => (req, res, next) => {
  const k = name + ':' + req.ip, now = Date.now(); let h = hits.get(k);
  if (!h || now > h.reset) { h = { n: 0, reset: now + winMs }; hits.set(k, h); }
  if (++h.n > max) return fail(res, 429, 'RATE_LIMITED', 'Too many requests. Please slow down.');
  next();
};
setInterval(() => { const n = Date.now(); for (const [k, h] of hits) if (n > h.reset) hits.delete(k); }, 60000).unref();

/* ---------- FamApi ---------- */
let famBackoff = 0;
async function fam(p, opt = {}) {
  if (!FAM_KEY) return { success: false, error: { code: 'NOT_CONFIGURED', message: 'Payment provider is not configured.' } };
  if (Date.now() < famBackoff) return { success: false, error: { code: 'RATE_LIMITED', message: 'Provider busy, retrying shortly.' } };
  try {
    const r = await fetch(FAM_BASE + p, { ...opt, headers: { 'Content-Type': 'application/json', 'X-FamApi-Key': FAM_KEY }, signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    if (d && d.error && d.error.code === 'RATE_LIMITED') famBackoff = Date.now() + 20000;
    return d;
  } catch (e) { return { success: false, error: { code: 'NETWORK', message: 'Payment provider unreachable.' } }; }
}

/* ---------- order logic ---------- */
const cleanOrder = o => { const { lock, famOrderId, ...rest } = o; return rest; };
const pubOrder = o => ({ id: o.id, amount: o.amount, status: o.status, merchantName: o.merchantName, upiId: o.upiId || '', expiresAt: o.expiresAt, redirectUrl: o.redirectUrl || '', ref: o.ref || '', paidAt: o.paidAt || 0 });
const safeUser = u => { const { pass, paidOrderIds, ...rest } = u; return rest; };
const checkoutUrl = (req, id) => (PUBLIC_URL || `${req.protocol}://${req.get('host')}`) + '/#/pay/' + id;

function safeUrl(u) {
  try {
    const x = new URL(u); if (!/^https?:$/.test(x.protocol)) return false;
    const h = x.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.local') || h === '::1' || h === '[::1]') return false;
    if (/^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) return false;
    return true;
  } catch (e) { return false; }
}

async function createOrder(m, amount, x = {}) {
  const cfg = await getCfg();
  amount = r2(Number(amount));
  if (!isFinite(amount) || amount < cfg.minAmount || amount > cfg.maxAmount) { const e = new Error(`Amount must be between ₹${cfg.minAmount} and ₹${cfg.maxAmount}`); e.status = 400; e.code = 'VALIDATION_ERROR'; throw e; }
  if (cfg.maintenance) { const e = new Error('PayX is under maintenance. Try again shortly.'); e.status = 503; e.code = 'MAINTENANCE'; throw e; }
  if (m.status === 'blocked') { const e = new Error('This merchant account is blocked.'); e.status = 403; e.code = 'BLOCKED'; throw e; }
  const id = rid('PX', 12), fee = r2(amount * cfg.feePercent / 100);
  const o = {
    id, merchantId: m.id, merchantName: m.name, amount, fee, net: r2(amount - fee),
    ref: String(x.ref || '').slice(0, 100), note: String(x.note || '').slice(0, 200),
    redirectUrl: x.redirectUrl && safeUrl(x.redirectUrl) ? String(x.redirectUrl).slice(0, 2000) : '',
    source: x.source || 'link', status: 'created', createdAt: Date.now(), expiresAt: Date.now() + 864e5
  };
  await db.ref('orders/' + id).set(o);
  return o;
}

async function finalizeSuccess(id) {
  const ref = db.ref('orders/' + id);
  const tx = await ref.transaction(o => {
    if (!o) return o;
    if (o.status === 'success') return;
    if (o.status !== 'pending') return o;
    o.status = 'success';
    o.paidAt = Date.now();
    return o;
  });
  if (!tx.committed || !tx.snapshot.exists()) return false;
  const o = tx.snapshot.val();
  if (o.status !== 'success' || !o.merchantId) return false;

  // The single FAM key is server-side only, so the actual customer payment
  // is collected into the gateway owner's/provider account. After FAM reports
  // success, PayX credits the merchant's internal wallet exactly by the paid
  // amount (fee is tracked separately and is NOT deducted from wallet credit).
  const creditRef = db.ref('users/' + o.merchantId);
  const creditTx = await creditRef.transaction(u => {
    if (!u) return u;
    const paidOrders = u.paidOrderIds || {};
    if (paidOrders[o.id]) return u; // idempotent wallet credit
    paidOrders[o.id] = true;
    u.paidOrderIds = paidOrders;
    u.balance = r2((u.balance || 0) + Number(o.amount || 0));
    u.totalReceived = r2((u.totalReceived || 0) + Number(o.amount || 0));
    u.totalFees = r2((u.totalFees || 0) + Number(o.fee || 0));
    u.successCount = (u.successCount || 0) + 1;
    return u;
  });

  if (creditTx.committed && creditTx.snapshot.exists()) {
    const already = !!(tx.snapshot.val().walletCreditedAt);
    if (!already) await ref.update({ walletCreditedAt: Date.now() });
    await db.ref('walletLedger/' + o.merchantId + '/' + o.id).set({
      id: o.id,
      merchantId: o.merchantId,
      type: 'payment',
      direction: 'credit',
      amount: Number(o.amount || 0),
      fee: Number(o.fee || 0),
      reference: o.ref || o.id,
      orderId: o.id,
      note: 'Payment received via PayX',
      status: 'success',
      createdAt: o.paidAt || Date.now()
    });
    sendHook(o).catch(() => {});
    return true;
  }
  return false;
}

const setFinal = (id, s) => db.ref('orders/' + id).transaction(o => { if (!o) return o; if (o.status === 'success' || o.status === s) return; o.status = s; o.closedAt = Date.now(); return o; });

async function sendHook(o) {
  const u = (await db.ref('users/' + o.merchantId).get()).val();
  if (!u || !u.webhookUrl || !safeUrl(u.webhookUrl)) return;
  const body = JSON.stringify({ event: 'payment.success', orderId: o.id, reference: o.ref || '', amount: o.amount, net: o.net, currency: 'INR', status: 'success', paidAt: o.paidAt });
  const sig = crypto.createHmac('sha256', u.apiKey).update(body).digest('hex');
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(u.webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PayX-Signature': sig }, body, signal: AbortSignal.timeout(8000) });
      if (r.ok) { await db.ref('orders/' + o.id).update({ webhookStatus: 'delivered' }); return; }
    } catch (e) {}
    await sleep(2000 * (i + 1));
  }
  await db.ref('orders/' + o.id).update({ webhookStatus: 'failed' });
}
const checkedAt = new Map();
async function refresh(o) {
  if (o.status !== 'pending' || !o.famOrderId) return o;
  if (Date.now() - (checkedAt.get(o.id) || 0) < 2500) return o;
  checkedAt.set(o.id, Date.now());
  const d = await fam('/api/v1/orders/' + o.famOrderId);
  if (d.success && d.order) {
    const s = d.order.status;
    if (s === 'success') { if (Number(d.order.amount) === Number(o.amount)) await finalizeSuccess(o.id); else console.warn('Amount mismatch on', o.id); }
    else if (s === 'failed' || s === 'expired' || s === 'refunded') await setFinal(o.id, s === 'refunded' ? 'failed' : s);
    else if (Date.now() > o.expiresAt) await setFinal(o.id, 'expired');
  }
  return (await db.ref('orders/' + o.id).get()).val() || o;
}
setInterval(() => { const n = Date.now(); for (const [k, t] of checkedAt) if (n - t > 120000) checkedAt.delete(k); }, 60000).unref();

/* ---------- background workers (so payments confirm even if the customer closes the tab) ---------- */
let sweeping = false;
async function sweep() {
  if (sweeping || Date.now() < famBackoff) return; sweeping = true;
  try {
    const snap = await db.ref('orders').orderByChild('status').equalTo('pending').limitToFirst(100).get();
    const list = []; snap.forEach(c => { list.push(c.val()); });
    list.sort((a, b) => (checkedAt.get(a.id) || 0) - (checkedAt.get(b.id) || 0));
    for (const o of list.slice(0, 12)) { await refresh(o); if (Date.now() < famBackoff) break; }
  } finally { sweeping = false; }
}
async function expireStale() {
  const snap = await db.ref('orders').orderByChild('status').equalTo('created').limitToFirst(300).get();
  const now = Date.now(), jobs = [];
  snap.forEach(c => { const o = c.val(); if (o.expiresAt < now) jobs.push(setFinal(o.id, 'expired')); });
  await Promise.all(jobs);
}
setInterval(() => sweep().catch(e => console.error('sweep:', e.message)), 10000).unref();
setInterval(() => expireStale().catch(e => console.error('expire:', e.message)), 600000).unref();

/* ---------- auth middleware ---------- */
const mAuth = ah(async (req, res, next) => {
  const p = readToken(bearer(req));
  if (!p || p.r !== 'm') return fail(res, 401, 'UNAUTHORIZED', 'Please log in again.');
  const u = (await db.ref('users/' + p.u).get()).val();
  if (!u || String(u.pass).slice(-8) !== p.pv) return fail(res, 401, 'UNAUTHORIZED', 'Session expired. Please log in again.');
  if (u.status === 'blocked') return fail(res, 403, 'BLOCKED', 'Your account is blocked. Contact support.');
  req.user = u; next();
});
const aAuth = ah(async (req, res, next) => {
  const p = readToken(bearer(req));
  if (!p || p.r !== 'a') return fail(res, 401, 'UNAUTHORIZED', 'Please sign in again.');
  const a = (await db.ref('settings/admin').get()).val();
  if (!a || String(a.pass).slice(-8) !== p.pv) return fail(res, 401, 'UNAUTHORIZED', 'Session expired. Please sign in again.');
  req.admin = a; next();
});
const keyAuth = ah(async (req, res, next) => {
  const k = String(req.headers['x-payx-key'] || '').trim();
  if (!k) return fail(res, 401, 'INVALID_API_KEY', 'Missing X-PayX-Key header.');
  if (!/^[a-z0-9_]{10,80}$/.test(k)) return fail(res, 401, 'INVALID_API_KEY', 'Invalid API key.');
  const uid = (await db.ref('apiKeys/' + k).get()).val();
  const u = uid && (await db.ref('users/' + uid).get()).val();
  if (!u) return fail(res, 401, 'INVALID_API_KEY', 'Invalid API key.');
  if (u.status === 'blocked') return fail(res, 403, 'BLOCKED', 'This merchant account is blocked.');
  req.user = u; next();
});

/* ---------- app ---------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors(ORIGINS.length ? { origin: ORIGINS } : { origin: true }));
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }); if (req.path.startsWith('/admin')) res.set('X-Frame-Options', 'DENY'); next(); });
app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

/* ----- public ----- */
app.get('/api/config/public', ah(async (req, res) => { const c = await getCfg(); ok(res, { config: { siteName: c.siteName, tagline: c.tagline, support: c.support, feePercent: c.feePercent, minAmount: c.minAmount, maxAmount: c.maxAmount, maintenance: c.maintenance, paymentUpiId: c.paymentUpiId || '', aiEnabled: c.aiEnabled !== false, aiWelcome: c.aiWelcome || 'Hi! I am PayX AI. Ask me about API integration, payment status, webhooks, wallet or Premium membership.', premiumEnabled: c.premiumEnabled !== false, premiumPrice: Number(c.premiumPrice ?? 399), premiumDays: Number(c.premiumDays ?? 30), premiumDescription: c.premiumDescription || 'More benefits for growing merchants.', premiumBenefit1: c.premiumBenefit1 || 'Priority support', premiumBenefit2: c.premiumBenefit2 || 'Faster support response', premiumBenefit3: c.premiumBenefit3 || 'Premium merchant tools' } }); }));

app.post('/api/auth/signup', limit('auth', 10, 60000), ah(async (req, res) => {
  const name = String(req.body.name || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (name.length < 2 || name.length > 60) return fail(res, 400, 'VALIDATION_ERROR', 'Enter your name (2 to 60 characters).');
  if (!/^[^\s@\/#$\[\]]+@[^\s@\/#$\[\]]+\.[^\s@\/#$\[\]]+$/.test(email) || email.length > 120) return fail(res, 400, 'VALIDATION_ERROR', 'Enter a valid email address.');
  if (pw.length < 6 || pw.length > 100) return fail(res, 400, 'VALIDATION_ERROR', 'Password needs at least 6 characters.');
  const id = rid('M', 10), key = email.replace(/\./g, ',');
  const tx = await db.ref('emailIndex/' + key).transaction(v => v ? undefined : id);
  if (!tx.committed) return fail(res, 409, 'EMAIL_EXISTS', 'This email is already registered. Log in instead.');
  const apiKey = 'px_live_' + rid('', 28).toLowerCase(), pass = await hashPw(pw);
  const u = { id, name, email, pass, apiKey, balance: 0, totalReceived: 0, successCount: 0, status: 'active', webhookUrl: '', createdAt: Date.now() };
  await db.ref().update({ ['users/' + id]: u, ['apiKeys/' + apiKey]: id });
  ok(res, { token: signToken({ r: 'm', u: id, pv: pass.slice(-8) }, 30 * 864e5), user: safeUser(u) });
}));
app.post('/api/auth/login', limit('auth', 10, 60000), ah(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const emailKey = email.replace(/\./g, ',');
  let id = email && (await db.ref('emailIndex/' + emailKey).get()).val();
  let u = id && (await db.ref('users/' + id).get()).val();

  // Backward-compatible login: if an older account has no emailIndex entry,
  // find it by the stored email and repair the index for future logins.
  if (!u && email) {
    const snap = await db.ref('users').get();
    snap.forEach(c => {
      if (!u) {
        const v = c.val() || {};
        if (String(v.email || '').trim().toLowerCase() === email) { id = c.key; u = v; }
      }
    });
    if (u && id) await db.ref('emailIndex/' + emailKey).set(id);
  }

  if (!u || !(await checkPw(pw, u.pass, u.email))) return fail(res, 401, 'BAD_LOGIN', 'Wrong email or password.');
  if (u.status === 'blocked') return fail(res, 403, 'BLOCKED', 'Your account is blocked. Contact support.');
  if (!u.pass.startsWith('scrypt$')) { u.pass = await hashPw(pw); await db.ref('users/' + id + '/pass').set(u.pass); }
  ok(res, { token: signToken({ r: 'm', u: id, pv: u.pass.slice(-8) }, 30 * 864e5), user: safeUser(u) });
}));

app.post('/api/checkout/create', limit('cocreate', 30, 60000), ah(async (req, res) => {
  const m = typeof req.body.merchantId === 'string' && /^M[A-Z0-9]{6,20}$/.test(req.body.merchantId) && (await db.ref('users/' + req.body.merchantId).get()).val();
  if (!m) return fail(res, 404, 'NOT_FOUND', 'Merchant not found.');
  const o = await createOrder(m, req.body.amount, { ref: req.body.ref, redirectUrl: req.body.redirect, source: 'link' });
  ok(res, { orderId: o.id });
}));
app.get('/api/checkout/:id', limit('coget', 90, 60000), ah(async (req, res) => {
  if (!ORDER_ID.test(req.params.id)) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  let o = (await db.ref('orders/' + req.params.id).get()).val();
  if (!o) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  o = await refresh(o);
  ok(res, { order: pubOrder(o) });
}));
app.post('/api/checkout/:id/prepare', limit('coprep', 20, 60000), ah(async (req, res) => {
  if (!ORDER_ID.test(req.params.id)) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  const cfg = await getCfg();
  if (cfg.maintenance) return fail(res, 503, 'MAINTENANCE', 'PayX is temporarily under maintenance. Please try again in a few minutes.');
  const ref = db.ref('orders/' + req.params.id); let o = (await ref.get()).val();
  if (!o) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  if (o.status !== 'created') return ok(res, { order: pubOrder(o) });
  if (Date.now() > o.expiresAt) { await setFinal(o.id, 'expired'); return ok(res, { order: pubOrder({ ...o, status: 'expired' }) }); }
  const lock = await ref.child('lock').transaction(v => (v && Date.now() - v < 30000) ? undefined : Date.now());
  if (!lock.committed) return ok(res, { order: pubOrder((await ref.get()).val()) });
  const d = await fam('/api/v1/orders', { method: 'POST', body: JSON.stringify({ amount: o.amount, reference: o.id }) });
  if (!d.success || !d.order) { await ref.child('lock').remove(); return fail(res, 502, 'PROVIDER_ERROR', (d.error && d.error.message) || 'Payment provider did not respond. Please try again.'); }
  await ref
.update({
    famOrderId: d.order.id,
    upiId: cfg.paymentUpiId || d.order.upiId || '',
    status: 'pending',
    startedAt: Date.now(),
    expiresAt: Date.now() + cfg.expiryMin * 60000
  });
  ok(res, { order: pubOrder((await ref.get()).val()) });
}));

/* ----- merchant panel ----- */
app.get('/api/me', mAuth, ah(async (req, res) => {
  const [snap, led, wd] = await Promise.all([
    db.ref('orders').orderByChild('merchantId').equalTo(req.user.id).get(),
    db.ref('walletLedger/' + req.user.id).limitToLast(200).get(),
    db.ref('withdrawals').orderByChild('merchantId').equalTo(req.user.id).limitToLast(100).get()
  ]);
  const l = [], wallet = [], withdrawals = [];
  snap.forEach(c => { l.push(cleanOrder(c.val())); });
  led.forEach(c => { wallet.push(c.val()); });
  wd.forEach(c => { withdrawals.push(c.val()); });
  l.sort((a, b) => b.createdAt - a.createdAt);
  wallet.sort((a, b) => b.createdAt - a.createdAt);
  withdrawals.sort((a, b) => b.createdAt - a.createdAt);
  const u = safeUser(req.user);
  u.pendingBalance = withdrawals.filter(x => x.status === 'pending').reduce((n, x) => n + Number(x.amount || 0), 0);
  ok(res, { user: u, orders: l.slice(0, 300), wallet: wallet.slice(0, 200), withdrawals: withdrawals.slice(0, 100) });
}));
app.post('/api/me/withdrawals', mAuth, limit('withdraw', 10, 60000), ah(async (req, res) => {
  const amount = r2(Number(req.body.amount));
  const upiId = String(req.body.upiId || '').trim().slice(0, 120);
  if (!isFinite(amount) || amount <= 0 || amount > 100000000) return fail(res, 400, 'VALIDATION_ERROR', 'Enter a valid withdrawal amount.');
  if (!upiId || upiId.length < 3) return fail(res, 400, 'VALIDATION_ERROR', 'Enter a valid UPI ID.');
  const id = rid('WD', 12);
  const userRef = db.ref('users/' + req.user.id);
  const tx = await userRef.transaction(u => {
    if (!u) return u;
    if (Number(u.balance || 0) < amount) return;
    u.balance = r2(Number(u.balance || 0) - amount);
    return u;
  });
  if (!tx.committed) return fail(res, 400, 'INSUFFICIENT_BALANCE', 'Insufficient wallet balance.');
  const w = { id, merchantId: req.user.id, merchantName: req.user.name, amount, upiId, status: 'pending', createdAt: Date.now() };
  try {
    await db.ref('withdrawals/' + id).set(w);
    await db.ref('walletLedger/' + req.user.id + '/' + id).set({ id, merchantId: req.user.id, type: 'withdrawal', direction: 'debit', amount, reference: id, note: 'Withdrawal request', status: 'pending', createdAt: w.createdAt });
  } catch (e) {
    await userRef.transaction(u => { if (!u) return u; u.balance = r2(Number(u.balance || 0) + amount); return u; });
    throw e;
  }
  ok(res, { withdrawal: w });
}));
app.put('/api/me', mAuth, ah(async (req, res) => {
  const name = String(req.body.name || '').trim(), w = String(req.body.webhookUrl || '').trim();
  if (name.length < 2 || name.length > 60) return fail(res, 400, 'VALIDATION_ERROR', 'Enter your name.');
  if (w && (w.length > 500 || !safeUrl(w))) return fail(res, 400, 'VALIDATION_ERROR', 'Webhook must be a public http(s) URL.');
  await db.ref('users/' + req.user.id).update({ name, webhookUrl: w }); ok(res);
}));
app.put('/api/me/password', mAuth, limit('pw', 10, 60000), ah(async (req, res) => {
  const pw = String(req.body.password || ''); if (pw.length < 6 || pw.length > 100) return fail(res, 400, 'VALIDATION_ERROR', 'Password needs at least 6 characters.');
  const pass = await hashPw(pw); await db.ref('users/' + req.user.id + '/pass').set(pass);
  ok(res, { token: signToken({ r: 'm', u: req.user.id, pv: pass.slice(-8) }, 30 * 864e5) });
}));
app.post('/api/me/apikey', mAuth, ah(async (req, res) => {
  const nk = 'px_live_' + rid('', 28).toLowerCase();
  await db.ref().update({ ['apiKeys/' + req.user.apiKey]: null, ['apiKeys/' + nk]: req.user.id, ['users/' + req.user.id + '/apiKey']: nk });
  ok(res, { apiKey: nk });
}));
app.post('/api/me/orders', mAuth, limit('meorders', 60, 60000), ah(async (req, res) => {
  const o = await createOrder(req.user, req.body.amount, { ref: req.body.ref, note: req.body.note, source: 'link' });
  ok(res, { order: cleanOrder(o) });
}));

/* ----- merchant server-to-server API (X-PayX-Key) ----- */
const v1 = (req, o) => ({ id: o.id, amount: o.amount, currency: 'INR', reference: o.ref || '', status: o.status, createdAt: o.createdAt, paidAt: o.paidAt || null, checkoutUrl: checkoutUrl(req, o.id) });
app.post('/api/v1/orders', keyAuth, limit('v1create', 120, 60000), ah(async (req, res) => {
  const o = await createOrder(req.user, req.body.amount, { ref: req.body.reference, note: req.body.note, redirectUrl: req.body.redirectUrl, source: 'api' });
  res.status(201).json({ success: true, order: v1(req, o) });
}));
app.get('/api/v1/orders/:id', keyAuth, limit('v1get', 120, 60000), ah(async (req, res) => {
  if (!ORDER_ID.test(req.params.id)) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  let o = (await db.ref('orders/' + req.params.id).get()).val();
  if (!o || o.merchantId !== req.user.id) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  o = await refresh(o);
  ok(res, { order: v1(req, o) });
}));

/* ----- admin ----- */
app.post('/api/admin/login', limit('alogin', 8, 600000), ah(async (req, res) => {
  const u = String(req.body.username || '').trim(), p = String(req.body.password || '');
  const a = (await db.ref('settings/admin').get()).val();
  if (!a || !safeEq(a.user, u) || !(await checkPw(p, a.pass, a.user))) return fail(res, 401, 'BAD_LOGIN', 'Wrong username or password.');
  if (!a.pass.startsWith('scrypt$')) { a.pass = await hashPw(p); await db.ref('settings/admin/pass').set(a.pass); }
  ok(res, { token: signToken({ r: 'a', pv: a.pass.slice(-8) }, 12 * 3600e3) });
}));
app.get('/api/admin/data', aAuth, ah(async (req, res) => {
  const [us, os, wd, docs, promptsSnap, cfg] = await Promise.all([
    db.ref('users').get(),
    db.ref('orders').orderByChild('createdAt').limitToLast(500).get(),
    db.ref('withdrawals').orderByChild('createdAt').limitToLast(300).get(),
    db.ref('settings/apiDocs').orderByChild('order').get(),
    db.ref('settings/aiPrompts').orderByChild('order').get(),
    getCfg(true)
  ]);
  const users = [], orders = [], withdrawals = [], apiDocs = [], prompts = [];
  us.forEach(c => { users.push(safeUser(c.val())); });
  os.forEach(c => { orders.push(cleanOrder(c.val())); });
  wd.forEach(c => { withdrawals.push(c.val()); });
  docs.forEach(c => { apiDocs.push(c.val()); });
  promptsSnap.forEach(c => { prompts.push(c.val()); });
  users.sort((a, b) => b.createdAt - a.createdAt); orders.sort((a, b) => b.createdAt - a.createdAt); withdrawals.sort((a, b) => b.createdAt - a.createdAt);
  ok(res, { users, orders, config: cfg, famConfigured: !!FAM_KEY, merchantFamConfigured: false, withdrawals, topups: [], apiDocs, prompts });
}));
app.put('/api/admin/config', aAuth, ah(async (req, res) => {
  const b = req.body, n = x => Number(x);
  const v = { siteName: String(b.siteName || 'PayX').trim().slice(0, 40) || 'PayX', tagline: String(b.tagline || '').trim().slice(0, 120), support: String(b.support || '').trim().slice(0, 300), feePercent: n(b.feePercent), minAmount: n(b.minAmount), maxAmount: n(b.maxAmount), expiryMin: n(b.expiryMin), maintenance: !!b.maintenance, paymentUpiId: String(b.paymentUpiId ?? '').trim().slice(0, 120), aiEnabled: b.aiEnabled !== false, aiWelcome: String(b.aiWelcome || 'Hi! I am PayX AI. Ask me about API integration, payment status, webhooks, wallet or Premium membership.').slice(0, 500), premiumEnabled: b.premiumEnabled !== false, premiumPrice: n(b.premiumPrice ?? 399), premiumDays: n(b.premiumDays ?? 30), premiumDescription: String(b.premiumDescription || 'More benefits for growing merchants.').slice(0, 250), premiumBenefit1: String(b.premiumBenefit1 || 'Priority support').slice(0, 120), premiumBenefit2: String(b.premiumBenefit2 || 'Faster support response').slice(0, 120), premiumBenefit3: String(b.premiumBenefit3 || 'Premium merchant tools').slice(0, 120) };
  if ([v.feePercent, v.minAmount, v.maxAmount, v.expiryMin, v.premiumPrice, v.premiumDays].some(x => !isFinite(x) || x < 0) || v.minAmount > v.maxAmount || v.expiryMin < 1 || v.feePercent > 50 || v.premiumDays < 1 || v.premiumDays > 3650 || v.premiumPrice > 10000000) return fail(res, 400, 'VALIDATION_ERROR', 'Check the numeric settings, limits and membership duration.');
  await db.ref('settings/config').set(v); await getCfg(true); ok(res);
}));
app.post('/api/admin/test-fam', aAuth, ah(async (req, res) => {
  if (!FAM_KEY) return ok(res, { valid: false, message: 'FAMAPI_KEY is not set on the server.' });
  const d = await fam('/api/v1/orders/ord_connection_test');
  if (d.success || (d.error && d.error.code === 'NOT_FOUND')) return ok(res, { valid: true, message: 'FamApi is reachable and the key is valid.' });
  ok(res, { valid: false, message: (d.error && d.error.message) || 'FamApi rejected the key.' });
}));
app.post('/api/admin/orders/:id/mark', aAuth, ah(async (req, res) => {
  if (!ORDER_ID.test(req.params.id)) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  const s = req.body.status; if (!['success', 'failed'].includes(s)) return fail(res, 400, 'VALIDATION_ERROR', 'Invalid status.');
  if (!(await db.ref('orders/' + req.params.id).get()).exists()) return fail(res, 404, 'NOT_FOUND', 'Order not found.');
  if (s === 'success') await finalizeSuccess(req.params.id); else await setFinal(req.params.id, 'failed');
  ok(res);
}));
app.post('/api/admin/users/:id/status', aAuth, ah(async (req, res) => {
  const s = req.body.status; if (!['active', 'blocked'].includes(s)) return fail(res, 400, 'VALIDATION_ERROR', 'Invalid status.');
  if (!(await db.ref('users/' + req.params.id).get()).exists()) return fail(res, 404, 'NOT_FOUND', 'Merchant not found.');
  await db.ref('users/' + req.params.id + '/status').set(s); ok(res);
}));
app.post('/api/admin/users/:id/password', aAuth, ah(async (req, res) => {
  const pw = String(req.body.password || ''); if (pw.length < 6 || pw.length > 100) return fail(res, 400, 'VALIDATION_ERROR', 'Password needs 6+ characters.');
  if (!(await db.ref('users/' + req.params.id).get()).exists()) return fail(res, 404, 'NOT_FOUND', 'Merchant not found.');
  await db.ref('users/' + req.params.id + '/pass').set(await hashPw(pw)); ok(res);
}));
app.post('/api/admin/users/:id/balance', aAuth, ah(async (req, res) => {
  const d = Number(req.body.delta); if (!isFinite(d) || Math.abs(d) > 1e9) return fail(res, 400, 'VALIDATION_ERROR', 'Invalid amount.');
  if (!(await db.ref('users/' + req.params.id).get()).exists()) return fail(res, 404, 'NOT_FOUND', 'Merchant not found.');
  await db.ref('users/' + req.params.id + '/balance').transaction(b => r2((b || 0) + d)); ok(res);
}));
app.post('/api/admin/wallet/withdrawals/:id/approve', aAuth, ah(async (req, res) => {
  const ref = db.ref('withdrawals/' + req.params.id);
  const tx = await ref.transaction(w => {
    if (!w) return w;
    if (w.status !== 'pending') return w;
    w.status = 'paid';
    w.payoutReference = String(req.body.payoutReference || '').slice(0, 120);
    w.paidAt = Date.now();
    return w;
  });
  if (!tx.committed || !tx.snapshot.exists()) return fail(res, 404, 'NOT_FOUND', 'Withdrawal not found.');
  const w = tx.snapshot.val();
  await db.ref('walletLedger/' + w.merchantId + '/' + w.id).update({ status: 'paid', payoutReference: w.payoutReference, completedAt: w.paidAt });
  ok(res, { withdrawal: w });
}));
app.post('/api/admin/wallet/withdrawals/:id/reject', aAuth, ah(async (req, res) => {
  const ref = db.ref('withdrawals/' + req.params.id);
  const tx = await ref.transaction(w => {
    if (!w) return w;
    if (w.status !== 'pending') return w;
    w.status = 'rejected';
    w.reason = String(req.body.reason || 'Rejected').slice(0, 300);
    w.closedAt = Date.now();
    return w;
  });
  if (!tx.committed || !tx.snapshot.exists()) return fail(res, 404, 'NOT_FOUND', 'Withdrawal not found.');
  const w = tx.snapshot.val();
  await db.ref('users/' + w.merchantId).transaction(u => { if (!u) return u; u.balance = r2(Number(u.balance || 0) + Number(w.amount || 0)); return u; });
  await db.ref('walletLedger/' + w.merchantId + '/' + w.id).update({ status: 'rejected', reason: w.reason, completedAt: w.closedAt });
  ok(res, { withdrawal: w });
}));

app.get('/api/docs', ah(async (req, res) => {
  const snap = await db.ref('settings/apiDocs').orderByChild('order').get();
  const docs = []; snap.forEach(c => { const d = c.val(); if (d.enabled !== false) docs.push(d); });
  ok(res, { docs });
}));
app.post('/api/admin/docs', aAuth, ah(async (req, res) => {
  const id = rid('DOC', 8);
  const b = req.body || {};
  const d = { id, title: String(b.title || '').slice(0, 120), method: String(b.method || 'POST').slice(0, 10), path: String(b.path || '').slice(0, 200), description: String(b.description || '').slice(0, 1000), auth: String(b.auth || '').slice(0, 200), requestHeaders: String(b.requestHeaders || '').slice(0, 2000), requestBody: String(b.requestBody || '').slice(0, 5000), responseBody: String(b.responseBody || '').slice(0, 5000), curl: String(b.curl || '').slice(0, 5000), notes: String(b.notes || '').slice(0, 1000), order: Number(b.order) || 1, enabled: b.enabled !== false, createdAt: Date.now() };
  if (!d.title || !d.path) return fail(res, 400, 'VALIDATION_ERROR', 'Title and path are required.');
  await db.ref('settings/apiDocs/' + id).set(d); ok(res, { doc: d });
}));
app.put('/api/admin/docs/:id', aAuth, ah(async (req, res) => {
  const ref = db.ref('settings/apiDocs/' + req.params.id);
  if (!(await ref.get()).exists()) return fail(res, 404, 'NOT_FOUND', 'Documentation not found.');
  const b = req.body || {};
  const d = { title: String(b.title || '').slice(0, 120), method: String(b.method || 'POST').slice(0, 10), path: String(b.path || '').slice(0, 200), description: String(b.description || '').slice(0, 1000), auth: String(b.auth || '').slice(0, 200), requestHeaders: String(b.requestHeaders || '').slice(0, 2000), requestBody: String(b.requestBody || '').slice(0, 5000), responseBody: String(b.responseBody || '').slice(0, 5000), curl: String(b.curl || '').slice(0, 5000), notes: String(b.notes || '').slice(0, 1000), order: Number(b.order) || 1, enabled: b.enabled !== false };
  if (!d.title || !d.path) return fail(res, 400, 'VALIDATION_ERROR', 'Title and path are required.');
  await ref.update(d); ok(res, { doc: { id: req.params.id, ...d } });
}));
app.delete('/api/admin/docs/:id', aAuth, ah(async (req, res) => { await db.ref('settings/apiDocs/' + req.params.id).remove(); ok(res); }));

/* ----- built-in AI prompts ----- */
app.get('/api/ai/prompts', ah(async (req, res) => {
  const snap = await db.ref('settings/aiPrompts').orderByChild('order').get();
  const prompts = [];
  snap.forEach(c => { const p = c.val(); if (p.enabled !== false) prompts.push({ id: p.id, title: p.title, category: p.category || 'General', prompt: p.prompt, description: p.description || '', order: p.order || 1 }); });
  ok(res, { prompts });
}));
app.post('/api/admin/prompts', aAuth, ah(async (req, res) => {
  const b = req.body || {}, title = String(b.title || '').trim().slice(0, 120), prompt = String(b.prompt || '').trim().slice(0, 10000);
  if (!title || !prompt) return fail(res, 400, 'VALIDATION_ERROR', 'Prompt title and prompt text are required.');
  const id = rid('PRM', 8);
  const d = { id, title, category: String(b.category || 'General').trim().slice(0, 60) || 'General', prompt, description: String(b.description || '').trim().slice(0, 500), order: Number(b.order) || 1, enabled: b.enabled !== false, createdAt: Date.now(), updatedAt: Date.now() };
  await db.ref('settings/aiPrompts/' + id).set(d); ok(res, { prompt: d });
}));
app.put('/api/admin/prompts/:id', aAuth, ah(async (req, res) => {
  const ref = db.ref('settings/aiPrompts/' + req.params.id);
  if (!(await ref.get()).exists()) return fail(res, 404, 'NOT_FOUND', 'AI prompt not found.');
  const b = req.body || {}, title = String(b.title || '').trim().slice(0, 120), prompt = String(b.prompt || '').trim().slice(0, 10000);
  if (!title || !prompt) return fail(res, 400, 'VALIDATION_ERROR', 'Prompt title and prompt text are required.');
  const d = { title, category: String(b.category || 'General').trim().slice(0, 60) || 'General', prompt, description: String(b.description || '').trim().slice(0, 500), order: Number(b.order) || 1, enabled: b.enabled !== false, updatedAt: Date.now() };
  await ref.update(d); ok(res, { prompt: { id: req.params.id, ...d } });
}));
app.delete('/api/admin/prompts/:id', aAuth, ah(async (req, res) => { await db.ref('settings/aiPrompts/' + req.params.id).remove(); ok(res); }));

app.put('/api/admin/credentials', aAuth, limit('acred', 10, 600000), ah(async (req, res) => {
  const u = String(req.body.username || '').trim(), p = String(req.body.password || '');
  if (u.length < 3 || u.length > 40 || p.length < 6 || p.length > 100) return fail(res, 400, 'VALIDATION_ERROR', 'Username 3+ and password 6+ characters.');
  const pass = await hashPw(p); await db.ref('settings/admin').set({ user: u, pass });
  ok(res, { token: signToken({ r: 'a', pv: pass.slice(-8) }, 12 * 3600e3) });
}));

app.use('/api', (req, res) => fail(res, 404, 'NOT_FOUND', 'Unknown endpoint.'));

/* ----- static front-end ----- */
const PUB = path.join(__dirname, 'public');
app.get('/admin', (req, res) => res.sendFile(path.join(PUB, 'admin.html')));
app.use(express.static(PUB, { index: 'index.html', maxAge: 0 }));

app.use((err, req, res, next) => {
  if (err && err.status && err.code) return fail(res, err.status, err.code, err.message);
  if (err && err.type === 'entity.parse.failed') return fail(res, 400, 'BAD_JSON', 'Invalid JSON body.');
  console.error(err); fail(res, 500, 'INTERNAL_ERROR', 'Something went wrong on our side. Please retry.');
});

/* ---------- start ---------- */
(async () => {
  try {
    if (!(await db.ref('settings/config').get()).exists()) await db.ref('settings/config').set(DEFAULTS);
    if (!(await db.ref('settings/admin').get()).exists()) {
      const u = process.env.ADMIN_USER || 'admin', p = process.env.ADMIN_PASS || 'admin123';
      await db.ref('settings/admin').set({ user: u, pass: await hashPw(p) });
      console.log('Admin account created:', u, p === 'admin123' ? '(DEFAULT PASSWORD - change it in Admin > Settings)' : '');
    }
  } catch (e) { console.error('Firebase connection failed:', e.message); process.exit(1); }
  app.listen(PORT, () => console.log('PayX backend listening on', PORT));
})();