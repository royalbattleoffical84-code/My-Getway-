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
const FAM_SECRET_ENC = process.env.FAM_SECRET_ENC || ''; // 32-byte AES key as 64 hex chars
const FAM_BASE = (process.env.FAMAPI_BASE || 'https://famapi-orcin.vercel.app').replace(/\/$/, '');
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

if (TOKEN_SECRET.length < 16) { console.error('FATAL: set TOKEN_SECRET env var (16+ random characters).'); process.exit(1); }
if (!FAM_SECRET_ENC || !/^[a-fA-F0-9]{64}$/.test(FAM_SECRET_ENC)) console.warn('WARNING: FAM_SECRET_ENC is not set/invalid. Merchants cannot connect FAM until it is configured.');

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
  support: 'https://t.me/ShivamXoffical01', maintenance: false
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

/* ---------- merchant FAM secret encryption ---------- */
function encKey() {
  if (!/^[a-fA-F0-9]{64}$/.test(FAM_SECRET_ENC)) {
    const e = new Error('FAM_SECRET_ENC is not configured on the server.'); e.code = 'FAM_SECRET_NOT_CONFIGURED'; e.status = 503; throw e;
  }
  return Buffer.from(FAM_SECRET_ENC, 'hex');
}
function encryptFamKey(value) {
  const iv = crypto.randomBytes(12), key = encKey();
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const out = Buffer.concat([c.update(String(value), 'utf8'), c.final()]);
  return [iv.toString('base64url'), c.getAuthTag().toString('base64url'), out.toString('base64url')].join(':');
}
function decryptFamKey(payload) {
  if (!payload || typeof payload !== 'string') return '';
  try {
    const [ivB64, tagB64, dataB64] = payload.split(':');
    if (!ivB64 || !tagB64 || !dataB64) return '';
    const d = crypto.createDecipheriv('aes-256-gcm', encKey(), Buffer.from(ivB64, 'base64url'));
    d.setAuthTag(Buffer.from(tagB64, 'base64url'));
    return Buffer.concat([d.update(Buffer.from(dataB64, 'base64url')), d.final()]).toString('utf8');
  } catch (e) { return ''; }
}
function maskKey(k) {
  const s = String(k || ''); return s ? `${s.slice(0, 4)}••••••${s.slice(-4)}` : '';
}
async function getMerchantFam(uid) {
  const f = (await db.ref('users/' + uid + '/fam').get()).val();
  if (!f || !f.keyEnc) {
    const e = new Error('Connect your FAM account before creating payments.'); e.code = 'FAM_NOT_CONNECTED'; e.status = 409; throw e;
  }
  const key = decryptFamKey(f.keyEnc);
  if (!key) {
    const e = new Error('Your FAM connection is unavailable. Please reconnect it.'); e.code = 'FAM_CONNECTION_INVALID'; e.status = 409; throw e;
  }
  return { key, meta: f };
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
const famBackoffs = new Map();
async function famWithKey(apiKey, p, opt = {}) {
  if (!apiKey) return { success: false, error: { code: 'NOT_CONFIGURED', message: 'Payment provider is not configured.' } };
  const keyId = sha256(apiKey).slice(0, 16), backoff = famBackoffs.get(keyId) || 0;
  if (Date.now() < backoff) return { success: false, error: { code: 'RATE_LIMITED', message: 'Provider busy, retrying shortly.' } };
  try {
    const r = await fetch(FAM_BASE + p, { ...opt, headers: { ...(opt.headers || {}), 'Content-Type': 'application/json', 'X-FamApi-Key': apiKey }, signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    if (d && d.error && d.error.code === 'RATE_LIMITED') famBackoffs.set(keyId, Date.now() + 20000);
    return d;
  } catch (e) {
    return { success: false, error: { code: 'NETWORK', message: 'Payment provider unreachable.' } };
  }
}
/* ---------- order logic ---------- */
const cleanOrder = o => { const { lock, famOrderId, ...rest } = o; return rest; };
const pubOrder = o => ({ id: o.id, amount: o.amount, status: o.status, merchantName: o.merchantName, upiId: o.upiId || '', expiresAt: o.expiresAt, redirectUrl: o.redirectUrl || '', ref: o.ref || '', paidAt: o.paidAt || 0 });
const safeUser = u => { const { pass, fam, ...rest } = u; return rest; };
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

function walletId(){ return rid('WT', 14); }
function requestId(p){ return rid(p, 12); }
async function walletLedger(uid, tx){
  const id = tx.id || walletId();
  const row = { id, merchantId: uid, type: String(tx.type||'adjustment'), amount: r2(Number(tx.amount)||0), direction: tx.direction === 'debit' ? 'debit' : 'credit', status: tx.status || 'success', reference: String(tx.reference||'').slice(0,120), note: String(tx.note||'').slice(0,300), createdAt: tx.createdAt || Date.now(), requestId: tx.requestId || '' };
  await db.ref('walletLedger/'+uid+'/'+id).set(row);
  return row;
}
async function creditWallet(uid, amount, meta={}){
  amount=r2(Number(amount)); if(!(amount>0)) throw new Error('Invalid wallet credit.');
  await db.ref('users/'+uid).transaction(u=>{ if(!u) return u; u.balance=r2((u.balance||0)+amount); return u; });
  return walletLedger(uid,{...meta,amount,direction:'credit',status:'success'});
}
async function debitWallet(uid, amount, meta={}){
  amount=r2(Number(amount)); if(!(amount>0)) throw new Error('Invalid wallet debit.');
  const tx=await db.ref('users/'+uid).transaction(u=>{ if(!u) return u; const bal=r2(u.balance||0); if(bal<amount) return; u.balance=r2(bal-amount); return u; });
  if(!tx.committed) { const e=new Error('Insufficient wallet balance.'); e.code='INSUFFICIENT_BALANCE'; e.status=400; throw e; }
  return walletLedger(uid,{...meta,amount,direction:'debit',status:'success'});
}
async function createOrder(m, amount, x = {}) {
  const cfg = await getCfg();
  amount = r2(Number(amount));
  if (!isFinite(amount) || amount < cfg.minAmount || amount > cfg.maxAmount) { const e = new Error(`Amount must be between ₹${cfg.minAmount} and ₹${cfg.maxAmount}`); e.status = 400; e.code = 'VALIDATION_ERROR'; throw e; }
  if (cfg.maintenance) { const e = new Error('PayX is under maintenance. Try again shortly.'); e.status = 503; e.code = 'MAINTENANCE'; throw e; }
  if (m.status === 'blocked') { const e = new Error('This merchant account is blocked.'); e.status = 403; e.code = 'BLOCKED'; throw e; }
  await getMerchantFam(m.id);
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
  const res = await db.ref('orders/' + id).transaction(o => { if (!o) return o; if (o.status === 'success') return; o.status = 'success'; o.paidAt = Date.now(); return o; });
  if (!res.committed || !res.snapshot.exists()) return false;
  const o = res.snapshot.val();
  await db.ref('users/' + o.merchantId).transaction(u => { if (!u) return u; u.balance = r2((u.balance || 0) + o.net); u.totalReceived = r2((u.totalReceived || 0) + o.amount); u.successCount = (u.successCount || 0) + 1; return u; }); await walletLedger(o.merchantId,{id:'PAY_'+o.id,type:'payment',amount:o.net,direction:'credit',status:'success',reference:o.ref||o.id,note:'Payment received',createdAt:o.paidAt}); await walletLedger(o.merchantId,{id:'FEE_'+o.id,type:'fee',amount:o.fee,direction:'debit',status:'success',reference:o.ref||o.id,note:'PayX platform fee',createdAt:o.paidAt});
  sendHook(o).catch(() => {});
  return true;
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
  let provider;
  try { provider = await getMerchantFam(o.merchantId); } catch (e) { return o; }
  const d = await famWithKey(provider.key, '/api/v1/orders/' + o.famOrderId);
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
  const bearerKey = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const k = String(req.headers['x-payx-key'] || bearerKey || '').trim();
  if (!k) return fail(res, 401, 'INVALID_API_KEY', 'Missing API key. Use X-PayX-Key or Authorization: Bearer <key>.');
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
app.get('/api/config/public', ah(async (req, res) => { const c = await getCfg(); ok(res, { config: { siteName: c.siteName, tagline: c.tagline, support: c.support, feePercent: c.feePercent, minAmount: c.minAmount, maxAmount: c.maxAmount, maintenance: c.maintenance } }); }));
app.get('/api/docs', ah(async (req, res) => { const s = (await db.ref('settings/apiDocs').get()).val() || {}; const docs = Object.values(s).filter(x => x && x.enabled !== false).sort((a,b)=>(a.order||0)-(b.order||0)); ok(res, { docs }); }));

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
  const id = email && (await db.ref('emailIndex/' + email.replace(/\./g, ',')).get()).val();
  const u = id && (await db.ref('users/' + id).get()).val();
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
  let provider;
  try { provider = await getMerchantFam(o.merchantId); } catch (e) { await ref.child('lock').remove(); return fail(res, e.status || 409, e.code || 'FAM_NOT_CONNECTED', e.message || 'Connect your FAM account first.'); }
  const d = await famWithKey(provider.key, '/api/v1/orders', { method: 'POST', body: JSON.stringify({ amount: o.amount, reference: o.id }) });
  if (!d.success || !d.order) { await ref.child('lock').remove(); return fail(res, 502, 'PROVIDER_ERROR', (d.error && d.error.message) || 'Payment provider did not respond. Please try again.'); }
  await ref
.update({
    famOrderId: d.order.id,
    upiId: d.order.upiId,
    status: 'pending',
    startedAt: Date.now(),
    expiresAt: Date.now() + cfg.expiryMin * 60000
  });
  ok(res, { order: pubOrder((await ref.get()).val()) });
}));

/* ----- merchant panel ----- */
app.get('/api/me', mAuth, ah(async (req, res) => {
  const snap = await db.ref('orders').orderByChild('merchantId').equalTo(req.user.id).get();
  const l = []; snap.forEach(c => { l.push(cleanOrder(c.val())); });
  l.sort((a, b) => b.createdAt - a.createdAt);
  const ws=await db.ref('walletLedger/'+req.user.id).orderByChild('createdAt').limitToLast(200).get(); const wallet=[]; ws.forEach(c=>wallet.push(c.val())); wallet.sort((a,b)=>b.createdAt-a.createdAt); const top=await db.ref('walletRequests/topups').orderByChild('merchantId').equalTo(req.user.id).get(); const wd=await db.ref('walletRequests/withdrawals').orderByChild('merchantId').equalTo(req.user.id).get(); const topups=[],withdrawals=[]; top.forEach(c=>topups.push(c.val())); wd.forEach(c=>withdrawals.push(c.val())); topups.sort((a,b)=>b.createdAt-a.createdAt); withdrawals.sort((a,b)=>b.createdAt-a.createdAt); ok(res, { user: safeUser(req.user), orders: l.slice(0, 300), wallet, topups:topups.slice(0,100), withdrawals:withdrawals.slice(0,100) });
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
app.get('/api/me/fam', mAuth, ah(async (req, res) => {
  const f = (await db.ref('users/' + req.user.id + '/fam').get()).val();
  ok(res, { connected: !!(f && f.keyEnc), fam: f ? { label: f.label || '', last4: f.last4 || '', connectedAt: f.connectedAt || 0, keyMasked: f.last4 ? `••••${f.last4}` : '' } : null });
}));
app.post('/api/me/fam', mAuth, limit('famconnect', 10, 600000), ah(async (req, res) => {
  const apiKey = String(req.body.apiKey || '').trim();
  const label = String(req.body.label || 'My FAM').trim().slice(0, 60) || 'My FAM';
  if (apiKey.length < 8 || apiKey.length > 300) return fail(res, 400, 'VALIDATION_ERROR', 'Enter a valid FAM API key.');
  if (!/^[a-zA-Z0-9_\-.:]+$/.test(apiKey)) return fail(res, 400, 'VALIDATION_ERROR', 'Invalid FAM API key format.');
  // The provider source available in this project does not expose a safe account-verification endpoint.
  // Therefore this saves the key securely but does NOT falsely claim that the provider verified it.
  const keyEnc = encryptFamKey(apiKey);
  await db.ref('users/' + req.user.id + '/fam').set({ keyEnc, label, last4: apiKey.slice(-4), connectedAt: Date.now() });
  ok(res, { connected: true, verified: false, message: 'FAM connected. Provider verification will happen on the first payment request.', fam: { label, last4: apiKey.slice(-4), connectedAt: Date.now() } });
}));
app.delete('/api/me/fam', mAuth, ah(async (req, res) => {
  await db.ref('users/' + req.user.id + '/fam').remove();
  ok(res, { connected: false });
}));
app.post('/api/me/orders', mAuth, limit('meorders', 60, 60000), ah(async (req, res) => {
  const o = await createOrder(req.user, req.body.amount, { ref: req.body.ref, note: req.body.note, source: 'link' });
  ok(res, { order: cleanOrder(o) });
}));

/* ----- merchant wallet ----- */
app.get('/api/me/wallet', mAuth, ah(async (req,res)=>{ const snap=await db.ref('walletLedger/'+req.user.id).orderByChild('createdAt').limitToLast(300).get(); const ledger=[]; snap.forEach(c=>ledger.push(c.val())); ledger.sort((a,b)=>b.createdAt-a.createdAt); const t=await db.ref('walletRequests/topups').orderByChild('merchantId').equalTo(req.user.id).get(); const w=await db.ref('walletRequests/withdrawals').orderByChild('merchantId').equalTo(req.user.id).get(); const topups=[],withdrawals=[]; t.forEach(c=>topups.push(c.val())); w.forEach(c=>withdrawals.push(c.val())); topups.sort((a,b)=>b.createdAt-a.createdAt); withdrawals.sort((a,b)=>b.createdAt-a.createdAt); ok(res,{balance:r2(req.user.balance||0),pending:r2(req.user.pendingBalance||0),ledger,topups:topups.slice(0,100),withdrawals:withdrawals.slice(0,100)}); }));
app.post('/api/me/wallet/topups', mAuth, limit('topup',10,60000), ah(async(req,res)=>{ const amount=r2(Number(req.body.amount)); const ref=String(req.body.reference||'').trim().slice(0,120); if(!isFinite(amount)||amount<1||amount>1000000)return fail(res,400,'VALIDATION_ERROR','Top-up amount must be between ₹1 and ₹10,00,000.'); const id=requestId('TU'); const row={id,merchantId:req.user.id,amount,status:'pending',reference:ref,note:String(req.body.note||'').slice(0,300),createdAt:Date.now()}; await db.ref('walletRequests/topups/'+id).set(row); ok(res,{request:row,message:'Top-up request submitted. Admin verification is required.'}); }));
app.post('/api/me/wallet/withdrawals', mAuth, limit('withdraw',10,60000), ah(async(req,res)=>{ const amount=r2(Number(req.body.amount)); const upi=String(req.body.upiId||'').trim().slice(0,120); if(!isFinite(amount)||amount<1||amount>1000000)return fail(res,400,'VALIDATION_ERROR','Withdrawal amount must be between ₹1 and ₹10,00,000.'); if(!upi||upi.length<3)return fail(res,400,'VALIDATION_ERROR','Enter a valid UPI ID.'); const tx=await db.ref('users/'+req.user.id).transaction(u=>{ if(!u)return u; const bal=r2(u.balance||0); if(bal<amount)return; u.balance=r2(bal-amount); u.pendingBalance=r2((u.pendingBalance||0)+amount); return u; }); if(!tx.committed)return fail(res,400,'INSUFFICIENT_BALANCE','Insufficient wallet balance.'); const id=requestId('WD'); const row={id,merchantId:req.user.id,amount,total:amount,fee:0,upiId:upi,status:'pending',createdAt:Date.now()}; await db.ref('walletRequests/withdrawals/'+id).set(row); await walletLedger(req.user.id,{id:'WDH_'+id,type:'withdrawal_hold',amount,direction:'debit',status:'pending',reference:id,note:'Withdrawal request hold'}); ok(res,{request:row}); }));
/* ----- merchant server-to-server API ----- */
const v1 = (req, o) => ({ id: o.id, amount: o.amount, currency: 'INR', reference: o.ref || '', status: o.status, createdAt: o.createdAt, paidAt: o.paidAt || null, checkoutUrl: checkoutUrl(req, o.id) });
app.post('/api/v1/orders', keyAuth, limit('v1create', 120, 60000), ah(async (req, res) => {
  const idem = String(req.headers['idempotency-key'] || '').trim();
  if (idem && !/^[A-Za-z0-9._:-]{8,100}$/.test(idem)) return fail(res, 400, 'INVALID_IDEMPOTENCY_KEY', 'Idempotency-Key must be 8-100 safe characters.');
  const requestHash = sha256(JSON.stringify({ amount: req.body.amount, reference: req.body.reference || '', note: req.body.note || '', redirectUrl: req.body.redirectUrl || '' }));
  if (idem) {
    const ir = db.ref('idempotency/' + req.user.id + '/' + idem);
    const existing = (await ir.get()).val();
    if (existing) {
      if (existing.requestHash !== requestHash) return fail(res, 409, 'IDEMPOTENCY_CONFLICT', 'This Idempotency-Key was already used with different request data.');
      const old = (await db.ref('orders/' + existing.orderId).get()).val();
      if (old) return res.status(200).json({ success: true, reused: true, order: v1(req, old) });
    }
  }
  const o = await createOrder(req.user, req.body.amount, { ref: req.body.reference, note: req.body.note, redirectUrl: req.body.redirectUrl, source: 'api' });
  if (idem) await db.ref('idempotency/' + req.user.id + '/' + idem).set({ orderId: o.id, requestHash, createdAt: Date.now() });
  res.status(201).json({ success: true, reused: false, order: v1(req, o) });
}));
app.get('/api/v1/orders', keyAuth, limit('v1list', 120, 60000), ah(async (req, res) => {
  const limitN = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  const snap = await db.ref('orders').orderByChild('merchantId').equalTo(req.user.id).get();
  const orders = []; snap.forEach(c => orders.push(c.val()));
  orders.sort((a,b) => b.createdAt - a.createdAt);
  ok(res, { orders: orders.slice(0, limitN).map(o => v1(req, o)) });
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
  const [us, os, cfg] = await Promise.all([db.ref('users').get(), db.ref('orders').orderByChild('createdAt').limitToLast(500).get(), getCfg(true)]);
  const users = [], orders = []; let connectedFams = 0; us.forEach(c => { const u = c.val(); if (u && u.fam && u.fam.keyEnc) connectedFams++; users.push(safeUser(u)); }); os.forEach(c => { orders.push(cleanOrder(c.val())); });
  users.sort((a, b) => b.createdAt - a.createdAt); orders.sort((a, b) => b.createdAt - a.createdAt);
  const apiDocs = Object.values((await db.ref('settings/apiDocs').get()).val() || {}).sort((a,b)=>(a.order||0)-(b.order||0));
  const ts=(await db.ref('walletRequests/topups').get()).val()||{}, ws=(await db.ref('walletRequests/withdrawals').get()).val()||{}; const topups=Object.values(ts).sort((a,b)=>b.createdAt-a.createdAt).slice(0,500), withdrawals=Object.values(ws).sort((a,b)=>b.createdAt-a.createdAt).slice(0,500); ok(res, { users, orders, config: cfg, apiDocs, topups, withdrawals, merchantFamConfigured: /^[a-fA-F0-9]{64}$/.test(FAM_SECRET_ENC), connectedFams });
}));
app.get('/api/admin/users/:id/fam', aAuth, ah(async (req, res) => {
  const f = (await db.ref('users/' + req.params.id + '/fam').get()).val();
  if (!f) return ok(res, { connected: false, fam: null });
  ok(res, { connected: !!f.keyEnc, fam: { label: f.label || '', last4: f.last4 || '', connectedAt: f.connectedAt || 0, keyMasked: f.last4 ? `••••${f.last4}` : '' } });
}));
app.post('/api/admin/docs', aAuth, ah(async (req, res) => {
 const b=req.body||{},id=String(b.id||rid('DOC',8)).replace(/[^A-Za-z0-9_-]/g,'').slice(0,40)||rid('DOC',8),method=String(b.method||'POST').toUpperCase(),title=String(b.title||'').trim().slice(0,100),path=String(b.path||'').trim().slice(0,180); if(!['GET','POST','PUT','PATCH','DELETE'].includes(method)||!title||!path.startsWith('/'))return fail(res,400,'VALIDATION_ERROR','Valid title, method and /path are required.'); const doc={id,title,method,path,description:String(b.description||'').slice(0,2000),auth:String(b.auth||'').slice(0,120),requestHeaders:String(b.requestHeaders||'').slice(0,5000),requestBody:String(b.requestBody||'').slice(0,10000),responseBody:String(b.responseBody||'').slice(0,10000),curl:String(b.curl||'').slice(0,10000),notes:String(b.notes||'').slice(0,2000),enabled:b.enabled!==false,order:Number(b.order)||Date.now(),updatedAt:Date.now()}; await db.ref('settings/apiDocs/'+id).set(doc); ok(res,{doc});
}));
app.put('/api/admin/docs/:id', aAuth, ah(async (req,res)=>{ const id=String(req.params.id||''),ref=db.ref('settings/apiDocs/'+id),snap=await ref.get(); if(!snap.exists())return fail(res,404,'NOT_FOUND','Documentation entry not found.'); const b=req.body||{},cur=snap.val()||{},method=String(b.method||cur.method||'POST').toUpperCase(),path=String(b.path||cur.path||'').trim().slice(0,180); if(!['GET','POST','PUT','PATCH','DELETE'].includes(method)||!path.startsWith('/'))return fail(res,400,'VALIDATION_ERROR','Valid method and /path are required.'); const doc={...cur,title:String(b.title||cur.title||'').trim().slice(0,100),method,path,description:String(b.description??cur.description??'').slice(0,2000),auth:String(b.auth??cur.auth??'').slice(0,120),requestHeaders:String(b.requestHeaders??cur.requestHeaders??'').slice(0,5000),requestBody:String(b.requestBody??cur.requestBody??'').slice(0,10000),responseBody:String(b.responseBody??cur.responseBody??'').slice(0,10000),curl:String(b.curl??cur.curl??'').slice(0,10000),notes:String(b.notes??cur.notes??'').slice(0,2000),enabled:b.enabled!==false,order:Number(b.order)||cur.order||Date.now(),updatedAt:Date.now()}; if(!doc.title)return fail(res,400,'VALIDATION_ERROR','Title is required.'); await ref.set(doc); ok(res,{doc}); }));
app.delete('/api/admin/docs/:id', aAuth, ah(async (req,res)=>{const id=String(req.params.id||'');await db.ref('settings/apiDocs/'+id).remove();ok(res);}));
app.put('/api/admin/config', aAuth, ah(async (req, res) => {
  const b = req.body, n = x => Number(x);
  const v = { siteName: String(b.siteName || 'PayX').trim().slice(0, 40) || 'PayX', tagline: String(b.tagline || '').trim().slice(0, 120), support: String(b.support || '').trim().slice(0, 300), feePercent: n(b.feePercent), minAmount: n(b.minAmount), maxAmount: n(b.maxAmount), expiryMin: n(b.expiryMin), maintenance: !!b.maintenance };
  if ([v.feePercent, v.minAmount, v.maxAmount, v.expiryMin].some(x => !isFinite(x) || x < 0) || v.minAmount > v.maxAmount || v.expiryMin < 1 || v.feePercent > 50) return fail(res, 400, 'VALIDATION_ERROR', 'Check the numbers: fee, limits and payment window must be valid.');
  await db.ref('settings/config').set(v); await getCfg(true); ok(res);
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
app.post('/api/admin/users/:id/balance', aAuth, ah(async (req,res)=>{ const d=r2(Number(req.body.delta)); if(!isFinite(d)||d===0||Math.abs(d)>1e9)return fail(res,400,'VALIDATION_ERROR','Invalid amount.'); const u=(await db.ref('users/'+req.params.id).get()).val(); if(!u)return fail(res,404,'NOT_FOUND','Merchant not found.'); if(d>0) await creditWallet(req.params.id,d,{type:'admin_credit',reference:'ADMIN',note:String(req.body.note||'Admin wallet credit').slice(0,300)}); else await debitWallet(req.params.id,Math.abs(d),{type:'admin_debit',reference:'ADMIN',note:String(req.body.note||'Admin wallet debit').slice(0,300)}); ok(res); }));
app.post('/api/admin/wallet/topups/:id/approve', aAuth, ah(async(req,res)=>{ const ref=db.ref('walletRequests/topups/'+req.params.id); const snap=await ref.get(); const x=snap.val(); if(!x)return fail(res,404,'NOT_FOUND','Top-up request not found.'); if(x.status!=='pending')return fail(res,409,'ALREADY_PROCESSED','Request already processed.'); await ref.update({status:'approved',approvedAt:Date.now()}); await creditWallet(x.merchantId,x.amount,{type:'wallet_topup',reference:x.reference||x.id,requestId:x.id,note:'Wallet top-up approved'}); ok(res); }));
app.post('/api/admin/wallet/topups/:id/reject', aAuth, ah(async(req,res)=>{ const ref=db.ref('walletRequests/topups/'+req.params.id); const snap=await ref.get(); const x=snap.val(); if(!x)return fail(res,404,'NOT_FOUND','Top-up request not found.'); if(x.status!=='pending')return fail(res,409,'ALREADY_PROCESSED','Request already processed.'); await ref.update({status:'rejected',rejectedAt:Date.now(),reason:String(req.body.reason||'Rejected').slice(0,300)}); ok(res); }));
app.post('/api/admin/wallet/withdrawals/:id/approve', aAuth, ah(async(req,res)=>{ const ref=db.ref('walletRequests/withdrawals/'+req.params.id); const snap=await ref.get(); const x=snap.val(); if(!x)return fail(res,404,'NOT_FOUND','Withdrawal request not found.'); if(x.status!=='pending')return fail(res,409,'ALREADY_PROCESSED','Request already processed.'); await ref.update({status:'approved',approvedAt:Date.now(),payoutReference:String(req.body.payoutReference||'').slice(0,120)}); await db.ref('users/'+x.merchantId+'/pendingBalance').transaction(v=>r2((v||0)-x.total)); await walletLedger(x.merchantId,{id:'WDP_'+x.id,type:'withdrawal',amount:x.total,direction:'debit',status:'success',reference:String(req.body.payoutReference||x.id),note:'Withdrawal paid'}); ok(res); }));
app.post('/api/admin/wallet/withdrawals/:id/reject', aAuth, ah(async(req,res)=>{ const ref=db.ref('walletRequests/withdrawals/'+req.params.id); const snap=await ref.get(); const x=snap.val(); if(!x)return fail(res,404,'NOT_FOUND','Withdrawal request not found.'); if(x.status!=='pending')return fail(res,409,'ALREADY_PROCESSED','Request already processed.'); await ref.update({status:'rejected',rejectedAt:Date.now(),reason:String(req.body.reason||'Rejected').slice(0,300)}); await db.ref('users/'+x.merchantId).transaction(u=>{if(!u)return u;u.pendingBalance=r2((u.pendingBalance||0)-x.total);u.balance=r2((u.balance||0)+x.total);return u;}); await walletLedger(x.merchantId,{id:'WDR_'+x.id,type:'withdrawal_refund',amount:x.total,direction:'credit',status:'success',reference:x.id,note:'Withdrawal rejected and balance restored'}); ok(res); }));
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