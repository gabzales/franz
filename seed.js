const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieSession = require('cookie-session');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const multer = require('multer');
const crypto = require('crypto');

// Load .env FIRST before anything reads process.env
require('dotenv').config();

// Perbandingan string tahan timing-attack — dipakai untuk SETUP_SECRET
// (audit 3 Sep 2026: sebelumnya pakai `!==` biasa di /franzzstore-setup dan
// /admin/migrate-images, yang secara teori bocorin sedikit info lewat waktu
// respons per-karakter yang cocok. SETUP_SECRET cuma dipakai sekali/jarang
// jadi risikonya kecil, tapi tetap dibenerin sekalian karena murah untuk
// diperbaiki). Otomatis anggap tidak match kalau salah satu kosong atau
// panjangnya beda (timingSafeEqual butuh Buffer dengan panjang sama persis).
const timingSafeStringEqual = (a, b) => {
  if (!a || !b) return false;
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

// PENTING — KEAMANAN: session cookie ditandatangani (signed) pakai secret ini.
// Sebelumnya ada fallback string HARDCODED di source code
// ('franzzstore-fallback-secret-2024-xK9mP3qR'). Itu lubang keamanan serius:
// siapa pun yang baca source code ini (termasuk lewat zip project ini) bisa
// tahu secret-nya, lalu memalsukan cookie session sendiri — termasuk bikin
// cookie isAdmin:true atau menyamar jadi reseller manapun untuk menguras
// saldo wallet mereka — TANPA perlu password sama sekali.
//
// FIX (audit 3 Sep 2026): sebelumnya fallback pakai crypto.randomBytes()
// PURE RANDOM tiap kali proses nyala. Ini "aman" (gak hardcoded/predictable)
// TAPI di Vercel serverless tiap cold start = proses baru = secret baru
// = SEMUA session lama otomatis invalid = user (termasuk admin) kelogout
// mendadak tanpa alasan jelas, bisa berkali-kali sehari tergantung traffic.
// Fallback sekarang di-derive dari SUPABASE_URL (env var yang sudah WAJIB
// ada dan stabil per-project di Vercel) di-hash SHA-256 -- hasilnya
// konsisten selama SUPABASE_URL gak berubah (jadi session stabil di semua
// instance/cold-start), TAPI tetap gak predictable dari luar (attacker gak
// bisa tebak SESSION_SECRET walau tau SUPABASE_URL project publik, karena
// proses hash-nya searah/one-way). Kalau SUPABASE_URL juga belum di-set
// (dev lokal awal banget, belum config Supabase sama sekali), baru jatuh
// ke random murni sebagai last resort.
// TETAP disarankan keras set SESSION_SECRET sendiri di env Vercel untuk
// keamanan maksimal -- fallback ini cuma jaring pengaman supaya app gak
// force-logout semua orang kalau lupa set.
const SESSION_SECRET = process.env.SESSION_SECRET
  || (process.env.SUPABASE_URL
      ? crypto.createHash('sha256').update('franzfront-session-fallback:' + process.env.SUPABASE_URL).digest('hex')
      : crypto.randomBytes(32).toString('hex'));

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET belum di-set! Pakai fallback yang di-derive dari SUPABASE_URL (stabil, tapi TIDAK sekuat secret acak sendiri).');
  console.warn('⚠️  Disarankan set SESSION_SECRET manual di environment variables (Vercel) untuk keamanan maksimal.');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');

const app = express();
const PORT = process.env.PORT || 3000;

// ══ AUDIT KEAMANAN 3 Sep 2026 (diminta user): security headers ══
// Sebelumnya TIDAK ADA security header sama sekali (no helmet) -- artinya
// browser gak dikasih tahu untuk block clickjacking (X-Frame-Options),
// MIME-sniffing (X-Content-Type-Options), dsb. helmet() pasang semua
// header standar ini otomatis. contentSecurityPolicy dimatikan (false)
// karena EJS + inline <script> dipakai luas di views/ -- CSP default
// helmet akan blokir semua inline script itu dan bikin web rusak total;
// mengaktifkan CSP yang benar butuh audit terpisah per halaman (nonce/hash
// di tiap <script> inline), jadi disengaja dimatikan dulu supaya tidak
// break functionality, TAPI header lain (X-Frame-Options: SAMEORIGIN,
// X-Content-Type-Options: nosniff, Strict-Transport-Security, dll) tetap
// aktif dan itu yang paling penting buat sekarang.
//
// FIX BUG (4 Sep 2026): helmet() default set Referrer-Policy: no-referrer,
// yang bikin browser BERHENTI kirim header Referer di semua navigasi --
// termasuk pas submit form login (/login, /vpr-secure-panel-8x, /register).
// Itu bentrok langsung sama CSRF Origin/Referer check di bawah (yang
// nolak request tanpa Origin/Referer sama sekali), jadi semua orang gagal
// login dengan pesan "Origin tidak valid." walau login dari web sendiri.
// Diganti ke 'same-origin' -- browser tetap kirim Referer untuk request
// SESAMA domain (yang justru dibutuhkan CSRF check di bawah), tapi tetap
// TIDAK kirim Referer ke situs lain kalau ada link keluar (privasi tetap
// terjaga, cuma dibatasi ke same-origin bukan no-referrer total).
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'same-origin' },
}));

// ══ AUDIT KEAMANAN 3 Sep 2026: rate limiting global ══
// Sebelumnya TIDAK ADA rate limiter di level Express sama sekali (cuma ada
// Map() in-memory khusus buat QR & login, dan itupun punya kelemahan di
// Vercel -- lihat catatan di checkLoginBlocked/isQrRateLimited di bawah).
// generalLimiter ini pasang batas kasar di SEMUA request supaya satu IP
// gak bisa spam ratusan request/detik ke endpoint manapun (mis. flooding
// /api/products berkali-kali buat bikin server berat -- pola DDoS paling
// dasar). Di-skip untuk asset statis (gambar/css/js) karena itu sudah
// di-serve CDN Vercel, bukan lewat Node process ini.
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120, // 120 request/menit/IP -- longgar untuk pemakaian normal, ketat untuk bot/flood
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Terlalu banyak request. Coba lagi sebentar lagi.' },
});
app.use((req, res, next) => {
  if (req.path.startsWith('/uploads/') || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/images/')) {
    return next();
  }
  return generalLimiter(req, res, next);
});

// ══ AUDIT KEAMANAN 3 Sep 2026: rate limiter khusus endpoint sensitif ══
// Lebih ketat dari generalLimiter, dipasang manual di route login admin,
// login user, dan endpoint OTP/pembayaran (lihat pemakaian authLimiter
// dan otpLimiter di bawah).
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20, // 20 percobaan/15 menit/IP -- di atas ini keburu kena checkLoginBlocked juga
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Terlalu banyak percobaan login. Coba lagi dalam beberapa menit.' },
});

// Rate limiting untuk QR Code
const qrRateLimit = new Map();
const QR_RATE_LIMIT = 30;
const QR_RATE_WINDOW = 60000;

// Rate limiting untuk login (brute force protection)
// CATATAN AUDIT (3 Sep 2026): Map() ini in-memory per-instance. Di Vercel,
// tiap cold start / instance serverless punya memory KOSONG dan TERPISAH
// satu sama lain -- Vercel bisa route request ke instance manapun yang
// available. Artinya penyerang yang brute-force login bisa "reset" hitungan
// percobaannya cuma dengan kena-route ke instance baru (misal request lambat
// beruntun yang masing-masing spawn cold start berbeda), sehingga proteksi
// ini TIDAK sepenuhnya efektif di production Vercel walau tetap membantu di
// VPS/server tradisional. Perbaikan proper: pindahkan counter ini ke
// Supabase (tabel/keyvalue_store terpisah dengan TTL), supaya konsisten
// di semua instance. Ditambahkan sebagai TODO -- lihat loginAttemptsToSupabase
// helper di bawah untuk versi yang sudah dipindah (dipanggil dari
// /vpr-secure-panel-8x POST handler).
const loginFailMap = new Map();
const LOGIN_MAX_FAIL = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkLoginBlocked = async (ip) => {
  const rec = loginFailMap.get(ip);
  if (rec && Date.now() <= rec.resetAt && rec.count >= LOGIN_MAX_FAIL) {
    return { blocked: true, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
  }
  if (rec && Date.now() > rec.resetAt) loginFailMap.delete(ip);

  // ══ AUDIT KEAMANAN 3 Sep 2026 (FIX): cek juga ke Supabase, bukan cuma
  // Map() in-memory. Ini yang membuat proteksi brute-force efektif di
  // Vercel -- kalau IP kena block di instance A, instance B (yang gak
  // punya Map lokal itu) tetap akan lihat block-nya karena baca dari
  // Supabase (shared antar semua instance). Kalau Supabase gagal/timeout,
  // fail-open ke hasil Map lokal saja (bukan fail sampai error 500 -- lebih
  // baik proteksi berkurang sedikit daripada login page mati total kalau
  // Supabase down).
  try {
    const key = `login-block:${ip}`;
    const rows = await db.readFresh('login-attempts.json');
    const entry = rows && rows[key];
    if (entry && Date.now() <= entry.resetAt && entry.count >= LOGIN_MAX_FAIL) {
      loginFailMap.set(ip, { count: entry.count, resetAt: entry.resetAt }); // sinkronkan cache lokal
      return { blocked: true, wait: Math.ceil((entry.resetAt - Date.now()) / 60000) };
    }
  } catch (e) {
    console.warn('checkLoginBlocked: gagal baca dari Supabase, pakai cache lokal saja:', e.message);
  }
  return { blocked: false };
};

const recordLoginFail = async (ip) => {
  const now = Date.now();
  const rec = loginFailMap.get(ip);
  const updated = (!rec || now > rec.resetAt) ? { count: 1, resetAt: now + LOGIN_WINDOW_MS } : { count: rec.count + 1, resetAt: rec.resetAt };
  loginFailMap.set(ip, updated);

  try {
    const key = `login-block:${ip}`;
    const rows = (await db.readFresh('login-attempts.json')) || {};
    rows[key] = updated;
    await db.writeDB('login-attempts.json', rows);
  } catch (e) {
    console.warn('recordLoginFail: gagal tulis ke Supabase, hitungan cuma lokal:', e.message);
  }
};

const clearLoginFail = async (ip) => {
  loginFailMap.delete(ip);
  try {
    const key = `login-block:${ip}`;
    const rows = (await db.readFresh('login-attempts.json')) || {};
    if (rows[key]) { delete rows[key]; await db.writeDB('login-attempts.json', rows); }
  } catch (e) {
    console.warn('clearLoginFail: gagal hapus dari Supabase:', e.message);
  }
};

// ── Cloudflare Turnstile verification ────────────────────────────────────────
async function verifyTurnstile(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true; // Turnstile tidak dikonfigurasi, skip verifikasi

  return new Promise((resolve) => {
    const body = JSON.stringify({
      secret,
      response: token,
    });

    const options = {
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.success === true);
        } catch {
          resolve(false);
        }
      });
    });

    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}
// ─────────────────────────────────────────────────────────────────────────────

// Invoice rate limiting (cegah brute force order code enumeration)
const invoiceRateMap = new Map();
const INVOICE_RATE_LIMIT = 10;
const INVOICE_RATE_WINDOW = 5 * 60 * 1000;

const checkInvoiceRateLimit = (ip) => {
  const now = Date.now();
  const rec = invoiceRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    invoiceRateMap.set(ip, { count: 1, resetAt: now + INVOICE_RATE_WINDOW });
    return true;
  }
  if (rec.count >= INVOICE_RATE_LIMIT) return false;
  rec.count++;
  return true;
};

// ── Validasi kekuatan password (dipakai di /api/auth/register dan
// /register, dua-duanya harus konsisten). Sebelumnya TIDAK ADA validasi
// sama sekali -- password 6 karakter tanpa angka ("danang") langsung
// diterima. Aturan minimal yang wajar: minimal 8 karakter, ada huruf
// DAN ada angka (tidak mewajibkan simbol supaya tidak terlalu
// menyulitkan pengguna awam toko digital ini). ──
function validatePasswordStrength(password) {
  if (!password || password.length < 8) {
    return 'Password minimal 8 karakter';
  }
  if (!/[a-zA-Z]/.test(password)) {
    return 'Password harus mengandung huruf';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password harus mengandung angka';
  }
  return null; // valid
}

// API rate limiting untuk endpoint publik
const apiRateMap = new Map();
const checkApiRateLimit = (ip, limit = 60, windowMs = 60000) => {
  const now = Date.now();
  const rec = apiRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    apiRateMap.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (rec.count >= limit) return false;
  rec.count++;
  return true;
};

// ── RATE LIMIT KHUSUS PEMBAYARAN (kebijakan wajib GensPay per 15 Agustus 2026) ──
// GensPay memblokir IP yang melakukan polling/generate QRIS berlebihan
// ("high-frequency request") dan mewajibkan merchant membatasi maksimal
// 30 request / 3 menit PER PENGGUNA untuk endpoint create-order &
// check-payment. Dibatasi per user ID (bukan per IP) karena endpoint ini
// sudah requireAuth — lebih akurat dan tidak mengganggu user lain yang
// kebetulan satu jaringan/NAT dengan user yang memang sedang di-throttle.
const paymentRateMap = new Map();
const PAYMENT_RATE_LIMIT = 30;
const PAYMENT_RATE_WINDOW = 3 * 60 * 1000;
const checkPaymentRateLimit = (userId) => {
  const now = Date.now();
  const rec = paymentRateMap.get(userId);
  if (!rec || now > rec.resetAt) {
    paymentRateMap.set(userId, { count: 1, resetAt: now + PAYMENT_RATE_WINDOW });
    return true;
  }
  if (rec.count >= PAYMENT_RATE_LIMIT) return false;
  rec.count++;
  return true;
};
// Bersihkan entry basi tiap 10 menit supaya Map tidak numpuk terus di memory.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of paymentRateMap) if (now > v.resetAt) paymentRateMap.delete(k);
}, 10 * 60 * 1000);

// ══════════════════════════════════════════════════════════════════
// SISTEM KEY DENGAN DURASI (per-hari & per-jam)
// ══════════════════════════════════════════════════════════════════
// Format key di stok (product.keys, array of string):
//   - "ABCD1234"        -> key generic, tanpa durasi spesifik
//   - "ABCD1234=30d"    -> key berlaku 30 HARI
//   - "ABCD1234=12h"    -> key berlaku 12 JAM
//
// FIX (dilaporkan client 21 Agu 2026): separator SEBELUMNYA pakai titik dua
// (":"), tapi key cheat "silent" ada yang isinya sendiri mengandung ":",
// jadi bentrok sama parsing (misal "abc:def:xyz" salah kesplit jadi durasi).
// Sekarang pakai "=" sebagai separator durasi -- karakter ini jauh lebih
// jarang muncul di key cheat manapun.
//
// Admin BEBAS pilih durasi berapa aja & unit apa aja per-baris key saat
// restock (tidak dikunci ke daftar durasi produk) -- cukup ketik
// "KEY=30d" atau "KEY=12h" satu per baris di textarea restock, sistem yang
// mem-parsing otomatis. Kalau baris key tidak ada "=", dianggap generic.
//
// parseKeyDuration("ABCD=30d") -> { raw: "ABCD", value: 30, unit: 'd' }
// parseKeyDuration("ABCD=12h") -> { raw: "ABCD", value: 12, unit: 'h' }
// parseKeyDuration("ABCD")     -> { raw: "ABCD", value: null, unit: null }
function parseKeyDuration(keyStr) {
  const idx = keyStr.lastIndexOf('=');
  if (idx === -1) return { raw: keyStr, value: null, unit: null };
  const raw = keyStr.slice(0, idx);
  const durationPart = keyStr.slice(idx + 1).trim().toLowerCase();
  const m = durationPart.match(/^(\d+)\s*(d|h)?$/);
  if (!m) return { raw: keyStr, value: null, unit: null }; // format tidak dikenali, treat sebagai generic (raw = seluruh string asli)
  return { raw, value: parseInt(m[1]), unit: m[2] || 'd' }; // default ke hari kalau unit tidak ditulis (backward-compat sama key lama format "KEY=30")
}

// isGenericKey: true kalau key tidak punya durasi sama sekali (tanpa "=").
function isGenericKey(keyStr) {
  return parseKeyDuration(keyStr).value === null;
}

// keyMatchesDuration: cocokkan key stok dengan durasi+unit yang dipesan
// customer. selectedUnit default 'd' (hari) untuk backward-compat sama
// pemanggil lama yang cuma kirim angka hari tanpa unit.
function keyMatchesDuration(keyStr, selectedValue, selectedUnit) {
  const parsed = parseKeyDuration(keyStr);
  if (parsed.value === null) return false;
  const unit = selectedUnit || 'd';
  return parsed.value === selectedValue && parsed.unit === unit;
}

// ══════════════════════════════════════════════════════════════════

// Lock set untuk mencegah race condition pada alokasi key
const processingOrders = new Set();
// Lock per-user untuk operasi wallet (beli pakai saldo). Tanpa ini, dua
// request /wallet/buy yang nyaris bersamaan (double-click, atau script abuse)
// bisa sama-sama baca saldo & stok key SEBELUM salah satu sempat nulis balik
// — hasilnya: saldo cuma kepotong sekali tapi key kekirim dua kali (double-spend).
const walletLocks = new Set();

// Riwayat webhook payment gateway yang masuk (GensPay/dll), buat debug kalau
// ada laporan "sudah bayar tapi key/saldo belum otomatis masuk".
const webhookLog = [];
function logWebhook(gateway, entry) {
  webhookLog.unshift({ gateway, time: new Date().toISOString(), ...entry });
  if (webhookLog.length > 30) webhookLog.length = 30;
}

const checkQrRateLimit = (ip) => {
  const now = Date.now();
  const record = qrRateLimit.get(ip);
  if (record) {
    const windowStart = now - QR_RATE_WINDOW;
    const recentRequests = record.filter(ts => ts > windowStart);
    if (recentRequests.length >= QR_RATE_LIMIT) {
      return false;
    }
    recentRequests.push(now);
    qrRateLimit.set(ip, recentRequests);
  } else {
    qrRateLimit.set(ip, [now]);
  }
  return true;
};

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('trust proxy', 1);
app.use(expressLayouts);
// `verify` di sini nyimpen raw body string ke req.rawBody -- dibutuhkan
// khusus buat verifikasi signature webhook GensPay (lihat app.post('/webhook/genspay')),
// karena signature dihitung dari string JSON MENTAH persis seperti yang
// dikirim GensPay, bukan dari object hasil re-serialize (urutan key bisa
// beda kalau di-JSON.stringify ulang dari object yang sudah di-parse).
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(express.urlencoded({ extended: true }));
// NOTE: di Vercel, express.static() diabaikan sepenuhnya -- public/**
// otomatis diserve lewat CDN Vercel (lihat vercel.json untuk header cache-nya).
// maxAge di sini cuma berlaku untuk local dev / VPS non-Vercel, supaya
// behavior-nya konsisten dengan yang di production.
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads'), { maxAge: '1h' }));
app.use('/uploads/avatars', express.static(path.join(__dirname, 'public/uploads/avatars'), { maxAge: '1h' }));

// Vercel: file di /uploads tidak persistent - redirect ke Supabase Storage
if (process.env.VERCEL === '1' || process.env.NOW_REGION) {
  app.get('/uploads/logo-main.png', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/logo-main.png' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#2563eb"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">FX</text></svg>');
  });
  app.get('/uploads/logo-text.png', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/logo-text.png' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.status(404).send('Logo text not found');
  });
  app.get('/uploads/banner-reseller.jpg', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/banner-reseller.jpg' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.status(404).send('Banner not found');
  });
}

app.use(cookieSession({
  name: 'vpr_session',
  secret: SESSION_SECRET,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

// ══ AUDIT KEAMANAN 3 Sep 2026 (diminta user): CSRF protection ══
// Kenapa gak pakai library csurf/token klasik: proyek ini punya puluhan
// state-changing request (5 <form method="POST"> + 24 fetch() POST/PUT/
// DELETE tersebar di banyak file EJS + inline <script>). Nambah CSRF
// token butuh nyentuh SEMUA titik itu satu-satu (inject token ke form,
// tambah header di tiap fetch call) -- risiko regresi sangat tinggi kalau
// dikerjakan sekaligus tanpa test manual tiap form.
//
// Solusi yang dipilih: Origin/Referer validation. Ini independen dari
// cookie (gak perlu ubah form/fetch manapun) dan efektif menutup CSRF
// klasik -- request state-changing (POST/PUT/DELETE/PATCH) HARUS datang
// dari origin yang sama dengan server ini. Attacker yang bikin form/fetch
// di website lain untuk auto-submit ke sini akan gagal karena
// Origin/Referer browser-nya beda domain (browser modern selalu kirim
// header ini untuk cross-origin request, gak bisa dipalsukan dari sisi
// attacker lewat JS biasa).
//
// sameSite:'lax' di atas TIDAK diketatkan ke 'strict' karena akan merusak
// Google OAuth callback (browser gak kirim cookie session pas redirect
// balik dari accounts.google.com -- itu third-party navigation). Jadi dua
// lapis ini saling melengkapi: sameSite:'lax' handle sebagian besar kasus
// + origin check ini nutup celah yang tersisa.
//
// Dikecualikan: webhook GensPay (pembayaran) karena requestnya DATANG dari
// server GensPay, bukan browser -- gak akan pernah punya Origin header
// browser yang valid, dan sudah divalidasi terpisah pakai signature HMAC.
const CSRF_EXEMPT_PATHS = ['/webhook/genspay', '/api/webhook/genspay', '/webhook/pakasir', '/api/webhook/pakasir'];
app.use((req, res, next) => {
  const stateChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
  if (!stateChangingMethods.includes(req.method)) return next();
  if (CSRF_EXEMPT_PATHS.some(p => req.path.startsWith(p))) return next();

  const origin = req.get('origin') || req.get('referer');
  if (!origin) {
    // Request tanpa Origin/Referer sama sekali -- browser modern SELALU
    // kirim salah satu untuk POST/PUT/DELETE, jadi ini kemungkinan besar
    // request non-browser (curl/script) atau percobaan bypass. Ditolak.
    return res.status(403).json({ success: false, error: 'Origin tidak valid.' });
  }
  try {
    const originHost = new URL(origin).host;
    const requestHost = req.get('host');
    if (originHost !== requestHost) {
      console.warn(`⚠️  CSRF blocked: origin=${originHost} != host=${requestHost} pada ${req.method} ${req.path}`);
      return res.status(403).json({ success: false, error: 'Origin tidak valid.' });
    }
  } catch (e) {
    return res.status(403).json({ success: false, error: 'Origin tidak valid.' });
  }
  next();
});

// ══════════════════════════════════════════════════════════════════
// GOOGLE OAUTH LOGIN (opsional, diminta client 21 Agu 2026 -- "daftar
// bisa pilih menggunakan login akun ggl (optional)")
// ══════════════════════════════════════════════════════════════════
// Perlu GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET di environment variable,
// didapat dari Google Cloud Console > APIs & Services > Credentials >
// buat OAuth 2.0 Client ID (tipe "Web application"). Authorized redirect
// URI yang harus didaftarkan di sana: https://domainkamu.com/auth/google/callback
//
// Kalau env var belum diisi, seluruh fitur Google Login otomatis
// dinonaktifkan (tombol "Login dengan Google" disembunyikan di
// login.ejs/register.ejs) -- TIDAK bikin app crash meski belum disetup.
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GOOGLE_OAUTH_ENABLED = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (GOOGLE_OAUTH_ENABLED) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    // FIX KEAMANAN (audit 22 Agu 2026): `state: true` mengaktifkan proteksi
    // CSRF standar OAuth 2.0 bawaan passport-oauth2 -- generate nonce acak,
    // simpan di session, kirim sebagai parameter `state` ke Google, lalu
    // verifikasi nonce yang di-echo balik cocok dengan yang tersimpan di
    // session sebelum melanjutkan login. Tanpa ini, attacker berpotensi
    // memulai OAuth flow dengan akun Google miliknya sendiri, mendapat
    // authorization code, lalu memancing korban untuk "menyelesaikan"
    // callback tersebut -- yang bisa berujung akun korban ter-link ke akun
    // Google attacker, atau skenario CSRF serupa. Ini kompatibel dengan
    // cookie-session yang dipakai app ini (nonce disimpan di req.session
    // sementara, bukan butuh passport.session() yang memang sengaja tidak
    // dipakai di sini -- lihat komentar di bawah).
    state: true,
  }, async (accessToken, refreshToken, profile, done) => {
    // NOTE: fungsi ini HANYA mencocokkan/membuat user, TIDAK menyentuh
    // req.session -- itu dilakukan manual di route callback (lihat di
    // bawah) karena app ini pakai cookie-session, bukan session store
    // biasa, jadi passport.session()/serializeUser tidak dipakai sama
    // sekali (redundant untuk arsitektur stateless-cookie ini).
    try {
      const users = await readFresh('users.json');
      const email = profile.emails?.[0]?.value || null;
      let user = users.find(u => u.googleId === profile.id) || (email && users.find(u => u.email === email));
      if (!user) {
        user = {
          id: uuidv4(),
          username: profile.displayName || (email ? email.split('@')[0] : 'user' + Date.now()),
          email,
          googleId: profile.id,
          password: null, // akun Google tidak punya password lokal
          wa: null, // dilengkapi belakangan di halaman lengkapi profil, lihat /complete-profile
          photo: profile.photos?.[0]?.value || null,
          balance: 0,
          createdAt: new Date().toISOString()
        };
        users.push(user);
        await writeDB('users.json', users);
      } else if (!user.googleId) {
        // User lama daftar manual, sekarang login pertama kali pakai Google dengan email yang sama -> link akun
        user.googleId = profile.id;
        await writeDB('users.json', users);
      }
      done(null, user);
    } catch (err) { done(err, null); }
  }));
  app.use(passport.initialize());
}
// ══════════════════════════════════════════════════════════════════

// ── FIX: Regenerate session object tiap request (cookie-session quirk) ──
app.use((req, res, next) => {
  // Pastikan session object tidak null
  if (!req.session) req.session = {};
  next();
});

// SECURITY: helper untuk embed data JSON ke dalam <script> block di EJS
// dengan aman. JSON.stringify() biasa TIDAK aman kalau string di dalamnya
// mengandung "</script>" — itu akan memutus tag <script> di HTML dan bisa
// jadi stored XSS (misal lewat nama produk yang diinput admin). Fungsi ini
// meng-escape karakter '<' jadi '\u003c' sehingga JSON tetap valid & sama
// persis secara data, tapi tidak bisa memutus tag HTML manapun.
// Dipakai di views lewat <%- safeJson(dataVariable) %> menggantikan
// <%- JSON.stringify(dataVariable) %> untuk data yang di-inject ke <script>.
app.locals.safeJson = (data) => JSON.stringify(data).replace(/</g, '\\u003c');

// Icon bundle offline untuk iconify-icon (lihat catatan lengkap di
// views/layout.ejs) -- dibaca SEKALI saat startup (bukan per-request),
// sudah dalam bentuk string JSON siap-pakai supaya layout.ejs tinggal
// <%- iconBundle %> tanpa parse ulang tiap render.
const iconBundleString = fs.readFileSync(path.join(__dirname, 'public', 'js', 'icon-bundle.json'), 'utf-8');
app.locals.iconBundle = iconBundleString;

// Inject settings + isAdmin ke semua view otomatis
app.use(async (req, res, next) => {
  // Kalau cache settings kosong, fetch dari Supabase dulu
  let settings = readDB('settings.json');
  if (!settings || Object.keys(settings).length === 0) {
    settings = await db.readFresh('settings.json').catch(() => ({}));
  }
  res.locals.settings = settings || {};
  res.locals.isAdmin = !!(req.session?.isAdmin || req.session?.userId === 'admin');
  res.locals.user = getSessionUser(req);
  res.locals.googleOAuthEnabled = GOOGLE_OAUTH_ENABLED;
  res.locals.hexToRgba = hexToRgba;
  res.locals.parseProductDescription = parseProductDescription;
  // ── SEO: URL kanonik situs (diminta client 22 Agu 2026) ──
  // Dipakai untuk <link rel="canonical">, Open Graph og:url, dan sitemap.xml.
  // Prioritas: domain custom yang diisi admin (settings.siteUrl) -> header
  // request asli (aman di belakang proxy Vercel) -> fallback req.protocol/host.
  res.locals.siteUrl = (settings?.siteUrl || `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host'] || req.get('host')}`).replace(/\/$/, '');
  next();
});

// Setup upload — gunakan /tmp di Vercel (satu-satunya writable path)
const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;

// ══════════════════════════════════════════════════════════════════
// FIX KEAMANAN (audit 22 Agu 2026): validasi MAGIC BYTES untuk file
// upload gambar. Multer fileFilter yang lama HANYA cek `file.mimetype`
// dari header Content-Type request -- itu diklaim oleh CLIENT, bisa
// dipalsukan dengan mudah (upload file .html/.php/.js apapun tapi kirim
// header "Content-Type: image/jpeg"). Kalau file itu nanti dibuka
// langsung di browser (mis. avatar/produk), ada risiko stored XSS atau
// worse tergantung bagaimana file itu di-render/diserve nantinya.
// Fungsi ini cek byte AWAL file (signature asli tiap format gambar),
// bukan cuma percaya klaim client -- defense-in-depth, dijalankan
// SETELAH multer fileFilter (yang tetap dipertahankan sebagai lapis
// pertama yang cepat), sebelum file dianggap final tersimpan.
function verifyImageMagicBytes(filePath) {
  try {
    const buf = Buffer.alloc(12);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, 12, 0);
    fs.closeSync(fd);

    // JPEG: FF D8 FF
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return true;
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return true;
    // GIF: "GIF87a" atau "GIF89a"
    if (buf.slice(0, 6).toString('ascii') === 'GIF87a' || buf.slice(0, 6).toString('ascii') === 'GIF89a') return true;
    // WEBP: "RIFF" (byte 0-3) + "WEBP" (byte 8-11)
    if (buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') return true;

    return false;
  } catch (e) {
    return false; // gagal baca file = anggap tidak valid, lebih aman daripada meloloskan
  }
}

// Middleware generik: pasang SETELAH multer upload single file, sebelum
// handler utama route. Kalau magic bytes tidak cocok gambar asli, hapus
// file yang sudah kepalang tersimpan dan tolak request.
function requireValidImageMagicBytes(req, res, next) {
  if (!req.file) return next(); // tidak ada file = biar divalidasi logic lain di handler
  if (!verifyImageMagicBytes(req.file.path)) {
    fs.unlink(req.file.path, () => {}); // best-effort cleanup, tidak perlu tunggu hasilnya
    return res.status(400).json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
  }
  next();
}

// Versi buffer-based (untuk multer.memoryStorage(), req.file.buffer bukan
// req.file.path) -- dipakai endpoint yang upload langsung ke Supabase
// Storage tanpa nyimpen file sementara ke disk lokal dulu.
function verifyImageMagicBytesBuffer(buffer) {
  if (!buffer || buffer.length < 12) return false;
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;
  if (buffer.slice(0, 6).toString('ascii') === 'GIF87a' || buffer.slice(0, 6).toString('ascii') === 'GIF89a') return true;
  if (buffer.slice(0, 4).toString('ascii') === 'RIFF' && buffer.slice(8, 12).toString('ascii') === 'WEBP') return true;
  return false;
}

function requireValidImageMagicBytesBuffer(req, res, next) {
  if (!req.file) return next();
  if (!verifyImageMagicBytesBuffer(req.file.buffer)) {
    return res.status(400).json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
  }
  next();
}

// Versi multi-file (untuk multer .array(), req.files bukan req.file tunggal)
// -- dipakai upload multi-gambar seperti listing Jual Beli Akun. FIX BUG
// KEAMANAN (3 Sep 2026): tanpa ini, requireValidImageMagicBytes/Buffer yang
// cuma ngecek req.file (singular) akan DIAM-DIAM SKIP validasi sama sekali
// buat endpoint yang pakai .array() -- req.file selalu undefined di situ,
// jadi kondisi "if (!req.file) return next()" bikin validasi gak pernah
// jalan, menerima file apapun asal mimetype-nya di-spoof jadi image/*.
function requireValidImageMagicBytesArray(req, res, next) {
  if (!req.files || !req.files.length) return next();
  for (const file of req.files) {
    if (!verifyImageMagicBytes(file.path)) {
      req.files.forEach(f => fs.unlink(f.path, () => {})); // best-effort cleanup semua file di batch ini
      return res.status(400).json({ success: false, message: `File "${file.originalname}" bukan gambar asli (gagal validasi format file).` });
    }
  }
  next();
}

const uploadsBase = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
const uploadsDir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');

// Buat direktori lokal hanya jika bukan Vercel
if (!isVercel) {
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Hanya file gambar yang diizinkan'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: fileFilter
});

// Database helpers (Supabase)
const dbPath = path.join(__dirname, 'database');
if (!isVercel && !fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const readDB = db.readDB;
const writeDB = db.writeDB;
const readFresh = db.readFresh;
const atomicUpdate = db.atomicUpdate;

// Banner lama (seed default "Open Reseller") tersimpan tanpa field `id` dan
// pakai key `url` bukan `imageUrl` — akibatnya tombol "Hapus"/"Toggle" di
// admin panel selalu gagal mencocokkan banner tersebut (id undefined !== id
// yang dikirim dari client) sehingga banner itu seolah tidak bisa dihapus.
// Banner default ini memang tidak diperlukan, jadi begitu terbaca langsung
// dibuang otomatis. Banner lain yang memang tidak punya `id` (kasus lama
// lainnya) tetap dipertahankan, hanya dibenahi id & imageUrl-nya.
function normalizeBanners(settings) {
  if (!Array.isArray(settings.banners)) return false;
  let changed = false;
  const isLegacyDefaultReseller = b => !b.id && b.url === '/uploads/banner-reseller.jpg' && b.title === 'Open Reseller' && b.link === '/reseller';
  const filtered = settings.banners.filter(b => !isLegacyDefaultReseller(b));
  if (filtered.length !== settings.banners.length) { settings.banners = filtered; changed = true; }
  settings.banners.forEach(b => {
    if (!b.id) { b.id = uuidv4(); changed = true; }
    if (!b.imageUrl && b.url) { b.imageUrl = b.url; changed = true; }
  });
  return changed;
}
const readSmart = db.readSmart; // TTL-based: auto-refresh jika cache >60 detik
const refreshForWrite = (...files) => Promise.all(files.map(f => db.refreshFromDB(f)));

// ── PERFORMANCE: user lookup Map, dipakai untuk hindari .find() berulang
// di tempat lain yang butuh cocokkan user by id/username (mis. testimonial
// photo attach).
const buildUserLookupMaps = (users) => ({
  byId: new Map(users.map(u => [u.id, u])),
  byUsername: new Map(users.map(u => [u.username, u]))
});

// Initialize database files with defaults (only if truly missing)
const initDB = async () => {
  // JANGAN hardcode username/password admin di source code (ini yang
  // sebelumnya bocor lewat GitHub). Kalau env var tidak diset, generate
  // password random tiap kali server start dari nol, dan print SEKALI ke
  // log server (bukan ke kode) supaya bisa langsung dipakai lalu diganti.
  const crypto = require('crypto');
  const fallbackUsername = process.env.INITIAL_ADMIN_USERNAME || 'admin';
  const fallbackPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  if (!process.env.INITIAL_ADMIN_PASSWORD) {
    console.log('🔐 Belum ada INITIAL_ADMIN_PASSWORD di env. Password admin awal di-generate random:');
    console.log(`   username: ${fallbackUsername}`);
    console.log(`   password: ${fallbackPassword}`);
    console.log('   GANTI password ini lewat Admin Panel setelah login pertama!');
  }

  const defaultSettings = {
    siteName: 'FranzzStore',
    gamePanelName: 'FranzzStore',
    // Rebrand FranzzStore (30 Agu 2026, dari referensi mallstore.id): deskripsi
    // spesifik menyebut nama game & jenis produk yang dijual, supaya relevan
    // untuk pencarian "topup ff", "topup ml", "diamond murah", dll.
    about: 'FranzzStore adalah platform topup game & premium app terpercaya #1 di Indonesia. Topup diamond Free Fire, Mobile Legends, PUBG Mobile, Genshin Impact, Valorant, dan langganan premium app (Spotify, YouTube, Netflix, Canva) dengan harga termurah, proses instan, dan pembayaran QRIS aman.',
    seoKeywords: 'topup ff, topup mobile legends, topup pubgm, diamond murah, topup genshin, topup valorant, uc pubg murah, spotify premium murah, youtube premium, netflix premium, canva pro, premium app murah, topup game termurah',
    siteUrl: '',
    marqueeText: 'TOPUP GAME & PREMIUM APP TERMURAH - PROSES CEPAT & AMAN',
    contact: {
      whatsapp: '6282253090432',
      telegram: 'FranzzStoreOfficial',
      email: 'support@franzzstore.id',
      youtube: '',
      waChannel: '',
      waGroup: '',
    },
    fonnteToken: '',
    pakasir: { apiKey: '', project: '', mode: 'production' },
    genspay: { apiKey: '', baseUrl: 'https://genspay.my.id/api/v1' },
    apiGateway: 'pakasir',
    adminUsername: fallbackUsername,
    adminPassword: bcrypt.hashSync(fallbackPassword, 12),
    logoUrl: '/uploads/logo-main.png',
    logoTextUrl: null,
    buyerGroupName: 'BUYER VIP FRANZZSTORE',
    buyerGroupUrl: 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
    resellerGroupName: 'RESELLER VIP FRANZZSTORE',
    resellerGroupUrl: 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
    categories: ['freefire', 'mlbb', 'pubgm', 'genshin', 'valorant', 'premium'],
    categoryLabels: { freefire: 'FREE FIRE', mlbb: 'MOBILE LEGENDS', pubgm: 'PUBG MOBILE', genshin: 'GENSHIN IMPACT', valorant: 'VALORANT', premium: 'PREMIUM APP' },
    resellerEnabled: true,
    resellerPrice: 50000,
    resellerDiscount: 20,
    resellerNote: 'Dapatkan diskon eksklusif untuk semua produk!',
    resellerMinDeposit: 50000,
    memberMinDeposit: 10000,
    popularProductIds: [],
    banners: [],
    // Tema warna brand FranzzStore (navy + biru) -- SEBELUMNYA tidak ada
    // field ini sama sekali di defaultSettings, cuma fallback hardcode
    // '#2563eb' di tiap template EJS (settings?.theme?.primaryColor ||
    // '#2563eb'). Sekarang eksplisit disimpan di sini supaya jadi bagian
    // dari FORCE_UPDATE_KEYS di bawah (lihat blok merge settings) -- kalau
    // tidak, force-update ke field 'theme' akan menimpa jadi undefined.
    theme: { primaryColor: '#2563eb', accentColor: '#0b1f45' }
  };

  const arrayFiles = ['users.json', 'products.json', 'transactions.json', 'testimonials.json', 'notifications.json', 'keyspool.json', 'vouchers.json', 'accounts.json'];

  // Seed arrays only if they don't exist at all
  for (const filename of arrayFiles) {
    const current = readDB(filename);
    if (!Array.isArray(current)) {
      await writeDB(filename, []);
    }
  }

  // Settings: merge defaults + existing. Jangan overwrite data yang sudah ada.
  const currentSettings = readDB('settings.json');
  if (!currentSettings || Object.keys(currentSettings).length === 0) {
    // Supabase kosong — push default penuh
    await writeDB('settings.json', defaultSettings);
    console.log('✅ Settings seeded with defaults');
  } else {
    // Merge: tambah field yang belum ada, jangan overwrite yang sudah ada
    let dirty = false;
    for (const [k, v] of Object.entries(defaultSettings)) {
      if (currentSettings[k] === undefined || currentSettings[k] === null) {
        currentSettings[k] = v;
        dirty = true;
      }
    }

    // FORCE-UPDATE branding inti (31 Agu 2026): field di bawah SELALU
    // ditimpa ke nilai dari kode setiap kali server start -- BUKAN cuma
    // diisi kalau kosong. Ini kebalikan dari logic merge di atas, sengaja
    // dipisah karena masalah nyata yang dialami: Supabase yang sudah
    // pernah punya data lama (branding lama, warna lama) bikin rebrand di
    // kode TIDAK PERNAH kelihatan efeknya walau sudah redeploy berkali-
    // kali -- karena logic "jangan overwrite yang sudah ada" di atas
    // menganggap field lama itu "sudah diisi", padahal isinya justru
    // yang mau diganti. Field yang TIDAK force-update (kredensial admin,
    // kontak WA, produk, dll) sengaja tetap pakai jalur merge biasa di
    // atas supaya perubahan manual admin dari Admin Panel tidak ketiban.
    const FORCE_UPDATE_KEYS = ['siteName', 'gamePanelName', 'theme', 'logoUrl', 'marqueeText'];
    for (const k of FORCE_UPDATE_KEYS) {
      if (JSON.stringify(currentSettings[k]) !== JSON.stringify(defaultSettings[k])) {
        currentSettings[k] = defaultSettings[k];
        dirty = true;
      }
    }

    if (dirty) {
      await writeDB('settings.json', currentSettings);
      console.log('✅ Settings merged missing fields + branding force-updated');
    }
  }

  // ── MIGRASI PRODUK LAMA ke sistem kategori baru (diminta client 22 Agu
  // 2026: gabung "platform" Android/iOS/PC hardcode jadi 1 sistem
  // "categories" yang admin atur bebas) ──
  // Sebelumnya produk lama masih tersimpan dengan field `platforms` (array
  // lama) atau `category` (string tunggal) di DATABASE-nya sendiri --
  // homepage/admin-product-edit sudah punya fallback tampilan yang baca
  // field lama ini, TAPI itu cuma "ngakalin" di level render, datanya
  // sendiri di database belum ikut berubah. Kalau admin belum pernah
  // buka+simpan ulang produk lama itu satu-satu, filter kategori baru
  // (yang scan field `categories`) tidak akan pernah menemukan produk itu
  // sama sekali. Migrasi ini jalan SEKALI tiap server start, permanen
  // convert field lama jadi `categories` array di database, supaya tidak
  // perlu admin re-save produk manual satu-satu.
  const productsForMigration = readDB('products.json');
  if (Array.isArray(productsForMigration) && productsForMigration.length > 0) {
    let productsMigrated = false;
    productsForMigration.forEach(p => {
      if (!Array.isArray(p.categories) || p.categories.length === 0) {
        if (Array.isArray(p.platforms) && p.platforms.length > 0) {
          p.categories = p.platforms;
          productsMigrated = true;
        } else if (p.category) {
          p.categories = [p.category];
          productsMigrated = true;
        }
      }
    });
    if (productsMigrated) {
      await writeDB('products.json', productsForMigration);
      console.log('✅ Produk lama dimigrasi ke sistem kategori baru (categories array)');
    }
  }
};

// Vercel: export app langsung (Vercel tidak pakai app.listen)
// Lokal: jalankan server setelah DB siap
if (isVercel) {
  // ── VERCEL FIX: pastikan DB init selesai sebelum request diproses ──
  let dbReady = false;
  let dbInitPromise = null;

  const ensureDBReady = async () => {
    if (dbReady) return;
    if (!dbInitPromise) {
      dbInitPromise = db.initializeDB().then(() => initDB()).then(() => { dbReady = true; });
    }
    await dbInitPromise;
  };

  // Middleware: block request sampai DB siap (max 8 detik)
  app.use(async (req, res, next) => {
    try {
      await Promise.race([
        ensureDBReady(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DB init timeout')), 8000))
      ]);
    } catch (e) {
      console.error('[DB] Init failed or timeout:', e.message);
      // Lanjut saja, pakai local fallback
    }
    next();
  });

  module.exports = app;
} else {
  // Lokal / VPS: tunggu DB siap baru listen
  db.initializeDB().then(() => {
    initDB(); // seed defaults only if missing
    app.listen(PORT, () => {
      console.log(`✅ Server berjalan di http://localhost:${PORT}`);
      console.log(`📁 Database: ${dbPath}`);
      console.log(`🔐 Admin: /admin`);
    });
  }).catch(err => {
    console.error('Fatal: Failed to initialize database:', err);
    process.exit(1);
  });
  module.exports = app;
}

// Helper: dapatkan user dari session (support admin yang tidak ada di users.json)
// Helper: konversi warna hex ("#2563eb") jadi rgba string dengan alpha
// tertentu. Dipakai supaya elemen UI yang butuh warna tema TRANSPARAN
// (background badge, border tipis, dll) tetap ikut warna tema custom dari
// admin panel (settings.theme.*), bukan hardcode merah. Kalau input bukan
// hex valid (mis. sudah rgba/CSS var lain), balikin fallback rgba abu netral.
function hexToRgba(hex, alpha) {
  if (!hex || typeof hex !== 'string' || !hex.startsWith('#')) return `rgba(148,163,184,${alpha})`;
  const clean = hex.replace('#', '');
  const full = clean.length === 3 ? clean.split('').map(c => c + c).join('') : clean;
  if (full.length !== 6) return `rgba(148,163,184,${alpha})`;
  const r = parseInt(full.slice(0, 2), 16), g = parseInt(full.slice(2, 4), 16), b = parseInt(full.slice(4, 6), 16);
  if ([r, g, b].some(isNaN)) return `rgba(148,163,184,${alpha})`;
  return `rgba(${r},${g},${b},${alpha})`;
}

const getSessionUser = (req) => {
  if (req.session?.isAdmin) {
    const s = readDB('settings.json');
    return { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, photo: null, role: 'admin', is_reseller: false };
  }
  if (req.session?.userId) return readDB('users.json').find(u => u.id === req.session.userId) || null;
  return null;
};

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.userId) {
    if (req.xhr || req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: false, message: 'Silakan login terlebih dahulu', redirect: '/login' });
    }
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  next();
};

const requireAdmin = async (req, res, next) => {
  if (!req.session?.isAdmin && req.session?.userId !== 'admin') {
    // Balas 404 bukan 403 agar penyerang tidak tahu route admin ada
    return res.status(404).send('Not found');
  }

  // ── Single-Device Admin Lock ──────────────────────────────────
  // Mencegah 2 orang (mis: web dev + client) login admin bersamaan di
  // device berbeda. Login bersamaan menyebabkan race condition saat
  // keduanya baca-ubah-simpan data produk di waktu hampir sama, sehingga
  // perubahan salah satu pihak tertimpa / produk "berubah-ubah" saat refresh.
  //
  // PENTING: pakai readFresh (bukan readDB) di sini. Vercel menjalankan
  // banyak instance serverless yang TIDAK berbagi memori — kalau pakai
  // cache lokal, satu instance bisa "telat tahu" kalau device lain baru
  // saja ambil alih sesi, dan tetap meloloskan device yang seharusnya
  // sudah diblokir. Ini satu-satunya pengecekan yang wajib selalu fresh.
  const lock = await db.readFresh('admin-lock.json');
  if (isLockActive(lock) && lock.sessionId !== req.session.adminSessionId) {
    req.session = null; // paksa logout sesi yang sudah digantikan
    if (ADMIN_PAGE_ROUTES.has(req.path)) {
      return res.redirect('/vpr-secure-panel-8x?kicked=1');
    }
    return res.status(401).json({
      success: false,
      sessionRevoked: true,
      message: `Sesi admin Anda diakhiri karena ada login dari perangkat lain (${lock.device || 'perangkat lain'}).`
    });
  }

  // Sesi ini pemegang lock yang sah → perpanjang heartbeat (di-throttle,
  // supaya tidak nulis ke Supabase di setiap request)
  touchAdminLock(req.session.adminSessionId, lock);

  next();
};

// Halaman admin yang dimuat lewat navigasi browser biasa (bukan fetch/XHR)
// → kalau lock-nya hilang, redirect ke halaman login, bukan balas JSON.
const ADMIN_PAGE_ROUTES = new Set(['/admin', '/admin/product-edit', '/admin/theme-settings']);

// Lock dianggap kosong/expired kalau tidak ada heartbeat selama ini
// (mis: tab ditutup / koneksi putus tanpa logout resmi).
const ADMIN_LOCK_TIMEOUT_MS = 6 * 60 * 1000; // 6 menit

const parseDeviceLabel = (ua = '') => {
  let browser = 'Browser';
  if (/edg/i.test(ua)) browser = 'Edge';
  else if (/chrome/i.test(ua)) browser = 'Chrome';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os/i.test(ua)) os = 'Mac';
  else if (/linux/i.test(ua)) os = 'Linux';
  return `${browser} · ${os}`;
};

const isLockActive = (lock) => {
  if (!lock || !lock.sessionId || !lock.lastSeen) return false;
  return (Date.now() - new Date(lock.lastSeen).getTime()) < ADMIN_LOCK_TIMEOUT_MS;
};

// Klaim lock untuk sesi admin yang baru login. Dipanggil SETELAH password
// terverifikasi & lock lama dipastikan kosong/expired (lihat route login).
const acquireAdminLock = async (req) => {
  const sessionId = uuidv4();
  await writeDB('admin-lock.json', {
    sessionId,
    ip: req.ip,
    device: parseDeviceLabel(req.headers['user-agent'] || ''),
    loginAt: new Date().toISOString(),
    lastSeen: new Date().toISOString()
  });
  return sessionId;
};

// Lepas lock saat logout resmi — supaya device lain bisa langsung login
// tanpa harus menunggu timeout.
const releaseAdminLock = async (sessionId) => {
  if (!sessionId) return;
  try {
    const lock = await db.readFresh('admin-lock.json');
    if (lock && lock.sessionId === sessionId) await writeDB('admin-lock.json', {});
  } catch {}
};

// Heartbeat di-throttle per sessionId supaya tidak nulis ke Supabase di
// setiap request admin (cukup tiap ≥60 detik aktivitas). `lock` di sini
// sudah hasil readFresh dari requireAdmin, jadi tidak perlu baca ulang.
const lastHeartbeatAt = new Map();
const touchAdminLock = (sessionId, lock) => {
  if (!sessionId || !lock || lock.sessionId !== sessionId) return;
  const now = Date.now();
  if (now - (lastHeartbeatAt.get(sessionId) || 0) < 60000) return;
  lastHeartbeatAt.set(sessionId, now);
  writeDB('admin-lock.json', { ...lock, lastSeen: new Date().toISOString() }).catch(() => {});
};

// Helper functions
// FIX KEAMANAN (audit 22 Agu 2026): Math.random() bukan cryptographically
// secure -- untuk kode yang berfungsi sebagai "kunci akses" ke data
// transaksi (dipakai di /invoice untuk lacak pesanan tanpa akun), lebih
// aman pakai crypto.randomBytes() yang tidak predictable. Kombinasi rate
// limit (lihat checkInvoiceRateLimit) + entropy kode ini (32^8 ≈ 1 triliun
// kombinasi) sudah memadai terhadap brute-force dari 1 IP, ini upgrade
// defense-in-depth tambahan.
const generateOrderCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const randomBytes = crypto.randomBytes(8);
  let code = 'FX-';
  for (let i = 0; i < 4; i++) code += chars[randomBytes[i] % chars.length];
  code += '-';
  for (let i = 4; i < 8; i++) code += chars[randomBytes[i] % chars.length];
  return code;
};

const formatDate = (date = new Date()) => {
  const d = new Date(date);
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  return `${day}/${month}/${year} ${hours}:${minutes}`;
};

// ── PakKasir API (app.pakasir.com) ──
const createQRISPaymentPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key atau Project PakKasir belum dikonfigurasi'));

    const body = JSON.stringify({ project, order_id: orderId, amount, api_key: apiKey });
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: '/api/transactioncreate/qris', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.payment?.payment_number || r.payment_number || r.qr_string || r.data?.payment_number;
          if (!qr) return reject(new Error(r.message || `Pakasir error: ${data.slice(0,100)}`));
          resolve({ qr_string: qr, total_payment: r.payment?.total_payment || amount, expired_at: r.payment?.expired_at || null });
        } catch(e) { reject(new Error('Gagal parse response PakKasir')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// ── GensPay API (genspay.my.id) ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs
// Base URL API: https://genspay.my.id/api/v1
// Cara pakai (SESUAI dokumentasi resmi, sama seperti diterapkan di
// project GhostNewEra):
//   1. Buat project di Dashboard → menu Project → dapat API Key
//   2. Kirim API Key di header X-API-Key pada SETIAP request
//   3. POST /transaction/create untuk generate QRIS (body wajib include
//      payment_method: "qris")
//   4. TIDAK ADA endpoint GET status manual / cancel -- status transaksi
//      HANYA dikirim lewat webhook (event "transaction.updated", lihat
//      app.post('/webhook/genspay')).
const createQRISPaymentGenspay = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const baseUrl = (settings.genspay?.baseUrl || process.env.GENSPAY_BASE_URL || 'https://genspay.my.id/api/v1').trim();
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    if (!apiKey) return reject(new Error('API Key GensPay belum dikonfigurasi'));

    let url;
    try { url = new URL(baseUrl.replace(/\/+$/, '') + '/transaction/create'); } catch (e) { return reject(new Error('Base URL GensPay tidak valid')); }

    const body = JSON.stringify({ amount, order_id: orderId, payment_method: 'qris' });
    const req = https.request({
      hostname: url.hostname, port: url.port || 443,
      path: url.pathname + url.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey, 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.data?.qr_string;
          if (!r.success || !qr) return reject(new Error(r.error || r.message || `GensPay error (HTTP ${res.statusCode}): ${data.slice(0,150)}`));
          resolve({ qr_string: qr, total_payment: r.data?.amount || amount, expired_at: r.data?.expiry_time || null });
        } catch(e) { reject(new Error(`Gagal parse response GensPay (HTTP ${res.statusCode}): ${data.slice(0,200) || '(response kosong)'}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('GensPay timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// ── Dispatcher gateway QRIS dinamis ──
// settings.apiGateway: 'pakasir' (default) | 'genspay'
// Semua call site lama tetap manggil createQRISPayment(orderId, amount, settings)
// apa adanya -- dispatcher ini yang nentuin ke gateway mana request-nya pergi.
const createQRISPayment = (orderId, amount, settings) => {
  const gateway = settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return createQRISPaymentGenspay(orderId, amount, settings);
  return createQRISPaymentPakasir(orderId, amount, settings);
};

// Kirim notifikasi WhatsApp otomatis ke admin via Fonnte (jika token dikonfigurasi)
const sendWhatsAppNotif = (target, message, settings) => {
  return new Promise((resolve) => {
    const token = settings?.fonnteToken?.trim() || '';
    if (!token || !target) return resolve(false);
    const body = `target=${encodeURIComponent(target)}&message=${encodeURIComponent(message)}`;
    const req = https.request({
      hostname: 'api.fonnte.com', port: 443,
      path: '/send', method: 'POST',
      headers: {
        'Authorization': token,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 10000
    }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body); req.end();
  });
};

const checkPaymentStatusPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key PakKasir belum dikonfigurasi'));

    const q = `project=${encodeURIComponent(project)}&amount=${parseInt(amount)}&order_id=${encodeURIComponent(orderId)}&api_key=${encodeURIComponent(apiKey)}`;
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: `/api/transactiondetail?${q}`, method: 'GET', timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Gagal parse response status')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir status timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.end();
  });
};

// PENTING: dokumentasi resmi GensPay (genspay.my.id/docs) TIDAK menyediakan
// endpoint GET untuk cek status transaksi -- GensPay sepenuhnya mengandalkan
// WEBHOOK (POST ke Webhook URL project kamu, event "transaction.updated")
// buat kasih tau perubahan status. Fungsi ini reject dengan jelas supaya
// polling /check-payment tidak diam-diam gagal terus tanpa penjelasan;
// finalize order untuk GensPay HARUS lewat webhook (lihat
// app.post('/webhook/genspay') di bawah).
const checkPaymentStatusGenspay = (orderId, amount, settings) => {
  return Promise.reject(new Error(
    'GensPay tidak menyediakan endpoint cek status manual -- status transaksi HANYA dikirim via webhook. ' +
    'Pastikan Webhook URL sudah didaftarkan di dashboard GensPay (Settings project).'
  ));
};

// Dispatcher, sama polanya seperti createQRISPayment di atas.
const checkPaymentStatus = (orderId, amount, settings, gatewayOverride) => {
  const gateway = gatewayOverride || settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return checkPaymentStatusGenspay(orderId, amount, settings);
  return checkPaymentStatusPakasir(orderId, amount, settings);
};

// Routes - Public
// ══════════════════════════════════════════════════════════════════
// SETUP ENDPOINT — Reset admin password + push semua settings
// Akses: /franzzstore-setup?secret=SETUP_SECRET (dari env var)
// Set SETUP_SECRET di Vercel env vars, lalu akses URL-nya via browser.
// Setelah berhasil, HAPUS SETUP_SECRET dari env Vercel untuk keamanan.
// ══════════════════════════════════════════════════════════════════
app.get('/franzzstore-setup', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!timingSafeStringEqual(req.query.secret, secret)) {
    return res.status(403).send('❌ Akses ditolak. Set SETUP_SECRET di env Vercel dulu.');
  }

  try {
    const currentSettings = await db.readFresh('settings.json') || {};

    // JANGAN hardcode password fallback di sini juga — endpoint ini bisa
    // dipicu ulang kapan saja oleh siapapun yang tahu SETUP_SECRET, jadi
    // fallback HARUS random per-run, bukan string tetap yang bisa dibaca
    // dari source code (lihat penjelasan yang sama di initDB()).
    const newUsername = process.env.INITIAL_ADMIN_USERNAME || 'admin';
    const newPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
    const newHash     = bcrypt.hashSync(newPassword, 12);

    const updatedSettings = {
      ...currentSettings,
      siteName:      'FranzzStore',
      gamePanelName: 'FranzzStore',
      about:         'FranzzStore — platform topup game & premium app termurah #1 Indonesia. Proses instan, pembayaran QRIS aman.',
      marqueeText:   'TOPUP GAME & PREMIUM APP TERMURAH - PROSES CEPAT & AMAN',
      contact: {
        ...(currentSettings.contact || {}),
        whatsapp:  currentSettings.contact?.whatsapp || '6282253090432',
        telegram:  currentSettings.contact?.telegram || 'FranzzStoreOfficial',
        email:     currentSettings.contact?.email || 'support@franzzstore.id',
        youtube:   currentSettings.contact?.youtube || '',
        waChannel: currentSettings.contact?.waChannel || '',
        waGroup:   currentSettings.contact?.waGroup || '',
      },
      adminUsername: newUsername,
      adminPassword: newHash,
      logoUrl: currentSettings.logoUrl || '/uploads/logo-main.png',
      logoTextUrl: currentSettings.logoTextUrl === '/uploads/logo-text.png' ? null : currentSettings.logoTextUrl,
      buyerGroupName: currentSettings.buyerGroupName || 'BUYER VIP FRANZZSTORE',
      buyerGroupUrl: currentSettings.buyerGroupUrl || 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
      resellerGroupName: currentSettings.resellerGroupName || 'RESELLER VIP FRANZZSTORE',
      resellerGroupUrl: currentSettings.resellerGroupUrl || 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
    };

    await db.writeDB('settings.json', updatedSettings);

    // Verify
    const saved   = await db.readFresh('settings.json');
    const verify  = bcrypt.compareSync(newPassword, saved.adminPassword);

    res.send(`
      <!DOCTYPE html><html><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Setup Result</title>
      <style>body{font-family:monospace;background:#121214;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}
      .ok{color:#4ade80;} .err{color:#60a5fa;} .box{background:#1c1c1f;border:1px solid rgba(37,99,235,.3);border-radius:10px;padding:20px;margin:16px 0;}
      h2{color:#60a5fa;} a{color:#60a5fa;}</style></head><body>
      <h2>${verify ? '✅ SETUP BERHASIL' : '❌ SETUP GAGAL'}</h2>
      <div class="box">
        <p class="ok">✅ adminUsername : <strong>${saved.adminUsername}</strong></p>
        <p class="${verify?'ok':'err'}">${verify?'✅':'❌'} password hash  : ${verify?'MATCH — password benar':'TIDAK MATCH — ada masalah!'}</p>
        <p class="ok">✅ whatsapp      : ${saved.contact?.whatsapp}</p>
        <p class="ok">✅ telegram      : ${saved.contact?.telegram}</p>
        <p class="ok">✅ waChannel     : ${saved.contact?.waChannel}</p>
        <p class="ok">✅ waGroup       : ${saved.contact?.waGroup}</p>
      </div>
      <div class="box">
        <p>🔐 <strong>Login Admin:</strong></p>
        <p>URL&nbsp;&nbsp;&nbsp;&nbsp;: <a href="/vpr-secure-panel-8x">/vpr-secure-panel-8x</a></p>
        <p>Username: <strong>${newUsername}</strong></p>
        <p>Password: <strong>${newPassword}</strong></p>
      </div>
      <p style="color:rgba(148,163,184,.5);font-size:11px;">⚠️ Setelah berhasil login, HAPUS SETUP_SECRET dari env Vercel!</p>
      </body></html>
    `);
  } catch (err) {
    res.status(500).send(`❌ Error: ${err.message}`);
  }
});

// ══════════════════════════════════════════════════════════════════
// SEO: robots.txt & sitemap.xml (diminta client 22 Agu 2026)
// ══════════════════════════════════════════════════════════════════
app.get('/robots.txt', (req, res) => {
  const siteUrl = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + (req.headers['x-forwarded-host'] || req.get('host'));
  res.type('text/plain').send(
`User-agent: *
Allow: /
Disallow: /vpr-secure-panel-8x
Disallow: /admin
Disallow: /dashboard
Disallow: /invoice
Disallow: /activate-key
Disallow: /complete-profile
Disallow: /api/

Sitemap: ${siteUrl}/sitemap.xml`
  );
});

app.get('/sitemap.xml', async (req, res) => {
  try {
    const siteUrl = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + (req.headers['x-forwarded-host'] || req.get('host'));
    const products = (await readSmart('products.json')).filter(p => p.status === 'active');

    // Halaman statis penting untuk SEO
    const staticUrls = [
      { loc: '/', priority: '1.0', changefreq: 'daily' },
      { loc: '/informasi?tab=cara-beli', priority: '0.6', changefreq: 'monthly' },
      { loc: '/informasi?tab=faq', priority: '0.6', changefreq: 'monthly' },
      { loc: '/informasi?tab=syarat', priority: '0.4', changefreq: 'monthly' },
      { loc: '/reseller', priority: '0.7', changefreq: 'weekly' },
      { loc: '/login', priority: '0.3', changefreq: 'yearly' },
      { loc: '/register', priority: '0.3', changefreq: 'yearly' },
    ];

    // Halaman produk dinamis -- ini yang paling penting untuk SEO produk
    // spesifik (mis. "topup ff diamond murah" bisa nemu halaman ini
    // langsung dari Google).
    const productUrls = products.map(p => ({
      loc: `/buy/${p.id}`,
      priority: '0.8',
      changefreq: 'weekly'
    }));

    const allUrls = [...staticUrls, ...productUrls];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${allUrls.map(u => `  <url>
    <loc>${siteUrl}${u.loc}</loc>
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`).join('\n')}
</urlset>`;

    res.type('application/xml').send(xml);
  } catch (error) {
    res.status(500).type('text/plain').send('Error generating sitemap');
  }
});

app.get('/', async (req, res) => {
  // FIX (egress): route publik dengan traffic tinggi -- pakai readSmart
  // (cache ber-TTL), BUKAN readFresh (selalu fetch Supabase). readFresh di
  // sini dulu bikin setiap visitor menarik ulang seluruh blob products.json
  // dari Supabase, menghabiskan kuota cached egress free tier dengan cepat.
  const products = (await readSmart('products.json')).filter(p => p.status === 'active');

  // ── Server-side fake testimonials ──
  const fakeTestimonials = [
    { id:'fake1', name:'Rizky F.',    rating:5, text:'Topup diamond FF-nya mantap, udah langganan 3 bulan dan gak pernah ada masalah. Prosesnya otomatis, CS juga responsif banget!', productName:'FREE FIRE DIAMOND',      date:'2025-05-20', verified:true },
    { id:'fake2', name:'Andi S.',     rating:5, text:'Topup ML lengkap banget! Diamond, weekly pass sampai twilight pass ada. Harganya juga paling murah dibanding tempat lain.', productName:'MOBILE LEGENDS DIAMOND',    date:'2025-05-18', verified:true },
    { id:'fake3', name:'Dimas P.',    rating:5, text:'Support fast response! Pas salah isi ID langsung dibantu sampai beres. Topup UC PUBG-nya juga cepat, langsung masuk.', productName:'PUBG MOBILE UC',   date:'2025-05-15', verified:true },
    { id:'fake4', name:'farhan',      rating:5, text:'Beli Spotify Premium udah 2x dan alhamdulillah gak pernah ada kendala. Worth it banget harganya segitu.', productName:'SPOTIFY PREMIUM', date:'2025-05-10', verified:true },
    { id:'fake5', name:'Wanda M.',    rating:4, text:'Produknya bagus, prosesnya cepet banget. Cuma pas lagi ramai agak nunggu dikit tapi overall oke lah.', productName:'MOBILE LEGENDS DIAMOND',    date:'2025-05-08', verified:true },
    { id:'fake6', name:'ACA',         rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung diproses. Recommended!', productName:'FREE FIRE DIAMOND',      date:'2025-05-05', verified:true },
    { id:'fake7', name:'bintang',     rating:5, text:'Welkin Genshin worth it banget. Udah 6 bulan langganan di sini, harga lebih murah dari in-game.', productName:'GENSHIN IMPACT',   date:'2025-04-28', verified:true },
    { id:'fake8', name:'Rizky',       rating:4, text:'Kalau topup FF di sini top. Pernah ada kendala tapi langsung di-handle sama admin. Keep up the good work!', productName:'FREE FIRE DIAMOND',      date:'2025-04-20', verified:true },
    { id:'fake9', name:'Kevin',       rating:5, text:'Canva Pro-nya smooth banget. Langsung aktif dan bisa dipakai buat tugas desain. Harga murmer parah.', productName:'CANVA PRO',    date:'2025-04-15', verified:true },
    { id:'fake10',name:'abil',        rating:5, text:'Ini toko topup terpercaya yang pernah aku coba. Transaksi aman, pesanan langsung diproses, CS ramah.', productName:'FREE FIRE DIAMOND',      date:'2025-04-10', verified:true },
    { id:'fake11',name:'Hergi',       rating:5, text:'Topup VP Valorant-nya akurat banget. Sudah 2 bulan langganan dan belum ada masalah sama sekali. Pelayanan top!', productName:'VALORANT POINT', date:'2025-04-05', verified:true },
    { id:'fake12',name:'rehan',       rating:5, text:'Netflix Premium-nya mantap, profil private dan kualitas 4K jalan terus. Proses beli cepet dan langsung aktif.', productName:'NETFLIX PREMIUM',     date:'2025-03-28', verified:true },
  ];
  const realTestimonials = readDB('testimonials.json').filter(t => t.verified);
  const testiUsernames = new Set(realTestimonials.map(t => (t.username||'').toLowerCase()));
  const paddedFake = fakeTestimonials.filter(f => !testiUsernames.has((f.name||'').toLowerCase()));
  const testimonialsForHome = [...realTestimonials, ...paddedFake].slice(0, 12);
  const avgRating = testimonialsForHome.length
    ? (testimonialsForHome.reduce((s, t) => s + (t.rating || 0), 0) / testimonialsForHome.length).toFixed(1)
    : '4.9';
  const ratingCounts = {1:0,2:0,3:0,4:0,5:0};
  testimonialsForHome.forEach(t => { if (t.rating >= 1 && t.rating <= 5) ratingCounts[t.rating]++; });
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  res.render('pages/home', { products,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    resellerSettings: {
      enabled: settings.resellerEnabled !== false,
      price: settings.resellerPrice || 50000,
      discount: settings.resellerDiscount || 20
    },
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    testimonialsForHome,
    avgRating,
    ratingCounts,
    totalSold
  });
});

// Auth routes
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/login', {
    error: null,
    redirect: req.query.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.post('/login', authLimiter, async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = await checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/login', {
      error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.`,
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // ── Verifikasi Cloudflare Turnstile ─────────────────────────────────────
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan gagal. Coba lagi.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
  }
  // ────────────────────────────────────────────────────────────────────────

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  // Admin login diblokir dari /login — gunakan halaman khusus
  if (username === settings.adminUsername) {
    await recordLoginFail(ip);
    return res.render('pages/login', {
      error: 'Username atau password salah.',
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // Check user
  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    await clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.redirect(req.body.redirect || (req.session.isAdmin ? '/admin' : '/'));
  }

  await recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.render('pages/login', {
    error: errMsg,
    redirect: req.body.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.get('/register', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/register', { error: null, turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
});

// ══════════════════════════════════════════════════════════════════
// API JSON untuk LOGIN/REGISTER via POPUP (diminta client 22 Agu 2026:
// "login daftar nya tuh di pop up dahsbord bkn di halaman beda") --
// endpoint /login /register HTML lama TETAP ADA sebagai fallback (mis.
// kalau JS disabled, atau diakses langsung via URL), tapi sekarang modal
// popup di homepage manggil endpoint JSON ini supaya submit tidak perlu
// reload/pindah halaman sama sekali. Logic validasinya identik dengan
// /login /register lama, cuma bentuk response-nya JSON bukan render/redirect.
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = await checkLoginBlocked(ip);
  if (blocked) {
    return res.json({ success: false, message: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.` });
  }

  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) return res.json({ success: false, message: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.' });
    const valid = await verifyTurnstile(token);
    if (!valid) return res.json({ success: false, message: 'Verifikasi keamanan gagal. Coba lagi.' });
  }

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  if (username === settings.adminUsername) {
    await recordLoginFail(ip);
    return res.json({ success: false, message: 'Username atau password salah.' });
  }

  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    await clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.json({ success: true, redirect: req.body.redirect || (req.session.isAdmin ? '/admin' : '/') });
  }

  await recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.json({ success: false, message: errMsg });
});

app.post('/api/auth/register', async (req, res) => {
  if (!checkApiRateLimit(req.ip, 5, 15 * 60 * 1000)) {
    return res.json({ success: false, message: 'Terlalu banyak percobaan pendaftaran. Coba lagi dalam beberapa menit.' });
  }

  // FIX: endpoint ini sebelumnya sama sekali tidak verifikasi turnstile
  // (beda dengan /api/auth/login yang sudah cek), padahal form Daftar di
  // modal juga punya widget captcha. Disamakan biar konsisten.
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) return res.json({ success: false, message: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.' });
    const valid = await verifyTurnstile(token);
    if (!valid) return res.json({ success: false, message: 'Verifikasi keamanan gagal. Coba lagi.' });
  }

  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.json({ success: false, message: 'Semua field wajib diisi' });
  }
  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.json({ success: false, message: pwError });
  }
  if (confirmPassword && password !== confirmPassword) {
    return res.json({ success: false, message: 'Konfirmasi password tidak cocok' });
  }
  if (username === 'Abdurahman Mulvi') {
    return res.json({ success: false, message: 'Username tidak diizinkan' });
  }

  const users = readDB('users.json');
  if (users.find(u => u.username === username)) {
    return res.json({ success: false, message: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    balance: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.json({ success: true, redirect: '/' });
});

app.post('/register', async (req, res) => {
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting sama sekali -- bisa disalahgunakan buat mass account
  // creation (bot spam ribuan akun palsu), yang membebani database dan
  // juga costly karena tiap request menjalankan bcrypt.hash() (operasi
  // yang sengaja lambat/mahal secara komputasi). Limit ketat (5x/15menit
  // per IP) karena registrasi akun itu action yang jarang dilakukan
  // berkali-kali oleh user normal dalam waktu singkat.
  if (!checkApiRateLimit(req.ip, 5, 15 * 60 * 1000)) {
    return res.render('pages/register', { error: 'Terlalu banyak percobaan pendaftaran. Coba lagi dalam beberapa menit.', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  // FIX KEAMANAN (audit 3 Sep 2026, diminta user): sebelumnya halaman
  // register SAMA SEKALI gak ada Turnstile -- cuma diproteksi rate limit
  // per-IP (yang gampang dilewati pakai proxy/residential IP rotator).
  // Ditambahkan verifikasi di posisi paling awal, sebelum baca field
  // form apapun, biar bot ditolak lebih dini.
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/register', { error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/register', { error: 'Verifikasi keamanan gagal. Coba lagi.', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
    }
  }

  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.render('pages/register', { error: 'Semua field wajib diisi', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.render('pages/register', { error: pwError, turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  if (confirmPassword && password !== confirmPassword) {
    return res.render('pages/register', { error: 'Konfirmasi password tidak cocok', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  if (username === 'Abdurahman Mulvi') {
    return res.render('pages/register', { error: 'Username tidak diizinkan', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  const users = readDB('users.json');

  if (users.find(u => u.username === username)) {
    return res.render('pages/register', { error: 'Username sudah digunakan', turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    balance: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.redirect('/');
});

// ══════════════════════════════════════════════════════════════════
// GOOGLE OAUTH ROUTES (opsional -- lihat setup passport di atas)
// ══════════════════════════════════════════════════════════════════
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) return res.redirect('/login?error=Google login belum diaktifkan admin');
  // redirect tujuan setelah login sukses (mis. balik ke halaman /buy/:id
  // yang lagi dibuka), disimpan sebentar di session sebelum lempar ke Google.
  if (req.query.redirect) req.session.oauthRedirect = req.query.redirect;
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) return res.redirect('/login');
  passport.authenticate('google', { session: false, failureRedirect: '/login?error=Login Google gagal' }, (err, user) => {
    if (err || !user) return res.redirect('/login?error=Login Google gagal');
    req.session.userId = user.id;
    req.session.isAdmin = false;
    const redirectTo = req.session.oauthRedirect || (!user.wa ? '/complete-profile' : '/');
    delete req.session.oauthRedirect;
    // Akun Google baru belum ada nomor WA (dipakai buat pengiriman notif
    // key/transaksi) -- giring ke halaman lengkapi profil sekali di awal.
    if (!user.wa) return res.redirect('/complete-profile');
    res.redirect(redirectTo);
  })(req, res, next);
});

// Lengkapi profil (nomor WA) untuk akun yang baru daftar via Google --
// WA dipakai buat kirim notifikasi key/transaksi, jadi tetap wajib diisi
// sekali meski proses signup awalnya "one-click" via Google.
app.get('/complete-profile', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  if (user?.wa) return res.redirect('/');
  res.render('pages/complete-profile', { user });
});

app.post('/complete-profile', requireAuth, async (req, res) => {
  try {
    const { wa } = req.body;
    if (!wa || !wa.trim()) return res.json({ success: false, message: 'Nomor WhatsApp wajib diisi' });
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.wa = wa.trim();
    await writeDB('users.json', users);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.get('/logout', async (req, res) => {
  if (req.session?.isAdmin && req.session?.adminSessionId) {
    await releaseAdminLock(req.session.adminSessionId);
  }
  req.session = null;
  res.redirect('/');
});

// ══ FRANZZSTORE: ADMIN SECRET LOGIN GATE (hidden from public) ══
app.get('/vpr-secure-panel-8x', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  const kicked = req.query.kicked === '1';
  res.render('pages/admin-login', {
    error: kicked ? 'Anda logout otomatis karena ada login admin dari perangkat lain.' : null,
    lockedInfo: null,
    username: '',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.post('/vpr-secure-panel-8x', authLimiter, async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = await checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/admin-login', {
      error: `Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.`,
      lockedInfo: null, username: '',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // ── FIX KEAMANAN (audit 3 Sep 2026): login admin sebelumnya SAMA SEKALI
  // tidak diverifikasi Turnstile -- padahal ini target paling berharga
  // buat bot brute-force (kalau tembus, penyerang dapat akses PENUH ke
  // seluruh toko: saldo semua user, produk, dsb). checkLoginBlocked/
  // authLimiter di atas cuma membatasi KECEPATAN percobaan per-IP, bukan
  // membedakan bot vs manusia -- bot yang pakai banyak IP/residential
  // proxy tetap bisa jalan terus tanpa captcha ini. Ditambahkan di posisi
  // PALING AWAL (sebelum baca username/password) supaya bot yang gak
  // punya token ditolak lebih dini, sebelum sempat mencoba kredensial. */
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/admin-login', {
        error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.',
        lockedInfo: null, username: '',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/admin-login', {
        error: 'Verifikasi keamanan gagal. Coba lagi.',
        lockedInfo: null, username: '',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
  }

  const { username, password, forceTakeover } = req.body;

  // ── FIX: readFresh() ambil langsung dari Supabase, bypass cache ──
  // Ini penting karena di Vercel tiap instance punya cache kosong
  const settings = await db.readFresh('settings.json');

  if (!settings || !settings.adminUsername) {
    return res.render('pages/admin-login', {
      error: 'Konfigurasi admin belum tersedia. Coba beberapa saat lagi.',
      lockedInfo: null, username: '',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  if (username === settings.adminUsername) {
    const match = await bcrypt.compare(password, settings.adminPassword);
    if (match) {
      // ── Single-Device Lock: cek apakah panel sedang dipakai device lain ──
      const currentLock = await db.readFresh('admin-lock.json');
      if (isLockActive(currentLock) && forceTakeover !== '1') {
        const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(currentLock.lastSeen).getTime()) / 60000));
        return res.render('pages/admin-login', {
          error: null,
          username,
          lockedInfo: {
            device: currentLock.device || 'Perangkat tidak diketahui',
            minutesAgo
          },
          turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
        });
      }
      await clearLoginFail(ip);
      req.session.userId = 'admin';
      req.session.isAdmin = true;
      req.session.adminSessionId = await acquireAdminLock(req);
      return res.redirect('/admin');
    }
  }
  await recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  res.render('pages/admin-login', {
    error: remaining > 0
      ? `Username atau password salah. Sisa percobaan: ${remaining}`
      : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.',
    lockedInfo: null, username: '',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});


// ── RESELLER ──
app.get('/reseller', (req, res) => {
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/reseller', { layout: false, settings, user });
});

app.post('/reseller/join', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak perlu join reseller' });
    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (user.is_reseller) return res.json({ success: false, message: 'Kamu sudah menjadi Reseller VIP!' });

    const settings = readDB('settings.json');
    const price = settings.resellerPrice || 50000;
    const orderId = `RES-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
      } catch (e) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'reseller',
      productName: 'Upgrade Reseller VIP',
      customerName: user.username, wa: user.wa,
      price, totalPayment: price, qrString, isStatic,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── WALLET (SALDO RESELLER) ──
// Khusus Reseller VIP top-up saldo via QRIS. Setelah dibayar & dikonfirmasi
// (lihat /check-payment/:refId), saldo otomatis bertambah dan bisa langsung
// dipakai untuk beli key tanpa scan QRIS lagi (lihat /wallet/buy).
app.post('/wallet/topup', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak memiliki wallet' });
    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (!user.is_reseller) return res.json({ success: false, message: 'Top up saldo khusus untuk Reseller VIP. Gabung reseller dulu yuk!' });

    const settings = readDB('settings.json');
    const minDeposit = settings.resellerMinDeposit || 50000;
    const amount = parseInt(req.body.amount);
    if (isNaN(amount) || amount < minDeposit) {
      return res.json({ success: false, message: `Minimal top up Rp ${minDeposit.toLocaleString('id-ID')}` });
    }

    const orderId = `DEP-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false, totalPayment = amount, expiredAt = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, amount, settings);
        qrString = r.qr_string;
        // total_payment dari Pakasir = amount + fee mereka (kalau ada). Ini
        // CUMA buat ditampilkan ke user biar nominal yang ditampilkan sama
        // persis dengan yang diminta di QR code-nya. Saldo yang dikreditkan
        // tetap pakai `amount` asli (lihat field `amount` di transaksi di
        // bawah) supaya fee Pakasir tidak ikut numpang masuk ke saldo user.
        totalPayment = r.total_payment || amount;
        expiredAt = r.expired_at || null;
      } catch (e) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'deposit',
      productName: 'Top Up Saldo Reseller',
      amount,
      customerName: user.username, wa: user.wa,
      price: amount, totalPayment, expiredAt, qrString, isStatic,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Beli key langsung pakai saldo wallet (khusus reseller) — tanpa scan QRIS,
// saldo langsung terpotong dan key langsung diberikan.
app.post('/wallet/buy', requireAuth, async (req, res) => {
  // Cegah race condition double-spend: tolak request kedua kalau request
  // sebelumnya dari user yang sama masih diproses (lihat komentar di
  // deklarasi walletLocks).
  if (walletLocks.has(req.session.userId)) {
    return res.json({ success: false, message: 'Transaksi sebelumnya masih diproses, tunggu sebentar...' });
  }
  walletLocks.add(req.session.userId);
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak bisa membeli produk' });
    const { productId, duration, durationUnit, customerName, wa, voucherCode, gameUserId, gameZoneId } = req.body;

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (!user.is_reseller) return res.json({ success: false, message: 'Fitur beli pakai saldo khusus Reseller VIP' });

    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);
    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    if (!product.keys || product.keys.length === 0) return res.json({ success: false, message: 'Stok habis' });

    // Validasi field akun game (User ID / Zone ID) kalau produk mewajibkan --
    // lihat catatan lengkap di /create-order (endpoint utama, guest checkout).
    if (product.requiresGameId && (!gameUserId || !gameUserId.trim())) {
      return res.json({ success: false, message: `${product.gameIdLabel || 'User ID'} wajib diisi` });
    }
    if (product.requiresZoneId && (!gameZoneId || !gameZoneId.trim())) {
      return res.json({ success: false, message: `${product.zoneIdLabel || 'Zone ID'} wajib diisi` });
    }

    // Resolusi harga paket — logika sama seperti /create-order (unit-aware, lihat komentar di sana)
    const selectedUnit = (durationUnit === 'h') ? 'h' : 'd';
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      let opt = null;
      if (durationUnit) {
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === selectedUnit);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      } else {
        const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
        if (itemMatch) {
          opt = product.pricingOptions.find(o => o.price === itemMatch.p);
          if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
          else { price = opt.price; selectedDays = opt.days; }
        } else {
          const days = parseInt(duration);
          opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === 'd');
          if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
          price = opt.price; selectedDays = days;
        }
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    const settings = readDB('settings.json');
    // Prioritas harga: reseller_price manual per-produk → global diskon %
    const matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
    const matchedOpt = product.pricingOptions?.find(o => o.days === selectedDays && (o.unit || 'd') === selectedUnit);
    const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
    if (manualResellerPrice != null && manualResellerPrice >= 0) {
      price = manualResellerPrice;
    } else {
      const disc = settings.resellerDiscount || 20;
      price = Math.round(price * (1 - disc / 100));
    }

    // Terapkan voucher (setelah diskon reseller) — opsional, sama seperti /create-order
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    const balance = user.balance || 0;
    if (balance < price) {
      return res.json({ success: false, message: 'insufficient_balance', shortfall: price - balance,
        needed: price, balance, plainMessage: `Saldo tidak cukup. Kurang Rp ${(price - balance).toLocaleString('id-ID')}, top up dulu yuk!` });
    }

    // Ambil key — HARUS sesuai durasi yang dibeli (format KEY=DAYSunit).
    //
    // FIX BUG KRITIS (dilaporkan client 21 Agu 2026): sebelumnya kalau stok
    // key durasi tertentu (misal 1-day / 3-day) HABIS, kode fallback ke
    // "key generic tanpa durasi" dulu, dan kalau itu juga kosong, fallback
    // TERAKHIR adalah allKeys.shift() -- ambil key APAPUN dari depan array,
    // termasuk key durasi 7/15/30-day milik produk lain. Akibatnya customer
    // yang beli durasi 1-day tapi stoknya kosong malah dapat key 7/15/30-day
    // secara gratis/tidak sengaja (kerugian buat penjual). Sekarang: kalau
    // user memilih durasi spesifik (selectedDays truthy) dan stok durasi itu
    // kosong, TOLAK transaksi dengan pesan jelas -- JANGAN kasih durasi lain.
    // Fallback ke key generic (tanpa "=") hanya berlaku untuk produk yang
    // MEMANG tidak punya sistem durasi sama sekali (selectedDays null/kosong).
    //
    // Sekarang unit-aware (hari 'd' / jam 'h') via keyMatchesDuration/
    // parseKeyDuration, dan separator "=" (bukan ":", lihat definisi helper
    // di atas untuk alasan lengkapnya).
    let key = null;
    const allKeys = product.keys;
    if (selectedDays) {
      const idx = allKeys.findIndex(k => keyMatchesDuration(k, selectedDays, selectedUnit));
      if (idx !== -1) key = parseKeyDuration(allKeys.splice(idx, 1)[0]).raw;
      else return res.json({ success: false, message: `Stok key durasi ${formatDurationLabel(selectedDays, selectedUnit)} sedang habis. Silakan pilih durasi lain atau tunggu admin restock.` });
    } else {
      const idx = allKeys.findIndex(k => isGenericKey(k));
      if (idx !== -1) key = allKeys.splice(idx, 1)[0];
    }
    if (!key) return res.json({ success: false, message: 'Stok habis' });

    // ── FIX BUG KEAMANAN (audit 3 Sep 2026): potong saldo pakai atomicUpdate ──
    // Sebelumnya: `user.balance = balance - price; await writeDB('users.json', users);`
    // langsung pakai variabel `balance` yang dibaca di AWAL fungsi ini — kalau
    // ada request lain (dari instance Vercel berbeda) yang juga motong saldo
    // user yang sama di antara pembacaan awal itu dan writeDB ini, salah satu
    // perubahan akan ketiban / hilang (lost update), berpotensi user belanja
    // lebih dari saldo yang sebenarnya dia punya. atomicUpdate mengulang baca
    // saldo TERBARU + coba tulis dengan compare-and-swap sampai berhasil tanpa
    // konflik (lihat komentar lengkap di supabase.js).
    const walletResult = await atomicUpdate('users.json', (freshUsers) => {
      const u = freshUsers.find(u => u.id === req.session.userId);
      if (!u) return { ok: false, reason: 'user_not_found' };
      if ((u.balance || 0) < price) return { ok: false, reason: 'insufficient_balance', currentBalance: u.balance || 0 };
      u.balance = (u.balance || 0) - price;
      return { ok: true, data: freshUsers, result: { newBalance: u.balance } };
    });

    if (!walletResult.ok) {
      // Saldo berubah tepat di detik terakhir (race condition asli, jarang
      // terjadi) ATAU user memang kurang saldo. CATATAN: key yang sempat
      // di-splice dari `product.keys` di atas MASIH DI MEMORI SAJA -- belum
      // pernah ditulis ke products.json (writeDB baru dipanggil di bawah,
      // setelah blok ini) -- jadi tidak perlu "dikembalikan", cukup jangan
      // ditulis sama sekali (biarkan `products` in-memory dibuang begitu
      // request ini selesai, stok asli di database tidak pernah berubah).
      if (walletResult.reason === 'insufficient_balance') {
        const bal = walletResult.currentBalance || 0;
        return res.json({ success: false, message: 'insufficient_balance', shortfall: price - bal,
          needed: price, balance: bal, plainMessage: `Saldo tidak cukup. Kurang Rp ${(price - bal).toLocaleString('id-ID')}, top up dulu yuk!` });
      }
      return res.json({ success: false, message: 'Terjadi kesalahan, silakan coba lagi.' });
    }

    product.sold = (product.sold || 0) + 1;
    await writeDB('products.json', products);

    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: refId, orderId: `WLT-${Date.now()}`, code: orderCode,
      userId: user.id, productId: product.id, productName: product.name,
      duration, selectedDays, selectedUnit,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment: price, paymentMethod: 'wallet',
      customerName: customerName || user.username, wa: wa || user.wa,
      gameUserId: gameUserId?.trim() || undefined, gameZoneId: gameZoneId?.trim() || undefined,
      status: 'done', key, paidAt: new Date().toISOString(),
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    const notifs = readDB('notifications.json');
    notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: customerName || user.username,
      buyerPhoto: user.photo || null, productName: product.name,
      price, time: new Date().toISOString(), timeStr: formatDate() });
    await writeDB('notifications.json', notifs.slice(0, 50));

    res.json({ success: true, key, code: orderCode, balance: user.balance, voucherDiscount: voucherDiscount || undefined });
  } catch (e) {
    console.error('[wallet/buy] error:', e.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + e.message });
  } finally {
    walletLocks.delete(req.session.userId);
  }
});

// ── PROFILE PHOTO ──
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/avatars' : path.join(__dirname, 'public', 'uploads', 'avatars');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${req.session.userId}-${Date.now()}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/profile/photo', requireAuth, avatarUpload.single('photo'), requireValidImageMagicBytes, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });

    // Admin tidak punya entry di users.json
    if (req.session.userId === 'admin') {
      return res.json({ success: false, message: 'Admin tidak bisa ganti foto profil dari sini' });
    }

    const users = readDB('users.json');
    const user  = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    // Hapus foto lama jika ada
    if (user.photo) {
      const oldPath = path.join(__dirname, 'public', user.photo.replace(/^\//, ''));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    if (!isVercel) { user.photo = `/uploads/avatars/${req.file.filename}`; }
    else { try { user.photo = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: 'Upload gagal: ' + e.message }); } }
    await writeDB('users.json', users);
    res.json({ success: true, photo: user.photo });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── BANNER CAROUSEL ──
const bannerCarouselUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/banners' : path.join(__dirname, 'public', 'uploads', 'banners');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `banner-${Date.now()}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.get('/api/banners', async (req, res) => {
  // FIX (loading lambat): sebelumnya pakai readFresh -- artinya SETIAP kali
  // ada yang buka homepage, server nunggu round-trip penuh ke Supabase dulu
  // sebelum banner carousel bisa muncul (banner ada di atas fold, jadi user
  // ngerasain langsung sebagai "lemot"). readSmart pakai cache ber-TTL 60
  // detik (sama seperti /api/products), jauh lebih cepat dan behavior akhir
  // tetap sama karena banner jarang berubah tiap detik.
  const settings = await readSmart('settings.json');
  if (normalizeBanners(settings)) await writeDB('settings.json', settings);
  res.json((settings.banners || []).filter(b => b.active !== false));
});

app.post('/admin/banners/add', requireAdmin, bannerCarouselUpload.single('bannerImg'), requireValidImageMagicBytes, async (req, res) => {
  try {
    const { title, subtitle, link, imageUrl } = req.body;
    const settings = await readFresh('settings.json');
    if (!settings.banners) settings.banners = [];
    let imgSrc = imageUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        imgSrc = `/uploads/banners/${req.file.filename}`;
      } else {
        try {
          imgSrc = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch (uploadErr) {
          // FIX (loading lambat): sebelumnya di sini ada fallback diam-diam
          // ke base64 data URL kalau upload ke Supabase Storage gagal.
          // Efeknya: banner (yang tampil di atas fold, langsung didownload
          // semua orang yang buka homepage) jadi ke-embed penuh sebagai teks
          // base64 di dalam settings.json -- ikut kebawa tiap kali endpoint
          // /api/banners dipanggil, TIDAK bisa di-cache browser sebagai file
          // gambar (karena bukan URL, tapi inline data), dan base64 sendiri
          // ~33% lebih besar dari file aslinya. Ini kemungkinan besar
          // penyebab homepage kerasa lemot. Sekarang upload yang gagal
          // dikembalikan sebagai error jelas ke admin (cek Supabase Storage:
          // bucket "product-images" ada, RLS policy benar, project tidak
          // paused) daripada diam-diam "berhasil" tapi bikin app berat.
          return res.json({ success: false, message: 'Gagal upload gambar banner ke storage: ' + uploadErr.message + '. Cek Supabase Storage (bucket product-images, RLS policy, atau project sedang paused).' });
        }
      }
    }
    if (!imgSrc) return res.json({ success: false, message: 'Gambar banner wajib diisi' });
    settings.banners.push({
      id: uuidv4(),
      imageUrl: imgSrc,
      title: title?.trim() || '',
      subtitle: subtitle?.trim() || '',
      link: link?.trim() || '/',
      active: true,
      createdAt: new Date().toISOString()
    });
    await writeDB('settings.json', settings);
    res.json({ success: true, banners: settings.banners });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/delete/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const old = (settings.banners || []).find(b => b.id === req.params.id);
    if (old?.imageUrl?.startsWith('/uploads/banners/')) {
      const fp = path.join(__dirname, 'public', old.imageUrl);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    settings.banners = (settings.banners || []).filter(b => b.id !== req.params.id);
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const b = (settings.banners || []).find(b => b.id === req.params.id);
    if (b) b.active = !b.active;
    await writeDB('settings.json', settings);
    res.json({ success: true, active: b?.active });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// ── JUAL BELI AKUN ──
// Marketplace jual-beli akun game, dipisah per kategori game (dipilih dari
// "Jual Beli Akun" di tab kategori homepage -> pilih game -> listing akun
// untuk game itu). User submit listing (status pending) -> admin
// approve/reject/tandai terjual -> publik lihat listing yang approved.
// ══════════════════════════════════════════════════════════════════
const accountImgUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/accounts' : path.join(__dirname, 'public', 'uploads', 'accounts');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `akun-${Date.now()}-${Math.round(Math.random() * 1e5)}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/jpg', 'image/png', 'image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

// Listing publik -- hanya akun yang sudah di-approve admin, opsional filter per game
app.get('/jual-beli-akun', async (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  const accounts = (await readSmart('accounts.json')).filter(a => a.status === 'approved');
  const { game } = req.query;
  const filtered = game ? accounts.filter(a => a.game === game) : accounts;
  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('pages/jual-beli-akun', {
    layout: false, settings, user: res.locals.user || getSessionUser(req),
    accounts: filtered, gameFilter: game || '',
    allCategories: settings.categories || [], categoryLabels: settings.categoryLabels || {}
  });
});

app.get('/jual-beli-akun/:id', async (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  const accounts = await readSmart('accounts.json');
  const account = accounts.find(a => a.id === req.params.id && a.status === 'approved');
  if (!account) return res.redirect('/jual-beli-akun');
  res.render('pages/akun-detail', { layout: false, settings, user: res.locals.user || getSessionUser(req), account });
});

// Form jual akun (harus login supaya kontaknya jelas & anti-spam)
app.get('/jual-beli-akun-jual', requireAuth, (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  res.render('pages/jual-akun-form', {
    layout: false, settings, user: res.locals.user || getSessionUser(req),
    allCategories: settings.categories || [], categoryLabels: settings.categoryLabels || {}
  });
});

app.post('/jual-beli-akun-jual', requireAuth, accountImgUpload.array('images', 5), requireValidImageMagicBytesArray, async (req, res) => {
  try {
    const { game, title, description, price, sellerWa } = req.body;
    if (!game || !title || !description || !price || !sellerWa) {
      return res.json({ success: false, message: 'Semua field wajib diisi' });
    }
    if (!/^(\+62|62|0)[0-9]{8,13}$/.test(sellerWa.trim())) {
      return res.json({ success: false, message: 'Format WhatsApp tidak valid' });
    }
    if (!req.files || !req.files.length) return res.json({ success: false, message: 'Minimal 1 foto akun wajib diupload' });

    let images = [];
    for (const file of req.files) {
      if (!isVercel) {
        images.push(`/uploads/accounts/${file.filename}`);
      } else {
        try {
          images.push(await db.uploadImage(fs.readFileSync(file.path), file.originalname, file.mimetype));
        } catch (uploadErr) {
          return res.json({ success: false, message: 'Gagal upload foto ke storage: ' + uploadErr.message });
        }
      }
    }

    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);

    const accounts = await readFresh('accounts.json');
    accounts.unshift({
      id: uuidv4(),
      userId: req.session.userId,
      sellerName: user?.username || 'Pengguna',
      sellerWa: sellerWa.trim(),
      game: game.trim(),
      title: title.trim(),
      description: description.trim(),
      price: parseInt(price) || 0,
      images,
      status: 'pending', // pending -> approved / rejected -> sold
      createdAt: new Date().toISOString()
    });
    await writeDB('accounts.json', accounts);
    res.json({ success: true, message: 'Akun berhasil disubmit, menunggu verifikasi admin.' });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/dashboard/jual-akun', requireAuth, async (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  const accounts = (await readSmart('accounts.json')).filter(a => a.userId === req.session.userId);
  accounts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('pages/akun-saya', { layout: false, settings, user: res.locals.user || getSessionUser(req), accounts });
});

// ── ADMIN: MODERASI JUAL BELI AKUN ──
app.post('/admin/akun/approve/:id', requireAdmin, async (req, res) => {
  try {
    const accounts = await readFresh('accounts.json');
    const acc = accounts.find(a => a.id === req.params.id);
    if (!acc) return res.json({ success: false, message: 'Listing tidak ditemukan' });
    acc.status = 'approved';
    await writeDB('accounts.json', accounts);
    res.json({ success: true, message: 'Listing akun disetujui' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/akun/reject/:id', requireAdmin, async (req, res) => {
  try {
    const accounts = await readFresh('accounts.json');
    const acc = accounts.find(a => a.id === req.params.id);
    if (!acc) return res.json({ success: false, message: 'Listing tidak ditemukan' });
    acc.status = 'rejected';
    acc.rejectReason = (req.body.reason || '').trim();
    await writeDB('accounts.json', accounts);
    res.json({ success: true, message: 'Listing akun ditolak' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/akun/sold/:id', requireAdmin, async (req, res) => {
  try {
    const accounts = await readFresh('accounts.json');
    const acc = accounts.find(a => a.id === req.params.id);
    if (!acc) return res.json({ success: false, message: 'Listing tidak ditemukan' });
    acc.status = 'sold';
    await writeDB('accounts.json', accounts);
    res.json({ success: true, message: 'Listing ditandai terjual' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/akun/delete/:id', requireAdmin, async (req, res) => {
  try {
    let accounts = await readFresh('accounts.json');
    const acc = accounts.find(a => a.id === req.params.id);
    (acc?.images || []).forEach(img => {
      if (img.startsWith('/uploads/accounts/')) {
        const fp = path.join(__dirname, 'public', img);
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
      }
    });
    accounts = accounts.filter(a => a.id !== req.params.id);
    await writeDB('accounts.json', accounts);
    res.json({ success: true, message: 'Listing dihapus' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});


// ── QRIS STATIS UPLOAD ──
const qrisUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `qris-static${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/admin/qris/upload', requireAdmin, qrisUpload.single('qrisImage'), requireValidImageMagicBytes, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });
    const settings = await readFresh('settings.json');
    if (!isVercel) {
      settings.qrisStaticImage = `/uploads/${req.file.filename}`;
    } else {
      try { settings.qrisStaticImage = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: e.message }); }
    }
    await writeDB('settings.json', settings);
    res.json({ success: true, path: settings.qrisStaticImage });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/profile/me', requireAuth, (req, res) => {
  if (req.session.isAdmin) {
    const s = readDB('settings.json');
    return res.json({ success: true, user: { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, is_reseller: false, photo: null } });
  }
  const users = readDB('users.json');
  const user  = users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ success: false });
  const { password: _, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ── User Dashboard ──
app.get('/dashboard', requireAuth, (req, res) => {
  const transactions = readDB('transactions.json');
  const user = getSessionUser(req);
  const settings = readDB('settings.json');

  // Filter transaksi milik user ini
  const myTransactions = transactions.filter(t => t.userId === req.session.userId);
  const totalOrders = myTransactions.length;
  const successOrders = myTransactions.filter(t => t.status === 'done').length;
  const pendingOrders = myTransactions.filter(t => t.status === 'pending').length;
  const totalSpent = myTransactions.filter(t => t.status === 'done').reduce((s, t) => s + (t.price || 0), 0);
  const doneTransactions = myTransactions.filter(t => t.status === 'done').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const recentTransactions = myTransactions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);

  res.render('pages/dashboard', { user, settings,
    stats: { totalOrders, successOrders, pendingOrders, totalSpent },
    doneTransactions,
    transactions: recentTransactions,
    walletTransactions: myTransactions.filter(t => t.type === 'deposit' || t.type === 'adjustment').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 15)
  });
});

// Product routes
// FIX (guest checkout, diminta client 21 Agu 2026): dulu wajib requireAuth
// (harus register/login dulu) sebelum bisa lihat halaman produk & checkout.
// Sekarang publik -- guest bisa checkout cukup isi nama+nomor WA (lihat
// /create-order di bawah, yang sekarang auto-create akun kalau belum login).
app.get('/buy/:id', (req, res) => {
  const products = readDB('products.json');
  const product = products.find(p => p.id === req.params.id);

  if (!product || product.status !== 'active') {
    return res.redirect('/');
  }

  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  const isReseller = !!(user?.is_reseller);
  const resellerDiscount = settings.resellerDiscount || 20;
  const allKeys = product.keys || [];
  const genericKeys = allKeys.filter(k => isGenericKey(k));
  if (product.items) {
    product.items = product.items.map(item => {
      // Label item sekarang bisa "... 30 HARI" atau "... 12 JAM" (lihat
      // formatDurationLabel) -- regex ini menangkap keduanya. Item lama
      // (format lawas "30 DAYS") tetap dikenali via alternasi DAYS|HARI.
      const m = (item.l || '').match(/(\d+)\s+(DAYS|HARI|JAM)/i);
      const days = m ? parseInt(m[1]) : null;
      const unit = m && /JAM/i.test(m[2]) ? 'h' : 'd';
      let stok;
      if (days) {
        const tagged = allKeys.filter(k => keyMatchesDuration(k, days, unit)).length;
        stok = tagged > 0 ? tagged : genericKeys.length;
      } else {
        stok = genericKeys.length;
      }
      // Prioritas harga reseller: 1) harga manual per-produk jika ada,
      // 2) harga dari pricingOptions, 3) fallback ke global diskon %
      let computedResellerPrice = null;
      if (isReseller) {
        if (item.reseller_price != null && item.reseller_price >= 0) {
          computedResellerPrice = item.reseller_price;
        } else {
          // Cek di pricingOptions (unit-aware)
          const pOpt = (product.pricingOptions || []).find(o => o.days === days && (o.unit || 'd') === unit);
          if (pOpt?.reseller_price != null && pOpt.reseller_price >= 0) {
            computedResellerPrice = pOpt.reseller_price;
          } else {
            computedResellerPrice = Math.round(item.p * (1 - resellerDiscount / 100));
          }
        }
      }
      return { ...item, stok, reseller_price: computedResellerPrice, durationValue: days, durationUnit: unit };
    });
  }

  // Cek apakah user sudah pernah membeli (transaksi sukses) produk ini
  const transactions = readDB('transactions.json');
  const hasPurchased = transactions.some(t =>
    t.userId === user?.id &&
    t.productId === product.id &&
    t.status === 'done'
  );

  // FIX KEAMANAN (audit 22 Agu 2026): field `keys` (array kode cheat ASLI
  // yang belum terjual) TIDAK BOLEH pernah sampai ke response halaman
  // publik ini -- sebelumnya `product` di-passing utuh ke res.render(),
  // termasuk `keys` mentahnya. Template EJS saat ini kebetulan cuma
  // memakai product.keys.length (bukan isinya), TAPI itu rapuh: siapapun
  // yang nambah <%- safeJson(product) %> atau sejenisnya di kemudian hari
  // (utk fitur baru/debug) otomatis membocorkan seluruh stok key gratis ke
  // siapapun yang buka halaman produk tanpa perlu login/bayar sama sekali.
  // Strip di sini, di level backend -- defense-in-depth, bukan bergantung
  // pada disiplin "jangan pernah pakai field ini di template nanti".
  const { keys: _rawKeys, ...productSafe } = product;
  productSafe.stockCount = (_rawKeys || []).length;

  res.render('pages/buy', { product: productSafe, settings, user, isReseller, hasPurchased, categoryLabels: settings.categoryLabels || {} });
});

// FIX (guest checkout, diminta client 21 Agu 2026 -- "isi data cukup nama
// dan nomor"): requireAuth dihapus. Kalau belum login (req.session.userId
// kosong), buat akun guest OTOMATIS di sini dari customerName+wa yang
// dikirim form checkout, lalu langsung set session -- supaya SEMUA logic
// existing di bawah (rate limit per-user, transaksi terikat userId, riwayat
// pembelian, dsb) tetap jalan tanpa perlu diubah sama sekali. User yang mau
// akun permanen/riwayat tersimpan tetap bisa daftar manual atau via Google
// (lihat /register, /auth/google) sebelum checkout.
app.post('/create-order', async (req, res) => {
  try {
    const { productId, duration, durationUnit, customerName, wa, voucherCode, gameUserId, gameZoneId } = req.body;

    // Guest checkout: kalau belum ada session user sama sekali, buat akun
    // guest baru dari nama+WA yang diisi di form. Kalau nomor WA yang sama
    // pernah dipakai guest sebelumnya, pakai ulang akun itu (supaya riwayat
    // pembelian nyambung meski tanpa password/login eksplisit).
    if (!req.session?.userId) {
      if (!customerName || !customerName.trim() || !wa || !wa.trim()) {
        return res.json({ success: false, message: 'Nama dan nomor WhatsApp wajib diisi' });
      }
      const users = await readFresh('users.json');
      let guestUser = users.find(u => u.isGuest && u.wa === wa.trim());
      if (!guestUser) {
        guestUser = {
          id: uuidv4(),
          username: customerName.trim(),
          wa: wa.trim(),
          password: null,
          isGuest: true, // penanda akun guest checkout, beda dari akun yang daftar manual/Google
          photo: null,
          balance: 0,
          createdAt: new Date().toISOString()
        };
        users.push(guestUser);
        await writeDB('users.json', users);
      }
      req.session.userId = guestUser.id;
      req.session.isAdmin = false;
    }

    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);

    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    if (!product.keys || product.keys.length === 0) return res.json({ success: false, message: 'Stok habis' });

    // Validasi field akun game (User ID / Zone ID) -- diminta owner 31 Agu
    // 2026, fokus topup diamond/asset game. Cek FLAG PER-PRODUK
    // (requiresGameId/requiresZoneId, diatur admin lewat Admin Panel), bukan
    // hardcode per-kategori, supaya produk non-game (premium app) tidak
    // dipaksa isi field yang tidak relevan.
    if (product.requiresGameId && (!gameUserId || !gameUserId.trim())) {
      return res.json({ success: false, message: `${product.gameIdLabel || 'User ID'} wajib diisi` });
    }
    if (product.requiresZoneId && (!gameZoneId || !gameZoneId.trim())) {
      return res.json({ success: false, message: `${product.zoneIdLabel || 'Zone ID'} wajib diisi` });
    }

    //
    // FIX (fitur key per-jam, diminta client 21 Agu 2026): sebelumnya durasi
    // dicocokkan cuma dengan ekstrak ANGKA dari label ("PRODUK 30 DAYS" -> 30),
    // jadi kalau produk sekarang punya opsi "30 jam" DAN "30 hari" sekaligus,
    // regex \d+ bakal ambigu (keduanya menghasilkan angka 30). Sekarang
    // frontend WAJIB kirim `durationUnit` ('d'/'h') terpisah dari `duration`,
    // dan matching pricingOptions memakai pasangan (days, unit) -- bukan
    // cuma angka. Fallback lama (match by label/regex) dipertahankan untuk
    // request lama yang belum kirim durationUnit sama sekali (backward-compat
    // dengan produk yang cuma punya opsi hari, unit default 'd').
    const selectedUnit = (durationUnit === 'h') ? 'h' : 'd';
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      let opt = null;
      if (durationUnit) {
        // Jalur baru: match presisi via (days, unit)
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === selectedUnit);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      } else {
        // Jalur lama (backward-compat): duration bisa berupa label teks ("PRODUK 30 DAYS") atau angka ("30")
        const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
        if (itemMatch) {
          opt = product.pricingOptions.find(o => o.price === itemMatch.p);
          if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
          else { price = opt.price; selectedDays = opt.days; }
        } else {
          const days = parseInt(duration);
          opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === 'd');
          if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
          price = opt.price; selectedDays = days;
        }
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    const settings = readDB('settings.json');
    // Terapkan harga reseller: gunakan harga manual per-produk jika ada,
    // fallback ke global diskon % jika tidak ada
    const orderUser = getSessionUser(req);
    if (orderUser?.is_reseller) {
      // Cari item yang sesuai untuk cek reseller_price manual
      const matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
      const matchedOpt = product.pricingOptions?.find(o => o.days === selectedDays && (o.unit || 'd') === selectedUnit);
      const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
      if (manualResellerPrice != null && manualResellerPrice >= 0) {
        price = manualResellerPrice;
      } else {
        const disc = settings.resellerDiscount || 20;
        price = Math.round(price * (1 - disc / 100));
      }
    }

    // Terapkan voucher (setelah diskon reseller)
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    const qrisMode = settings.qrisMode || 'static';
    const orderId = `FX-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    let qrString = null, isStatic = false, totalPayment = price, expiredAt = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Upload gambar QRIS di admin panel terlebih dahulu.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
        totalPayment = r.total_payment || price;
        expiredAt = r.expired_at || null;
      } catch (error) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS API error: ' + error.message });
      }
    }

    const transactions = await readFresh('transactions.json');

    // Cegah transaksi duplikat: tolak jika ada pending untuk produk yang sama dalam 30 menit
    const existingPending = transactions.find(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'pending' &&
      (Date.now() - new Date(t.createdAt).getTime()) < 30 * 60 * 1000
    );
    if (existingPending) {
      return res.json({ success: false, message: 'Kamu masih memiliki pesanan pending untuk produk ini. Selesaikan pembayaran atau tunggu 30 menit.' });
    }

    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: req.session.userId, productId: product.id, productName: product.name,
      duration, selectedDays, selectedUnit,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment,
      customerName, wa, qrString, isStatic,
      gameUserId: gameUserId?.trim() || undefined, gameZoneId: gameZoneId?.trim() || undefined,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    // Catat pemakaian voucher jika dipakai
    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      voucherDiscount: voucherDiscount || undefined,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (error) {
    console.error('[create-order] error:', error.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// finalizeOrder — tandai transaksi lunas & proses sesuai tipenya
// (reseller upgrade / top up saldo / kirim key produk). Diekstrak dari
// logic /check-payment supaya bisa dipakai bareng dari webhook GensPay
// (lihat app.post('/webhook/genspay') di bawah) TANPA duplikasi logic.
// Selalu re-fetch transaksi terbaru dari Supabase sebelum memutuskan apa
// pun -- transaction.status === 'done' di sini artinya sudah diproses
// instance lain / caller lain, jadi tidak diproses ulang (idempotent).
// ══════════════════════════════════════════════════════════════════
async function finalizeOrder(refId, settings) {
  const freshTransactions = await readFresh('transactions.json');
  const transaction = freshTransactions.find(t => t.id === refId);
  if (!transaction) return { status: 'not_found' };
  if (transaction.status === 'done') {
    return { status: 'already_done', type: transaction.type, key: transaction.key, code: transaction.code, outOfStock: transaction.outOfStock };
  }

  // Jika transaksi reseller, upgrade status user
  if (transaction.type === 'reseller') {
    const users = await readFresh('users.json');
    const u = users.find(u => u.id === transaction.userId);
    if (u) {
      u.is_reseller = true;
      u.role = 'reseller';
      u.reseller_since = new Date().toISOString();
      u.reseller_code = 'RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
      await writeDB('users.json', users);
    }
    transaction.status = 'done';
    transaction.paidAt = new Date().toISOString();
    const txList = await readFresh('transactions.json');
    const txIdx = txList.findIndex(t => t.id === refId);
    if (txIdx !== -1) txList[txIdx] = transaction; else txList.push(transaction);
    await writeDB('transactions.json', txList);
    return { status: 'done', type: 'reseller' };
  }

  // Jika transaksi top up saldo wallet, kreditkan saldo user
  if (transaction.type === 'deposit') {
    // FIX BUG KEAMANAN (audit 3 Sep 2026): pakai atomicUpdate, bukan
    // readFresh+writeDB manual -- webhook Pakasir/GensPay dan polling
    // /check-payment bisa saja memanggil finalizeOrder() untuk transaksi
    // yang sama nyaris bersamaan dari instance Vercel berbeda (guard
    // `processingOrders` cuma in-memory per-instance, tidak lintas-instance).
    // Tanpa CAS, saldo bisa kekredit dua kali dari basis baca yang sama.
    const amount = transaction.amount || transaction.price || 0;
    const depositResult = await atomicUpdate('users.json', (freshUsers) => {
      const u = freshUsers.find(u => u.id === transaction.userId);
      if (!u) return { ok: false, reason: 'user_not_found' };
      u.balance = (u.balance || 0) + amount;
      return { ok: true, data: freshUsers, result: { newBalance: u.balance } };
    });
    transaction.status = 'done';
    transaction.paidAt = new Date().toISOString();
    const txList = await readFresh('transactions.json');
    const txIdx = txList.findIndex(t => t.id === refId);
    if (txIdx !== -1) txList[txIdx] = transaction; else txList.push(transaction);
    await writeDB('transactions.json', txList);
    return { status: 'done', type: 'deposit', balance: depositResult.ok ? depositResult.result.newBalance : undefined };
  }

  // Produk biasa: potong stok key
  //
  // FIX BUG KRITIS (dilaporkan client 21 Agu 2026): sebelumnya kalau stok
  // durasi yang dipesan (misal 1-day) habis, kode fallback ke key generic,
  // dan kalau itu juga kosong fallback TERAKHIR adalah product.keys.shift()
  // -- ambil key APAPUN, termasuk durasi 7/15/30-day. Sekarang: kalau
  // transaction.selectedDays truthy dan stok durasi itu kosong, JANGAN
  // ambil durasi lain -- tandai outOfStock (sudah dibayar, admin notif
  // WA buat proses manual / restock), sama seperti kalau stok kosong total.
  //
  // Memakai helper parseKeyDuration/keyMatchesDuration (separator "=", lihat
  // definisi di atas) dan sekarang unit-aware (hari 'd' / jam 'h') untuk
  // dukung fitur key per-jam.
  //
  // FIX BUG KEAMANAN (audit 3 Sep 2026): pengambilan key sekarang lewat
  // atomicUpdate juga -- alasan sama seperti saldo di atas: webhook &
  // polling bisa memanggil finalizeOrder() untuk 2 transaksi BERBEDA yang
  // kebetulan minta durasi key yang sama, nyaris bersamaan, dari instance
  // berbeda. Tanpa CAS, keduanya bisa lolos findIndex() dengan basis array
  // yang sama dan berpotensi mengambil key yang sama persis / menimpa
  // pengurangan stok satu sama lain.
  const days = transaction.selectedDays;
  const unit = transaction.selectedUnit || 'd';
  const keyResult = await atomicUpdate('products.json', (freshProducts) => {
    const p = freshProducts.find(p => p.id === transaction.productId);
    if (!p?.keys?.length) return { ok: false, reason: 'out_of_stock' };
    let k = null;
    if (days) {
      const idx = p.keys.findIndex(kk => keyMatchesDuration(kk, days, unit));
      if (idx !== -1) k = parseKeyDuration(p.keys.splice(idx, 1)[0]).raw;
      // else: stok durasi ini kosong -- JANGAN fallback ke durasi lain.
    } else {
      const idx = p.keys.findIndex(kk => isGenericKey(kk));
      if (idx !== -1) k = p.keys.splice(idx, 1)[0];
    }
    if (!k) return { ok: false, reason: 'out_of_stock' };
    p.sold = (p.sold || 0) + 1;
    return { ok: true, data: freshProducts, result: { key: k } };
  });
  const key = keyResult.ok ? keyResult.result.key : null;
  const outOfStock = !key;

  transaction.status = 'done';
  transaction.key = key;
  transaction.outOfStock = outOfStock;
  transaction.paidAt = new Date().toISOString();
  const txListFinal = await readFresh('transactions.json');
  const txIdxFinal = txListFinal.findIndex(t => t.id === refId);
  if (txIdxFinal !== -1) txListFinal[txIdxFinal] = transaction; else txListFinal.push(transaction);
  await writeDB('transactions.json', txListFinal);

  if (outOfStock) {
    const waMsg = `⚠️ STOK HABIS - Pesanan butuh diproses manual!\n\n` +
      `Order: ${transaction.code}\n` +
      `Produk: ${transaction.productName}\n` +
      `Customer: ${transaction.customerName} (${transaction.wa || '-'})\n` +
      `Total: Rp ${Number(transaction.price).toLocaleString('id-ID')}\n\n` +
      `Pembayaran sudah masuk tapi stok key kosong. Segera tambah stok & kirim key manual ke pembeli.`;
    sendWhatsAppNotif(settings.contact?.whatsapp, waMsg, settings).catch(() => {});
  }

  const notifs = readDB('notifications.json');
  const buyer = readDB('users.json').find(u => u.id === transaction.userId);
  notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: transaction.customerName,
    buyerPhoto: buyer?.photo || null, productName: transaction.productName,
    price: transaction.price, time: transaction.paidAt, timeStr: formatDate(new Date(transaction.paidAt)) });
  await writeDB('notifications.json', notifs.slice(0, 50));

  return { status: 'done', type: 'product', key, code: transaction.code, outOfStock };
}

app.get('/check-payment/:refId', requireAuth, async (req, res) => {
  const refId = req.params.refId;
  // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit
  // di atas) -- polling client bisa manggil endpoint ini berkali-kali sampai status
  // berubah, jadi ini titik paling rawan kena limit 30 req/3 menit.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.json({ success: true, status: 'pending', rateLimited: true });
  }
  // Cegah race condition: jika transaksi sedang diproses, kembalikan pending
  if (processingOrders.has(refId)) {
    return res.json({ success: true, status: 'pending' });
  }
  processingOrders.add(refId);
  try {
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.id === refId);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    // FIX KEAMANAN — IDOR (audit 22 Agu 2026): endpoint ini sebelumnya HANYA
    // cek requireAuth (harus login), TAPI TIDAK PERNAH memverifikasi bahwa
    // transaksi ini benar milik user yang sedang login. Akibatnya: siapapun
    // yang tahu/menebak refId (UUID transaksi) bisa memanggil endpoint ini
    // dan mengambil KEY CHEAT milik transaksi orang lain secara gratis --
    // padahal refId bisa saja bocor lewat cara tidak sengaja (mis. customer
    // share link invoice ke grup chat sebagai bukti pembelian, screenshot,
    // dll). Admin dikecualikan karena memang berwenang mengecek status
    // transaksi siapapun untuk keperluan support.
    if (!req.session.isAdmin && transaction.userId !== req.session.userId) {
      return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    }
    if (transaction.status === 'done') {
      if (transaction.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      if (transaction.type === 'deposit') {
        const u = readDB('users.json').find(u => u.id === transaction.userId);
        return res.json({ success: true, status: 'done', type: 'deposit', balance: u?.balance || 0 });
      }
      return res.json({ success: true, status: 'done', key: transaction.key, code: transaction.code });
    }

    // Static QRIS: tunggu konfirmasi manual admin
    if (transaction.isStatic) return res.json({ success: true, status: 'pending_static' });

    const settings = readDB('settings.json');
    let paid = false;
    // PENTING: selalu verifikasi ke gateway yang SAMA dengan yang dipakai
    // saat transaksi ini dibuat (transaction.paymentGateway), BUKAN
    // settings.apiGateway yang sedang aktif sekarang — supaya transaksi lama
    // tetap benar dicek walau admin sudah ganti gateway di panel.
    const gateway = transaction.paymentGateway || settings.apiGateway || 'pakasir';

    // GensPay TIDAK punya endpoint cek status manual (lihat catatan panjang
    // di checkPaymentStatusGenspay) -- satu-satunya sumber kebenaran soal
    // status transaksi GensPay adalah webhook (app.post('/webhook/genspay')).
    // Jangan panggil checkPaymentStatus untuk gateway ini sama sekali,
    // supaya tidak spam error ke log tiap kali browser polling. Balas
    // "pending" apa adanya -- kalau webhook sudah masuk & finalize,
    // transaction.status di database sudah 'done' duluan dan ke-tangkep
    // oleh pengecekan status di atas sebelum sampai sini.
    if (gateway === 'genspay') {
      return res.json({ success: true, status: 'pending' });
    }
    try {
      // PENTING: Pakasir mewajibkan parameter `amount` di /api/transactiondetail
      // adalah NOMINAL ASLI yang diminta saat transaksi dibuat (field `price`
      // kita), BUKAN `total_payment` (yang sudah ditambah fee Pakasir).
      // Sebelumnya kode ini salah kirim totalPayment, jadi setiap kali
      // Pakasir mengenakan fee (tergantung channel/bank pembayaran, mis.
      // saat dirutekan lewat "Zona ID"), query ke Pakasir gagal mencocokkan
      // transaksinya — hasilnya status selalu balik pending walau uang
      // sudah benar-benar masuk ke saldo Pakasir. Lihat dokumentasi resmi:
      // https://pakasir.com/p/docs
      const r = await checkPaymentStatus(transaction.orderId, transaction.price, settings, gateway);
      // Normalize status dari berbagai format response PakKasir
      const status = (r.transaction?.status || r.status || r.data?.status || '').toLowerCase();
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(status) || r.success === true;
      if (!paid && !['expired','canceled','cancelled',''].includes(status)) {
        // Status nggak match daftar di atas tapi juga bukan expired — log biar kelihatan di server log kalau Pakasir balikin status baru yang belum kita tangani
        console.warn(`[check-payment] Status tidak dikenali untuk order ${transaction.orderId}: "${status}" | raw response:`, JSON.stringify(r).slice(0, 300));
      }
      if (['expired','canceled','cancelled'].includes(status)) {
        transaction.status = 'expired';
        const txListExpired = await readFresh('transactions.json');
        const txIdxExpired = txListExpired.findIndex(t => t.id === refId);
        if (txIdxExpired !== -1) txListExpired[txIdxExpired] = transaction; else txListExpired.push(transaction);
        await writeDB('transactions.json', txListExpired);
        return res.json({ success: true, status: 'expired' });
      }
    } catch(e) {
      // Sebelumnya error di sini ditelan total tanpa jejak (komentar doang).
      // Sekarang dicatat ke log server supaya kalau status macet pending
      // terus, gampang ketahuan apakah penyebabnya error koneksi/API,
      // bukan cuma nebak-nebak.
      console.error(`[check-payment] Gagal cek status order ${transaction.orderId}:`, e.message);
    }

    if (paid) {
      // ── ANTI DOUBLE-PROCESSING (lintas-instance Vercel) ──
      // finalizeOrder() sendiri sudah re-fetch transaksi terbaru & idempotent
      // (return status 'already_done' kalau sudah diproses instance/caller
      // lain), jadi aman dipanggil langsung dari sini.
      const result = await finalizeOrder(refId, settings);
      if (result.status === 'not_found') return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
      if (result.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      if (result.type === 'deposit') return res.json({ success: true, status: 'done', type: 'deposit', balance: result.balance });
      return res.json({ success: true, status: 'done', key: result.key, code: result.code, outOfStock: result.outOfStock });
    }

    res.json({ success: true, status: transaction.status });
  } catch (error) {
    console.error('[check-payment] error:', error.message);
    res.json({ success: false, message: error.message });
  } finally {
    processingOrders.delete(refId);
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK GENSPAY — dipanggil server-to-server oleh GensPay begitu
// pembayaran QRIS sukses & dana masuk, TANPA bergantung pembeli membuka
// atau tetap membuka halaman pembayaran. Sebelumnya store lama cuma
// mengandalkan polling client di /check-payment, jadi kalau pembeli
// tutup tab sebelum polling sempat nangkep status "paid", order nyangkut
// pending selamanya sampai admin approve manual.
//
// CARA AKTIFKAN: buka dashboard GensPay → pilih project → isi kolom
// "Webhook URL" dengan:
//   https://domainkamu.com/webhook/genspay
//
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
// ══════════════════════════════════════════════════════════════════
app.post('/webhook/genspay', async (req, res) => {
  try {
    const settings = readDB('settings.json');
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    const signatureHeader = req.headers['x-genspay-signature'];
    if (!apiKey || !signatureHeader) { logWebhook('genspay', { result: 'no_apikey_or_signature' }); return res.status(401).send('Unauthorized'); }

    // Signature = sha256(rawBody + apiKey). Pakai req.rawBody (string mentah,
    // lihat opsi `verify` di express.json() setup di atas) -- BUKAN
    // JSON.stringify(req.body) ulang, karena re-serialize objek yang sudah
    // di-parse tidak dijamin identik persis dengan raw body asli (urutan
    // key bisa berubah), jadi hash yang dihitung dari situ tidak akan
    // pernah match signature asli dari GensPay.
    if (!req.rawBody) { logWebhook('genspay', { result: 'no_raw_body' }); return res.status(401).send('Unauthorized: Raw body tidak tersedia'); }
    const computedSignature = crypto.createHash('sha256')
      .update(req.rawBody + apiKey)
      .digest('hex');

    // Perbandingan tahan timing-attack
    const sigA = Buffer.from(String(signatureHeader));
    const sigB = Buffer.from(computedSignature);
    if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
      logWebhook('genspay', { result: 'invalid_signature', orderId: req.body?.data?.order_id || null });
      return res.status(401).send('Unauthorized: Invalid Signature');
    }

    // Sesuai dokumentasi resmi GensPay (genspay.my.id/docs bagian
    // "7. WEBHOOK NOTIFIKASI"): payload berbentuk
    // { event: "transaction.updated", data: { order_id, status, ... } },
    // dan status sukses SELALU dikirim sebagai string "SUCCESS" (huruf besar).
    const { event, data } = req.body || {};
    if (event !== 'transaction.updated' || !data?.order_id) { logWebhook('genspay', { result: 'event_not_matched', event, orderId: data?.order_id || null }); return res.status(200).send('OK'); }

    const orderId = data.order_id;
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.orderId === orderId);
    if (!transaction) { logWebhook('genspay', { result: 'transaction_not_found', orderId }); return res.status(200).send('OK'); }
    if (transaction.status === 'done') { logWebhook('genspay', { result: 'already_done', orderId }); return res.status(200).send('OK'); }

    const status = (data.status || '').toUpperCase();
    const paid = status === 'SUCCESS';
    if (!paid) { logWebhook('genspay', { result: 'not_paid', orderId, statusFromWebhook: status || '(kosong)' }); return res.status(200).send('OK'); }

    if (processingOrders.has(transaction.id)) { logWebhook('genspay', { result: 'already_processing', orderId }); return res.status(200).send('OK'); }
    processingOrders.add(transaction.id);
    try {
      const result = await finalizeOrder(transaction.id, settings);
      logWebhook('genspay', { result: 'finalized', orderId, type: result.type, key: result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)') });
      res.status(200).send('OK');
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    console.error('[webhook/genspay] error:', error.message);
    logWebhook('genspay', { result: 'error', error: error.message });
    res.status(200).send('OK'); // tetap 200 biar GensPay tidak retry terus akibat error internal kita
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK PAKASIR — dipanggil server-to-server oleh Pakasir begitu QRIS
// dibayar, TANPA bergantung pembeli tetap membuka halaman invoice.
//
// SEBELUM INI: Pakasir (gateway yang AKTIF dipakai) cuma diverifikasi
// lewat polling /check-payment yang dipicu browser tiap beberapa detik.
// Kalau pembeli menutup tab sebelum polling sempat menangkap status
// "paid", order nyangkut pending selamanya sampai admin cek manual.
//
// CATATAN PENTING SOAL KEAMANAN (baca sebelum ubah endpoint ini):
// Dokumentasi resmi Pakasir (https://pakasir.com/p/docs) TIDAK dicek
// ulang saat kode ini ditulis, jadi format payload & mekanisme signature
// webhook Pakasir yang PERSIS belum bisa dipastikan di sini. Daripada
// menebak skema signature (yang kalau salah tebak justru bisa membuka
// celah "webhook palsu" diterima begitu saja karena verifikasinya cuma
// pura-pura), endpoint ini didesain supaya AMAN WALAU ISI PAYLOAD WEBHOOK
// TIDAK DIVERIFIKASI SAMA SEKALI:
//   Webhook HANYA dipakai sebagai "pemicu" (sinyal "coba cek order ini
//   sekarang") -- bukan sumber kebenaran. Begitu dipicu, server balik
//   nanya ke Pakasir sendiri lewat checkPaymentStatusPakasir() pakai
//   api_key kita, dan HANYA finalize kalau Pakasir (via API resmi,
//   otentikasi pakai api_key kita, bukan payload webhook yang masuk)
//   benar-benar konfirmasi status paid. Jadi walau ada orang iseng kirim
//   POST palsu ke endpoint ini dengan order_id sembarangan, tidak ada
//   dampak apa-apa -- order itu cuma di-double-check ke Pakasir, dan
//   kalau Pakasir bilang belum paid ya tidak terjadi apa-apa.
//
// CARA AKTIFKAN: buka dashboard Pakasir (app.pakasir.com) -> project ->
// cari kolom Webhook/Callback URL (kalau tersedia di UI mereka) -> isi:
//   https://domainkamu.com/webhook/pakasir
// Kalau Pakasir MEWAJIBKAN payload dikirim dalam format tertentu supaya
// mereka mau memanggil webhook (misal harus HTTP 200 body tertentu),
// sesuaikan response di bawah sesuai dokumentasi resmi mereka -- response
// "OK" 200 di sini seharusnya kompatibel dengan kebanyakan gateway.
//
// TETAP AKTIF juga /check-payment (polling) sebagai fallback -- kalau
// webhook ini gagal terpanggil (belum sempat disetel di dashboard Pakasir,
// network issue, dll), user yang masih membuka halaman invoice tetap bisa
// menyelesaikan order lewat polling seperti sebelumnya.
// ══════════════════════════════════════════════════════════════════
app.post('/webhook/pakasir', async (req, res) => {
  try {
    // Coba beberapa nama field umum -- karena format payload resmi Pakasir
    // belum dipastikan di sini, ekstraksi order_id dibuat toleran daripada
    // gagal total kalau nama field ternyata beda dari yang diduga.
    const body = req.body || {};
    const orderId = body.order_id || body.orderId || body.reference || body.merchant_order_id
      || body.data?.order_id || req.query.order_id;

    if (!orderId) {
      logWebhook('pakasir', { result: 'no_order_id', bodyKeys: Object.keys(body) });
      return res.status(200).send('OK'); // 200 supaya Pakasir tidak retry terus untuk payload yang memang tidak relevan
    }

    const settings = readDB('settings.json');
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.orderId === orderId);
    if (!transaction) { logWebhook('pakasir', { result: 'transaction_not_found', orderId }); return res.status(200).send('OK'); }
    if (transaction.status === 'done') { logWebhook('pakasir', { result: 'already_done', orderId }); return res.status(200).send('OK'); }
    if (transaction.isStatic) { logWebhook('pakasir', { result: 'static_qris_ignored', orderId }); return res.status(200).send('OK'); }

    if (processingOrders.has(transaction.id)) { logWebhook('pakasir', { result: 'already_processing', orderId }); return res.status(200).send('OK'); }
    processingOrders.add(transaction.id);
    try {
      // JANGAN percaya status dari body webhook -- selalu tanya balik ke
      // Pakasir pakai api_key kita sendiri (pola sama seperti /check-payment).
      let paid = false;
      try {
        const r = await checkPaymentStatusPakasir(orderId, transaction.price, settings);
        const status = (r.transaction?.status || r.status || r.data?.status || '').toLowerCase();
        paid = ['completed', 'success', 'paid', 'settlement', 'capture', 'complete', 'authorize', 'accepted'].includes(status) || r.success === true;
      } catch (e) {
        logWebhook('pakasir', { result: 'verify_error', orderId, error: e.message });
      }

      if (!paid) { logWebhook('pakasir', { result: 'not_paid_on_reverify', orderId }); return res.status(200).send('OK'); }

      const result = await finalizeOrder(transaction.id, settings);
      logWebhook('pakasir', { result: 'finalized', orderId, type: result.type, key: result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)') });
      res.status(200).send('OK');
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    console.error('[webhook/pakasir] error:', error.message);
    logWebhook('pakasir', { result: 'error', error: error.message });
    res.status(200).send('OK');
  }
});

app.get('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.query;
  if (code) {
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.code === code.toUpperCase());
    let productChannelUrl = '';
    if (transaction && transaction.productId) {
      const products = await readFresh('products.json');
      const product = products.find(p => p.id === transaction.productId);
      productChannelUrl = product?.channelUrl || '';
    }
    return res.render('pages/invoice', { transaction: transaction || null, error: transaction ? null : 'Pesanan tidak ditemukan', productChannelUrl });
  }
  res.render('pages/invoice', { transaction: null, error: null, productChannelUrl: '' });
});

app.post('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.body;
  const transactions = readDB('transactions.json');
  const transaction = transactions.find(t => t.code === code.toUpperCase());

  if (!transaction) {
    return res.render('pages/invoice', { transaction: null, error: 'Pesanan tidak ditemukan', productChannelUrl: '' });
  }

  let productChannelUrl = '';
  if (transaction.productId) {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === transaction.productId);
    productChannelUrl = product?.channelUrl || '';
  }

  res.render('pages/invoice', { transaction, error: null, productChannelUrl });
});

// Admin routes
// Heartbeat dari tab admin yang masih terbuka — requireAdmin di atasnya
// sudah otomatis menolak (sessionRevoked) kalau lock sudah diambil device
// lain, dan otomatis memperpanjang lastSeen kalau masih sah.
app.post('/admin/session/heartbeat', requireAdmin, (req, res) => {
  res.json({ success: true });
});

// Status koneksi Supabase, dipakai widget "Status Database" di Settings.
// BUG SEBELUMNYA: frontend sudah fetch('/admin/db-status') tapi route ini
// belum pernah didaftarkan → selalu 404 → ketangkep catch(e){} kosong di
// frontend → teks "Memeriksa koneksi..." nyangkut selamanya, padahal
// koneksi Supabase-nya sendiri sebenarnya baik-baik saja.
app.get('/admin/db-status', requireAdmin, async (req, res) => {
  try {
    const status = await db.getDbStatus();
    res.json(status);
  } catch (e) {
    res.json({ connected: false, errorMsg: e.message });
  }
});

// FIX (bug performa 23 Agu 2026, disesuaikan lagi 23 Agu 2026): endpoint
// sekali-jalan untuk migrasi gambar LAMA di Supabase Storage jadi WebP
// terkompres (lihat migrate-images-to-webp.js untuk detail lengkap kenapa
// ini perlu -- PageSpeed sebelumnya menunjukkan LCP puluhan detik &
// payload ~14MB, hampir semuanya gambar yang belum pernah dikompres).
//
// Awalnya dilindungi requireAdmin (perlu login dulu), tapi diminta diganti
// pakai SETUP_SECRET (pola sama dengan /franzzstore-setup di atas) supaya
// bisa diakses tanpa perlu login admin sama sekali -- berguna kalau admin
// sedang lupa password atau mau migrasi sebelum akun admin siap.
// Akses: /admin/migrate-images?secret=SETUP_SECRET (dari env var Vercel).
// Set SETUP_SECRET di env Vercel dulu, akses URL-nya, lalu HAPUS
// SETUP_SECRET dari env Vercel setelah selesai (endpoint ini otomatis
// nonaktif total / 404 kalau SETUP_SECRET tidak di-set, jadi aman by
// default -- tidak akan kebuka ke publik selama env itu kosong).
app.get('/admin/migrate-images', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!timingSafeStringEqual(req.query.secret, secret)) {
    return res.status(403).send('<pre>❌ Akses ditolak. Set SETUP_SECRET di env Vercel, lalu akses /admin/migrate-images?secret=SETUP_SECRET_KAMU</pre>');
  }

  const { runMigration, formatSummary } = require('./migrate-images-to-webp');
  const client = db.getClient();
  if (!client) {
    return res.status(500).send('<pre>Supabase belum terkonfigurasi (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set di env Vercel).</pre>');
  }

  // Stream progress sebagai plain text yang keupdate live di browser,
  // supaya tidak terlihat "hang" selama proses (bisa makan waktu kalau
  // gambarnya banyak).
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.write('Memulai migrasi gambar ke WebP...\n\n');
  // Beberapa proxy/browser menahan buffer kecil sebelum flush pertama --
  // paksa flush kalau tersedia supaya baris ini langsung muncul.
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  try {
    // maxFiles dibatasi supaya tidak kena timeout Vercel kalau gambarnya
    // banyak -- aman karena idempotent, tinggal refresh URL ini beberapa
    // kali sampai ringkasan menunjukkan "Sisa belum diproses: 0".
    const summary = await runMigration(client, {
      onProgress: (line) => res.write(line + '\n'),
      maxFiles: 15
    });
    res.write('\n' + formatSummary(summary) + '\n');
    if (summary.remaining > 0) {
      res.write('\nMasih ada sisa -- refresh/buka lagi halaman ini untuk lanjutkan batch berikutnya.\n');
    } else {
      res.write('\nSelesai. Buka kembali homepage dan cek PageSpeed Insights untuk verifikasi.\n');
    }
    res.end();
  } catch (err) {
    res.write('\n❌ Migrasi berhenti karena error: ' + err.message + '\n');
    res.end();
  }
});

// Migrasi seed data (users/products/transactions/dll) langsung ke Supabase
// keyvalue_store, dijalankan LANGSUNG dari Vercel (gak perlu terminal lokal).
// Pola akses sama persis dengan /admin/migrate-images di atas:
// /admin/migrate-seed?secret=SETUP_SECRET (dari env var Vercel).
// Set SETUP_SECRET di env Vercel dulu, akses URL-nya, lalu HAPUS
// SETUP_SECRET dari env Vercel setelah selesai. Endpoint ini otomatis
// nonaktif (403) selama SETUP_SECRET tidak di-set di env.
//
// PERHATIAN: ini nge-generate ULANG semua data fake (users/products/dst)
// dan overwrite key yang sama di keyvalue_store -- kalau sudah ada data
// PRODUKSI asli (bukan seed), JANGAN akses endpoint ini karena akan ketimpa.
app.get('/admin/migrate-seed', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!timingSafeStringEqual(req.query.secret, secret)) {
    return res.status(403).send('<pre>❌ Akses ditolak. Set SETUP_SECRET di env Vercel, lalu akses /admin/migrate-seed?secret=SETUP_SECRET_KAMU</pre>');
  }

  const client = db.getClient();
  if (!client) {
    return res.status(500).send('<pre>Supabase belum terkonfigurasi (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set di env Vercel).</pre>');
  }

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.write('Memulai migrasi seed data ke Supabase...\n\n');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  try {
    const { runMigration } = require('./migrate-seed');
    const result = await runMigration(client, {
      onProgress: (line) => res.write(line + '\n')
    });
    res.write('\n✅ Migrasi selesai! Key yang berhasil di-upsert:\n');
    result.upserted.forEach((k) => res.write(`   - ${k}\n`));
    res.write('\nSemua dilakukan dalam SATU kali request, tidak ada insert manual per baris.\n');
    res.write('Jangan lupa hapus SETUP_SECRET dari env Vercel kalau sudah tidak dipakai lagi.\n');
    res.end();
  } catch (err) {
    res.write('\n❌ Migrasi gagal: ' + err.message + '\n');
    res.end();
  }
});

// ══ Reset kredensial admin langsung dari Vercel (4 Sep 2026, diminta user) ══
// Porting logic reset-admin.js jadi endpoint HTTP -- dipakai kalau user gak
// punya Node.js di lokal buat jalanin `node reset-admin.js`. Pola akses
// SAMA PERSIS dengan /admin/migrate-seed: proteksi SETUP_SECRET (env var
// Vercel), akses lewat browser, HAPUS SETUP_SECRET setelah selesai.
//
// Bedanya endpoint ini nerima username & password BARU lewat query string
// juga (?username=...&password=...) -- karena itu WAJIB diakses HANYA
// sekali lalu URL-nya jangan disimpan di riwayat browser/dishare, dan
// SETUP_SECRET harus dihapus dari env Vercel segera setelah dipakai
// (persis prosedur yang sama seperti /admin/migrate-seed).
//
// Endpoint ini HANYA update field adminUsername + adminPassword (hash
// bcrypt) di settings.json -- tidak menyentuh data lain (produk, user,
// transaksi, dll), sama seperti reset-admin.js aslinya.
app.get('/admin/reset-admin', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!timingSafeStringEqual(req.query.secret, secret)) {
    return res.status(403).send('<pre>❌ Akses ditolak. Set SETUP_SECRET di env Vercel, lalu akses /admin/reset-admin?secret=SETUP_SECRET_KAMU&username=USERNAME_BARU&password=PASSWORD_BARU</pre>');
  }

  const { username, password } = req.query;
  if (!username || !password) {
    return res.status(400).send('<pre>❌ Wajib isi username dan password.\nContoh: /admin/reset-admin?secret=SETUP_SECRET_KAMU&username=admin&password=passwordBaru123</pre>');
  }
  if (String(password).length < 8) {
    return res.status(400).send('<pre>❌ Password minimal 8 karakter demi keamanan.</pre>');
  }

  const client = db.getClient();
  if (!client) {
    return res.status(500).send('<pre>Supabase belum terkonfigurasi (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set di env Vercel).</pre>');
  }

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.write('Reset kredensial admin...\n\n');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  try {
    // 1. Ambil settings existing (biar field lain gak ketimpa)
    const current = (await db.readFresh('settings.json')) || {};
    res.write(`Username lama: ${current.adminUsername || '(belum ada)'}\n`);

    // 2. Hash password baru
    res.write('Hashing password baru...\n');
    const newHash = await bcrypt.hash(String(password), 12);

    // 3. Verifikasi hash sebelum simpan
    const verifyOk = await bcrypt.compare(String(password), newHash);
    if (!verifyOk) {
      res.write('❌ Hash verification gagal! Dibatalkan, tidak ada yang disimpan.\n');
      return res.end();
    }
    res.write('✅ Hash password OK\n');

    // 4. Update HANYA adminUsername + adminPassword
    const updatedSettings = { ...current, adminUsername: String(username), adminPassword: newHash };
    await db.writeDB('settings.json', updatedSettings);

    // 5. Verifikasi ulang dari Supabase (bukan dari cache lokal)
    const saved = await db.readFresh('settings.json');
    const finalVerify = await bcrypt.compare(String(password), saved?.adminPassword || '');

    if (!finalVerify) {
      res.write('❌ GAGAL: password yang tersimpan tidak match. Coba lagi.\n');
      return res.end();
    }

    res.write('\n🎉 BERHASIL! Kredensial admin sudah diupdate.\n');
    res.write(`   Username: ${username}\n`);
    res.write('   Password: (sesuai yang barusan kamu masukkan di URL)\n\n');
    res.write('📌 Langkah selanjutnya:\n');
    res.write('   1. Buka /vpr-secure-panel-8x lalu login pakai kredensial di atas.\n');
    res.write('   2. HAPUS SETUP_SECRET dari environment variables Vercel sekarang juga.\n');
    res.write('   3. Setelah login, disarankan ganti password lagi lewat Admin Panel → Settings.\n');
    res.end();
  } catch (err) {
    res.write('\n❌ Gagal: ' + err.message + '\n');
    res.end();
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  // ── FIX: readFresh() bypass cache per-instance Vercel ──
  // Sebelumnya pakai readDB (cache lokal tiap instance), jadi setelah
  // tambah/edit produk di satu instance, refresh halaman bisa nyasar ke
  // instance lain yang cache-nya masih lama → produk kelihatan hilang/berubah.
  const [products, transactions, users, settings, accounts] = await Promise.all([
    readFresh('products.json'),
    readFresh('transactions.json'),
    readFresh('users.json'),
    readFresh('settings.json'),
    readFresh('accounts.json')
  ]);
  if (normalizeBanners(settings)) await writeDB('settings.json', settings);

  // PERFORMANCE: single-pass untuk stats + chart 7 hari, menggantikan
  // pola sebelumnya yang men-scan SELURUH transactions SEBANYAK 7 KALI
  // (sekali per hari) plus beberapa .filter()/.reduce() terpisah untuk
  // stats. Sekarang cukup 1 kali iterasi transactions, hasil akhir
  // (angka, urutan chart, format tanggal) identik dengan sebelumnya.
  const today = new Date();
  const dateKeys = [];
  const chartByDate = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    dateKeys.push(dateStr);
    chartByDate[dateStr] = {
      date: d.toLocaleDateString('id-ID', { weekday: 'short', day: 'numeric', month: 'short' }),
      count: 0,
      revenue: 0
    };
  }

  let pendingTransactions = 0, doneTransactions = 0, totalRevenue = 0;
  for (const t of transactions) {
    if (t.status === 'pending') pendingTransactions++;
    if (t.status === 'done') {
      doneTransactions++;
      totalRevenue += t.price;
      const dKey = t.createdAt && t.createdAt.slice(0, 10);
      if (dKey && chartByDate[dKey]) {
        chartByDate[dKey].count++;
        chartByDate[dKey].revenue += t.price;
      }
    }
  }

  let activeProducts = 0;
  for (const p of products) if (p.status === 'active') activeProducts++;
  let totalResellers = 0;
  for (const u of users) if (u.is_reseller) totalResellers++;

  const stats = {
    totalProducts: products.length,
    activeProducts,
    totalTransactions: transactions.length,
    pendingTransactions,
    doneTransactions,
    totalUsers: users.length,
    totalResellers,
    totalRevenue
  };

  const chartData = dateKeys.map(k => chartByDate[k]);

  res.render('pages/admin', {
    layout: false,
    products,
    transactions: transactions.slice(-20).reverse(),
    users,
    settings,
    stats,
    chartData,
    accounts: accounts.slice().reverse()
  });
});

// Helper: parse pricingOptions
// FIX (fitur baru: key per-jam, diminta client 21 Agu 2026): pricingOptions
// sekarang punya field `unit` ('d' hari atau 'h' jam) selain `days` (dipakai
// sebagai `value` numerik durasi, nama field dipertahankan "days" demi
// backward-compat data produk lama yang sudah tersimpan -- HANYA readable
// sebagai angka durasi, satuannya ikut field unit terpisah).
function parsePricingOptions(days, prices, resellerPrices, units, strikePrices) {
  const da = Array.isArray(days) ? days : (days ? [days] : []);
  const pa = Array.isArray(prices) ? prices : (prices ? [prices] : []);
  const rpa = Array.isArray(resellerPrices) ? resellerPrices : (resellerPrices ? [resellerPrices] : []);
  const ua = Array.isArray(units) ? units : (units ? [units] : []);
  // FIX (diminta client 22 Agu 2026, referensi screenshot produk "SENJU"):
  // harga coret itu PER-OPSI DURASI (mis. paket 30 hari punya harga coret
  // sendiri beda dari paket 60 hari), BUKAN satu harga coret global untuk
  // seluruh produk seperti implementasi sebelumnya (product.strikePrice).
  const spa = Array.isArray(strikePrices) ? strikePrices : (strikePrices ? [strikePrices] : []);
  const opts = []; const seen = new Set();
  for (let i = 0; i < da.length; i++) {
    const d = parseInt(da[i]), p = parseInt(pa[i]);
    const unit = (ua[i] === 'h' ? 'h' : 'd'); // default 'd' kalau tidak diisi/tidak valid
    const seenKey = `${d}${unit}`;
    if (d > 0 && p >= 0 && !seen.has(seenKey)) {
      seen.add(seenKey);
      const rp = rpa[i] !== undefined && rpa[i] !== '' ? parseInt(rpa[i]) : null;
      let sp = null;
      if (spa[i] !== undefined && spa[i] !== null && spa[i] !== '') {
        const parsed = parseInt(spa[i]);
        if (!isNaN(parsed) && parsed > p) sp = parsed; // harga coret harus LEBIH BESAR dari harga jual, kalau tidak dianggap tidak valid (diabaikan)
      }
      opts.push({ days: d, unit, price: p, reseller_price: (rp !== null && !isNaN(rp) && rp >= 0) ? rp : null, strike_price: sp });
    }
  }
  // Urutkan: jam dulu (durasi lebih pendek umumnya), lalu hari, masing-masing ascending
  return opts.sort((a, b) => a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
}

// Label tampilan buat 1 opsi durasi, dipakai konsisten di seluruh app
// (nama item `items[].l`, tampilan buy.ejs, invoice, dll).
function formatDurationLabel(days, unit) {
  return unit === 'h' ? `${days} JAM` : `${days} HARI`;
}

// ══════════════════════════════════════════════════════════════════
// PARSE DESKRIPSI PRODUK (auto-format ringan, diminta client 22 Agu 2026
// -- referensi screenshot fixaonly.com: badge tagline, daftar fitur cheat,
// link Telegram). Admin tetap cukup ngetik di 1 textarea description biasa,
// TIDAK perlu form/field baru -- baris yang diawali "-" atau "•" otomatis
// jadi bullet list fitur, baris polos jadi paragraf. Ini dipakai HANYA
// untuk RENDER (halaman /buy/:id), data tersimpan tetap 1 string apa
// adanya di product.description.
function parseProductDescription(description) {
  if (!description || typeof description !== 'string') return { paragraphs: [], bullets: [] };
  const lines = description.split('\n').map(l => l.trim()).filter(l => l);
  const paragraphs = [];
  const bullets = [];
  for (const line of lines) {
    if (/^[-•*]\s+/.test(line)) bullets.push(line.replace(/^[-•*]\s+/, ''));
    else paragraphs.push(line);
  }
  return { paragraphs, bullets };
}

// Helper: validasi URL gambar (cegah XSS via javascript:/data: protocol)
const isValidImageUrl = (url) => {
  if (!url) return true;
  const lower = url.toLowerCase().trim();
  return !lower.startsWith('javascript:') && !lower.startsWith('data:') && !lower.startsWith('vbscript:');
};

app.post('/admin/product/add', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    // FIX KEAMANAN (audit 22 Agu 2026): validasi magic bytes, lihat
    // requireValidImageMagicBytes untuk penjelasan lengkap kenapa ini perlu.
    if (req.file && !verifyImageMagicBytes(req.file.path)) {
      fs.unlink(req.file.path, () => {});
      return res.json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
    }
    next();
  });
}, async (req, res) => {
  try {
    const {name,categories,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices,keys,status,channelUrl,fakeSold,requiresGameId,requiresZoneId,gameIdLabel,gameIdPlaceholder,zoneIdLabel,zoneIdPlaceholder}=req.body;
    if(!name)return res.json({success:false,message:'Nama produk wajib diisi'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(channelUrl && !isValidImageUrl(channelUrl)) return res.json({success:false,message:'URL channel tidak valid'});
    const products=await readFresh('products.json');
    const pricingOptions=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices);
    if(!pricingOptions.length)return res.json({success:false,message:'Tambahkan minimal 1 opsi harga'});
    const keyArray=keys?keys.split('\n').map(k=>k.trim()).filter(k=>k):[];
    let image = imgUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        image = `/uploads/products/${req.file.filename}`;
      } else {
        try {
          image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch { image = imgUrl?.trim() || '/images/placeholder.jpg'; }
      }
    }
    if (!image) image = '/images/placeholder.jpg';
    // items.strike_price ikut dari pricingOptions (per-durasi, lihat parsePricingOptions)
    const items=pricingOptions.map(o=>({l:`${name.toUpperCase()} ${formatDurationLabel(o.days,o.unit)}`,p:o.price,reseller_price:o.reseller_price,strike_price:o.strike_price}));
    // Angka "terjual" palsu/manual (opsional, diminta client 21 Agu 2026) --
    // lihat komentar lengkap di /admin/product/:id. Harga coret SEKARANG
    // per-durasi (ada di dalam tiap pricingOptions/items, lihat di atas),
    // bukan lagi field tunggal per-produk.
    let fakeSoldVal = null;
    if (fakeSold !== undefined && fakeSold !== '' && fakeSold !== null) { const fs = parseInt(fakeSold); if (!isNaN(fs) && fs >= 0) fakeSoldVal = fs; }
    // FIX (diminta client 22 Agu 2026): categories sekarang array (bisa
    // lebih dari 1 sekaligus), dari multer bisa berupa string tunggal
    // (kalau cuma 1 checkbox dicentang) atau array (kalau lebih dari 1) --
    // dinormalisasi jadi array selalu.
    const categoriesArray = categories ? (Array.isArray(categories) ? categories : [categories]) : [];
    const newProduct={id:uuidv4(),name,categories:categoriesArray,description:description||'',image,pricingOptions,items,status:status==='inactive'?'inactive':'active',keys:keyArray,channelUrl:channelUrl?.trim()||'',fakeSold:fakeSoldVal,sold:0,
      // Field akun game (diminta owner 31 Agu 2026, fokus topup diamond/asset
      // game): admin toggle per-produk apakah butuh User ID / Zone ID sebelum
      // checkout. Produk non-game (mis. premium app Spotify/Netflix) biarkan
      // false -- checkout tetap jalan tanpa field ini seperti sebelumnya.
      requiresGameId: requiresGameId === 'true' || requiresGameId === true,
      requiresZoneId: requiresZoneId === 'true' || requiresZoneId === true,
      gameIdLabel: gameIdLabel?.trim() || 'User ID',
      gameIdPlaceholder: gameIdPlaceholder?.trim() || 'Masukkan User ID kamu',
      zoneIdLabel: zoneIdLabel?.trim() || 'Zone ID',
      zoneIdPlaceholder: zoneIdPlaceholder?.trim() || 'Masukkan Zone ID kamu',
      createdAt:new Date().toISOString()};
    products.push(newProduct);await writeDB('products.json',products);
    res.json({success:true,product:newProduct});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/edit/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    if (req.file && !verifyImageMagicBytes(req.file.path)) {
      fs.unlink(req.file.path, () => {});
      return res.json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
    }
    next();
  });
}, async (req, res) => {
  try {
    const {name,categories,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices,keys,keysMode,status,channelUrl,fakeSold,requiresGameId,requiresZoneId,gameIdLabel,gameIdPlaceholder,zoneIdLabel,zoneIdPlaceholder}=req.body;
    const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(channelUrl && !isValidImageUrl(channelUrl)) return res.json({success:false,message:'URL channel tidak valid'});
    if(name)product.name=name;
    if(categories!==undefined) product.categories = Array.isArray(categories) ? categories : (categories ? [categories] : []);
    if(description!==undefined)product.description=description;if(status)product.status=status;
    if(channelUrl!==undefined)product.channelUrl=channelUrl.trim();
    // Angka "terjual" palsu/manual (diminta client 21 Agu 2026, contoh
    // kingstore) -- TERPISAH dari product.sold asli (counter transaksi
    // riil, dipakai untuk laporan internal/analitik). Kalau fakeSold diisi
    // angka >= 0, dipakai buat TAMPILAN saja (lihat home.ejs); kalau
    // dikosongkan (string ''), override dihapus dan tampilan balik pakai
    // product.sold asli.
    if (fakeSold !== undefined) {
      if (fakeSold === '' || fakeSold === null) product.fakeSold = null;
      else { const fs = parseInt(fakeSold); if (!isNaN(fs) && fs >= 0) product.fakeSold = fs; }
    }
    // Harga coret (strikethrough) -- FIX (diminta client 22 Agu 2026,
    // referensi screenshot produk "SENJU"): sekarang PER-OPSI DURASI, ada
    // di dalam tiap pricingOptions/items (lihat parsePricingOptions), bukan
    // lagi field tunggal product.strikePrice. Field lama dihapus supaya
    // tidak ada 2 sumber kebenaran yang bisa saling tidak sinkron.
    if (product.strikePrice !== undefined) delete product.strikePrice;
    // Field akun game -- lihat catatan lengkap di /admin/product/add.
    if (requiresGameId !== undefined) product.requiresGameId = requiresGameId === 'true' || requiresGameId === true;
    if (requiresZoneId !== undefined) product.requiresZoneId = requiresZoneId === 'true' || requiresZoneId === true;
    if (gameIdLabel !== undefined) product.gameIdLabel = gameIdLabel.trim() || 'User ID';
    if (gameIdPlaceholder !== undefined) product.gameIdPlaceholder = gameIdPlaceholder.trim() || 'Masukkan User ID kamu';
    if (zoneIdLabel !== undefined) product.zoneIdLabel = zoneIdLabel.trim() || 'Zone ID';
    if (zoneIdPlaceholder !== undefined) product.zoneIdPlaceholder = zoneIdPlaceholder.trim() || 'Masukkan Zone ID kamu';
    if(pricingDays){const opts=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices);if(opts.length){product.pricingOptions=opts;product.items=opts.map(o=>({l:`${product.name.toUpperCase()} ${formatDurationLabel(o.days,o.unit)}`,p:o.price,reseller_price:o.reseller_price,strike_price:o.strike_price}));}}
    if(keys!==undefined&&keys!==null){const nk=keys.split('\n').map(k=>k.trim()).filter(k=>k);product.keys=keysMode==='append'?[...(product.keys||[]),...nk]:nk;}
    if (req.file) {
      if (!isVercel) product.image=`/uploads/products/${req.file.filename}`;
      else { try { product.image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch {} }
    }
    else if(imgUrl?.trim()) product.image=imgUrl.trim();
    await writeDB('products.json',products);res.json({success:true,product});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/keys/:id', requireAdmin, async (req, res) => {
  try {
    const{keys,mode}=req.body;const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    const nk=(keys||'').split('\n').map(k=>k.trim()).filter(k=>k);
    product.keys=mode==='replace'?nk:[...(product.keys||[]),...nk];
    await writeDB('products.json',products);res.json({success:true,keyCount:product.keys.length});
  }catch(e){res.json({success:false,message:e.message});}
});

app.post('/admin/product/delete/:id', requireAdmin, async (req, res) => {
  try {
    let products = await readFresh('products.json');
    products = products.filter(p => p.id !== req.params.id);
    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/user/delete/:id', requireAdmin, async (req, res) => {
  try {
    let users = await readFresh('users.json');
    users = users.filter(u => u.id !== req.params.id);
    await writeDB('users.json', users);
    res.json({ success: true, message: 'User berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/delete/:id', requireAdmin, async (req, res) => {
  try {
    let transactions = await readFresh('transactions.json');
    transactions = transactions.filter(t => t.id !== req.params.id);
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Transaksi berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/status/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const transactions = await readFresh('transactions.json');
    const trx = transactions.find(t => t.id === req.params.id);
    if (!trx) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    trx.status = status;
    trx.updatedBy = 'admin';
    trx.updatedAt = new Date().toISOString();
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Status berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    product.status = product.status === 'active' ? 'inactive' : 'active';
    await writeDB('products.json', products);

    res.json({ success: true, message: 'Status produk berhasil diubah', status: product.status });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/add-keys/:id', requireAdmin, async (req, res) => {
  try {
    const { keys } = req.body;
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    const newKeys = keys.split('\n').map(k => k.trim()).filter(k => k);
    product.keys = product.keys || [];
    product.keys.push(...newKeys);

    await writeDB('products.json', products);
    res.json({ success: true, message: `${newKeys.length} key berhasil ditambahkan`, keyCount: product.keys.length });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/update', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, email, downloadUrl, waChannel, adminUsername, categories, categoryLabels, logoUrl, fonnteToken, buyerGroupName, buyerGroupUrl, resellerGroupName, resellerGroupUrl, siteUrl, seoKeywords, paymentMethods } = req.body;

    if (siteName)      settings.siteName      = siteName;
    if (gamePanelName) settings.gamePanelName = gamePanelName;
    if (about !== undefined) settings.about   = about;
    if (marqueeText)   settings.marqueeText   = marqueeText;
    if (adminUsername) settings.adminUsername = adminUsername;
    if (logoUrl !== undefined) settings.logoUrl = logoUrl;
    if (fonnteToken !== undefined) settings.fonnteToken = fonnteToken;
    if (buyerGroupName !== undefined) settings.buyerGroupName = buyerGroupName.trim();
    if (buyerGroupUrl !== undefined) settings.buyerGroupUrl = buyerGroupUrl.trim();
    if (resellerGroupName !== undefined) settings.resellerGroupName = resellerGroupName.trim();
    if (resellerGroupUrl !== undefined) settings.resellerGroupUrl = resellerGroupUrl.trim();
    // SEO (diminta client 22 Agu 2026): domain kanonik & keyword target,
    // dipakai di <link rel="canonical">, Open Graph, sitemap.xml, dll.
    if (siteUrl !== undefined) settings.siteUrl = siteUrl.trim().replace(/\/$/, '');
    if (seoKeywords !== undefined) settings.seoKeywords = seoKeywords.trim();
    // Logo metode pembayaran di footer (diminta client 22 Agu 2026) --
    // dikirim sebagai JSON string dari textarea/hidden-input, di-parse
    // dan divalidasi minimal (harus array, tiap entry harus punya logoUrl
    // yang bukan javascript:/data: URL berbahaya).
    if (paymentMethods !== undefined) {
      try {
        const parsed = JSON.parse(paymentMethods);
        if (Array.isArray(parsed)) {
          settings.paymentMethods = parsed.filter(pm => pm && typeof pm.logoUrl === 'string' && isValidImageUrl(pm.logoUrl)).map(pm => ({
            name: (pm.name || '').trim().slice(0, 50),
            logoUrl: pm.logoUrl.trim()
          }));
        }
      } catch { /* JSON tidak valid, diabaikan -- settings.paymentMethods lama dipertahankan */ }
    }

    settings.contact = settings.contact || {};
    if (whatsapp !== undefined) settings.contact.whatsapp = whatsapp;
    if (telegram !== undefined) settings.contact.telegram = telegram;
    if (email    !== undefined) settings.contact.email    = email;
    if (downloadUrl !== undefined) settings.contact.downloadUrl = downloadUrl.trim();
    if (waChannel !== undefined) settings.contact.waChannel = waChannel.trim();

    // Handle categories update from JSON string or array
    if (categories) {
      try {
        settings.categories = JSON.parse(categories);
      } catch(e) {
        if (Array.isArray(categories)) settings.categories = categories;
      }
    }
    if (categoryLabels) {
      try {
        settings.categoryLabels = JSON.parse(categoryLabels);
      } catch(e) {
        if (typeof categoryLabels === 'object') settings.categoryLabels = categoryLabels;
      }
    }

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Pengaturan berhasil diupdate' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/pakasir', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, project, mode, apiBaseUrl, qrisMode } = req.body;

    settings.pakasir = {
      apiKey: apiKey !== undefined ? apiKey : (settings.pakasir?.apiKey || ''),
      project: project !== undefined ? project : (settings.pakasir?.project || ''),
      mode: mode || settings.pakasir?.mode || 'production',
      apiBaseUrl: apiBaseUrl !== undefined ? apiBaseUrl : (settings.pakasir?.apiBaseUrl || 'api.pakasir.com')
    };
    settings.apiGateway = 'pakasir';

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── GensPay Settings ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
app.post('/admin/settings/genspay', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, baseUrl, qrisMode } = req.body;

    settings.genspay = {
      apiKey: apiKey !== undefined ? apiKey : (settings.genspay?.apiKey || ''),
      baseUrl: baseUrl !== undefined ? baseUrl : (settings.genspay?.baseUrl || 'https://genspay.my.id/api/v1')
    };
    settings.apiGateway = 'genspay';

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/qris/test', requireAdmin, async (req, res) => {
  try {
    // gateway: 'pakasir' (default) atau 'genspay' — menentukan gateway mana yang dites
    const { apiKey, project, apiBaseUrl, gateway, baseUrl } = req.body;
    try {
      if (gateway === 'genspay') {
        const testSettings = { apiGateway: 'genspay', genspay: { apiKey, baseUrl: baseUrl || 'https://genspay.my.id/api/v1' } };
        await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      } else {
        const hostname = apiBaseUrl || 'api.pakasir.com';
        const testSettings = { apiGateway: 'pakasir', pakasir: { apiKey, project, apiBaseUrl: hostname } };
        await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      }
      res.json({ success: true });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/password', requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.json({ success: false, message: 'Password minimal 6 karakter' });
    }

    const settings = await readFresh('settings.json');
    settings.adminPassword = await bcrypt.hash(newPassword, 12);

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Password admin berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/popular-products', requireAdmin, async (req, res) => {
  try {
    const { popularProductIds } = req.body;
    const settings = await readFresh('settings.json');
    settings.popularProductIds = Array.isArray(popularProductIds) ? popularProductIds : [];
    await writeDB('settings.json', settings);
    res.json({ success: true, popularProductIds: settings.popularProductIds });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/settings/reseller', requireAdmin, async (req, res) => {
  try {
    const { resellerEnabled, resellerPrice, resellerDiscount, resellerNote } = req.body;
    const settings = await readFresh('settings.json');
    settings.resellerEnabled = resellerEnabled === 'true' || resellerEnabled === true;
    if (resellerPrice !== undefined && resellerPrice !== '') {
      const price = parseInt(resellerPrice);
      if (isNaN(price) || price < 0) return res.json({ success: false, message: 'Harga reseller tidak valid' });
      settings.resellerPrice = price;
    }
    if (resellerDiscount !== undefined && resellerDiscount !== '') {
      const discount = parseInt(resellerDiscount);
      if (isNaN(discount) || discount < 0 || discount > 100) return res.json({ success: false, message: 'Diskon harus antara 0-100%' });
      settings.resellerDiscount = discount;
    }
    if (resellerNote !== undefined) settings.resellerNote = resellerNote;
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Minimal top up saldo — dipisah per role biar member biasa & reseller VIP
// bisa diatur beda (member biasa umumnya lebih kecil daripada reseller).
app.post('/admin/settings/wallet', requireAdmin, async (req, res) => {
  try {
    const { memberMinDeposit, resellerMinDeposit } = req.body;
    const settings = await readFresh('settings.json');
    if (memberMinDeposit !== undefined && memberMinDeposit !== '') {
      const minDep = parseInt(memberMinDeposit);
      if (isNaN(minDep) || minDep < 0) return res.json({ success: false, message: 'Minimal top up member tidak valid' });
      settings.memberMinDeposit = minDep;
    }
    if (resellerMinDeposit !== undefined && resellerMinDeposit !== '') {
      const minDep = parseInt(resellerMinDeposit);
      if (isNaN(minDep) || minDep < 0) return res.json({ success: false, message: 'Minimal top up reseller tidak valid' });
      settings.resellerMinDeposit = minDep;
    }
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/user/toggle-reseller/:id', requireAdmin, async (req, res) => {
  try {
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.is_reseller = !user.is_reseller;
    user.role = user.is_reseller ? 'reseller' : 'user';
    if (user.is_reseller) {
      user.reseller_since = user.reseller_since || new Date().toISOString();
      user.reseller_code = user.reseller_code || ('RSL-' + user.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    await writeDB('users.json', users);
    res.json({ success: true, is_reseller: user.is_reseller });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Admin koreksi/tambah saldo wallet user secara manual (mis. transfer di luar QRIS)
app.post('/admin/user/adjust-balance/:id', requireAdmin, async (req, res) => {
  try {
    const amount = parseInt(req.body.amount);
    if (isNaN(amount) || amount === 0) return res.json({ success: false, message: 'Nominal tidak valid' });

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    const newBalance = (user.balance || 0) + amount;
    if (newBalance < 0) return res.json({ success: false, message: 'Saldo tidak boleh minus' });
    user.balance = newBalance;
    await writeDB('users.json', users);

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: uuidv4(), orderId: `ADJ-${Date.now()}`, code: generateOrderCode(),
      userId: user.id, type: 'adjustment', productName: amount > 0 ? 'Penambahan Saldo (Admin)' : 'Pengurangan Saldo (Admin)',
      amount, price: Math.abs(amount), customerName: user.username, wa: user.wa,
      status: 'done', paidAt: new Date().toISOString(),
      createdAt: new Date().toISOString(), time: formatDate(), confirmedBy: 'admin'
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, balance: user.balance });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
app.post('/admin/transaction/confirm/:id', requireAdmin, async (req, res) => {
  try {
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === req.params.id);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (transaction.status === 'done') return res.json({ success: false, message: 'Transaksi sudah selesai' });

    // Jika transaksi reseller, upgrade user
    if (transaction.type === 'reseller') {
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === transaction.userId);
      if (u) {
        u.is_reseller = true;
        u.role = 'reseller';
        u.reseller_since = u.reseller_since || new Date().toISOString();
        u.reseller_code = u.reseller_code || ('RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
        await writeDB('users.json', users);
      }
      transaction.status = 'done';
      transaction.paidAt = new Date().toISOString();
      await writeDB('transactions.json', transactions);
      return res.json({ success: true, type: 'reseller' });
    }

    // Jika transaksi top up saldo wallet, kreditkan saldo user
    if (transaction.type === 'deposit') {
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === transaction.userId);
      if (u) {
        u.balance = (u.balance || 0) + (transaction.amount || transaction.price || 0);
        await writeDB('users.json', users);
      }
      transaction.status = 'done';
      transaction.paidAt = new Date().toISOString();
      await writeDB('transactions.json', transactions);
      return res.json({ success: true, type: 'deposit', balance: u?.balance || 0 });
    }

    // Transaksi produk biasa: ambil key
    // FIX BUG KRITIS (sama seperti finalizeOrder & /wallet/buy): kalau stok
    // durasi yang dipesan habis, JANGAN fallback ke durasi lain (dulu
    // fallback terakhirnya product.keys.shift() = ambil key durasi apapun).
    // Unit-aware (hari/jam) via parseKeyDuration/keyMatchesDuration, separator "=".
    const products = readDB('products.json');
    const product = products.find(p => p.id === transaction.productId);
    let key = null;
    let outOfStock = false;
    if (product?.keys?.length > 0) {
      const days = transaction.selectedDays;
      const unit = transaction.selectedUnit || 'd';
      if (days) {
        const idx = product.keys.findIndex(k => keyMatchesDuration(k, days, unit));
        if (idx !== -1) key = parseKeyDuration(product.keys.splice(idx, 1)[0]).raw;
        // else: stok durasi ini kosong -- jangan ambil durasi lain, tandai outOfStock di bawah.
      } else {
        const idx = product.keys.findIndex(k => isGenericKey(k));
        if (idx !== -1) key = product.keys.splice(idx, 1)[0];
      }
      if (key) {
        product.sold = (product.sold || 0) + 1;
        await writeDB('products.json', products);
      } else {
        outOfStock = true;
      }
    } else {
      outOfStock = true;
    }

    transaction.status = 'done';
    transaction.key = key;
    transaction.outOfStock = outOfStock;
    transaction.paidAt = new Date().toISOString();
    transaction.confirmedBy = 'admin';
    await writeDB('transactions.json', transactions);

    res.json({ success: true, key });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// HALAMAN INFORMASI (Cara Beli, FAQ, Syarat & Ketentuan)
// diminta client 21 Agu 2026 -- sebelumnya semua link footer "Informasi"
// (Cara Beli/FAQ/Syarat) asal redirect ke /invoice, tidak jelas fungsinya.
// ══════════════════════════════════════════════════════════════════
app.get('/informasi', (req, res) => {
  const section = ['cara-beli', 'faq', 'syarat'].includes(req.query.tab) ? req.query.tab : 'cara-beli';
  res.render('pages/informasi', { activeTab: section });
});

// API endpoints
app.get('/api/products', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  // FIX (egress): endpoint publik paling sering dipanggil frontend -- ini
  // penyumbang terbesar cached egress karena dulu readFresh() menarik ulang
  // seluruh blob products dari Supabase di SETIAP request. readSmart pakai
  // cache ber-TTL sehingga data yang sama tidak ditransfer berulang.
  const products = (await readSmart('products.json'))
    .filter(p => p.status === 'active')
    // SECURITY: jangan kirim keys ke publik — keys hanya dikirim setelah pembayaran sukses
    .map(({ keys, ...safe }) => ({ ...safe, stockCount: (keys || []).length }));
  res.json(products);
});

// ── Helper: validasi & hitung diskon voucher ──
const validateVoucher = async (code, price, userId) => {
  if (!code) return { valid: false, error: 'Kode kosong' };
  const vouchers = await readFresh('vouchers.json');
  const v = vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase());
  if (!v) return { valid: false, error: 'Kode voucher tidak ditemukan' };
  if (!v.active) return { valid: false, error: 'Voucher tidak aktif' };
  if (v.expiresAt && new Date(v.expiresAt) < new Date()) return { valid: false, error: 'Voucher sudah kadaluarsa' };
  if (v.maxUses > 0 && v.usedCount >= v.maxUses) return { valid: false, error: 'Voucher sudah habis digunakan' };
  if (v.minPurchase > 0 && price < v.minPurchase) return { valid: false, error: `Minimal pembelian Rp ${v.minPurchase.toLocaleString('id-ID')}` };
  // Cegah reseller double-discount: kalau voucher punya flag excludeReseller,
  // tolak pemakaian oleh akun reseller (mereka sudah dapat diskon harga reseller).
  if (v.excludeReseller && userId) {
    const users = readDB('users.json');
    const u = users.find(u => u.id === userId);
    if (u?.is_reseller) return { valid: false, error: 'Voucher ini tidak berlaku untuk akun Reseller' };
  }
  if (v.perUserLimit > 0 && userId) {
    const userUses = (v.usages || []).filter(u => u.userId === userId).length;
    if (userUses >= v.perUserLimit) return { valid: false, error: 'Kamu sudah pernah memakai voucher ini' };
  }
  const discount = v.type === 'percent'
    ? Math.round(price * v.value / 100)
    : Math.min(v.value, price);
  const finalPrice = Math.max(price - discount, 0);
  return { valid: true, voucher: v, discount, finalPrice };
};

app.get('/api/stats', async (req, res) => {
  const products = await readSmart('products.json');
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const active = products.filter(p => p.status === 'active');
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  const avgRating = testimonials.length
    ? (testimonials.reduce((s, t) => s + (t.rating || 0), 0) / testimonials.length).toFixed(1)
    : '0.0';
  res.json({
    totalSold,
    totalActiveProducts: active.length,
    totalUsers: users.length,
    avgRating: parseFloat(avgRating)
  });
});

// Cek voucher (user)
app.post('/api/voucher/check', requireAuth, async (req, res) => {
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting -- bisa disalahgunakan buat brute-force menebak kode
  // voucher yang valid (terutama kalau formatnya pendek/predictable).
  // Dibatasi per user (bukan per IP) karena endpoint ini requireAuth.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.json({ valid: false, error: 'Terlalu banyak percobaan, coba lagi sebentar.' });
  }
  const { code, price } = req.body;
  if (!code || !price) return res.json({ valid: false, error: 'Data tidak lengkap' });
  const result = await validateVoucher(code, parseInt(price), req.session.userId);
  if (!result.valid) return res.json({ valid: false, error: result.error });
  res.json({
    valid: true,
    code: result.voucher.code,
    type: result.voucher.type,
    value: result.voucher.value,
    description: result.voucher.description || '',
    discount: result.discount,
    finalPrice: result.finalPrice
  });
});

app.get('/api/transactions', requireAdmin, (req, res) => {
  const transactions = readDB('transactions.json');
  res.json(transactions);
});

app.get('/api/testimonials', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const featured = req.query.featured === 'true';
  const verifiedOnly = req.query.verified === 'true';
  const productId = req.query.product;

  let filtered = testimonials;

  if (featured) {
    filtered = filtered.filter(t => t.featured && t.verified);
  } else if (verifiedOnly) {
    filtered = filtered.filter(t => t.verified);
  }

  if (productId) {
    filtered = filtered.filter(t => t.product === productId || t.productName === productId);
  }

  // Sort by date descending
  filtered.sort((a, b) => new Date(b.date) - new Date(a.date));

  // Attach user photo if available
  // PERFORMANCE: Map lookup dibangun sekali (O(1) per lookup), bukan
  // users.find() yang scan ulang seluruh array users untuk tiap testimonial.
  const userByUsername = buildUserLookupMaps(users).byUsername;
  filtered = filtered.map(t => {
    const u = userByUsername.get(t.username);
    return { ...t, photo: u?.photo || null };
  });

  // Pad with fake entries so page always looks alive
  const fakeTestimonials = [
    { id:'fake1', username:'Rizky F.',    name:'Rizky F.',    rating:5, text:'Topup diamond FF-nya mantap, udah langganan 3 bulan dan gak pernah ada masalah. Proses otomatis, CS-nya juga responsif banget!', product:'freefire',  productName:'FREE FIRE DIAMOND',  date:'2025-05-20', verified:true },
    { id:'fake2', username:'Andi S.',     name:'Andi S.',     rating:5, text:'Topup ML lengkap banget! Diamond, weekly pass sampai twilight pass ada. Harganya juga paling murah dibanding tempat lain.', product:'mlbb',      productName:'MOBILE LEGENDS DIAMOND', date:'2025-05-18', verified:true },
    { id:'fake3', username:'Dimas P.',    name:'Dimas P.',    rating:5, text:'Support fast response! Pas salah isi ID langsung dibantu sampai beres. Topup UC PUBG-nya juga cepat, langsung masuk.', product:'pubgm',     productName:'PUBG MOBILE UC', date:'2025-05-15', verified:true },
    { id:'fake4', username:'farhan99',    name:'farhan',      rating:5, text:'Beli Spotify Premium udah 2x dan alhamdulillah gak pernah ada kendala. Worth it banget harganya segitu.', product:'premium',   productName:'SPOTIFY PREMIUM', date:'2025-05-10', verified:true },
    { id:'fake5', username:'gamer_mlbb',  name:'Wanda M.',    rating:4, text:'Produknya bagus, prosesnya cepet banget. Cuma pas lagi ramai agak nunggu dikit tapi overall oke lah.', product:'mlbb',      productName:'MOBILE LEGENDS DIAMOND', date:'2025-05-08', verified:true },
    { id:'fake6', username:'ACA XITERZ', name:'ACA',          rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung diproses. Recommended!', product:'freefire', productName:'FREE FIRE DIAMOND', date:'2025-05-05', verified:true },
    { id:'fake7', username:'bintang_07',  name:'bintang',     rating:5, text:'Welkin Genshin worth it banget. Udah 6 bulan langganan di sini, harga lebih murah dari in-game.', product:'genshin',   productName:'GENSHIN IMPACT', date:'2025-04-28', verified:true },
    { id:'fake8', username:'rizky_ff',    name:'Rizky',       rating:4, text:'Kalau topup FF di sini top. Pernah ada kendala tapi langsung di-handle sama admin. Keep up the good work!', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2025-04-20', verified:true },
    { id:'fake9', username:'keymaster',   name:'Kevin',       rating:5, text:'Canva Pro-nya smooth banget. Langsung aktif dan bisa dipakai buat tugas desain. Harga murmer parah.', product:'premium',   productName:'CANVA PRO', date:'2025-04-15', verified:true },
    { id:'fake10',username:'abil',        name:'abil',        rating:5, text:'Ini toko topup terpercaya yang pernah aku coba. Transaksi aman, pesanan langsung diproses, CS ramah.', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2025-04-10', verified:true },
    { id:'fake11',username:'Hergi',       name:'Hergi',       rating:5, text:'Topup VP Valorant-nya akurat banget. Sudah 2 bulan langganan dan belum ada masalah sama sekali. Pelayanan top!', product:'valorant', productName:'VALORANT POINT', date:'2025-04-05', verified:true },
    { id:'fake12',username:'rehan',       name:'rehan',       rating:5, text:'Netflix Premium-nya mantap, profil private dan kualitas 4K jalan terus. Proses beli cepet dan langsung aktif.', product:'premium',  productName:'NETFLIX PREMIUM', date:'2025-03-28', verified:true },
    { id:'fake13',username:'Saell',       name:'Saell',       rating:5, text:'Topup 140 diamond FF, prosesnya cepet banget! Cuma 2 menit langsung masuk ke akun. Puas sampai sekarang.', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2025-03-25', verified:true },
    { id:'fake14',username:'GamerKing99', name:'GamerKing99', rating:5, text:'Topup MLBB-nya juara! Diamond langsung masuk, adminnya juga friendly dan fast respon.', product:'mlbb',      productName:'MOBILE LEGENDS DIAMOND', date:'2025-03-20', verified:true },
    { id:'fake15',username:'SkyyFire',    name:'SkyyFire',    rating:5, text:'Topup UC PUBG lancar jaya di coba dimana aja. Proses cepat, harga juga affordable banget!', product:'pubgm',     productName:'PUBG MOBILE UC', date:'2025-03-15', verified:true },
    { id:'fake16',username:'ShadowX',     name:'ShadowX',     rating:5, text:'Udah 4x topup di sini, selalu puas. Legit, murah, dan cepat. Best store for topup!', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2025-03-10', verified:true },
    { id:'fake17',username:'NightWolf',   name:'NightWolf',   rating:4, text:'YouTube Premium murah banget, tapi proses aktifnya agak nunggu dikit. Overall masih oke sih, worth the price.', product:'premium',   productName:'YOUTUBE PREMIUM', date:'2025-03-05', verified:true },
    { id:'fake18',username:'LunarKing',   name:'LunarKing',   rating:5, text:'Topup Genesis Crystal Genshin works perfectly! Langsung masuk ke UID, gak pake lama. Recommended!', product:'genshin',   productName:'GENSHIN IMPACT', date:'2025-02-28', verified:true },
    { id:'fake19',username:'NeonVibes',   name:'NeonVibes',   rating:5, text:'Weekly Diamond Pass ML murah banget di sini. UDAH 3 BULAN langganan dan belum pernah ada masalah. Mantap!', product:'mlbb',      productName:'MOBILE LEGENDS DIAMOND', date:'2025-02-20', verified:true },
    { id:'fake20',username:'StormRider',  name:'StormRider',  rating:4, text:'Produk bagus, cuma prosesnya agak lama pas weekend. Tapi overall puas, CS-nya ramah.', product:'pubgm',     productName:'PUBG MOBILE UC', date:'2025-02-15', verified:true },
    { id:'fake21',username:'GhostByte',   name:'GhostByte',   rating:5, text:'Topup diamond FF jernih prosesnya, tinggal isi ID player langsung masuk. Gampang banget dan menang terus belanja di sini!', product:'freefire', productName:'FREE FIRE DIAMOND', date:'2025-02-10', verified:true },
    { id:'fake22',username:'CyberRush',   name:'CyberRush',   rating:5, text:'CapCut Pro-nya langsung aktif, efek premium kebuka semua! Bikin konten jadi makin keren. Teman-teman pada nanya beli dimana.', product:'premium',  productName:'CAPCUT PRO', date:'2025-02-05', verified:true },
    { id:'fake23',username:'AlphaGod',    name:'AlphaGod',    rating:5, text:'Topup UC versi terbaru udah support semua metode pembayaran. Smooth, nggak ada kendala. Top banget!', product:'pubgm',     productName:'PUBG MOBILE UC', date:'2025-01-28', verified:true },
    { id:'fake24',username:'IronPhoenix', name:'IronPhoenix', rating:5, text:'Topup FF di sini yang paling murah dari semua yang pernah aku coba. Langganan mingguan, worth it!', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2025-01-20', verified:true },
    { id:'fake25',username:'TurboAce',    name:'TurboAce',    rating:4, text:'Disney+ Hotstar bagus, bisa nonton MPL lancar jaya. Overall recommend buat yang mau nonton bola.', product:'premium',   productName:'DISNEY+ HOTSTAR', date:'2025-01-15', verified:true },
    { id:'fake26',username:'NovaStar',    name:'NovaStar',    rating:5, text:'Topup VP Valorant akurat, langsung masuk ke Riot ID. Harga lebih murah dari in-game, auto langganan!', product:'valorant',  productName:'VALORANT POINT', date:'2025-01-10', verified:true },
    { id:'fake27',username:'DragonByte',  name:'DragonByte',  rating:5, text:'Topup 875 diamond ML buat beli skin collector! Proses cepat, diamond masuk dalam 2 menit. Mantap!', product:'mlbb',      productName:'MOBILE LEGENDS DIAMOND', date:'2025-01-05', verified:true },
    { id:'fake28',username:'MegaBoss',    name:'MegaBoss',    rating:5, text:'Topup di sini gampang banget, bayar pakai QRIS langsung diproses otomatis. Nggak ribet!', product:'freefire',  productName:'FREE FIRE DIAMOND', date:'2024-12-28', verified:true },
    { id:'fake29',username:'PulseWave',   name:'PulseWave',   rating:4, text:'Spotify Premium oke, cuma aktivasi agak nunggu 10 menit. Harusnya auto langsung sih. Overall puas.', product:'premium',   productName:'SPOTIFY PREMIUM', date:'2024-12-20', verified:true },
    { id:'fake30',username:'HyperCore',   name:'HyperCore',   rating:5, text:'Topup UC 1800 buat Royal Pass! Masuk langsung, murah, dan aman. Asik banget!', product:'pubgm',     productName:'PUBG MOBILE UC', date:'2024-12-15', verified:true },
  ];

  // Filter fake by product if requested
  let finalFake = fakeTestimonials;
  if (productId) {
    finalFake = fakeTestimonials.filter(f => f.product === productId || f.productName === productId);
  }

  // Only add fake entries that don't duplicate real usernames
  const realUsernames = new Set(filtered.map(t => (t.username||'').toLowerCase()));
  const paddedFake = finalFake.filter(f => !realUsernames.has((f.username||'').toLowerCase()));

  // Merge: real first, then fake (capped so total stays reasonable)
  const maxDisplay = 30;
  const combined = [...filtered, ...paddedFake].slice(0, maxDisplay);

  res.json(combined);
});

app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
    // FIX (audit 22 Agu 2026): sebelumnya tidak ada rate limit maupun cek
    // duplikat -- user yang sudah beli bisa spam testimoni berkali-kali
    // untuk produk yang sama, membanjiri list dan merusak kredibilitas
    // rating (bukan celah keamanan data, tapi integritas data publik).
    if (!checkApiRateLimit(req.ip, 10, 60000)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const { productId, productName, rating, text } = req.body;
    if (!productId || !rating || !text) return res.json({ success: false, message: 'Data tidak lengkap' });
    const ratingNum = parseInt(rating);
    if (ratingNum < 1 || ratingNum > 5) return res.json({ success: false, message: 'Rating tidak valid' });
    if (!text.trim()) return res.json({ success: false, message: 'Ulasan tidak boleh kosong' });
    if (text.trim().length > 500) return res.json({ success: false, message: 'Ulasan maksimal 500 karakter' });

    // Hanya user yang sudah membeli (transaksi sukses/done) produk ini yang boleh kirim testimoni
    const transactions = readDB('transactions.json');
    const hasPurchased = transactions.some(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'done'
    );
    if (!hasPurchased) {
      return res.json({ success: false, message: 'Hanya pembeli produk ini yang bisa memberikan rating/testimoni' });
    }

    // Cegah spam: satu user cuma boleh kasih 1 testimoni per produk.
    const testimonials = readDB('testimonials.json');
    const alreadyReviewed = testimonials.some(t => t.userId === req.session.userId && t.product === productId);
    if (alreadyReviewed) {
      return res.json({ success: false, message: 'Kamu sudah memberikan ulasan untuk produk ini' });
    }

    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);

    testimonials.unshift({
      id: uuidv4(),
      userId: req.session.userId,
      product: productId,
      productName: productName || '',
      username: user?.username || 'Pengguna',
      rating: ratingNum,
      text: text.trim(),
      date: new Date().toISOString(),
      verified: true,
      featured: false
    });

    await writeDB('testimonials.json', testimonials);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/testimonial/add', requireAdmin, async (req, res) => {
  try {
    if (!req.body.name || !req.body.text) {
      return res.json({ success: false, message: 'Nama dan isi testimoni wajib diisi' });
    }
    const { name, username, rating, text, product, verified, featured } = req.body;
    const testimonials = await readFresh('testimonials.json');

    // FIX (bug 24 Agu 2026): `product` sekarang berisi ID produk (dari
    // dropdown di form admin, bukan lagi text bebas -- lihat catatan
    // lengkap di admin.ejs dekat <select name="product">). productName
    // ikut diisi supaya konsisten dengan struktur testimoni ASLI dari
    // pembeli (lihat POST /api/testimonials di atas) dan tetap match
    // dengan kondisi t.productName === productId di endpoint GET, kalau
    // ada pemanggil lama yang masih mengandalkan itu.
    const productsAll = readDB('products.json');
    const matchedProduct = product ? productsAll.find(p => p.id === product) : null;

    const newTestimonial = {
      id: `testi-${Date.now()}`,
      name,
      username: username || null,
      rating: parseInt(rating) || 5,
      text,
      product: product || null,
      productName: matchedProduct ? matchedProduct.name : '',
      date: new Date().toISOString(),
      verified: verified === true || verified === 'true',
      featured: featured === true || featured === 'true'
    };

    testimonials.push(newTestimonial);
    await writeDB('testimonials.json', testimonials);

    res.json({ success: true, message: 'Testimoni berhasil ditambahkan' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/delete/:id', requireAdmin, async (req, res) => {
  try {
    let testimonials = await readFresh('testimonials.json');
    testimonials = testimonials.filter(t => t.id !== req.params.id);
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Testimoni berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-featured/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.featured = !testi.featured;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Status featured berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-verified/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.verified = !testi.verified;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: testi.verified ? 'Testimoni berhasil diverifikasi' : 'Verifikasi dicabut' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.get('/api/notifications', (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const notifs = readDB('notifications.json').slice(0, 20);
  // SECURITY: anonimkan nama pembeli — hanya tampilkan initial agar tidak bocor daftar username asli
  const anonymize = (name = '') => {
    if (!name) return '***';
    return name[0] + '*'.repeat(Math.max(name.length - 1, 2));
  };
  const enriched = notifs.map(({ id, type, productName, price, timeStr, buyerName }) => ({
    id, type, productName, price, timeStr,
    buyerName: anonymize(buyerName),
    buyerPhoto: null
  }));
  res.json(enriched);
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// Admin Product Edit Page
app.get('/admin/product-edit', requireAdmin, async (req, res) => {
  const [products, settings] = await Promise.all([readFresh('products.json'), readFresh('settings.json')]);
  const productId = req.query.id;
  const product = productId ? products.find(p => p.id === productId) : null;
  res.render('pages/admin-product-edit', { product, products, settings });
});

// Admin Theme Settings Page
app.get('/admin/theme-settings', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.render('pages/admin-theme', { settings });
});

// Admin Product Management
app.get('/admin/products', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  res.json({ success: true, data: products });
});

// Admin Get Single Product
app.get('/admin/product/:id', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === req.params.id);
  if (!product) return res.json({ success: false, message: 'Produk tidak ditemukan' });
  res.json({ success: true, data: product });
});

// Admin Update Product (image, status, keys)
app.post('/admin/product/:id', requireAdmin, async (req, res) => {
  try {
    const { items, bannerUrl, status, keys, keysMode, categories, channelUrl, fakeSold, description, videoUrl, compatibility, featureList, requiresGameId, requiresZoneId, gameIdLabel, gameIdPlaceholder, zoneIdLabel, zoneIdPlaceholder } = req.body;
    const products = await readFresh('products.json');
    const productIndex = products.findIndex(p => p.id === req.params.id);

    if (productIndex === -1) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    const p = products[productIndex];

    // Simpan ke image (yang dibaca frontend) DAN bannerUrl
    if (bannerUrl && bannerUrl.trim()) {
      p.image    = bannerUrl.trim();
      p.bannerUrl = bannerUrl.trim();
    }

    if (status) p.status = status;
    // FIX (diminta client 22 Agu 2026): sebelumnya "platform" (Android/iOS/PC)
    // itu HARDCODE 3 pilihan tetap, terpisah dari sistem "categories" (Free
    // Fire/Mobile Legends/dst) yang sudah admin-editable. Sekarang digabung
    // jadi SATU sistem: categories yang sepenuhnya diatur admin lewat Admin
    // Panel (bisa "Free Fire", bisa "Android", bisa "iOS", apa saja -- admin
    // yang tentukan), dan 1 produk bisa masuk LEBIH DARI SATU kategori
    // sekaligus (array, bukan string tunggal seperti field `category` lama).
    if (Array.isArray(categories)) p.categories = categories;
    // Deskripsi produk (diminta client 22 Agu 2026, referensi fixaonly.com)
    // -- sebelumnya halaman edit produk ini TIDAK punya field description
    // sama sekali, jadi admin tidak bisa ubah deskripsi produk yang sudah
    // ada, hanya bisa isi sekali pas awal create. String polos, diparsing
    // ke bullet/paragraf saat render (lihat parseProductDescription).
    if (description !== undefined) p.description = description;
    // ── Tab "Showcase" & "Information" di halaman produk (diminta client
    // 22 Agu 2026, referensi screenshot vipibmstore.com) ──
    // videoUrl: link YouTube/direct video (BUKAN upload file -- admin cukup
    // isi link, sesuai keputusan client). compatibility: teks bebas
    // (mis. "ANDROID NON ROOT"). featureList: array baris fitur, satu
    // fitur per baris (dikirim sebagai string newline-separated dari
    // textarea, disimpan sebagai array supaya gampang di-render sebagai
    // bullet list).
    if (videoUrl !== undefined) {
      if (videoUrl && !isValidImageUrl(videoUrl)) return res.json({ success: false, message: 'URL video tidak valid' });
      p.videoUrl = videoUrl.trim();
    }
    if (compatibility !== undefined) p.compatibility = compatibility.trim();
    if (featureList !== undefined) {
      p.featureList = featureList.split('\n').map(f => f.trim()).filter(f => f);
    }
    if (channelUrl !== undefined) {
      if (channelUrl && !isValidImageUrl(channelUrl)) return res.json({ success: false, message: 'URL channel tidak valid' });
      p.channelUrl = channelUrl.trim();
    }
    // Field akun game -- lihat catatan lengkap di /admin/product/add.
    if (requiresGameId !== undefined) p.requiresGameId = requiresGameId === 'true' || requiresGameId === true;
    if (requiresZoneId !== undefined) p.requiresZoneId = requiresZoneId === 'true' || requiresZoneId === true;
    if (gameIdLabel !== undefined) p.gameIdLabel = gameIdLabel.trim() || 'User ID';
    if (gameIdPlaceholder !== undefined) p.gameIdPlaceholder = gameIdPlaceholder.trim() || 'Masukkan User ID kamu';
    if (zoneIdLabel !== undefined) p.zoneIdLabel = zoneIdLabel.trim() || 'Zone ID';
    if (zoneIdPlaceholder !== undefined) p.zoneIdPlaceholder = zoneIdPlaceholder.trim() || 'Masukkan Zone ID kamu';

    // Angka "terjual" palsu/manual (diminta client 21 Agu 2026, contoh
    // referensi kingstore) -- lihat komentar lengkap di
    // /admin/product/edit/:id untuk penjelasan kenapa ini terpisah dari
    // product.sold asli.
    if (fakeSold !== undefined) {
      if (fakeSold === '' || fakeSold === null) p.fakeSold = null;
      else { const fs = parseInt(fakeSold); if (!isNaN(fs) && fs >= 0) p.fakeSold = fs; }
    }
    // FIX (diminta client 22 Agu 2026, referensi screenshot produk "SENJU"):
    // harga coret sekarang PER-OPSI DURASI (strike_price di dalam tiap
    // pricingOptions di bawah), bukan lagi field tunggal p.strikePrice.
    if (p.strikePrice !== undefined) delete p.strikePrice;

    // Kelola harga / pricing options
    const { pricingOptions } = req.body;
    if (Array.isArray(pricingOptions) && pricingOptions.length > 0) {
      const seenDays = new Set();
      const validOpts = [];
      for (const o of pricingOptions) {
        const days = parseInt(o.days);
        const price = parseInt(o.price);
        const unit = (o.unit === 'h' ? 'h' : 'd'); // default 'd' (hari) kalau tidak dikirim, backward-compat
        const seenKey = `${days}${unit}`;
        // Lewati baris yang harinya tidak valid, harga tidak valid, atau duplikat hari+unit
        // (baris lain dengan hari+unit sama akan menimpa data secara tak sengaja).
        if (!(days > 0) || isNaN(price) || price < 0 || seenDays.has(seenKey)) continue;
        seenDays.add(seenKey);
        // reseller_price manual diambil dari input yang baru dikirim form.
        // Kalau field-nya dikosongkan/tidak dikirim, dianggap "tidak ada harga manual"
        // (checkout akan fallback ke diskon % global) — bukan otomatis dari data lama.
        let resellerPrice = null;
        if (o.reseller_price !== undefined && o.reseller_price !== null && o.reseller_price !== '') {
          const rp = parseInt(o.reseller_price);
          if (!isNaN(rp) && rp >= 0) resellerPrice = rp;
        }
        // Harga coret per-durasi. Harus LEBIH BESAR dari harga jual paket
        // ini, kalau tidak dianggap tidak valid dan diabaikan (bukan error
        // keras, supaya tidak mengganggu simpan opsi harga lain yang valid).
        let strikePriceVal = null;
        if (o.strike_price !== undefined && o.strike_price !== null && o.strike_price !== '') {
          const sp = parseInt(o.strike_price);
          if (!isNaN(sp) && sp > price) strikePriceVal = sp;
        }
        validOpts.push({ days, unit, price, reseller_price: resellerPrice, strike_price: strikePriceVal });
      }
      // Kalau SEMUA baris yang dikirim gagal validasi (mis. semuanya kosong/0/duplikat),
      // JANGAN timpa harga lama — anggap tidak ada perubahan pada harga.
      if (validOpts.length > 0) {
        validOpts.sort((a, b) => a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
        p.pricingOptions = validOpts;
        p.items = validOpts.map(o => ({ l: `${(p.name||'PRODUK').toUpperCase()} ${formatDurationLabel(o.days, o.unit)}`, p: o.price, reseller_price: o.reseller_price, strike_price: o.strike_price }));
      }
    }

    // Kelola keys
    if (keys !== undefined && keys !== null) {
      const newKeys = String(keys).split('\n').map(k => k.trim()).filter(k => k);
      if (newKeys.length > 0) {
        p.keys = keysMode === 'replace' ? newKeys : [...(p.keys || []), ...newKeys];
      }
    }

    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil diupdate', data: p });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Upload Banner — di Vercel upload ke Supabase Storage, lokal ke filesystem
app.post('/admin/upload-banner', requireAdmin, multer({ storage: multer.memoryStorage(), fileFilter }).single('banner'), requireValidImageMagicBytesBuffer, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'Tidak ada file diupload' });

    if (isVercel) {
      // Vercel: upload ke Supabase Storage
      try {
        const url = await db.uploadImage(req.file.buffer, req.file.originalname, req.file.mimetype);
        return res.json({ success: true, bannerUrl: url });
      } catch (e) {
        return res.json({ success: false, message: e.message });
      }
    }

    // Lokal: simpan di filesystem
    const bannersDir = path.join(__dirname, 'public', 'uploads', 'banners');
    if (!fs.existsSync(bannersDir)) fs.mkdirSync(bannersDir, { recursive: true });
    const filename = `${Date.now()}-${uuidv4()}${path.extname(req.file.originalname)}`;
    fs.writeFileSync(path.join(bannersDir, filename), req.file.buffer);
    res.json({ success: true, bannerUrl: `/uploads/banners/${filename}` });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Get Theme Settings
app.get('/admin/theme', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.json({ success: true, data: settings.theme || {} });
});

// Admin Update Theme Settings
app.post('/admin/theme', requireAdmin, async (req, res) => {
  try {
    const { primaryColor, secondaryColor, accentColor, backgroundColor, cardBackground, borderColor, glowColor } = req.body;
    const settings = await readFresh('settings.json');

    // FIX KEAMANAN (audit 22 Agu 2026): sebelumnya warna tema disimpan
    // MENTAH tanpa validasi format sama sekali, padahal nilai ini di-render
    // langsung di dalam <style> block (bukan attribute HTML biasa) di
    // layout.ejs -- kalau isinya bukan hex color valid (mis. mengandung
    // "; } body { ... } /*"), itu bisa BREAK OUT dari CSS declaration dan
    // inject CSS arbitrary (CSS injection). Endpoint ini memang di belakang
    // requireAdmin, tapi validasi input tetap wajib sebagai defense-in-depth
    // -- jangan percaya input attacker meski sudah "admin", karena skenario
    // realistis: akun admin dikompromis, atau ada bug privilege-escalation
    // lain di kemudian hari yang bisa mengeksploitasi endpoint ini.
    const isValidHexColor = (v) => typeof v === 'string' && /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(v.trim());
    const isValidCssColorValue = (v) => typeof v === 'string' && /^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,\s%]+\))$/.test(v.trim());

    const prevTheme = settings.theme || {};
    const newTheme = {
      primaryColor: isValidHexColor(primaryColor) ? primaryColor.trim() : (prevTheme.primaryColor || '#2563eb'),
      secondaryColor: isValidHexColor(secondaryColor) ? secondaryColor.trim() : (prevTheme.secondaryColor || '#3b82f6'),
      accentColor: isValidHexColor(accentColor) ? accentColor.trim() : (prevTheme.accentColor || '#60a5fa'),
      backgroundColor: isValidHexColor(backgroundColor) ? backgroundColor.trim() : (prevTheme.backgroundColor || '#0a0a0a'),
      cardBackground: isValidHexColor(cardBackground) ? cardBackground.trim() : (prevTheme.cardBackground || '#151520'),
      // borderColor/glowColor historis diisi dalam format rgba(...), bukan hex -- validasi terpisah yang menerima keduanya.
      borderColor: isValidCssColorValue(borderColor) ? borderColor.trim() : (prevTheme.borderColor || 'rgba(157,78,221,.15)'),
      glowColor: isValidCssColorValue(glowColor) ? glowColor.trim() : (prevTheme.glowColor || 'rgba(157, 78, 221, 0.1)'),
    };
    // Kalau ADA field yang dikirim tapi tidak lolos validasi, kasih tau
    // dengan jelas alih-alih diam-diam pakai fallback -- supaya admin tahu
    // input yang dia masukkan salah format, bukan sekedar "kelihatannya
    // tidak tersimpan".
    const rejected = [];
    if (primaryColor !== undefined && !isValidHexColor(primaryColor)) rejected.push('Warna Utama');
    if (secondaryColor !== undefined && !isValidHexColor(secondaryColor)) rejected.push('Warna Sekunder');
    if (accentColor !== undefined && !isValidHexColor(accentColor)) rejected.push('Warna Aksen');
    if (backgroundColor !== undefined && !isValidHexColor(backgroundColor)) rejected.push('Background');
    if (cardBackground !== undefined && !isValidHexColor(cardBackground)) rejected.push('Card Background');
    if (rejected.length > 0) {
      return res.json({ success: false, message: `Format warna tidak valid (harus hex, contoh #2563eb): ${rejected.join(', ')}` });
    }

    settings.theme = newTheme;
    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Tema berhasil diupdate', data: settings.theme });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// ═══════════════════════════════════════════════════════════
// KEY POOL SYSTEM — Format: CODE - X Hari
// ═══════════════════════════════════════════════════════════

// User: halaman aktifkan key
app.get('/activate-key', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  res.render('pages/activate-key', { user, settings, result: null, error: null, code: '' });
});

app.post('/activate-key', requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting sama sekali -- ini titik PALING BERISIKO untuk brute-force
  // di seluruh aplikasi, karena kode key diisi BEBAS oleh admin (bisa saja
  // pendek/predictable, mis. serial number produk fisik) dan endpoint ini
  // langsung memberi hak pakai produk premium ke siapapun yang menebak kode
  // yang benar -- beda dari voucher yang "cuma" diskon, ini bisa mencuri
  // hak milik produk utuh. Dibatasi ketat per user.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.render('pages/activate-key', { user, settings, result: null, error: 'Terlalu banyak percobaan, coba lagi sebentar.', code: '' });
  }
  const code = (req.body.code || '').trim().toUpperCase();

  if (!code) return res.render('pages/activate-key', { user, settings, result: null, error: 'Masukkan kode key terlebih dahulu', code: '' });

  const keyspool = readDB('keyspool.json');
  const key = keyspool.find(k => k.code.toUpperCase() === code);

  if (!key) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key tidak ditemukan atau tidak valid', code });
  if (key.used) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sudah pernah digunakan', code });

  key.used = true;
  key.usedBy = user.id;
  key.usedByUsername = user.username;
  key.usedAt = new Date().toISOString();
  await writeDB('keyspool.json', keyspool);

  res.render('pages/activate-key', { user, settings, code,
    result: { code: key.code, duration: key.duration, label: key.label || `${key.duration} Hari`, note: key.note || '' },
    error: null
  });
});

// Admin: lihat semua key pool
app.get('/admin/keyspool', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('keyspool.json') });
});

// Admin: tambah key baru
app.post('/admin/keyspool/add', requireAdmin, async (req, res) => {
  try {
    const { code, duration, label, note } = req.body;
    if (!code || !duration) return res.json({ success: false, message: 'Kode dan durasi wajib diisi' });
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid (harus > 0 hari)' });
    const keyspool = await readFresh('keyspool.json');
    if (keyspool.find(k => k.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode key sudah ada' });
    }
    keyspool.push({
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      duration: d,
      label: label?.trim() || `${d} Hari`,
      used: false, usedBy: null, usedByUsername: null, usedAt: null,
      note: note?.trim() || '',
      createdAt: new Date().toISOString()
    });
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: generate key otomatis (bulk)
app.post('/admin/keyspool/generate', requireAdmin, async (req, res) => {
  try {
    const { count, duration, prefix, label } = req.body;
    const n = Math.min(parseInt(count) || 1, 100);
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid' });
    const keyspool = await readFresh('keyspool.json');
    const pref = (prefix || 'KEY').toUpperCase();
    const added = [];
    for (let i = 0; i < n; i++) {
      const code = `${pref}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      keyspool.push({
        id: uuidv4(), code, duration: d,
        label: label?.trim() || `${d} Hari`,
        used: false, usedBy: null, usedByUsername: null, usedAt: null,
        note: '', createdAt: new Date().toISOString()
      });
      added.push(code);
    }
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, generated: added.length, codes: added, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: hapus key
app.post('/admin/keyspool/delete/:id', requireAdmin, async (req, res) => {
  try {
    let keyspool = await readFresh('keyspool.json');
    keyspool = keyspool.filter(k => k.id !== req.params.id);
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// VOUCHER SYSTEM
// ═══════════════════════════════════════════════════════════

app.get('/admin/vouchers', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('vouchers.json') });
});

app.post('/admin/vouchers/add', requireAdmin, async (req, res) => {
  try {
    const { code, type, value, minPurchase, maxUses, perUserLimit, expiresAt, description, excludeReseller } = req.body;
    if (!code || !type || value === undefined) return res.json({ success: false, message: 'Kode, tipe, dan nilai wajib diisi' });
    const val = parseFloat(value);
    if (isNaN(val) || val <= 0) return res.json({ success: false, message: 'Nilai voucher tidak valid' });
    if (type === 'percent' && val > 100) return res.json({ success: false, message: 'Persentase diskon maksimal 100%' });
    const vouchers = await readFresh('vouchers.json');
    if (vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode voucher sudah ada' });
    }
    const newV = {
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      type,
      value: val,
      minPurchase: parseInt(minPurchase) || 0,
      maxUses: parseInt(maxUses) || 0,
      perUserLimit: parseInt(perUserLimit) || 1,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      description: description?.trim() || '',
      excludeReseller: excludeReseller === true || excludeReseller === 'true',
      active: true,
      usedCount: 0,
      usages: [],
      createdAt: new Date().toISOString()
    };
    vouchers.push(newV);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, data: vouchers });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/vouchers/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const vouchers = await readFresh('vouchers.json');
    const v = vouchers.find(v => v.id === req.params.id);
    if (!v) return res.json({ success: false, message: 'Voucher tidak ditemukan' });
    v.active = !v.active;
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, active: v.active });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/vouchers/delete/:id', requireAdmin, async (req, res) => {
  try {
    let vouchers = await readFresh('vouchers.json');
    vouchers = vouchers.filter(v => v.id !== req.params.id);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
