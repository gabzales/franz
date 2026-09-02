const express = require('express');
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

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET tidak di-set. Menggunakan fallback. Segera set di Vercel env vars!');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting untuk QR Code
const qrRateLimit = new Map();
const QR_RATE_LIMIT = 30;
const QR_RATE_WINDOW = 60000;

// Rate limiting untuk login (brute force protection)
const loginFailMap = new Map();
const LOGIN_MAX_FAIL = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkLoginBlocked = (ip) => {
  const rec = loginFailMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { loginFailMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= LOGIN_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordLoginFail = (ip) => {
  const now = Date.now();
  const rec = loginFailMap.get(ip);
  if (!rec || now > rec.resetAt) loginFailMap.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else { rec.count++; loginFailMap.set(ip, rec); }
};

const clearLoginFail = (ip) => loginFailMap.delete(ip);

// Rate limiting untuk aktivasi key (cegah brute-force nebak kode key)
const activateKeyRateMap = new Map();
const ACTIVATE_KEY_MAX_FAIL = 8;
const ACTIVATE_KEY_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkActivateKeyBlocked = (ip) => {
  const rec = activateKeyRateMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { activateKeyRateMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= ACTIVATE_KEY_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordActivateKeyFail = (ip) => {
  const now = Date.now();
  const rec = activateKeyRateMap.get(ip);
  if (!rec || now > rec.resetAt) activateKeyRateMap.set(ip, { count: 1, resetAt: now + ACTIVATE_KEY_WINDOW_MS });
  else { rec.count++; activateKeyRateMap.set(ip, rec); }
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

// Lock set untuk mencegah race condition pada alokasi key
const processingOrders = new Set();

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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use('/uploads/avatars', express.static(path.join(__dirname, 'public/uploads/avatars')));

// Vercel: /uploads/logo-franzzstore.png tidak persistent jika ditulis runtime — redirect ke Supabase Storage
// (Tidak berlaku untuk file yang sudah ikut ter-deploy statis di public/uploads/)
if (process.env.VERCEL === '1' || process.env.NOW_REGION) {
  app.get('/uploads/logo-franzzstore.png', (req, res, next) => {
    const staticPath = path.join(__dirname, 'public/uploads/logo-franzzstore.png');
    if (fs.existsSync(staticPath)) return next();
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl
      ? `${supabaseUrl}/storage/v1/object/public/product-images/logo-franzzstore.png`
      : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send(`<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#2DEEFF"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#05070B" font-size="14" font-weight="bold">A</text></svg>`);
  });
}

app.use(cookieSession({
  name: 'vpr_session',
  secret: process.env.SESSION_SECRET || 'franzzstore-fallback-secret-2026-xK9mP3qR',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production' && !!process.env.SESSION_SECRET,
}));

// ── FIX: Regenerate session object tiap request (cookie-session quirk) ──
app.use((req, res, next) => {
  // Pastikan session object tidak null
  if (!req.session) req.session = {};
  next();
});

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
  next();
});

// Setup upload — gunakan /tmp di Vercel (satu-satunya writable path)
const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;
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
const readSmart = db.readSmart; // TTL-based: auto-refresh jika cache >8 detik
const refreshForWrite = (...files) => Promise.all(files.map(f => db.refreshFromDB(f)));

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
    siteName: 'FRANZZSTORE',
    gamePanelName: 'FRANZZSTORE',
    about: 'FRANZZSTORE adalah Top Up Game & Marketplace Jual Beli Akun #1 di Indonesia — proses cepat, harga bersaing, dan 100% aman.',
    marqueeText: 'TOP UP GAME • JUAL BELI AKUN • PROSES CEPAT & AMAN - FRANZZSTORE #BANYAKUNTUNGNYA',
    contact: {
      whatsapp: '6285133408356',
      telegram: '0029VbC4ZyhCcW4sLQRefe3s',
      tiktok: 'franzzstore',
      apkChannel: '0029VbChj7435fM1YttT8n40',
      email: 'support@franzzstore.web.id'
    },
    fonnteToken: '',
    pakasir: { apiKey: '', project: '', mode: 'production' },
    adminUsername: fallbackUsername,
    adminPassword: bcrypt.hashSync(fallbackPassword, 12),
    adminLockEnabled: true,
    logoUrl: '/uploads/logo-franzzstore.png',
    faviconUrl: '/uploads/favicon-franzzstore.png',
    theme: {
      primaryColor: '#2DEEFF',
      secondaryColor: '#4CF5FF',
      accentColor: '#78FFFF',
      backgroundColor: '#24272B',
      cardBackground: '#2E3237',
      borderColor: 'rgba(45,238,255,.18)',
      glowColor: 'rgba(45,238,255,0.55)'
    },
    categories: ['freefire', 'mlbb', 'pubgm', 'akun'],
    categoryLabels: { freefire: 'FREE FIRE', mlbb: 'MOBILE LEGENDS', pubgm: 'PUBG MOBILE', akun: 'JUAL BELI AKUN' },
    resellerEnabled: true,
    resellerPrice: 50000,
    resellerDiscount: 20,
    resellerNote: 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: [],
    banners: [
      {
        id: 'banner-default-1',
        imageUrl: '/uploads/banners/banner-1.jpg',
        title: 'Top Up Game Tercepat & Termurah',
        subtitle: 'Diamond, UC, dan semua top up game — proses instan & 100% aman',
        link: '/',
        active: true,
        createdAt: new Date().toISOString()
      },
      {
        id: 'banner-default-2',
        imageUrl: '/uploads/banners/banner-2.jpg',
        title: 'Jual Beli Akun Aman & Terpercaya',
        subtitle: 'Jual akun gamemu atau cari akun impian — mudah, cepat & bergaransi',
        link: '/jual-beli-akun',
        active: true,
        createdAt: new Date().toISOString()
      }
    ]
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

    // Reset paksa kredensial admin — hanya jalan kalau FORCE_RESET_ADMIN=true
    // di env. Set env ini + INITIAL_ADMIN_USERNAME/PASSWORD, lalu redeploy.
    // SETELAH berhasil login, HAPUS lagi env FORCE_RESET_ADMIN supaya tidak
    // ke-reset terus tiap kali server restart/redeploy.
    if (process.env.FORCE_RESET_ADMIN === 'true') {
      currentSettings.adminUsername = fallbackUsername;
      currentSettings.adminPassword = bcrypt.hashSync(fallbackPassword, 12);
      dirty = true;
      console.log('🔐 FORCE_RESET_ADMIN aktif — kredensial admin di-reset ke:');
      console.log(`   username: ${fallbackUsername}`);
      console.log(`   password: ${fallbackPassword}`);
      console.log('⚠️  Jangan lupa HAPUS env FORCE_RESET_ADMIN setelah berhasil login!');
    }

    if (dirty) {
      await writeDB('settings.json', currentSettings);
      console.log('✅ Settings merged missing fields');
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

  try {
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
    const lockSettings = await db.readFresh('settings.json');
    const lockEnabled = lockSettings?.adminLockEnabled !== false; // default: aktif
    let lock; // deklarasi di luar blok — dipakai lagi di touchAdminLock() di bawah
    if (lockEnabled) {
      lock = await db.readFresh('admin-lock.json');
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
    }

    // Sesi ini pemegang lock yang sah → perpanjang heartbeat (di-throttle,
    // supaya tidak nulis ke Supabase di setiap request)
    touchAdminLock(req.session.adminSessionId, lock);

    next();
  } catch (err) {
    // SAFETY NET: kalau ada bug tak terduga di blok di atas, jangan biarkan
    // request menggantung sampai Vercel timeout (504) — langsung balas error
    // dan tetap izinkan request lanjut (fail-open) supaya panel admin tidak
    // ikut lumpuh total gara-gara 1 fitur lock ini.
    console.error('requireAdmin error (fail-open, lock check dilewati):', err);
    next();
  }
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
const generateOrderCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'VR-';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  code += '-';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
};

// ── Timezone bisnis: WIB (Asia/Jakarta, UTC+7) ──
// BUG LAMA: formatDate() pakai d.getDate()/getHours() dkk, yang selalu
// ikut timezone SERVER (di Vercel = UTC), bukan timezone toko (WIB).
// Makanya jam yang tampil di admin panel / notif pembelian meleset ~7 jam
// dari jam Indonesia asli. Fix: selalu convert eksplisit ke Asia/Jakarta
// pakai Intl.DateTimeFormat, apapun timezone server-nya.
const APP_TIMEZONE = 'Asia/Jakarta';

const jakartaParts = (date = new Date()) => {
  const d = new Date(date);
  const parts = {};
  new Intl.DateTimeFormat('en-GB', {
    timeZone: APP_TIMEZONE,
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(d).forEach(p => { parts[p.type] = p.value; });
  return parts;
};

const formatDate = (date = new Date()) => {
  const p = jakartaParts(date);
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}`;
};

// Kunci kalender harian (YYYY-MM-DD) berbasis WIB — dipakai untuk
// pengelompokan per-hari (chart revenue dkk) supaya transaksi yang
// terjadi jam 00:00-06:59 WIB tidak "nyasar" dihitung ke hari
// sebelumnya (karena jam segitu di UTC masih tanggal kemarin).
const jakartaDateKey = (date = new Date()) => {
  const p = jakartaParts(date);
  return `${p.year}-${p.month}-${p.day}`;
};

// Label tanggal pendek buat chart, contoh: "Sen, 6 Jul" — eksplisit WIB.
const jakartaDayLabel = (date = new Date()) => new Intl.DateTimeFormat('id-ID', {
  timeZone: APP_TIMEZONE, weekday: 'short', day: 'numeric', month: 'short'
}).format(new Date(date));

// Hitung ULANG field waktu tampilan dari createdAt asli setiap kali
// di-render, alih-alih percaya field `time` yang sudah tersimpan di DB.
// Ini penting: transaksi LAMA yang kena bug timezone di atas otomatis
// ikut ke-fix begitu halaman di-refresh, tanpa perlu migrasi data manual
// ke Supabase.
const withDisplayTime = (t) => {
  if (!t) return t;
  const refTime = (t.status === 'done' && t.paidAt) ? t.paidAt : t.createdAt;
  const ts = refTime ? new Date(refTime) : null;
  const valid = ts && !isNaN(ts.getTime());
  return { ...t, time: valid ? formatDate(ts) : (t.time || '-') };
};
const withDisplayTimeList = (list) => (list || []).map(withDisplayTime);

// ── PakKasir API (app.pakasir.com) ──
const createQRISPayment = (orderId, amount, settings) => {
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

const checkPaymentStatus = (orderId, amount, settings) => {
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

// Routes - Public
app.get('/', async (req, res) => {
  const products = (await readFresh('products.json')).filter(p => p.status === 'active');

  // ── Leaderboard real-time (hanya dari transaksi sukses) ──
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });
  const realEntries = Object.values(userStats).map(stat => {
    const u = users.find(u => u.id === stat.userId);
    return { username: u?.username || 'User', totalTransactions: stat.totalTransactions, totalSpent: stat.totalSpent };
  });
  const leaderboardEntries = realEntries
    .sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent)
    .slice(0, 8);

  // ── Testimoni real dari database (tidak ada lagi padding data palsu) ──
  const realTestimonials = readDB('testimonials.json').filter(t => t.verified);
  const testimonialsForHome = realTestimonials.slice(0, 12);
  const avgRating = testimonialsForHome.length
    ? (testimonialsForHome.reduce((s, t) => s + (t.rating || 0), 0) / testimonialsForHome.length).toFixed(1)
    : '4.9';
  const ratingCounts = {1:0,2:0,3:0,4:0,5:0};
  testimonialsForHome.forEach(t => { if (t.rating >= 1 && t.rating <= 5) ratingCounts[t.rating]++; });
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  // Popular products: if admin configured popularProductIds, use those; else show all products
  const popularProductIds = settings.popularProductIds || [];
  let popularProducts;
  if (popularProductIds.length > 0) {
    popularProducts = products.filter(p => popularProductIds.includes(p.id));
    // Append any active products not in the popular list
    const remaining = products.filter(p => !popularProductIds.includes(p.id));
    popularProducts = [...popularProducts, ...remaining];
  } else {
    popularProducts = [...products].sort((a, b) => (b.sold || 0) - (a.sold || 0));
  }

  // SECURITY: strip keys sebelum dikirim ke view — home.ejs embed popularProducts
  // ke dalam <script> via JSON.stringify, jadi keys harus dihapus dari sini.
  const popularProductsSafe = popularProducts.map(({ keys, ...p }) => ({
    ...p, stockCount: (keys || []).length
  }));

  res.render('pages/home', {
    products,
    popularProducts: popularProductsSafe,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    resellerSettings: {
      enabled: settings.resellerEnabled !== false,
      price: settings.resellerPrice || 50000,
      discount: settings.resellerDiscount || 20
    },
    leaderboardEntries,
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

app.post('/login', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
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
    recordLoginFail(ip);
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
    clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.redirect(req.body.redirect || (req.session.isAdmin ? '/admin' : '/'));
  }

  recordLoginFail(ip);
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
  res.render('pages/register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.render('pages/register', { error: 'Semua field wajib diisi' });
  }

  if (confirmPassword && password !== confirmPassword) {
    return res.render('pages/register', { error: 'Konfirmasi password tidak cocok' });
  }

  if (username === 'admin') {
    return res.render('pages/register', { error: 'Username tidak diizinkan' });
  }

  const users = readDB('users.json');

  if (users.find(u => u.username === username)) {
    return res.render('pages/register', { error: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.redirect('/');
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
    username: ''
  });
});

app.post('/vpr-secure-panel-8x', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/admin-login', {
      error: `Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.`,
      lockedInfo: null, username: ''
    });
  }
  const { username, password, forceTakeover } = req.body;

  // ── FIX: readFresh() ambil langsung dari Supabase, bypass cache ──
  // Ini penting karena di Vercel tiap instance punya cache kosong
  const settings = await db.readFresh('settings.json');

  if (!settings || !settings.adminUsername) {
    return res.render('pages/admin-login', {
      error: 'Konfigurasi admin belum tersedia. Coba beberapa saat lagi.',
      lockedInfo: null, username: ''
    });
  }

  if (username === settings.adminUsername) {
    const match = await bcrypt.compare(password, settings.adminPassword);
    if (match) {
      // ── Single-Device Lock: cek apakah panel sedang dipakai device lain ──
      const lockEnabled = settings.adminLockEnabled !== false; // default: aktif
      const currentLock = lockEnabled ? await db.readFresh('admin-lock.json') : null;
      if (lockEnabled && isLockActive(currentLock) && forceTakeover !== '1') {
        const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(currentLock.lastSeen).getTime()) / 60000));
        return res.render('pages/admin-login', {
          error: null,
          username,
          lockedInfo: {
            device: currentLock.device || 'Perangkat tidak diketahui',
            minutesAgo
          }
        });
      }
      clearLoginFail(ip);
      req.session.userId = 'admin';
      req.session.isAdmin = true;
      req.session.adminSessionId = await acquireAdminLock(req);
      return res.redirect('/admin');
    }
  }
  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  res.render('pages/admin-login', {
    error: remaining > 0
      ? `Username atau password salah. Sisa percobaan: ${remaining}`
      : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.',
    lockedInfo: null, username: ''
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

app.post('/profile/photo', requireAuth, avatarUpload.single('photo'), async (req, res) => {
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
  const settings = await readFresh('settings.json');
  res.json((settings.banners || []).filter(b => b.active !== false));
});

app.post('/admin/banners/add', requireAdmin, bannerCarouselUpload.single('bannerImg'), async (req, res) => {
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
        } catch {
          // Fallback: simpan sebagai base64 data URL agar muncul tanpa storage eksternal
          const buf = require('fs').readFileSync(req.file.path);
          imgSrc = `data:${req.file.mimetype};base64,${buf.toString('base64')}`;
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

app.post('/admin/qris/upload', requireAdmin, qrisUpload.single('qrisImage'), async (req, res) => {
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

// ══════════════════════════════════════════════
// ── JUAL BELI AKUN ──
// Marketplace jual-beli akun game: user submit listing (status pending),
// admin approve/reject/tandai terjual, publik lihat listing yang approved.
// ══════════════════════════════════════════════
const accountImgUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/accounts' : path.join(__dirname, 'public', 'uploads', 'accounts');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `akun-${Date.now()}-${Math.round(Math.random()*1e5)}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024, files: 5 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

// Listing publik — hanya akun yang sudah di-approve admin & belum terjual
app.get('/jual-beli-akun', async (req, res) => {
  return res.redirect('/?category=akun#games');
});

app.get('/jual-beli-akun/:id', async (req, res) => {
  return res.redirect('/?category=akun#games');
});

// Form jual akun (harus login supaya ada kontak yang jelas & anti-spam)
app.get('/jual-beli-akun-jual', requireAuth, (req, res) => {
  res.render('pages/jual-akun-form', { pageTitle: 'Jual Akun Kamu' });
});

app.post('/jual-beli-akun-jual', requireAuth, accountImgUpload.array('images', 5), async (req, res) => {
  try {
    const { game, title, description, price, sellerWa } = req.body;
    if (!game || !title || !description || !price || !sellerWa) {
      return res.json({ success: false, message: 'Semua field wajib diisi' });
    }
    if (!/^(\+62|62|0)[0-9]{8,13}$/.test(sellerWa.trim())) {
      return res.json({ success: false, message: 'Format WhatsApp tidak valid' });
    }

    let images = [];
    if (req.files && req.files.length) {
      for (const file of req.files) {
        if (!isVercel) {
          images.push(`/uploads/accounts/${file.filename}`);
        } else {
          try {
            images.push(await db.uploadImage(require('fs').readFileSync(file.path), file.originalname, file.mimetype));
          } catch {
            const buf = require('fs').readFileSync(file.path);
            images.push(`data:${file.mimetype};base64,${buf.toString('base64')}`);
          }
        }
      }
    }
    if (!images.length) return res.json({ success: false, message: 'Minimal 1 foto akun wajib diupload' });

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
  const accounts = (await readSmart('accounts.json')).filter(a => a.userId === req.session.userId);
  accounts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.render('pages/akun-saya', { pageTitle: 'Listing Akun Saya', accounts });
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
    acc.rejectReason = req.body.reason || '';
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
app.get('/dashboard', requireAuth, async (req, res) => {
  // readFresh: histori pembelian & key harus data terbaru dari Supabase,
  // bukan cache basi instance lambda ini (lihat catatan di /check-payment).
  const transactions = await readFresh('transactions.json');
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

  res.render('pages/dashboard', {
    user, settings,
    stats: { totalOrders, successOrders, pendingOrders, totalSpent },
    doneTransactions: withDisplayTimeList(doneTransactions),
    transactions: withDisplayTimeList(recentTransactions)
  });
});

// Product routes
app.get('/buy/:id', requireAuth, (req, res) => {
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
  const genericKeys = allKeys.filter(k => !k.includes(':'));
  if (product.items) {
    product.items = product.items.map(item => {
      const m = (item.l || '').match(/(\d+)\s+DAYS/i);
      const days = m ? parseInt(m[1]) : null;
      let stok;
      if (days) {
        const tagged = allKeys.filter(k => {
          const parts = k.split(':');
          return parts.length > 1 && parseInt(parts[parts.length - 1]) === days;
        }).length;
        stok = tagged > 0 ? tagged : genericKeys.length;
      } else {
        stok = genericKeys.length;
      }
      return {
        ...item,
        stok,
        reseller_price: isReseller ? Math.round(item.p * (1 - resellerDiscount / 100)) : null
      };
    });
  }

  // Cek apakah user sudah pernah membeli (transaksi sukses) produk ini
  const transactions = readDB('transactions.json');
  const hasPurchased = transactions.some(t =>
    t.userId === user?.id &&
    t.productId === product.id &&
    t.status === 'done'
  );

  res.render('pages/buy', { product, settings, user, isReseller, hasPurchased });
});

app.post('/create-order', requireAuth, async (req, res) => {
  try {
    const { productId, duration, customerName, wa, voucherCode, gameUserId, gameNickname } = req.body;
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);

    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    if (!product.keys || product.keys.length === 0) return res.json({ success: false, message: 'Stok habis' });

    // Produk top up game (bukan kategori jual-beli akun) wajib isi ID Server/User ID & Nickname
    if (product.category !== 'akun') {
      if (!gameUserId || !gameUserId.trim()) return res.json({ success: false, message: 'ID Server / User ID wajib diisi' });
      if (!gameNickname || !gameNickname.trim()) return res.json({ success: false, message: 'Nickname wajib diisi' });
    }

    // Support pricingOptions (deem style: {days,price}) dan items (lama: {l,p})
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      // duration bisa berupa label teks ("PRODUK 30 DAYS") atau angka ("30")
      // Coba match by label dulu via items, lalu fallback ke ekstrak angka
      let opt = null;
      const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
      if (itemMatch) {
        // Cari pricingOptions yang cocok dengan price dari items
        opt = product.pricingOptions.find(o => o.price === itemMatch.p);
        if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
        else { price = opt.price; selectedDays = opt.days; }
      } else {
        // Fallback: parseInt langsung (untuk case duration dikirim sebagai angka)
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    const settings = readDB('settings.json');
    // Terapkan diskon reseller
    const orderUser = getSessionUser(req);
    if (orderUser?.is_reseller) {
      const disc = settings.resellerDiscount || 20;
      price = Math.round(price * (1 - disc / 100));
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
    const orderId = `VR-${Date.now()}`;
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
      duration, selectedDays,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment,
      customerName, wa, qrString, isStatic,
      gameUserId: gameUserId ? gameUserId.trim() : undefined,
      gameNickname: gameNickname ? gameNickname.trim() : undefined,
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

app.get('/check-payment/:refId', requireAuth, async (req, res) => {
  const refId = req.params.refId;
  // Cegah race condition: jika transaksi sedang diproses, kembalikan pending
  if (processingOrders.has(refId)) {
    return res.json({ success: true, status: 'pending' });
  }
  processingOrders.add(refId);
  try {
    // PENTING: pakai readFresh (bukan readDB) di sini. readDB cuma baca cache
    // in-memory instance lambda ini sendiri — di Vercel, tiap instance punya
    // cache terpisah. Kalau order dibuat di instance A lalu dicek dari instance
    // B, instance B bisa saja belum tahu transaksi itu ada / masih lihat stok
    // key yang belum berkurang, akibatnya key tidak pernah dikirim ke user
    // meskipun pembayaran sudah sukses. readFresh selalu ambil data terbaru
    // langsung dari Supabase supaya konsisten di semua instance.
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === refId);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });

    // SECURITY: cegah IDOR — pastikan transaksi ini benar milik user yang login
    // (sebelumnya siapa saja yang login bisa lihat key orang lain kalau tahu/tebak refId-nya)
    if (transaction.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).json({ success: false, message: 'Tidak diizinkan mengakses transaksi ini' });
    }

    if (transaction.status === 'done') {
      if (transaction.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      return res.json({ success: true, status: 'done', key: transaction.key, code: transaction.code });
    }

    // Static QRIS: tunggu konfirmasi manual admin
    if (transaction.isStatic) return res.json({ success: true, status: 'pending_static' });

    const settings = await readFresh('settings.json');
    let paid = false;
    try {
      const r = await checkPaymentStatus(transaction.orderId, transaction.totalPayment || transaction.price, settings);
      // Normalize status dari berbagai format response PakKasir
      const status = (r.transaction?.status || r.status || r.data?.status || '').toLowerCase();
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(status) || r.success === true;
      if (['expired','canceled','cancelled'].includes(status)) {
        transaction.status = 'expired';
        await writeDB('transactions.json', transactions);
        return res.json({ success: true, status: 'expired' });
      }
    } catch(e) { /* API error, keep pending */ }

    if (paid) {
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
        await writeDB('transactions.json', transactions);
        return res.json({ success: true, status: 'done', type: 'reseller' });
      }

      // Re-ambil transaksi paling fresh sekali lagi tepat sebelum alokasi key —
      // mengecilkan window race kalau ada 2 polling nyaris bersamaan dari 2 instance.
      const transactionsRecheck = await readFresh('transactions.json');
      const freshTx = transactionsRecheck.find(t => t.id === refId) || transaction;
      if (freshTx.status === 'done') {
        if (freshTx.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
        return res.json({ success: true, status: 'done', key: freshTx.key, code: freshTx.code });
      }

      const products = await readFresh('products.json');
      const product = products.find(p => p.id === freshTx.productId);
      let key = null;
      let outOfStock = false;

      if (product?.keys?.length > 0) {
        const days = freshTx.selectedDays;
        // Cari key duration-specific dulu (format KEY:DAYS dari deem)
        if (days) {
          const idx = product.keys.findIndex(k => {
            const parts = k.split(':');
            return parts.length > 1 && parseInt(parts[parts.length - 1]) === days;
          });
          if (idx !== -1) { key = product.keys.splice(idx, 1)[0].split(':')[0]; }
        }
        // Fallback: ambil generic key (tanpa colon) — key yang di-tag durasi lain (mis. :3, :7)
        // TIDAK BOLEH dipakai untuk durasi yang beda, biar gak ketuker (misal 1D kebagian key jatah 3D).
        if (!key) {
          const idx = product.keys.findIndex(k => !k.includes(':'));
          if (idx !== -1) key = product.keys.splice(idx, 1)[0];
          // kalau gak ada yang cocok & gak ada generic key, biarkan key = null -> outOfStock
        }
      }

      if (key) {
        product.sold = (product.sold || 0) + 1;
        await writeDB('products.json', products);
      } else {
        // Stok habis — jangan kirim key palsu. Tandai transaksi & beri tahu admin via WA.
        outOfStock = true;
      }

      freshTx.status = 'done';
      freshTx.key = key;
      freshTx.outOfStock = outOfStock;
      freshTx.paidAt = new Date().toISOString();
      const idx2 = transactionsRecheck.findIndex(t => t.id === refId);
      if (idx2 !== -1) transactionsRecheck[idx2] = freshTx;
      await writeDB('transactions.json', transactionsRecheck);

      if (outOfStock) {
        const waMsg = `⚠️ STOK HABIS - Pesanan butuh diproses manual!\n\n` +
          `Order: ${freshTx.code}\n` +
          `Produk: ${freshTx.productName}\n` +
          `Customer: ${freshTx.customerName} (${freshTx.wa || '-'})\n` +
          `Total: Rp ${Number(freshTx.price).toLocaleString('id-ID')}\n\n` +
          `Pembayaran sudah masuk tapi stok key kosong. Segera tambah stok & kirim key manual ke pembeli.`;
        sendWhatsAppNotif(settings.contact?.whatsapp, waMsg, settings).catch(() => {});
      }

      const notifs = await readFresh('notifications.json');
      const buyer = (await readFresh('users.json')).find(u => u.id === freshTx.userId);
      notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: freshTx.customerName,
        buyerPhoto: buyer?.photo || null, productName: freshTx.productName,
        price: freshTx.price, time: freshTx.paidAt, timeStr: formatDate(new Date(freshTx.paidAt)) });
      await writeDB('notifications.json', notifs.slice(0, 50));

      return res.json({ success: true, status: 'done', key, code: freshTx.code, outOfStock });
    }

    res.json({ success: true, status: transaction.status });
  } catch (error) {
    console.error('[check-payment] error:', error.message);
    res.json({ success: false, message: error.message });
  } finally {
    processingOrders.delete(refId);
  }
});

app.get('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.query;
  if (code) {
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.code === code.toUpperCase());
    return res.render('pages/invoice', { transaction: transaction ? withDisplayTime(transaction) : null, error: transaction ? null : 'Pesanan tidak ditemukan' });
  }
  res.render('pages/invoice', { transaction: null, error: null });
});

app.post('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.body;
  const transactions = await readFresh('transactions.json');
  const transaction = transactions.find(t => t.code === code.toUpperCase());

  if (!transaction) {
    return res.render('pages/invoice', { transaction: null, error: 'Pesanan tidak ditemukan' });
  }

  res.render('pages/invoice', { transaction: withDisplayTime(transaction), error: null });
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

  const stats = {
    totalProducts: products.length,
    activeProducts: products.filter(p => p.status === 'active').length,
    totalTransactions: transactions.length,
    pendingTransactions: transactions.filter(t => t.status === 'pending').length,
    doneTransactions: transactions.filter(t => t.status === 'done').length,
    totalUsers: users.length,
    totalResellers: users.filter(u => u.is_reseller).length,
    totalRevenue: transactions.filter(t => t.status === 'done').reduce((sum, t) => sum + t.price, 0)
  };

  // Data chart: 7 hari terakhir — dikelompokkan berdasarkan kalender WIB
  // (bukan UTC), supaya transaksi jam 00:00-06:59 WIB tidak salah masuk
  // ke hari sebelumnya. Indonesia tidak pakai DST jadi aman kurangi per
  // 24 jam pasti.
  const chartData = [];
  const nowMs = Date.now();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(nowMs - i * 86400000);
    const dateStr = jakartaDateKey(d);
    const dayTrx = transactions.filter(t => t.status === 'done' && t.createdAt && jakartaDateKey(t.createdAt) === dateStr);
    chartData.push({
      date: jakartaDayLabel(d),
      count: dayTrx.length,
      revenue: dayTrx.reduce((s, t) => s + t.price, 0)
    });
  }

  res.render('pages/admin', {
    layout: false,
    products,
    transactions: withDisplayTimeList(transactions.slice(-20).reverse()),
    users,
    settings,
    stats,
    chartData,
    accounts: accounts.slice().reverse()
  });
});

// Helper: parse pricingOptions
function parsePricingOptions(days, prices) {
  const da = Array.isArray(days)?days:(days?[days]:[]);
  const pa = Array.isArray(prices)?prices:(prices?[prices]:[]);
  const opts=[];const seen=new Set();
  for(let i=0;i<da.length;i++){const d=parseInt(da[i]),p=parseInt(pa[i]);if(d>0&&p>=0&&!seen.has(d)){seen.add(d);opts.push({days:d,price:p});}}
  return opts.sort((a,b)=>a.days-b.days);
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
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,imageUrl:imgUrl,pricingDays,pricingPrices,keys,status}=req.body;
    if(!name)return res.json({success:false,message:'Nama produk wajib diisi'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    const products=await readFresh('products.json');
    const pricingOptions=parsePricingOptions(pricingDays,pricingPrices);
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
    const items=pricingOptions.map(o=>({l:`${name.toUpperCase()} ${o.days} DAYS`,p:o.price}));
    const newProduct={id:uuidv4(),name,category:category||'freefire',description:description||'',image,pricingOptions,items,status:status==='inactive'?'inactive':'active',keys:keyArray,sold:0,createdAt:new Date().toISOString()};
    products.push(newProduct);await writeDB('products.json',products);
    res.json({success:true,product:newProduct});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/edit/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,imageUrl:imgUrl,pricingDays,pricingPrices,keys,keysMode,status}=req.body;
    const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(name)product.name=name;if(category)product.category=category;
    if(description!==undefined)product.description=description;if(status)product.status=status;
    if(pricingDays){const opts=parsePricingOptions(pricingDays,pricingPrices);if(opts.length){product.pricingOptions=opts;product.items=opts.map(o=>({l:`${product.name.toUpperCase()} ${o.days} DAYS`,p:o.price}));}}
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
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, email, adminUsername, categories, categoryLabels, logoUrl, fonnteToken } = req.body;

    if (siteName)      settings.siteName      = siteName;
    if (gamePanelName) settings.gamePanelName = gamePanelName;
    if (about !== undefined) settings.about   = about;
    if (marqueeText)   settings.marqueeText   = marqueeText;
    if (adminUsername) settings.adminUsername = adminUsername;
    if (logoUrl !== undefined) settings.logoUrl = logoUrl;
    if (fonnteToken !== undefined) settings.fonnteToken = fonnteToken;

    settings.contact = settings.contact || {};
    if (whatsapp !== undefined) settings.contact.whatsapp = whatsapp;
    if (telegram !== undefined) settings.contact.telegram = telegram;
    if (email    !== undefined) settings.contact.email    = email;

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

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/qris/test', requireAdmin, async (req, res) => {
  try {
    const { apiKey, project, apiBaseUrl } = req.body;
    const hostname = apiBaseUrl || 'api.pakasir.com';
    const testSettings = { pakasir: { apiKey, project, apiBaseUrl: hostname } };
    try {
      await createQRISPayment('test-' + Date.now(), 1000, testSettings);
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

app.post('/admin/settings/admin-lock', requireAdmin, async (req, res) => {
  try {
    const { adminLockEnabled } = req.body;
    const settings = await readFresh('settings.json');
    settings.adminLockEnabled = adminLockEnabled === 'true' || adminLockEnabled === true;
    await writeDB('settings.json', settings);
    res.json({ success: true, adminLockEnabled: settings.adminLockEnabled });
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

// Konfirmasi transaksi manual oleh admin (untuk QRIS statis atau reseller)
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

    // Transaksi produk biasa: ambil key
    const products = readDB('products.json');
    const product = products.find(p => p.id === transaction.productId);
    let key = null;
    if (product?.keys?.length > 0) {
      const days = transaction.selectedDays;
      if (days) {
        const idx = product.keys.findIndex(k => {
          const parts = k.split(':');
          return parts.length > 1 && parseInt(parts[parts.length - 1]) === days;
        });
        if (idx !== -1) { key = product.keys.splice(idx, 1)[0].split(':')[0]; }
      }
      if (!key) {
        const idx = product.keys.findIndex(k => !k.includes(':'));
        if (idx !== -1) key = product.keys.splice(idx, 1)[0];
        else key = product.keys.shift();
      }
      product.sold = (product.sold || 0) + 1;
      await writeDB('products.json', products);
    }

    transaction.status = 'done';
    transaction.key = key;
    transaction.paidAt = new Date().toISOString();
    transaction.confirmedBy = 'admin';
    await writeDB('transactions.json', transactions);

    res.json({ success: true, key });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Leaderboard route
app.get('/leaderboard', (req, res) => {
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const settings = readDB('settings.json');

  // Calculate leaderboard
  const userStats = {};

  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) {
        userStats[t.userId] = {
          userId: t.userId,
          totalTransactions: 0,
          totalSpent: 0
        };
      }
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });

  // Convert to array and add user info
  const leaderboard = Object.values(userStats).map(stat => {
    const user = users.find(u => u.id === stat.userId);
    return {
      ...stat,
      username: user?.username || 'Unknown',
      photo: user?.photo || null
    };
  });

  // Sort by total transactions descending
  leaderboard.sort((a, b) => b.totalTransactions - a.totalTransactions);

  // Add rank
  leaderboard.forEach((item, index) => {
    item.rank = index + 1;
  });

  const user = getSessionUser(req);

  res.render('pages/leaderboard', {
    leaderboard,
    settings,
    user
  });
});

// API endpoints
app.get('/api/products', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  const products = (await readFresh('products.json'))
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
  res.json(withDisplayTimeList(transactions));
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
  filtered = filtered.map(t => {
    const u = users.find(u => u.username === t.username);
    return { ...t, photo: u?.photo || null };
  });

  // Data 100% real dari database — tidak ada lagi padding testimoni palsu.
  const maxDisplay = 30;
  res.json(filtered.slice(0, maxDisplay));
});

app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
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

    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    const testimonials = readDB('testimonials.json');

    testimonials.unshift({
      id: uuidv4(),
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
    const { name, username, rating, text, product, verified, featured } = req.body;
    const testimonials = await readFresh('testimonials.json');

    const newTestimonial = {
      id: `testi-${Date.now()}`,
      name,
      username: username || null,
      rating: parseInt(rating) || 5,
      text,
      product: product || null,
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

app.get('/api/notifications', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  // readSmart: ambil langsung dari Supabase kalau cache instance ini sudah >8 detik,
  // supaya notifikasi selalu data transaksi asli & konsisten di semua instance Vercel,
  // bukan cache basi milik satu lambda instance saja.
  const all = await readSmart('notifications.json');
  const notifs = all.slice(0, 20);
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

app.get('/api/leaderboard', (req, res) => {
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');

  // Calculate real leaderboard
  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });

  const realEntries = Object.values(userStats).map(stat => {
    const user = users.find(u => u.id === stat.userId);
    return { username: user?.username || 'User', totalTransactions: stat.totalTransactions, totalSpent: stat.totalSpent, isReal: true };
  });

  realEntries.sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent);
  realEntries.forEach((item, i) => { item.rank = i + 1; });

  res.json({ success: true, data: realEntries.slice(0, 10) });
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
    const { items, bannerUrl, status, keys, keysMode, platforms } = req.body;
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
    if (Array.isArray(platforms)) p.platforms = platforms;

    // Kelola harga / pricing options
    const { pricingOptions } = req.body;
    if (Array.isArray(pricingOptions) && pricingOptions.length > 0) {
      const validOpts = pricingOptions
        .map(o => ({ days: parseInt(o.days), price: parseInt(o.price) }))
        .filter(o => o.days > 0 && o.price >= 0);
      if (validOpts.length > 0) {
        p.pricingOptions = validOpts;
        p.items = validOpts.map(o => ({ l: `${(p.name||'PRODUK').toUpperCase()} ${o.days} DAYS`, p: o.price }));
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
app.post('/admin/upload-banner', requireAdmin, multer({ storage: multer.memoryStorage() }).single('banner'), async (req, res) => {
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

    const prevTheme = settings.theme || {};
    settings.theme = {
      primaryColor: primaryColor || prevTheme.primaryColor || '#13D8FF',
      secondaryColor: secondaryColor || prevTheme.secondaryColor || '#4CF5FF',
      accentColor: accentColor || prevTheme.accentColor || '#78FFFF',
      backgroundColor: backgroundColor || prevTheme.backgroundColor || '#05070B',
      cardBackground: cardBackground || prevTheme.cardBackground || '#0A1118',
      borderColor: borderColor || prevTheme.borderColor || 'rgba(45,238,255,.15)',
      glowColor: glowColor || prevTheme.glowColor || 'rgba(45,238,255, 0.1)'
    };

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
  const code = (req.body.code || '').trim().toUpperCase();

  // SECURITY: cegah brute-force nebak kode key (sebelumnya tidak ada limit sama sekali)
  const blockCheck = checkActivateKeyBlocked(req.ip);
  if (blockCheck.blocked) {
    return res.render('pages/activate-key', {
      user, settings, result: null, code: '',
      error: `Terlalu banyak percobaan gagal. Coba lagi dalam ${blockCheck.wait} menit.`
    });
  }

  if (!code) return res.render('pages/activate-key', { user, settings, result: null, error: 'Masukkan kode key terlebih dahulu', code: '' });

  const keyspool = readDB('keyspool.json');
  const key = keyspool.find(k => k.code.toUpperCase() === code);

  if (!key) {
    recordActivateKeyFail(req.ip);
    return res.render('pages/activate-key', { user, settings, result: null, error: 'Key tidak ditemukan atau tidak valid', code });
  }
  if (key.used) {
    recordActivateKeyFail(req.ip);
    return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sudah pernah digunakan', code });
  }

  key.used = true;
  key.usedBy = user.id;
  key.usedByUsername = user.username;
  key.usedAt = new Date().toISOString();
  await writeDB('keyspool.json', keyspool);

  res.render('pages/activate-key', {
    user, settings, code,
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
    const { code, type, value, minPurchase, maxUses, perUserLimit, expiresAt, description } = req.body;
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
