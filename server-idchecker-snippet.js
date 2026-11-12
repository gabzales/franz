// ══════════════════════════════════════════════════════════════════════
// CEK ID GAME — tempel di server.js, TEPAT SEBELUM `app.get('/invoice', ...`
// (butuh: rateLimit, readDB, getSessionUser, verifyTurnstile — semuanya
// sudah ada di server.js).
//
// UI sudah jadi (views/pages/idchecker.ejs). Yang BELUM ada: sumber data
// nickname. haybi.js hanya punya saldo/produk/harga/transaksi/status —
// tidak ada endpoint cek nickname. Isi fungsi lookupGameNickname() dengan
// provider yang kamu pakai (mis. dari docs Haybi kalau ada endpoint cek
// akun, atau provider lain). Selama belum diisi, tombol cek menampilkan
// pesan "belum aktif" dan TIDAK mengarang hasil.
// ══════════════════════════════════════════════════════════════════════
const idCheckLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10, // 10 cek/menit/IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Terlalu banyak pengecekan. Coba lagi sebentar.' },
});

// TODO: sambungkan ke provider. Harus mengembalikan string nickname,
// atau melempar Error dengan pesan yang aman ditampilkan ke pengguna
// (mis. 'ID tidak ditemukan').
async function lookupGameNickname(settings, { gameUserId, gameZoneId }) {
  const err = new Error('Fitur cek ID belum diaktifkan.');
  err.code = 'NOT_CONFIGURED';
  throw err;
}

app.get('/idchecker', (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/idchecker', {
    settings, user,
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    game: { name: 'Mobile Legend', needsZone: true, userLabel: 'User ID', zoneLabel: 'Zone ID' },
  });
});

app.post('/api/idchecker', idCheckLimiter, async (req, res) => {
  const { gameUserId, gameZoneId } = req.body || {};
  if (!/^\d{4,20}$/.test(String(gameUserId || ''))) {
    return res.status(400).json({ success: false, message: 'User ID tidak valid.' });
  }
  if (!/^\d{1,10}$/.test(String(gameZoneId || ''))) {
    return res.status(400).json({ success: false, message: 'Zone ID tidak valid.' });
  }
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token || !(await verifyTurnstile(token))) {
      return res.status(400).json({ success: false, message: 'Verifikasi keamanan gagal. Coba lagi.' });
    }
  }
  try {
    const settings = res.locals.settings || readDB('settings.json');
    const nickname = await lookupGameNickname(settings, { gameUserId: String(gameUserId), gameZoneId: String(gameZoneId) });
    return res.json({ success: true, nickname });
  } catch (e) {
    const notConfigured = e.code === 'NOT_CONFIGURED';
    return res.status(notConfigured ? 501 : 200).json({ success: false, message: e.message || 'Gagal mengecek ID.' });
  }
});
