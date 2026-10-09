'use strict';
// Satu function untuk semua /api/<nama>: instance tetap hangat, jumlah function minimal (irit kuota Vercel gratis).
const ROUTES = { status: 'GET', me: 'GET', login: 'POST', page: 'POST', fill: 'POST', analyze: 'POST', chat: 'POST', gemini: 'POST', admin: 'POST' };

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const name = String((req.query && req.query.name) || '');
  if (!Object.prototype.hasOwnProperty.call(ROUTES, name)) return res.status(404).json({ error: 'Tidak ditemukan.' });
  const method = ROUTES[name];
  if (req.method !== method) return res.status(405).json({ error: 'Metode tidak diizinkan.' });
  try {
    let body = {};
    if (method === 'POST') {
      if (Number(req.headers['content-length'] || 0) > 200000) return res.status(413).json({ error: 'Permintaan terlalu besar.' });
      try { const b = req.body; if (b && typeof b === 'object') body = b; } catch (e) { return res.status(400).json({ error: 'Isi permintaan bukan JSON yang valid.' }); }
    }
    // Dimuat di sini (bukan di atas file) supaya kegagalan memuat tampil sebagai JSON 500 dengan alasannya, bukan error kosong.
    const api = require('../lib/api');
    const r = await api[name](body, { auth: req.headers.authorization || '' });
    return res.status(r.status).json(r.body);
  } catch (e) {
    console.error('[orbit] function gagal:', e && e.stack || e);
    return res.status(500).json({ error: 'Server gagal: ' + String((e && e.message) || e).split('\n')[0].slice(0, 200) });
  }
};
