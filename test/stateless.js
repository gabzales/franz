'use strict';
// Mode produksi: tanpa database. Admin hanya dari env; sesi, Gemini, dan model juga dari env.
const assert = require('assert');
delete process.env.ORBIT_MEMORY_DB;
process.env.SESSION_SECRET = 'rahasia-sesi-yang-panjang-sekali-0123456789';
process.env.ADMIN_USERNAME = 'Admin-Uji!'; process.env.ADMIN_PASSWORD = 'pw-dari-env';
const api = require('../lib/api');
const { resetMemory } = require('../lib/db');
const H = require('../api/[name].js');
const call = async (name, method, body, tok) => {
  const res = { code: 200, setHeader() {}, status(c) { res.code = c; return res; }, json(b) { res.body = b; return res; } };
  await H({ method, query: { name }, headers: tok ? { authorization: 'Bearer ' + tok } : {}, body }, res); return res;
};
(async () => {
  let r = await call('status', 'GET');
  assert.deepStrictEqual(r.body, { configured: true, adminReady: true, panel: false });
  r = await call('login', 'POST', { username: ' admin-uji! ', password: 'pw-dari-env' });
  assert.strictEqual(r.code, 200); assert.strictEqual(r.body.role, 'admin');
  const tok = r.body.token;
  assert.strictEqual((await call('me', 'GET', null, tok)).code, 200);
  resetMemory(); // simulasi instance baru / cold start: tidak ada data apa pun di memori
  assert.strictEqual((await call('me', 'GET', null, tok)).code, 200, 'sesi tetap sah tanpa penyimpanan');
  assert.strictEqual((await call('page', 'POST', { url: 'http://127.0.0.1/' }, tok)).code, 400, 'fitur halaman jalan tanpa database (alamat internal ditolak)');
  assert.strictEqual((await call('admin', 'POST', { action: 'list' }, tok)).code, 501, 'panel admin nonaktif');
  assert.strictEqual((await call('login', 'POST', { username: 'orang-lain', password: 'pw-dari-env' })).code, 401);
  assert.strictEqual((await call('me', 'GET', null, 'bukan.token')).code, 401);
  // Gemini dari env: tanpa key -> pesan jelas; dengan key -> lolos ke tahap berikutnya
  assert.strictEqual((await call('fill', 'POST', { url: 'https://docs.google.com/forms/d/e/x/viewform' }, tok)).code, 503);
  process.env.GEMINI_API_KEY = 'AIza-contoh-kunci-yang-cukup-panjang-123';
  process.env.GEMINI_MODEL = 'model-uji-1'; process.env.GEMINI_FALLBACK_MODEL = 'model-uji-2';
  const seen = []; const realFetch = global.fetch;
  global.fetch = async (u, o) => { seen.push(String(u)); return { ok: false, status: 400, text: async () => '{}', json: async () => ({}), headers: new Map() }; };
  await call('gemini', 'POST', { questions: [{ id: 'q1', title: 'Nama?', type: 'text' }] }, tok);
  global.fetch = realFetch;
  assert.ok(seen.some(u => u.includes('model-uji-1')), 'memakai GEMINI_MODEL: ' + seen.join(' | '));
  // lockout best effort: 5 salah mengunci (dalam instance yang sama)
  for (let i = 0; i < 5; i++) assert.strictEqual((await call('login', 'POST', { username: 'admin-uji!', password: 'salah' + i })).code, 401);
  assert.strictEqual((await call('login', 'POST', { username: 'admin-uji!', password: 'pw-dari-env' })).code, 429);
  // ganti password di env -> sesi lama hangus
  resetMemory(); process.env.ADMIN_PASSWORD = 'pw-baru-env';
  assert.strictEqual((await call('me', 'GET', null, tok)).code, 401, 'ganti password mencabut sesi lama');
  assert.strictEqual((await call('login', 'POST', { username: 'admin-uji!', password: 'pw-baru-env' })).code, 200);
  // tanpa env admin: tidak ada yang bisa masuk
  delete process.env.ADMIN_USERNAME; resetMemory();
  assert.strictEqual((await call('me', 'GET', null, tok)).code, 401);
  assert.strictEqual((await call('status', 'GET')).body.adminReady, false);
  console.log('TES TANPA DATABASE LULUS');
})().catch(e => { console.error(e); process.exit(1); });
