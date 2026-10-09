'use strict';
process.env.ORBIT_MEMORY_DB = '1';
const assert = require('assert');
const { parseForm, buildPlans, prefillUrl, fetchForm } = require('../lib/form');
const { answer } = require('../lib/gemini');
const api = require('../lib/api');
const { store, resetMemory } = require('../lib/db');

// Fixture buatan sendiri (struktur FB_PUBLIC_LOAD_DATA_ dari ingatan, BELUM dicocokkan dengan Google Forms asli).
const data = [null, ['desc', [
  [111, 'Nama kamu', null, 0, [[1001, null, 1]]],
  [112, 'OS yang dipakai?', null, 2, [[1002, [['Android'], ['iPhone'], ['', null, null, null, 1]], 1]]],
  [113, 'Fitur favorit', null, 4, [[1003, [['A'], ['B'], ['C']], 0]]],
  [114, 'Skala', null, 5, [[1004, [['1'], ['2'], ['3'], ['4'], ['5']], 1]]],
  [115, 'Judul bagian', null, 8]
]], 'title'];
const HTML = '<html><script nonce="x">var FB_PUBLIC_LOAD_DATA_ = ' + JSON.stringify(data) + ';</script></html>';
const FORM = 'https://docs.google.com/forms/d/e/ABC/viewform';
const bearer = t => ({ auth: 'Bearer ' + t });
const gem = text => ({ ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text }] } }] }) });
const realFetch = global.fetch;

(async () => {
  // ---------- parser & Gemini (tetap) ----------
  const qs = parseForm(HTML);
  assert.strictEqual(qs.length, 4); assert.deepStrictEqual(qs[1].options, ['Android', 'iPhone']);
  const plans = buildPlans(qs, [{ id: 'q1', text: 'Budi', choices: [] }, { id: 'q2', choices: [0] }, { id: 'q3', choices: [0, 2, 9] }]);
  assert.strictEqual(prefillUrl(FORM + '?usp=send_form', plans), FORM + '?usp=pp_url&entry.1001=Budi&entry.1002=Android&entry.1003=A&entry.1003=C');
  await assert.rejects(fetchForm('https://evil.example.com/x'), /hanya mendukung Google Forms/);
  let n = 0;
  global.fetch = async () => (++n < 3 ? { ok: false, status: 503 } : gem('{"answers":[{"id":"q1","text":"x"}]}'));
  assert.strictEqual((await answer({ key: 'k', models: ['m-one'], questions: [], delays: [5, 5] })).length, 1);

  // ---------- konfigurasi & admin dari env ----------
  let r = await api.status(); assert.strictEqual(r.body.configured, false, 'tanpa SESSION_SECRET: belum dikonfigurasi');
  assert.strictEqual((await api.login({ username: 'boss', password: 'x' })).status, 500);
  process.env.SESSION_SECRET = 'rahasia-sesi-yang-panjang-sekali-0123456789';
  assert.deepStrictEqual((await api.status()).body, { configured: true, adminReady: false, panel: true });
  assert.strictEqual((await api.login({ username: 'boss', password: 'rahasia-admin' })).status, 401, 'tanpa env admin tidak ada yang bisa masuk');
  process.env.ADMIN_USERNAME = 'Boss'; process.env.ADMIN_PASSWORD = 'rahasia-admin';
  assert.deepStrictEqual((await api.status()).body, { configured: true, adminReady: true, panel: true });
  assert.strictEqual(typeof api.setup, 'undefined', 'tidak ada endpoint setup');
  r = await api.login({ username: 'Boss', password: 'rahasia-admin' });
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.role, 'admin'); assert.strictEqual(r.body.username, 'boss');
  const A = r.body.token;
  assert.strictEqual((await api.login({ username: 'hacker', password: 'password123' })).status, 401);

  // ---------- login admin ----------
  r = await api.login({ username: 'boss', password: 'salah' }); assert.strictEqual(r.status, 401);
  r = await api.login({ username: 'BOSS', password: 'rahasia-admin' }); assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body.role, 'admin');
  assert.strictEqual((await api.me({}, bearer(A))).body.role, 'admin');

  // ---------- admin membuat pengguna ----------
  const adm = async (b, t = A) => api.admin(b, bearer(t));
  assert.strictEqual((await adm({ action: 'createUser', username: 'ab', password: 'password123' })).status, 400);
  assert.strictEqual((await adm({ action: 'createUser', username: 'budi', password: 'pendek' })).status, 400);
  assert.strictEqual((await adm({ action: 'createUser', username: 'boss', password: 'password123' })).status, 409, 'username admin sudah dipakai');
  r = await adm({ action: 'createUser', username: 'Budi', password: 'password123', quota: 2 }); assert.strictEqual(r.status, 200);
  assert.strictEqual((await adm({ action: 'createUser', username: 'budi', password: 'password123' })).status, 409);
  assert.ok(!JSON.stringify(r.body).includes('scrypt'), 'hash tidak boleh bocor ke admin');

  // ---------- login pengguna & pemalsuan token ----------
  r = await api.login({ username: 'BUDI', password: 'password123' }); assert.strictEqual(r.status, 200);
  const U = r.body.token; assert.strictEqual(r.body.role, 'user');
  assert.strictEqual((await api.me({}, bearer(U))).status, 200);
  const [p, m] = U.split('.');
  const forged = Buffer.from(JSON.stringify({ u: 'boss', tv: 1, exp: 9999999999 })).toString('base64url') + '.' + m;
  assert.strictEqual((await api.admin({ action: 'list' }, bearer(forged))).status, 401, 'token dipalsukan harus ditolak');
  assert.strictEqual((await adm({ action: 'list' }, U)).status, 403, 'user biasa tidak boleh admin');
  assert.strictEqual((await api.me({}, { auth: '' })).status, 401);
  assert.strictEqual((await api.fill({ url: FORM }, { auth: '' })).status, 401);

  // ---------- belum ada API key ----------
  assert.strictEqual((await api.gemini({ questions: [{ id: 'q1', title: 'T', type: 'text' }] }, bearer(U))).status, 503);
  r = await adm({ action: 'setSettings', geminiKey: 'AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456', model: 'model-test', fallback: '', defaultQuota: 50 });
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.settings.hasKey, true); assert.strictEqual(r.body.settings.keyLast4, '3456');
  assert.ok(!JSON.stringify(r.body).includes('AIzaSy'), 'key tidak boleh dikirim balik utuh');
  const raw = await (await store()).get('settings'); assert.ok(!JSON.stringify(raw).includes('AIzaSy'), 'key harus terenkripsi di penyimpanan');
  assert.strictEqual((await adm({ action: 'setSettings', model: 'bad model!' })).status, 400);

  // ---------- panggilan AI + kuota (budi: kuota 2) ----------
  let calls = 0, lastKey = '';
  global.fetch = async (u, o) => { calls++; lastKey = o.headers['x-goog-api-key']; return gem('{"answers":[{"id":"q1","text":"Budi"}]}'); };
  const ask = () => api.gemini({ profile: 'p', questions: [{ id: 'q1', title: 'Nama', type: 'text', options: [], evil: 'x' }] }, bearer(U));
  r = await ask(); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.answers[0].text, 'Budi');
  assert.strictEqual(lastKey, 'AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456', 'server memakai key admin');
  assert.strictEqual((await ask()).status, 200);
  r = await ask(); assert.strictEqual(r.status, 429); assert.strictEqual(calls, 2, 'kuota habis tidak boleh memanggil Gemini');
  assert.strictEqual((await api.gemini({ questions: 'bukan array' }, bearer(A))).status, 400);
  assert.strictEqual((await api.gemini({ questions: [{ id: 'q1', title: 'x', type: 'aneh' }] }, bearer(A))).status, 400);

  // kuota dikembalikan jika Gemini gagal (error non-sementara)
  await adm({ action: 'createUser', username: 'sari', password: 'password123', quota: 1 });
  const S = (await api.login({ username: 'sari', password: 'password123' })).body.token;
  global.fetch = async () => ({ ok: false, status: 403 });
  const askS = () => api.gemini({ questions: [{ id: 'q1', title: 'Nama', type: 'text' }] }, bearer(S));
  assert.strictEqual((await askS()).status, 502);
  global.fetch = async () => gem('{"answers":[]}');
  assert.strictEqual((await askS()).status, 200, 'kuota harus dikembalikan setelah gagal');

  // ---------- /api/fill (web) lewat server ----------
  global.fetch = async (u) => String(u).includes('generativelanguage')
    ? gem('{"answers":[{"id":"q1","text":"Budi"},{"id":"q2","choices":[0]}]}')
    : { ok: true, status: 200, headers: { get: () => null }, text: async () => HTML };
  r = await api.fill({ url: FORM }, bearer(A)); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.filled, 2);
  assert.ok(r.body.prefill.includes('entry.1001=Budi'));
  assert.strictEqual((await api.fill({ url: 'https://evil.com' }, bearer(A))).status, 400);

  // ---------- nonaktifkan, aktifkan, reset, hapus ----------
  await adm({ action: 'setActive', username: 'budi', active: false });
  assert.strictEqual((await api.me({}, bearer(U))).status, 403, 'akun nonaktif ditolak');
  assert.strictEqual((await api.login({ username: 'budi', password: 'password123' })).status, 403);
  await adm({ action: 'setActive', username: 'budi', active: true });
  assert.strictEqual((await api.me({}, bearer(U))).status, 401, 'token lama harus hangus');
  const U2 = (await api.login({ username: 'budi', password: 'password123' })).body.token;
  await adm({ action: 'resetPassword', username: 'budi', password: 'passwordBaru1' });
  assert.strictEqual((await api.me({}, bearer(U2))).status, 401, 'reset password mencabut sesi');
  assert.strictEqual((await api.login({ username: 'budi', password: 'password123' })).status, 401);
  assert.strictEqual((await api.login({ username: 'budi', password: 'passwordBaru1' })).status, 200);
  r = await adm({ action: 'deleteUser', username: 'sari' });
  assert.deepStrictEqual(r.body.users.map(u => u.username), ['boss', 'budi']);
  assert.strictEqual((await api.login({ username: 'sari', password: 'password123' })).status, 401);
  assert.strictEqual((await adm({ action: 'hapusSemua' })).status, 400);

  // ---------- perlindungan admin ----------
  assert.strictEqual((await adm({ action: 'setActive', username: 'boss', active: false })).status, 400, 'tidak boleh menonaktifkan diri sendiri');
  assert.strictEqual((await adm({ action: 'deleteUser', username: 'boss' })).status, 400, 'tidak boleh menghapus diri sendiri');
  r = await adm({ action: 'createUser', username: 'ani', password: 'password123', role: 'admin' }); assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.body.users.filter(u => u.role === 'admin').map(u => u.username), ['ani', 'boss']);
  const AN = (await api.login({ username: 'ani', password: 'password123' })).body.token;
  assert.strictEqual((await api.admin({ action: 'list' }, bearer(AN))).status, 200, 'admin kedua bisa mengelola');
  assert.strictEqual((await api.admin({ action: 'setActive', username: 'boss', active: false }, bearer(AN))).status, 200);
  assert.strictEqual((await api.admin({ action: 'setActive', username: 'ani', active: false }, bearer(AN))).status, 400, 'admin aktif terakhir tidak boleh dinonaktifkan');
  assert.strictEqual((await api.admin({ action: 'deleteUser', username: 'ani' }, bearer(AN))).status, 400);
  await api.admin({ action: 'setActive', username: 'boss', active: true }, bearer(AN));

  // ---------- brute force: 5 salah -> terkunci walau password benar ----------
  for (let i = 0; i < 5; i++) assert.strictEqual((await api.login({ username: 'budi', password: 'salah' + i })).status, 401);
  assert.strictEqual((await api.login({ username: 'budi', password: 'passwordBaru1' })).status, 429);

  // ---------- function Vercel (api/[name].js) ----------
  global.fetch = realFetch;
  const H = require('../api/[name].js');
  const call = async (name, method, body, tok, extra) => {
    const res = { code: 200, headers: {}, body: null, setHeader(k, v) { res.headers[k] = v; }, status(c) { res.code = c; return res; }, json(b) { res.body = b; return res; } };
    const req = Object.assign({ method, query: { name }, headers: tok ? { authorization: 'Bearer ' + tok } : {}, body }, extra);
    await H(req, res); return res;
  };
  let x = await call('status', 'GET'); assert.strictEqual(x.code, 200); assert.strictEqual(x.body.adminReady, true); assert.strictEqual(x.headers['Cache-Control'], 'no-store');
  assert.ok(!require('fs').existsSync(require('path').join(__dirname, '../netlify')), 'folder netlify sudah dihapus');
  x = await call('login', 'POST', { username: 'boss', password: 'rahasia-admin' }); assert.strictEqual(x.code, 200);
  const tok = x.body.token;
  assert.strictEqual((await call('me', 'GET', null, tok)).code, 200);
  assert.strictEqual((await call('me', 'POST', {})).code, 405);
  assert.strictEqual((await call('login', 'GET')).code, 405);
  assert.strictEqual((await call('admin', 'POST', { action: 'list' }, tok)).code, 200);
  assert.strictEqual((await call('admin', 'POST', { action: 'list' })).code, 401);
  assert.strictEqual((await call('setup', 'POST', {})).code, 404, 'tidak ada endpoint setup');
  assert.strictEqual((await call('constructor', 'POST', {})).code, 404, 'nama bawaan Object bukan rute');
  assert.strictEqual((await call('login', 'POST', {}, null, { headers: { 'content-length': '999999' } })).code, 413);
  const bad = { method: 'POST', query: { name: 'login' }, headers: {}, get body() { throw new Error('Invalid JSON'); } };
  const rb = { code: 0, setHeader() {}, status(c) { rb.code = c; return rb; }, json() { return rb; } }; await H(bad, rb); assert.strictEqual(rb.code, 400);
  console.log('SEMUA TES LULUS');
})().catch(e => { console.error('GAGAL:', e.stack || e.message); process.exit(1); });
