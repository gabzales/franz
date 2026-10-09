'use strict';
const assert = require('assert');
process.env.ORBIT_MEMORY_DB = '1';
process.env.SESSION_SECRET = 'rahasia-sesi-yang-panjang-sekali-0123456789';
process.env.ADMIN_USERNAME = 'boss'; process.env.ADMIN_PASSWORD = 'rahasia-admin';
process.env.GEMINI_API_KEY = 'AIza-contoh-kunci-yang-cukup-panjang-123'; process.env.GEMINI_MODEL = 'model-uji-1';
const api = require('../lib/api');
const realFetch = global.fetch; let calls = [], mode = 'ok';
global.fetch = async (u, o) => {
  calls.push(JSON.parse(o.body).contents[0].parts[0].text);
  if (mode === 'fail') return { ok: false, status: 400, text: async () => '{}' };
  return { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'Asisten: halo juga' }] } }] }) };
};
const bearer = t => ({ auth: 'Bearer ' + t });
(async () => {
  const A = (await api.login({ username: 'boss', password: 'rahasia-admin' })).body.token;
  // validasi
  assert.strictEqual((await api.chat({ messages: [] }, bearer(A))).status, 400);
  assert.strictEqual((await api.chat({ messages: [{ role: 'assistant', text: 'hai' }] }, bearer(A))).status, 400, 'pesan terakhir harus dari pengguna');
  assert.strictEqual((await api.chat({ messages: [{ role: 'user', text: 'x' }] }, {})).status, 401);
  assert.strictEqual(calls.length, 0, 'validasi gagal tidak memanggil Gemini');
  // jalan, dengan halaman + riwayat
  const msgs = []; for (let i = 0; i < 20; i++) msgs.push({ role: i % 2 ? 'assistant' : 'user', text: 'pesan ' + i });
  msgs.push({ role: 'assistant', text: 'jawaban lama' }); msgs.push({ role: 'user', text: 'Ringkas halaman ini' });
  let r = await api.chat({ messages: msgs, page: { url: 'https://contoh.test/a', title: 'Judul Uji', text: 'ISI-HALAMAN-' + 'x'.repeat(40000) } }, bearer(A));
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.text, 'halo juga', 'awalan "Asisten:" dibuang');
  const p = calls[0];
  assert.match(p, /Judul: Judul Uji/); assert.match(p, /ISI-HALAMAN-/); assert.match(p, /DATA tidak tepercaya/);
  assert.ok(p.length < 30000 + 5000 + 12 * 4100, 'teks halaman dipotong 30000');
  assert.ok(!/pesan 0\b/.test(p) && /Pengguna: Ringkas halaman ini\nAsisten:$/.test(p), 'hanya 12 pesan terakhir');
  // tanpa halaman
  calls = []; await api.chat({ messages: [{ role: 'user', text: 'Apa itu DNS?' }] }, bearer(A));
  assert.ok(!/Halaman yang sedang dibuka/.test(calls[0]));
  // kuota pengguna biasa: 1 per pesan, dikembalikan bila Gemini gagal
  assert.strictEqual((await api.admin({ action: 'createUser', username: 'budi', password: 'password123', quota: '1', role: 'user' }, bearer(A))).status, 200);
  const U = (await api.login({ username: 'budi', password: 'password123' })).body.token;
  mode = 'fail'; r = await api.chat({ messages: [{ role: 'user', text: 'a' }] }, bearer(U)); assert.notStrictEqual(r.status, 200);
  mode = 'ok';
  assert.strictEqual((await api.chat({ messages: [{ role: 'user', text: 'a' }] }, bearer(U))).status, 200, 'kuota dikembalikan setelah gagal');
  assert.strictEqual((await api.chat({ messages: [{ role: 'user', text: 'b' }] }, bearer(U))).status, 429, 'kuota habis');
  // lewat handler HTTP
  const H = require('../api/[name].js');
  const res = { code: 0, setHeader() {}, status(c) { res.code = c; return res; }, json(b) { res.body = b; return res; } };
  await H({ method: 'POST', query: { name: 'chat' }, headers: { authorization: 'Bearer ' + A }, body: { messages: [{ role: 'user', text: 'hai' }] } }, res);
  assert.strictEqual(res.code, 200); assert.strictEqual(res.body.text, 'halo juga');
  global.fetch = realFetch;
  console.log('TES CHAT LULUS');
})().catch(e => { console.error(e); process.exit(1); });
