'use strict';
const assert = require('assert');
const { answer, thinkingFor } = require('../lib/gemini');
const gem = o => ({ ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: JSON.stringify(o) }] } }] }) });
const mk = n => Array.from({ length: n }, (_, i) => ({ id: 'q' + (i + 1), title: 'Soal ' + (i + 1), type: 'text', options: [], required: false }));
const real = global.fetch;

(async () => {
  assert.deepStrictEqual(thinkingFor('gemini-3.5-flash'), { thinkingLevel: 'low' });
  assert.deepStrictEqual(thinkingFor('gemini-2.5-flash'), { thinkingBudget: 0 });
  assert.strictEqual(thinkingFor('model-lain'), null);

  // pengaturan berpikir terkirim; jika ditolak 400, diulang tanpa pengaturan itu
  const bodies = [];
  global.fetch = async (u, o) => { const b = JSON.parse(o.body); bodies.push(b.generationConfig); return b.generationConfig.thinkingConfig ? { ok: false, status: 400 } : gem({ answers: [{ id: 'q1', text: 'ok' }] }); };
  assert.strictEqual((await answer({ key: 'k', models: ['gemini-3.5-flash'], questions: mk(1), delays: [1] })).length, 1);
  assert.deepStrictEqual(bodies.map(g => !!g.thinkingConfig), [true, false], 'harus coba dengan lalu tanpa thinkingConfig');

  // 20 soal -> 3 panggilan paralel, hasil digabung berurutan
  let calls = 0, active = 0, peak = 0;
  global.fetch = async (u, o) => {
    calls++; active++; peak = Math.max(peak, active); await new Promise(r => setTimeout(r, 30)); active--;
    const ids = JSON.parse(JSON.parse(o.body).contents[0].parts[0].text.split('Questions: ')[1]).map(q => q.id);
    return gem({ answers: ids.map(id => ({ id, text: 'jawab-' + id })) });
  };
  const t0 = Date.now();
  const out = await answer({ key: 'k', models: ['m-one'], questions: mk(20), delays: [1] });
  assert.strictEqual(calls, 3); assert.ok(peak >= 2, 'harus berjalan paralel'); assert.strictEqual(out.length, 20);
  assert.deepStrictEqual(out.map(a => a.id), mk(20).map(q => q.id), 'urutan terjaga');
  assert.ok(Date.now() - t0 < 85, 'paralel harus lebih cepat dari berurutan (3x30ms)');

  // satu bagian gagal -> bagian lain tetap dipakai; semua gagal -> error
  let n = 0;
  global.fetch = async (u, o) => (++n === 2 ? { ok: false, status: 403 } : gem({ answers: [{ id: 'q1', text: 'x' }] }));
  assert.ok((await answer({ key: 'k', models: ['m-one'], questions: mk(20), delays: [1] })).length >= 1);
  global.fetch = async () => ({ ok: false, status: 403 });
  await assert.rejects(answer({ key: 'k', models: ['m-one'], questions: mk(20), delays: [1] }), /ditolak/);
  global.fetch = real;
  console.log('TES KECEPATAN LULUS');
})().catch(e => { console.error('GAGAL:', e.stack || e.message); process.exit(1); });
