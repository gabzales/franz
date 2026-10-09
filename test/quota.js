'use strict';
const assert = require('assert');
const { ask } = require('../lib/gemini');
const body = (quotaId, extra) => JSON.stringify({ error: { code: 429, status: 'RESOURCE_EXHAUSTED', message: 'You exceeded your current quota. Please retry in 34.5s.',
  details: [{ '@type': 'type.googleapis.com/google.rpc.QuotaFailure', violations: [Object.assign({ quotaId }, extra)] }, { '@type': 'type.googleapis.com/google.rpc.RetryInfo', retryDelay: '34s' }] } });
const realFetch = global.fetch;
const mock = (map, log) => { global.fetch = async (u) => { const m = /models\/([^:]+):/.exec(u)[1]; log.push(m); const r = map[m]; return r.ok ? { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'ok dari ' + m }] } }] }) } : { ok: false, status: r.status, text: async () => r.body }; }; };
const opts = (models) => ({ key: 'k', models, prompt: 'p', delays: [10, 10], deadlineMs: 20000 });
(async () => {
  let log = [];
  mock({ 'mod-a': { status: 429, body: body('GenerateRequestsPerDayPerProjectPerModel-FreeTier', { quotaValue: '20' }) } }, log);
  await assert.rejects(ask(opts(['mod-a'])), e => /429 \(mod-a\).*HARIAN/.test(e.message));
  assert.strictEqual(log.length, 1, 'batas harian tidak diulang: ' + log);
  log = [];
  mock({ 'mod-a': { status: 429, body: body('GenerateRequestsPerDayPerProjectPerModel-FreeTier', { quotaValue: '0' }) }, 'mod-b': { ok: true } }, log);
  assert.strictEqual(await ask(opts(['mod-a', 'mod-b'])), 'ok dari mod-b'); assert.deepStrictEqual(log, ['mod-a', 'mod-b'], 'langsung ke model cadangan tanpa mengulang');
  log = [];
  mock({ 'mod-a': { status: 429, body: body('GenerateRequestsPerDayPerProjectPerModel-FreeTier', { quotaValue: '0' }) } }, log);
  await assert.rejects(ask(opts(['mod-a'])), e => /limit 0/.test(e.message));
  log = [];
  mock({ 'mod-a': { status: 429, body: body('GenerateRequestsPerMinutePerProjectPerModel-FreeTier', { quotaValue: '5' }) } }, log);
  await assert.rejects(ask(opts(['mod-a'])), e => /per menit.*34 dtk/.test(e.message));
  assert.strictEqual(log.length, 3, 'batas per menit diulang sesuai jeda: ' + log);
  log = [];
  mock({ 'mod-a': { status: 429, body: 'bukan json' } }, log);
  await assert.rejects(ask(opts(['mod-a'])), e => /429 \(mod-a\): kuota habis atau terlalu cepat\./.test(e.message));
  global.fetch = realFetch;
  console.log('TES KUOTA GEMINI LULUS');
})().catch(e => { console.error(e); process.exit(1); });
