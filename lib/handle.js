'use strict';
const { fail, fetchForm, parseForm, buildPlans, prefillUrl } = require('./form');
const { answer } = require('./gemini');

// Inti permintaan, dipakai oleh api/[name].js (lewat lib/api.js).
// Kunci API pengguna hanya dipakai untuk satu request ini. Tidak disimpan dan tidak di-log.
async function handle(b, opts) {
  try {
    b = b && typeof b === 'object' ? b : {};
    const key = typeof b.key === 'string' ? b.key.trim() : '';
    if (!key) throw fail('Isi API key Gemini di Pengaturan.', 400);
    const models = [b.model, b.fallback].map(m => (typeof m === 'string' ? m.trim() : '')).filter(Boolean);
    if (!models.length) throw fail('Isi nama model di Pengaturan.', 400);

    const { html, finalUrl } = await fetchForm(String(b.url || ''));
    const questions = parseForm(html);
    const sent = questions.map(q => ({ id: q.id, title: q.title, type: q.type, options: q.options, required: q.required }));
    const answers = await answer(Object.assign({
      key, models: [...new Set(models)], profile: String(b.profile || '').slice(0, 2000), questions: sent
    }, opts || {}));
    const plans = buildPlans(questions, answers);
    if (!plans.length) throw fail('Tidak ada jawaban yang cukup yakin. Isi manual.', 422);
    return { status: 200, body: {
      prefill: prefillUrl(finalUrl, plans), total: questions.length, filled: plans.length,
      plans: plans.map(p => ({ title: p.q.title, summary: p.values.join(', ') }))
    } };
  } catch (e) {
    return { status: e.http || 500, body: { error: e.http ? e.message : 'Terjadi kesalahan di server.' } };
  }
}

module.exports = { handle };
