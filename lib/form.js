'use strict';
// Hanya Google Forms publik. Daftar host dibatasi agar server tidak bisa dipakai mengambil URL sembarang (SSRF).
const ALLOWED = new Set(['docs.google.com', 'forms.gle', 'forms.google.com']);

function fail(message, http) { return Object.assign(new Error(message), { http: http || 400 }); }
function hostOf(u) { try { const x = new URL(u); return x.protocol === 'https:' ? x.hostname : null; } catch (e) { return null; } }

async function fetchForm(url) {
  let cur = url;
  for (let hop = 0; hop < 4; hop++) {
    const h = hostOf(cur);
    if (h === 'accounts.google.com') throw fail('Form ini butuh login Google. Belum didukung.');
    if (!h || !ALLOWED.has(h)) throw fail('Versi web hanya mendukung Google Forms (docs.google.com / forms.gle). Untuk situs lain, pakai aplikasi Android FRANZZ Orbit.');
    let r;
    try {
      r = await fetch(cur, {
        redirect: 'manual', signal: AbortSignal.timeout(15000),
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; FranzzOrbit/1.0)', 'accept-language': 'id,en;q=0.8' }
      });
    } catch (e) { throw fail('Form tidak merespons.', 504); }
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { cur = new URL(loc, cur).toString(); continue; }
    if (!r.ok) throw fail('Form tidak bisa dibuka (' + r.status + ').', 502);
    const html = await r.text();
    if (html.length > 3000000) throw fail('Halaman form terlalu besar.');
    return { html, finalUrl: cur };
  }
  throw fail('Terlalu banyak pengalihan link.');
}

// Membaca data form dari FB_PUBLIC_LOAD_DATA_ (struktur internal Google, bisa berubah sewaktu-waktu).
function parseForm(html) {
  const m = html.match(/FB_PUBLIC_LOAD_DATA_\s*=\s*(\[[\s\S]*?\]);\s*<\/script>/);
  if (!m) throw fail('Struktur form tidak dikenali (form privat, atau Google mengubah formatnya).', 422);
  let data;
  try { data = JSON.parse(m[1]); } catch (e) { throw fail('Data form tidak bisa dibaca.', 422); }
  const items = (data[1] && data[1][1]) || [];
  const questions = [];
  for (const it of items) {
    const ans = it[4];
    if (!Array.isArray(ans) || !Array.isArray(ans[0])) continue; // judul, pemisah bagian, gambar
    const a = ans[0], entry = a[0], title = String(it[1] || '').trim();
    const options = Array.isArray(a[1]) ? a[1].map(o => String((o && o[0]) || '')).filter(Boolean) : [];
    const typeCode = it[3];
    const type = typeCode === 0 || typeCode === 1 ? 'text'
      : typeCode === 2 || typeCode === 5 ? 'single'
      : typeCode === 3 ? 'select'
      : typeCode === 4 ? 'multi' : null;
    if (!type || entry == null || !title) continue;
    if (type !== 'text' && options.length < 1) continue;
    questions.push({ entry, title, type, options: type === 'text' ? [] : options, required: a[2] === 1 });
  }
  questions.forEach((q, i) => { q.id = 'q' + (i + 1); });
  if (!questions.length) throw fail('Tidak ada soal yang didukung di form ini.', 422);
  if (questions.length > 80) throw fail('Soal terlalu banyak (maks 80).', 422);
  return questions;
}

function buildPlans(qs, answers) {
  const byId = new Map((Array.isArray(answers) ? answers : [])
    .filter(a => a && typeof a === 'object').map(a => [String(a.id), a]));
  const out = [];
  for (const q of qs) {
    const a = byId.get(q.id);
    if (!a || a.skip === true) continue;
    if (q.type === 'text') {
      const t = typeof a.text === 'string' ? a.text.trim() : '';
      if (t && t.length <= 500) out.push({ q, values: [t] });
      continue;
    }
    const idx = [...new Set((Array.isArray(a.choices) ? a.choices : [])
      .filter(i => Number.isInteger(i) && i >= 0 && i < q.options.length))];
    if (!idx.length) continue;
    if ((q.type === 'single' || q.type === 'select') && idx.length !== 1) continue;
    out.push({ q, values: idx.map(i => q.options[i]) });
  }
  return out;
}

// Link "prefilled" milik Google Forms: pengguna memeriksa lalu menekan Kirim sendiri.
function prefillUrl(finalUrl, plans) {
  const u = new URL(finalUrl);
  u.hash = ''; u.search = '';
  u.pathname = u.pathname.replace(/\/(viewform|formResponse|edit)?\/?$/, '') + '/viewform';
  const p = new URLSearchParams({ usp: 'pp_url' });
  for (const { q, values } of plans) for (const v of values) p.append('entry.' + q.entry, v);
  return u.toString() + '?' + p.toString();
}

module.exports = { fail, fetchForm, parseForm, buildPlans, prefillUrl };
