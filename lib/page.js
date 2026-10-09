'use strict';
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const { fail } = require('./form');

const MAX_BYTES = 2 * 1024 * 1024, MAX_TEXT = 20000, MAX_HOPS = 4;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const PORTS = new Set(['', '80', '443', '8080', '8443']);

// ---- Anti-SSRF: server tidak boleh dipakai membuka alamat internal ----
const bl = new net.BlockList();
[['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
 ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
 ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]].forEach(([a, p]) => bl.addSubnet(a, p, 'ipv4'));
[['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96]]
  .forEach(([a, p]) => bl.addSubnet(a, p, 'ipv6'));

function isPrivateIp(ip) {
  ip = String(ip).replace(/^\[|\]$/g, '');
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) ip = m[1];
  const h = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip); // bentuk hex: ::ffff:7f00:1
  if (h) { const x = parseInt(h[1], 16), y = parseInt(h[2], 16); ip = [x >> 8, x & 255, y >> 8, y & 255].join('.'); }
  if (net.isIPv4(ip)) return bl.check(ip, 'ipv4');
  if (net.isIPv6(ip)) return bl.check(ip, 'ipv6');
  return true; // tidak dikenali: tolak
}

function parseTarget(raw) {
  let s = String(raw || '').trim();
  if (!s || s.length > 2000) throw fail('Link tidak valid.', 400);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch (e) { throw fail('Link tidak valid.', 400); }
  return u;
}

function checkTarget(u, allowPrivate) {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw fail('Hanya link http atau https yang didukung.', 400);
  if (u.username || u.password) throw fail('Link berisi username atau password tidak didukung.', 400);
  if (allowPrivate) return; // hanya tes lokal
  if (!PORTS.has(u.port)) throw fail('Port tidak diizinkan.', 400);
  const h = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIP(h) ? isPrivateIp(h) : (h === 'localhost' || /\.(localhost|local|internal|lan|home|corp)$/.test(h) || !h.includes('.'))) {
    throw fail('Alamat tujuan tidak diizinkan.', 400);
  }
}

function getOnce(u, allowPrivate, ms) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    // Validasi alamat saat koneksi dibuat, agar kebal terhadap DNS rebinding.
    const lookup = (host, o, cb) => {
      if (typeof o === 'function') { cb = o; o = {}; }
      dns.lookup(host, Object.assign({}, o, { all: true }), (err, addrs) => {
        if (err) return cb(err);
        const ok = addrs.filter(a => allowPrivate || !isPrivateIp(a.address));
        if (!ok.length) return cb(Object.assign(new Error('blocked'), { code: 'EBLOCKED' }));
        if (o && o.all) return cb(null, ok);
        cb(null, ok[0].address, ok[0].family);
      });
    };
    const timer = setTimeout(() => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), ms);
    const req = lib.request(u, {
      method: 'GET', lookup, timeout: ms,
      headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5', 'accept-language': 'id,en;q=0.8', 'accept-encoding': 'identity' }
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); clearTimeout(timer); return resolve({ status: res.statusCode, headers: res.headers, body: Buffer.alloc(0) }); }
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size > MAX_BYTES) req.destroy(Object.assign(new Error('big'), { code: 'EBIG' })); else chunks.push(c); });
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }); });
      res.on('error', e => { clearTimeout(timer); reject(e); });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })));
    req.on('error', e => { clearTimeout(timer); reject(e); });
    req.end();
  });
}

function mapError(e) {
  if (e && e.http) return e;
  const c = e && e.code;
  if (c === 'EBLOCKED') return fail('Alamat tujuan tidak diizinkan.', 400);
  if (c === 'EBIG') return fail('Halaman terlalu besar (maksimal 2 MB).', 413);
  if (c === 'ETIMEOUT') return fail('Situs terlalu lama merespons.', 422);
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return fail('Alamat situs tidak ditemukan.', 422);
  return fail('Tidak bisa membuka halaman itu.', 422);
}

function frameInfo(u, headers) {
  if (u.protocol !== 'https:') return { frameable: false, reason: 'Situs memakai http, jadi browser memblokirnya di dalam halaman ini.' };
  if (String(headers['x-frame-options'] || '').trim()) return { frameable: false, reason: 'Situs ini melarang ditampilkan di dalam halaman lain (X-Frame-Options).' };
  const m = /frame-ancestors\s+([^;]+)/i.exec(String(headers['content-security-policy'] || ''));
  if (m && m[1].trim() !== '*') return { frameable: false, reason: 'Situs ini melarang ditampilkan di dalam halaman lain (frame-ancestors).' };
  return { frameable: true, reason: '' };
}

// ---- Ekstraksi isi halaman (tanpa dependensi: pembaca HTML sederhana buatan sendiri) ----
// Sengaja tidak memakai library DOM: modul yang gagal terpasang/ter-bundle di hosting tidak boleh mematikan fitur ini.
const HIDE = new Set(['script', 'style', 'noscript', 'svg', 'iframe', 'template', 'head', 'canvas', 'link', 'meta', 'select', 'option', 'textarea']);
const BLOCK = new Set(['p', 'div', 'section', 'article', 'header', 'footer', 'main', 'aside', 'nav', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'table', 'tr', 'form', 'fieldset', 'legend', 'label', 'blockquote', 'pre', 'hr', 'br', 'dd', 'dt', 'figure', 'figcaption']);
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'frame']);
const RAWTEXT = new Set(['script', 'style', 'title', 'textarea']);
const AUTO_END = { option: ['option'], li: ['li'], dt: ['dt', 'dd'], dd: ['dt', 'dd'], tr: ['tr', 'td', 'th'], td: ['td', 'th'], th: ['td', 'th'], p: ['p'] };
const MAX_DEPTH = 3000, CLOSE = { close: true };
const clean = s => String(s || '').replace(/\s+/g, ' ').trim();
const normalize = s => s.replace(/[ \t\r\f\v]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();

// Membangun pohon sederhana: {tag, attrs, kids, parent, hasField} dan simpul teks {tag:null, text}. Toleran terhadap HTML rusak.
function parseDom(src) {
  const html = String(src || '');
  const root = { tag: '#root', attrs: Object.create(null), kids: [], parent: null, hasField: false };
  const doc = { root, body: null, title: '', byId: new Map(), labelFor: new Map(), inputs: [] };
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<[!?][^>]*>|<(\/?)([a-zA-Z][^\s\/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>|[^<]+|</g;
  const AT = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = re.exec(html))) {
    const tok = m[0];
    let top = stack[stack.length - 1];
    if (m[2] === undefined) {
      if (tok.length > 1 && tok[0] === '<' && (tok[1] === '!' || tok[1] === '?')) continue; // komentar, doctype
      top.kids.push({ tag: null, text: unent(tok) });
      continue;
    }
    const tag = m[2].toLowerCase();
    if (m[1] === '/') { // tag penutup: cari pasangannya di 200 tingkat teratas saja
      for (let i = stack.length - 1, lim = Math.max(1, stack.length - 200); i >= lim; i--) {
        if (stack[i].tag === tag) { stack.length = i; break; }
      }
      continue;
    }
    const auto = AUTO_END[tag];
    while (auto && stack.length > 1 && auto.includes(top.tag)) { stack.pop(); top = stack[stack.length - 1]; }
    const raw = m[3] || '';
    const attrs = Object.create(null);
    if (raw.trim()) {
      AT.lastIndex = 0;
      let a;
      while ((a = AT.exec(raw))) {
        const k = a[1].toLowerCase();
        if (!(k in attrs)) attrs[k] = unent(a[2] !== undefined ? a[2] : a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : '');
      }
    }
    const selfClose = VOID.has(tag) || /(["'\s])\/\s*$/.test(raw) || raw.trim() === '/';
    const node = { tag, attrs, kids: [], parent: top, hasField: false };
    top.kids.push(node);
    if (attrs.id && !doc.byId.has(attrs.id)) doc.byId.set(attrs.id, node);
    if (tag === 'label' && attrs.for && !doc.labelFor.has(attrs.for)) doc.labelFor.set(attrs.for, node);
    if (tag === 'body' && !doc.body) doc.body = node;
    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
      doc.inputs.push(node);
      for (let a = top; a && !a.hasField; a = a.parent) a.hasField = true; // tandai wadah yang memuat isian
    }
    if (RAWTEXT.has(tag) && !selfClose) { // isi script/style/title/textarea bukan markup
      const rx = new RegExp('</' + tag, 'ig'); rx.lastIndex = re.lastIndex;
      const e = rx.exec(html), from = re.lastIndex, end = e ? e.index : html.length;
      if (tag === 'title' && !doc.title) doc.title = unent(html.slice(from, end));
      const gt = e ? html.indexOf('>', end) : -1;
      re.lastIndex = gt < 0 ? html.length : gt + 1;
      continue;
    }
    if (!selfClose && stack.length < MAX_DEPTH) stack.push(node);
  }
  return doc;
}

function textContent(n, limit) {
  let out = ''; const st = [n];
  while (st.length && out.length < limit) {
    const x = st.pop();
    if (!x.tag) { out += x.text; continue; }
    for (let i = x.kids.length - 1; i >= 0; i--) st.push(x.kids[i]);
  }
  return out;
}
const up = (n, tag) => { for (let p = n.parent; p; p = p.parent) if (p.tag === tag) return p; return null; };
function findFirst(n, tag) {
  const st = [n];
  while (st.length) {
    const x = st.pop();
    if (x !== n && x.tag === tag) return x;
    if (x.tag) for (let i = x.kids.length - 1; i >= 0; i--) st.push(x.kids[i]);
  }
  return null;
}
function findAll(n, tag, max) {
  const out = [], st = [n];
  while (st.length && out.length < max) {
    const x = st.pop();
    if (x !== n && x.tag === tag) out.push(x);
    if (x.tag) for (let i = x.kids.length - 1; i >= 0; i--) st.push(x.kids[i]);
  }
  return out;
}
const isUnder = (x, a) => { for (let p = x.parent; p; p = p.parent) if (p === a) return true; return false; };

function hidden(n) {
  return 'hidden' in n.attrs || n.attrs['aria-hidden'] === 'true' || /display\s*:\s*none/i.test(n.attrs.style || '');
}
function textOf(root) {
  let out = '', cut = false; const st = [root];
  while (st.length) {
    const n = st.pop();
    if (n === CLOSE) { out += '\n'; continue; }
    if (!n.tag) { out += n.text; if (out.length > MAX_TEXT * 4) { cut = true; break; } continue; }
    if (n.tag !== '#root' && (HIDE.has(n.tag) || hidden(n))) continue;
    if (BLOCK.has(n.tag)) { out += '\n'; st.push(CLOSE); }
    for (let i = n.kids.length - 1; i >= 0; i--) st.push(n.kids[i]);
  }
  return { text: normalize(out), cut };
}
function near(el) {
  let n = el;
  for (let d = 0; d < 7 && n && n.tag !== '#root' && n.tag !== 'body'; d++) {
    const sibs = n.parent ? n.parent.kids : [];
    let i = sibs.indexOf(n) - 1, hops = 0;
    while (i >= 0 && hops < 4) {
      const p = sibs[i--];
      if (!p.tag) continue;
      const t = clean(textContent(p, 400));
      if (t.length >= 4 && !p.hasField) return t.slice(0, 160);
      hops++;
    }
    n = n.parent;
  }
  return '';
}
function labelOf(doc, el) {
  const a = el.attrs['aria-label']; if (clean(a)) return clean(a);
  const lb = el.attrs['aria-labelledby'];
  if (lb) { const t = clean(lb.split(/\s+/).map(i => { const x = doc.byId.get(i); return x ? textContent(x, 400) : ''; }).join(' ')); if (t) return t; }
  if (el.attrs.id) { const f = doc.labelFor.get(el.attrs.id); if (f) return clean(textContent(f, 400)).slice(0, 160); }
  const p = up(el, 'label'); if (p) return clean(textContent(p, 400)).slice(0, 160);
  return clean(el.attrs.placeholder || '');
}
const NAMES = { text: 'teks', email: 'email', tel: 'telepon', number: 'angka', date: 'tanggal', time: 'jam', url: 'tautan', search: 'pencarian',
  textarea: 'teks panjang', select: 'dropdown', radio: 'pilihan tunggal', checkbox: 'pilihan ganda' };

function collectFields(doc) {
  const out = [], groups = new Map();
  // Checkbox satu pertanyaan sering punya name berbeda: kelompokkan menurut wadah terdekat yang memuat 2+ checkbox.
  const cbs = doc.inputs.filter(e => e.tag === 'input' && (e.attrs.type || '').toLowerCase() === 'checkbox' && !('disabled' in e.attrs) && !hidden(e)).slice(0, 500);
  const cnt = new Map();
  cbs.forEach(e => { for (let a = e.parent; a; a = a.parent) cnt.set(a, (cnt.get(a) || 0) + 1); });
  const cbGroup = new Map(), done = new Set();
  cbs.forEach(e => {
    if (done.has(e)) return;
    let a = e.parent, grp = null;
    while (a && a.tag !== 'html' && a.tag !== '#root') {
      if ((cnt.get(a) || 0) >= 2) {
        const g = cbs.filter(x => !done.has(x) && isUnder(x, a));
        if (g.length >= 2) { grp = g; break; }
      }
      a = a.parent;
    }
    grp = grp || [e];
    grp.forEach(x => { done.add(x); cbGroup.set(x, grp); });
  });
  doc.inputs.forEach(el => {
    if (out.length >= 60) return;
    const tag = el.tag;
    const type = (tag === 'input' ? (el.attrs.type || 'text') : tag).toLowerCase();
    if (['hidden', 'submit', 'button', 'reset', 'image', 'password', 'file'].includes(type)) return; // password/file tidak ditampilkan
    if ('disabled' in el.attrs || hidden(el)) return;
    if (type === 'checkbox') {
      const grp = cbGroup.get(el);
      if (!grp || grp[0] !== el) return;
      const fs = up(el, 'fieldset'); const lg = fs && findFirst(fs, 'legend');
      const options = grp.map(x => labelOf(doc, x) || x.attrs.value || '').filter(Boolean).slice(0, 30).map(l => l.slice(0, 120));
      out.push({ type: NAMES.checkbox, label: (lg && clean(textContent(lg, 400))) || near(el), options });
      return;
    }
    if (type === 'radio') {
      const key = 'radio:' + (el.attrs.name || ('#' + out.length));
      let g = groups.get(key);
      if (!g) {
        const fs = up(el, 'fieldset'); const lg = fs && findFirst(fs, 'legend');
        g = { type: NAMES.radio, label: (lg && clean(textContent(lg, 400))) || near(el), options: [] };
        groups.set(key, g); out.push(g);
      }
      const l = labelOf(doc, el) || el.attrs.value || '';
      if (l && g.options.length < 30) g.options.push(l.slice(0, 120));
      return;
    }
    const f = { type: NAMES[type] || type, label: labelOf(doc, el) || near(el) };
    if (tag === 'select') f.options = findAll(el, 'option', 60).map(o => clean(textContent(o, 400))).filter(Boolean).slice(0, 30);
    out.push(f);
  });
  return out.filter(f => f.label || (f.options && f.options.length));
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
function unent(t) {
  return t.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch (x) { return ' '; } }
    return Object.prototype.hasOwnProperty.call(ENT, e.toLowerCase()) ? ENT[e.toLowerCase()] : m;
  });
}
// Cadangan paling sederhana (regex): dipakai bila pembaca utama gagal (HTML rusak, tanpa elemen, terlalu dalam, dll).
function looseExtract(html) {
  html = String(html || '').slice(0, 500000);
  const t = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  let x = html.replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|svg|template|head)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<\/?(?:p|div|section|article|header|footer|main|aside|nav|ul|ol|li|h[1-6]|table|tr|form|fieldset|legend|label|blockquote|pre|hr|br|dd|dt|figure|figcaption)\b[^>]*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ');
  x = unent(x).replace(/[ \t\r\f\v]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const truncated = x.length > MAX_TEXT;
  return { title: clean(unent(t ? t[1] : '')).slice(0, 200), text: truncated ? x.slice(0, MAX_TEXT) : x, truncated, fields: [] };
}

function extract(html) {
  try {
    const doc = parseDom(String(html || '').slice(0, MAX_BYTES));
    const { text: full, cut } = textOf(doc.body || doc.root);
    const r = { title: clean(doc.title).slice(0, 200), text: full.length > MAX_TEXT ? full.slice(0, MAX_TEXT) : full, truncated: cut || full.length > MAX_TEXT, fields: collectFields(doc) };
    if (!r.text && !r.fields.length) { const l = looseExtract(html); if (l.text) { l.title = l.title || r.title; return l; } }
    return r;
  } catch (e) {
    console.error('[orbit] pembaca HTML gagal, pakai pembaca cadangan:', e && e.message);
    return looseExtract(html);
  }
}

function decode(buf, contentType) {
  const m = /charset=([\w-]+)/i.exec(contentType || '') || /<meta[^>]+charset=["']?([\w-]+)/i.exec(buf.subarray(0, 2048).toString('latin1'));
  try { return new TextDecoder(m ? m[1] : 'utf-8').decode(buf); } catch (e) { return buf.toString('utf8'); }
}

// opts.allowPrivate hanya dipakai tes lokal. Lapisan API tidak pernah mengirimkannya.
async function fetchPage(raw, opts = {}) {
  const allowPrivate = opts.allowPrivate === true;
  let u = parseTarget(raw);
  const deadline = Date.now() + (opts.budgetMs || 8000);
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    checkTarget(u, allowPrivate);
    const left = deadline - Date.now();
    if (left < 500) throw fail('Situs terlalu lama merespons.', 422);
    let r;
    try { r = await getOnce(u, allowPrivate, left); } catch (e) { throw mapError(e); }
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      try { u = new URL(r.headers.location, u); } catch (e) { throw fail('Pengalihan tidak valid.', 422); }
      continue;
    }
    if (r.status === 401 || r.status === 403) throw fail('Situs menolak akses dari server (kode ' + r.status + '). Biasanya karena halaman butuh login atau situs memblokir bot.', 422);
    if (r.status >= 400) throw fail('Situs menjawab dengan kode ' + r.status + '.', 422);
    let type = String(r.headers['content-type'] || '').toLowerCase();
    if (!type && /^\s*<[!a-z?]/i.test(r.body.subarray(0, 256).toString('latin1'))) type = 'text/html'; // server tanpa Content-Type
    if (!/^(text\/html|application\/xhtml\+xml|text\/plain)/.test(type)) throw fail('Tipe isi halaman tidak didukung (' + (type.split(';')[0] || 'tidak diketahui') + ').', 415);
    const html = decode(r.body, type);
    const ex = type.startsWith('text/plain') ? { title: '', text: html.slice(0, MAX_TEXT), truncated: html.length > MAX_TEXT, fields: [] } : extract(html);
    return Object.assign({ finalUrl: u.toString() }, frameInfo(u, r.headers), ex);
  }
  throw fail('Terlalu banyak pengalihan link.', 422);
}

module.exports = { fetchPage, isPrivateIp, extract, frameInfo };
