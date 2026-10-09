'use strict';
const assert = require('assert');
const { extract } = require('../lib/page');
// Bentuk isi yang membuat parser DOM melempar error atau membaca kosong: harus tetap menghasilkan hasil.
const ok = (h, re) => { const r = extract(h); assert.ok(re.test(r.text), JSON.stringify(h.slice(0, 40)) + ' -> ' + JSON.stringify(r.text)); return r; };
['', '   \n ', 'Forbidden', '<!doctype html>', '<!-- x -->'].forEach(h => assert.doesNotThrow(() => extract(h)));
ok('Forbidden', /Forbidden/);
ok('<p>halo</p>', /halo/);
ok('<body><p>halo</p></body>', /halo/);
ok('<!doctype html><html><head><title>T</title></head><body><p>isi &amp; teks</p></body></html>', /isi & teks/);
assert.strictEqual(extract('<title>Judul &amp; Co</title><p>x</p>').title, 'Judul & Co');
assert.strictEqual(extract('<html><body><form><label for=a>Nama</label><input id=a></form></body></html>').fields.length, 1);
assert.doesNotThrow(() => extract('<div>'.repeat(30000) + 'x'));
console.log('TES EKSTRAKSI LULUS');
