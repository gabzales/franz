'use strict';
const assert = require('assert');
const http = require('http');
const { fetchPage } = require('../lib/page');
const srv = http.createServer(() => { /* sengaja menggantung */ });
srv.listen(0, '127.0.0.1', async () => {
  const t = Date.now();
  try {
    await fetchPage('http://127.0.0.1:' + srv.address().port + '/', { allowPrivate: true, budgetMs: 1500 });
    assert.fail('harus gagal');
  } catch (e) {
    assert.strictEqual(e.http, 422); assert.match(e.message, /terlalu lama/i);
    assert.ok(Date.now() - t < 3000, 'harus berhenti sesuai tenggat');
  }
  srv.close(); srv.closeAllConnections && srv.closeAllConnections();
  console.log('TES TENGGAT LULUS');
});
