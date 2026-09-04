// migrate-seed.js — Jalanin seed.js lalu upsert hasilnya ke Supabase
// keyvalue_store, SEMUA dalam satu proses (dipanggil dari route
// /admin/migrate-seed di server.js, jadi bisa dieksekusi langsung dari
// Vercel tanpa perlu akses terminal/SSH ke server).
//
// Kenapa gak jalanin `node seed.js` terus `node migrate.js` manual?
// Karena Vercel serverless functions gak punya terminal yang bisa diakses
// user -- filesystem-nya juga read-only KECUALI folder /tmp. Jadi seed.js
// diarahkan nulis ke /tmp/database (lihat SEED_DB_PATH di seed.js), lalu
// modul ini baca dari situ dan upsert ke Supabase, semua dalam satu
// request HTTP.

const fs = require('fs');
const path = require('path');

const DB_FILES = [
  'users.json',
  'products.json',
  'transactions.json',
  'testimonials.json',
  'notifications.json',
  'settings.json',
  'keyspool.json',
  'vouchers.json',
  'admin-lock.json',
  'accounts.json',
];
const OBJECT_FILES = new Set(['settings.json', 'admin-lock.json']);

async function runMigration(supabaseClient, { onProgress = () => {} } = {}) {
  const tmpDbPath = path.join('/tmp', 'database');

  onProgress('📦 Menjalankan seed.js (generate data fake)...');
  process.env.SEED_DB_PATH = tmpDbPath;

  // Hapus dari cache require supaya seed.js benar-benar re-run tiap kali
  // endpoint ini dipanggil (bukan pakai hasil generate yang lama).
  const seedPath = require.resolve('./seed.js');
  delete require.cache[seedPath];
  require(seedPath); // seed.js langsung nulis semua file ke tmpDbPath saat di-require

  onProgress('✅ seed.js selesai, file ada di /tmp/database\n');
  onProgress(`🚀 Upsert ${DB_FILES.length} file ke Supabase keyvalue_store...`);

  const rows = DB_FILES.map((filename) => {
    const fp = path.join(tmpDbPath, filename);
    let value;
    if (fs.existsSync(fp)) {
      value = JSON.parse(fs.readFileSync(fp, 'utf-8'));
    } else {
      value = OBJECT_FILES.has(filename) ? {} : [];
    }
    const count = Array.isArray(value) ? value.length : Object.keys(value).length;
    onProgress(`   ${filename} — ${count} item`);
    return { key: filename, value };
  });

  const { data, error } = await supabaseClient
    .from('keyvalue_store')
    .upsert(rows, { onConflict: 'key' })
    .select('key');

  if (error) {
    throw new Error(`Upsert gagal: ${error.message}${error.details ? ' — ' + error.details : ''}`);
  }

  return { upserted: data.map((r) => r.key) };
}

module.exports = { runMigration };
