// haybi.js — HAYBI H2H API client
// Provider top up game/PPOB (Mobile Legends, Free Fire, dst) — BUKAN payment
// gateway. Dokumentasi resmi: https://haybi.id/docs
//
// Kredensial (username/api_key) bisa diisi lewat:
//   1. Environment variable: HAYBI_USERNAME, HAYBI_API_KEY
//   2. Admin Panel -> Settings -> HAYBI (disimpan di settings.haybi)
// Kalau dua-duanya diisi, nilai dari Admin Panel yang menang (pola sama
// seperti Pakasir/GensPay di server.js) supaya admin bisa ganti kredensial
// tanpa perlu redeploy.
//
// KEAMANAN: file ini HANYA boleh dipanggil dari kode server (server.js).
// Jangan pernah expose HAYBI_API_KEY ke frontend/browser.

const crypto = require('crypto');

const BASE_URL = 'https://haybi.id/api/h2h';

function getCreds(settings) {
  const username = settings?.haybi?.username?.trim() || process.env.HAYBI_USERNAME || '';
  const apiKey = settings?.haybi?.apiKey?.trim() || process.env.HAYBI_API_KEY || '';
  return { username, apiKey };
}

// Signature HAYBI: MD5(username + api_key + ref_id) — lihat docs bagian 3.
function createSignature(username, apiKey, refId) {
  return crypto.createHash('md5').update(username + apiKey + refId).digest('hex');
}

function genRefId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomUUID()}`;
}

async function haybiRequest(endpoint, payload) {
  let response;
  try {
    response = await fetch(`${BASE_URL}/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    throw new Error(`HAYBI network error (${endpoint}): ${e.message}`);
  }
  if (!response.ok) {
    throw new Error(`HAYBI HTTP ERROR ${response.status} (${endpoint})`);
  }
  return response.json();
}

// ── Cek Saldo ──
async function getBalance(settings) {
  const { username, apiKey } = getCreds(settings);
  const refId = genRefId('SALDO');
  return haybiRequest('cek-saldo', {
    username, ref_id: refId, sign: createSignature(username, apiKey, refId),
  });
}

// ── Daftar Produk (default kategori "Game") ──
// PENTING: jangan hard-code kode produk di tempat lain -- selalu ambil dari
// hasil fungsi ini (lihat docs bagian 1 & 9).
async function getProducts(settings, kategori = 'Game') {
  const { username, apiKey } = getCreds(settings);
  const refId = genRefId('PRODUCT');
  return haybiRequest('produk', {
    username, ref_id: refId, kategori, sign: createSignature(username, apiKey, refId),
  });
}

// ── Cek Harga satu kode produk ──
async function checkPrice(settings, productCode) {
  const { username, apiKey } = getCreds(settings);
  const refId = genRefId('PRICE');
  return haybiRequest('cek-harga', {
    username, ref_id: refId, produk: productCode, sign: createSignature(username, apiKey, refId),
  });
}

// ── Transaksi Top-Up ──
// refId WAJIB dikirim oleh caller (server.js pakai transaction.id lokal
// sebagai ref_id) supaya 1 order lokal = 1 ref_id HAYBI. Ini yang bikin
// checkStatus() dan webhook callback bisa dicocokkan balik ke transaksi yang
// sama, dan mencegah top-up dobel kalau finalizeOrder() terpanggil 2x untuk
// order yang sama (lihat docs bagian 24 & 16 soal keunikan ref_id/idempotency).
async function createTransaction(settings, { productCode, target, refId }) {
  const { username, apiKey } = getCreds(settings);
  return haybiRequest('transaksi', {
    username, ref_id: refId, produk: productCode, no_tujuan: target,
    sign: createSignature(username, apiKey, refId),
  });
}

// ── Cek Status Transaksi ──
// Dipakai juga untuk KONFIRMASI ULANG isi webhook callback -- dokumentasi
// HAYBI tidak menyebutkan mekanisme verifikasi signature untuk callback
// masuk (beda dari GensPay yang pakai HMAC), jadi body callback POST TIDAK
// BOLEH langsung dipercaya mentah-mentah. Lihat app.post('/webhook/haybi')
// di server.js untuk detail mitigasinya.
async function checkStatus(settings, refId) {
  const { username, apiKey } = getCreds(settings);
  return haybiRequest('cek-status', {
    username, ref_id: refId, sign: createSignature(username, apiKey, refId),
  });
}

module.exports = { getBalance, getProducts, checkPrice, createTransaction, checkStatus };
