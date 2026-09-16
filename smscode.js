// smscode.js — SMSCode API client (NOKOS / nomor virtual OTP provider)
// Dokumentasi resmi: https://smscode.gg (dari doc yang dikasih user, 12 Sep 2026)
// Pakai versi v1 (IDR native) -- storefront ini pakai Rupiah, jadi gak perlu
// urus konversi USD/IDR dari v2 sama sekali.
//
// Auth: Bearer token (BUKAN username+api_key+MD5 sign kayak HAYBI). Token
// bisa dari environment variable SMSCODE_API_TOKEN atau Admin Panel ->
// Settings -> NOKOS (settings.smscode.apiToken), pola sama kayak HAYBI:
// Admin Panel menang kalau dua-duanya diisi.
//
// KEAMANAN: file ini HANYA boleh dipanggil dari kode server. Jangan pernah
// expose token ini ke frontend/browser.

const BASE_URL = 'https://api.smscode.gg/v1';

function getToken(settings) {
  return settings?.smscode?.apiToken?.trim() || process.env.SMSCODE_API_TOKEN || '';
}

async function request(settings, method, endpoint, body) {
  const token = getToken(settings);
  let response;
  try {
    response = await fetch(`${BASE_URL}${endpoint}`, {
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error(`SMSCode network error (${endpoint}): ${e.message}`);
  }
  let json;
  try { json = await response.json(); } catch (e) { throw new Error(`SMSCode: respons bukan JSON (${endpoint}, HTTP ${response.status})`); }
  if (!response.ok || json.success === false) {
    const code = json?.error?.code || response.status;
    const msg = json?.error?.message || `HTTP ${response.status}`;
    const err = new Error(`SMSCode ${code}: ${msg} (${endpoint})`);
    err.code = code;
    throw err;
  }
  return json.data;
}

// ── Katalog ──
async function getCountries(settings) {
  return request(settings, 'GET', '/catalog/countries');
}
async function getServices(settings, countryId) {
  const qs = countryId ? `?country_id=${countryId}` : '';
  return request(settings, 'GET', `/catalog/services${qs}`);
}
async function getOperators(settings, countryId, platformId) {
  return request(settings, 'GET', `/catalog/operators?country_id=${countryId}&platform_id=${platformId}`);
}
async function getProducts(settings, { countryId, platformId, operatorId, sort, limit, page } = {}) {
  const params = new URLSearchParams();
  if (countryId) params.set('country_id', countryId);
  if (platformId) params.set('platform_id', platformId);
  if (operatorId) params.set('operator_id', operatorId);
  if (sort) params.set('sort', sort);
  if (limit) params.set('limit', limit);
  if (page) params.set('page', page);
  return request(settings, 'GET', `/catalog/products?${params.toString()}`);
}

// ── Saldo ──
async function getBalance(settings) {
  return request(settings, 'GET', '/balance');
}

// ── Order (rental nomor) ──
// idempotencyKey WAJIB dipakai (transaction.id lokal) supaya retry aman
// (docs: "Reusing a key with a different body returns 422
// IDEMPOTENCY_KEY_REUSED"). productId ATAU catalogProductId, jangan dua-duanya.
async function createOrder(settings, { productId, catalogProductId, operatorId, minPrice, maxPrice, quantity, idempotencyKey } = {}) {
  const body = {};
  if (productId) body.product_id = productId;
  if (catalogProductId) body.catalog_product_id = catalogProductId;
  if (operatorId) body.operator_id = operatorId;
  if (minPrice) body.min_price = minPrice;
  if (maxPrice) body.max_price = maxPrice;
  body.quantity = quantity || 1;

  const token = getToken(settings);
  let response;
  try {
    response = await fetch(`${BASE_URL}/orders/create`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
      },
      body: JSON.stringify(body),
    });
  } catch (e) {
    throw new Error(`SMSCode network error (/orders/create): ${e.message}`);
  }
  let json;
  try { json = await response.json(); } catch (e) { throw new Error(`SMSCode: respons bukan JSON (/orders/create, HTTP ${response.status})`); }
  if (!response.ok || json.success === false) {
    const code = json?.error?.code || response.status;
    const err = new Error(`SMSCode ${code}: ${json?.error?.message || `HTTP ${response.status}`} (/orders/create)`);
    err.code = code;
    throw err;
  }
  return json.data;
}

async function getOrder(settings, id) {
  return request(settings, 'GET', `/orders/${id}`);
}
async function listActiveOrders(settings) {
  return request(settings, 'GET', '/orders/active');
}
async function cancelOrder(settings, id) {
  return request(settings, 'POST', '/orders/cancel', { id });
}
async function finishOrder(settings, id) {
  return request(settings, 'POST', '/orders/finish', { id });
}
async function resendOrder(settings, id) {
  return request(settings, 'POST', '/orders/resend', { id });
}

// ── Webhook config ──
// PATCH /webhook mendaftarkan URL callback kita ke SMSCode DAN mengembalikan
// webhook_secret yang harus disimpan buat verifikasi HMAC-SHA256 nanti (lihat
// app.post('/webhook/smscode') di server.js). Secret di-generate otomatis
// oleh SMSCode saat set URL pertama kali -- kita gak boleh ngarang sendiri.
async function getWebhookConfig(settings) {
  return request(settings, 'GET', '/webhook');
}
async function setWebhookUrl(settings, webhookUrl) {
  return request(settings, 'PATCH', '/webhook', { webhook_url: webhookUrl });
}
async function testWebhook(settings) {
  return request(settings, 'POST', '/webhook/test');
}

module.exports = {
  getCountries, getServices, getOperators, getProducts, getBalance,
  createOrder, getOrder, listActiveOrders, cancelOrder, finishOrder, resendOrder,
  getWebhookConfig, setWebhookUrl, testWebhook,
};
