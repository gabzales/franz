/**
 * seed-settings.js — Push settings + logo ke Supabase
 * 
 * CARA PAKAI:
 *   node seed-settings.js
 * 
 * Jalankan SEKALI setelah deploy atau setiap kali ganti credentials.
 * Script ini akan:
 *   1. Upload logo ke Supabase Storage → dapat URL publik
 *   2. Overwrite settings di Supabase dengan kredensial & konfigurasi terbaru
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // bukan anon key — RLS sekarang blokir anon

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di file .env dulu!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });

// ── KREDENSIAL — WAJIB diisi via .env, TIDAK ADA fallback hardcoded ──
// (sebelumnya ada default 'Abdurahman Mulvi Tarakan' / 'Tarakan11#' di sini —
// itu kredensial admin asli yang nangkring di source code, artinya siapa pun
// yang baca file ini/dapat salinan project ini tahu password admin. Sudah
// dihapus total. Kalau kredensial itu PERNAH benar-benar dipakai di
// production, anggap sudah bocor — segera ganti password admin lewat Admin
// Panel dan jangan pernah pakai password yang sama lagi.)
const ADMIN_USERNAME = process.env.SEED_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('❌ Set SEED_ADMIN_USERNAME dan SEED_ADMIN_PASSWORD di file .env lokal dulu (JANGAN commit .env ke git).');
  console.error('   Script ini sengaja TIDAK punya nilai default — kredensial admin tidak boleh ada di source code.');
  process.exit(1);
}

const SITE_NAME   = 'FranzzStore';
const WA_NUMBER   = '6282253090432';
const WA_TELEGRAM = 'FranzzStoreOfficial';
const WA_CHANNEL  = ''; // isi manual lewat admin panel — Pengaturan > Kontak > Link Saluran WA
const WA_GROUP    = ''; // isi manual lewat admin panel — Pengaturan > Kontak > Link Grup WA
const YOUTUBE_URL = ''; // isi manual lewat admin panel kalau ada
// ─────────────────────────────────────────────────────────

async function uploadLogo() {
  const logoPath = path.join(__dirname, 'public', 'uploads', 'logo-main.png');
  if (!fs.existsSync(logoPath)) {
    console.log('⚠️  Logo file tidak ditemukan di public/uploads/logo-main.png, skip upload.');
    return null;
  }
  const fileBuffer = fs.readFileSync(logoPath);

  // Selalu upload ulang logo (upsert: true) agar logo baru menimpa yang lama
  const { error } = await supabase.storage
    .from('product-images')
    .upload('logo-main.png', fileBuffer, { contentType: 'image/png', upsert: true });

  if (error) {
    console.error('⚠️  Gagal upload logo ke storage:', error.message);
    return null;
  }
  const { data: { publicUrl } } = supabase.storage
    .from('product-images').getPublicUrl('logo-main.png');
  console.log('✅ Logo diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

async function uploadLogoText() {
  // Logo text sekarang di-render sebagai teks dinamis (siteName), bukan gambar,
  // supaya otomatis ikut berubah kalau siteName diganti dari admin panel dan
  // tidak ada nama brand lama yang "nyantol" di gambar statis.
  return null;
}

async function uploadBanner() {
  const bannerPath = path.join(__dirname, 'public', 'uploads', 'banner-reseller.jpg');
  if (!require('fs').existsSync(bannerPath)) {
    console.log('⚠️  Banner file tidak ditemukan di public/uploads/banner-reseller.jpg, skip upload.');
    return null;
  }
  const fileBuffer = require('fs').readFileSync(bannerPath);
  const { data: existList } = await supabase.storage.from('product-images').list('', { search: 'banner-reseller.jpg' });
  if (existList && existList.length > 0) {
    const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl('banner-reseller.jpg');
    console.log('ℹ️  Banner sudah ada di storage:', publicUrl);
    return publicUrl;
  }
  const { error } = await supabase.storage.from('product-images').upload('banner-reseller.jpg', fileBuffer, { contentType: 'image/jpeg', upsert: true });
  if (error) { console.error('⚠️  Gagal upload banner:', error.message); return null; }
  const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl('banner-reseller.jpg');
  console.log('✅ Banner diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

// Upload gambar produk (game populer) ke Supabase Storage supaya bisa diakses
// publik lewat product.image -- dipakai untuk seed products.json (lihat seed.js)
// dan sebagai sumber gambar row "Produk Populer" di homepage.
// CATATAN: ini PLACEHOLDER netral (nama game di atas warna aksen), BUKAN logo
// resmi tiap game -- logo resmi berhak cipta pemilik masing-masing, jadi tidak
// di-hardcode di sini. Ganti via Admin Panel > Produk > Edit Gambar kalau mau
// pakai artwork resmi/lisensi sendiri.
async function uploadProductPlaceholders() {
  const dir = path.join(__dirname, 'public', 'uploads', 'products');
  if (!fs.existsSync(dir)) { console.log('⚠️  Folder public/uploads/products tidak ditemukan, skip upload.'); return {}; }
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.png'));
  const urls = {};
  for (const file of files) {
    const buf = fs.readFileSync(path.join(dir, file));
    const key = `products/${file}`;
    const { error } = await supabase.storage.from('product-images').upload(key, buf, { contentType: 'image/png', upsert: true });
    if (error) { console.error(`⚠️  Gagal upload ${file}:`, error.message); continue; }
    const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl(key);
    urls[file.replace('.png', '')] = publicUrl;
  }
  console.log(`✅ ${Object.keys(urls).length} gambar produk diupload ke Supabase Storage`);
  return urls;
}

// Upload badge metode pembayaran (footer "Metode Pembayaran") ke Supabase
// Storage, lalu susun jadi array settings.paymentMethods = [{name, logoUrl}].
// CATATAN: sama seperti di atas, ini BADGE NETRAL (nama metode di kotak
// rounded), BUKAN logo resmi QRIS/GoPay/DANA/OVO/ShopeePay -- logo resmi
// e-wallet berhak cipta pihak ketiga (lihat catatan yang sama di
// views/pages/home.ejs). Ganti via Admin Panel > Pengaturan > Metode
// Pembayaran begitu ada logo resmi yang mau dipakai.
async function uploadPaymentIcons() {
  const dir = path.join(__dirname, 'public', 'uploads', 'payments');
  if (!fs.existsSync(dir)) { console.log('⚠️  Folder public/uploads/payments tidak ditemukan, skip upload.'); return []; }
  const labels = { qris: 'QRIS', gopay: 'GoPay', dana: 'DANA', ovo: 'OVO', shopeepay: 'ShopeePay', 'bank-transfer': 'Transfer Bank' };
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.png'));
  const methods = [];
  for (const file of files) {
    const buf = fs.readFileSync(path.join(dir, file));
    const key = `payments/${file}`;
    const { error } = await supabase.storage.from('product-images').upload(key, buf, { contentType: 'image/png', upsert: true });
    if (error) { console.error(`⚠️  Gagal upload ${file}:`, error.message); continue; }
    const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl(key);
    const slug = file.replace('.png', '');
    methods.push({ name: labels[slug] || slug.toUpperCase(), logoUrl: publicUrl });
  }
  console.log(`✅ ${methods.length} badge metode pembayaran diupload ke Supabase Storage`);
  return methods;
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  FRANZZSTORE — Seed Settings ke Supabase');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // 1. Upload logo & banner
  const logoUrl = await uploadLogo();
  const logoTextUrl = await uploadLogoText();
  const bannerUrl = await uploadBanner();
  const productImageUrls = await uploadProductPlaceholders();
  const paymentMethods = await uploadPaymentIcons();

  // 2. Ambil settings existing
  const { data: existing } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const current = (existing?.value && typeof existing.value === 'object') ? existing.value : {};
  console.log('📋 Existing adminUsername:', current.adminUsername || '(none)');

  // 3. Build settings baru
  const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  const newSettings = {
    ...current,                          // pertahankan data yang ada (produk, pakasir key, dll)
    siteName: SITE_NAME,
    gamePanelName: SITE_NAME,
    about: `${SITE_NAME} — platform topup game & premium app termurah #1 Indonesia. Proses instan, pembayaran QRIS aman.`,
    marqueeText: 'TOPUP GAME & PREMIUM APP TERMURAH - PROSES CEPAT & AMAN',
    contact: {
      whatsapp: current.contact?.whatsapp || WA_NUMBER,
      telegram: current.contact?.telegram || WA_TELEGRAM,
      email: current.contact?.email || 'support@franzzstore.id',
      youtube: current.contact?.youtube || YOUTUBE_URL,
      waChannel: current.contact?.waChannel || WA_CHANNEL,
      waGroup: current.contact?.waGroup || WA_GROUP,
    },
    adminUsername: ADMIN_USERNAME,
    adminPassword: adminHash,
    logoUrl: logoUrl || current.logoUrl || '/uploads/logo-main.png',
    logoTextUrl: logoTextUrl || (current.logoTextUrl === '/uploads/logo-text.png' ? null : current.logoTextUrl),
    buyerGroupName: current.buyerGroupName || 'BUYER VIP FRANZZSTORE',
    buyerGroupUrl: current.buyerGroupUrl || 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
    resellerGroupName: current.resellerGroupName || 'RESELLER VIP FRANZZSTORE',
    resellerGroupUrl: current.resellerGroupUrl || 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
    categories: current.categories || ['freefire','mlbb','pubgm','genshin','valorant','premium'],
    categoryLabels: current.categoryLabels || {
      freefire:'FREE FIRE', mlbb:'MOBILE LEGENDS', pubgm:'PUBG MOBILE', genshin:'GENSHIN IMPACT', valorant:'VALORANT', premium:'PREMIUM APP'
    },
    resellerEnabled: true,
    resellerPrice: current.resellerPrice ?? 50000,
    resellerDiscount: current.resellerDiscount ?? 20,
    resellerNote: current.resellerNote || 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: current.popularProductIds || [],
    // Kalau admin sudah pernah isi manual lewat Admin Panel, JANGAN ditimpa --
    // paymentMethods hasil upload placeholder cuma dipakai kalau belum ada
    // sama sekali (current.paymentMethods kosong/belum diset).
    paymentMethods: (current.paymentMethods && current.paymentMethods.length) ? current.paymentMethods : paymentMethods,
    pakasir: current.pakasir || { apiKey:'', project:'', mode:'production' },
    banners: current.banners?.length ? current.banners : [
      { url: bannerUrl || '/uploads/banner-reseller.jpg', title: 'Open Reseller', link: '/reseller', active: true }
    ],
  };

  // 4. Upsert ke Supabase
  const { error } = await supabase
    .from('keyvalue_store')
    .upsert({ key: 'settings.json', value: newSettings }, { onConflict: 'key' });

  if (error) {
    console.error('❌ Gagal simpan ke Supabase:', error.message);
    process.exit(1);
  }

  // 5. Verifikasi
  const { data: v } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const saved = v?.value;

  console.log('\n✅ BERHASIL disimpan ke Supabase!');
  console.log('┌─────────────────────────────────────────');
  console.log('│ siteName     :', saved?.siteName);
  console.log('│ adminUsername:', saved?.adminUsername);
  console.log('│ logoUrl      :', saved?.logoUrl);
  console.log('│ whatsapp     :', saved?.contact?.whatsapp);
  console.log('│ banners      :', saved?.banners?.length ?? 0, 'item(s)');
  console.log('│ paymentMethods:', saved?.paymentMethods?.length ?? 0, 'item(s)');
  console.log('│ hash verify  :', bcrypt.compareSync(ADMIN_PASSWORD, saved?.adminPassword || '') ? '✅ OK' : '❌ GAGAL');
  console.log('└─────────────────────────────────────────');
  if (Object.keys(productImageUrls).length) {
    console.log('\n🖼️  Placeholder gambar produk (upload manual ke tiap produk lewat Admin');
    console.log('   Panel > Produk > Edit kalau mau ganti dengan artwork resmi):');
    Object.entries(productImageUrls).forEach(([name, url]) => console.log(`   - ${name}: ${url}`));
  }
  console.log(`\n🔐 Login admin: username=${ADMIN_USERNAME}  password=(dari .env, tidak ditampilkan)`);
  console.log('🌐 Deploy ulang Vercel agar settings baru aktif.\n');
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
