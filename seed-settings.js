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

// ── KREDENSIAL DIAMBIL DARI .env, JANGAN DI-HARDCODE DI SINI ──
// Isi ADMIN_USERNAME dan ADMIN_PASSWORD di file .env lokal kamu
// (file .env tidak ikut ke-push ke GitHub karena ada di .gitignore).
const ADMIN_USERNAME = process.env.SEED_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD;
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error('❌ Set SEED_ADMIN_USERNAME dan SEED_ADMIN_PASSWORD di file .env lokal dulu (jangan di-hardcode di script ini).');
  process.exit(1);
}
const SITE_NAME      = 'FRANZZSTORE';
const WA_NUMBER      = '6285133408356';
const WA_CHANNEL     = '0029VbC4ZyhCcW4sLQRefe3s';
const APK_CHANNEL    = '0029VbChj7435fM1YttT8n40';
const TIKTOK_USER    = 'franzzstore';
// ─────────────────────────────────────────────────────────

async function uploadLogo() {
  const logoPath = path.join(__dirname, 'public', 'uploads', 'logo-franzzstore.png');
  if (!fs.existsSync(logoPath)) {
    console.log('⚠️  Logo file tidak ditemukan di public/uploads/logo-franzzstore.png, skip upload.');
    return null;
  }
  const fileBuffer = fs.readFileSync(logoPath);

  // Cek apakah sudah ada di storage
  const { data: existList } = await supabase.storage
    .from('product-images').list('', { search: 'logo-franzzstore.png' });
  if (existList && existList.length > 0) {
    const { data: { publicUrl } } = supabase.storage
      .from('product-images').getPublicUrl('logo-franzzstore.png');
    console.log('ℹ️  Logo sudah ada di storage:', publicUrl);
    return publicUrl;
  }

  const { error } = await supabase.storage
    .from('product-images')
    .upload('logo-franzzstore.png', fileBuffer, { contentType: 'image/png', upsert: true });

  if (error) {
    console.error('⚠️  Gagal upload logo ke storage:', error.message);
    return null;
  }
  const { data: { publicUrl } } = supabase.storage
    .from('product-images').getPublicUrl('logo-franzzstore.png');
  console.log('✅ Logo diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  FRANZZSTORE — Seed Settings ke Supabase');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // 1. Upload logo
  const logoUrl = await uploadLogo();

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
    about: `${SITE_NAME} adalah Top Up Game & Marketplace Jual Beli Akun #1 di Indonesia — proses cepat, harga bersaing, dan 100% aman.`,
    marqueeText: 'TOP UP GAME • JUAL BELI AKUN • PROSES CEPAT & AMAN - FRANZZSTORE #BANYAKUNTUNGNYA',
    contact: {
      whatsapp: WA_NUMBER,
      telegram: WA_CHANNEL,
      tiktok: TIKTOK_USER,
      apkChannel: APK_CHANNEL,
      email: 'support@franzzstore.web.id'
    },
    adminUsername: ADMIN_USERNAME,
    adminPassword: adminHash,
    adminLockEnabled: current.adminLockEnabled !== undefined ? current.adminLockEnabled : true,
    logoUrl: logoUrl || current.logoUrl || '/uploads/logo-franzzstore.png',
    faviconUrl: current.faviconUrl || '/uploads/favicon-franzzstore.png',
    theme: current.theme || {
      primaryColor: '#2DEEFF',
      secondaryColor: '#4CF5FF',
      accentColor: '#78FFFF',
      backgroundColor: '#05070B',
      cardBackground: '#111B26',
      borderColor: 'rgba(45,238,255,.18)',
      glowColor: 'rgba(45,238,255,0.55)'
    },
    categories: current.categories || ['freefire','mlbb','pubgm','sertifikat'],
    categoryLabels: current.categoryLabels || {
      freefire:'FREE FIRE', mlbb:'MOBILE LEGENDS', pubgm:'PUBG MOBILE', sertifikat:'SERTIFIKAT'
    },
    resellerEnabled: true,
    resellerPrice: current.resellerPrice ?? 50000,
    resellerDiscount: current.resellerDiscount ?? 20,
    resellerNote: current.resellerNote || 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: current.popularProductIds || [],
    pakasir: current.pakasir || { apiKey:'', project:'', mode:'production' },
    banners: current.banners?.length ? current.banners : [
      {
        id: 'banner-default-1',
        imageUrl: '/uploads/banners/banner-1.jpg',
        title: 'Buy Key Game Paling Murah & Aman',
        subtitle: 'TOP 1 VIP Mods Indonesia — Key Instan, 100% Aman & Bergaransi',
        link: '/',
        active: true,
        createdAt: new Date().toISOString()
      },
      {
        id: 'banner-default-2',
        imageUrl: '/uploads/banners/banner-2.jpg',
        title: 'Semua Akses Dalam 1 Tempat',
        subtitle: 'Mudah, Cepat & Terpercaya — Channel WA, TikTok & Download APK',
        link: '/reseller',
        active: true,
        createdAt: new Date().toISOString()
      }
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
  console.log('│ hash verify  :', bcrypt.compareSync(ADMIN_PASSWORD, saved?.adminPassword || '') ? '✅ OK' : '❌ GAGAL');
  console.log('└─────────────────────────────────────────');
  console.log(`\n🔐 Login admin: username=${ADMIN_USERNAME}  password=(dari .env, tidak ditampilkan)`);
  console.log('🌐 Deploy ulang Vercel agar settings baru aktif.\n');
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
