# FranzzStore — Panduan Setup Singkat

## 1. Jalankan di komputer
1. Install Node.js (versi LTS) dari nodejs.org.
2. Klik dua kali `start-windows.bat` (Windows). Pertama kali ia akan membuat file `.env` dan membukanya.
3. Isi di `.env`: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SESSION_SECRET`
   (buat secret: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`).
4. Di Supabase → SQL Editor, jalankan isi `supabase-schema.sql` (sekali saja).
5. Jalankan `start-windows.bat` lagi. Server aktif di `http://localhost:3000`.

Cara manual: `npm install` lalu `node server.js`.

## 2. Masuk admin
- Alamat: `/vpr-secure-panel-8x` (bukan tombol "Masuk" di navbar).
- Login pertama: pakai `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` dari `.env`.
  Kalau kosong, password acak dicetak sekali di terminal saat server pertama jalan.
- Lupa password: isi `SEED_ADMIN_USERNAME` dan `SEED_ADMIN_PASSWORD` di `.env`, lalu `node reset-admin.js`.
- Hanya 1 perangkat admin sekaligus. Kalau login saat panel dipakai perangkat lain,
  klik "Ambil alih & masuk". Logout resmi (`/logout`) melepas kunci langsung.

## 3. Checklist sebelum diserahkan ke client
- [ ] Ganti username admin dan password admin (Admin Panel → Settings)
- [ ] Upload logo asli (sekarang masih logo sementara "FZ")
- [ ] Isi kunci pembayaran (Pakasir / GensPay) dan layanan lain (Haybi, SMSCode, Fonnte)
- [ ] Isi produk (`node seed.js` untuk contoh, atau tambah manual)
- [ ] Isi kontak WhatsApp / Telegram dan link grup
- [ ] Aktifkan captcha: `TURNSTILE_SITE_KEY` + `TURNSTILE_SECRET_KEY` (keduanya harus terisi)
- [ ] Di production: `SETUP_SECRET` dikosongkan, `NODE_ENV=production`
- [ ] Jangan kirim folder `database/` atau file `.env` ke siapa pun

Dokumen lama yang tumpang tindih dipindah ke `docs/arsip/`.
