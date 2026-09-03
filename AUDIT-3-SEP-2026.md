# Audit Keamanan & Backend — 3 September 2026

Semua temuan di bawah sudah diperbaiki di project ini. Urutan sesuai prioritas.

## 🔴 KRITIS — Kredensial admin hardcoded (SUDAH DIPERBAIKI)
`seed-settings.js` dan `reset-admin.js` sebelumnya punya default fallback:
```js
const ADMIN_USERNAME = process.env.SEED_ADMIN_USERNAME || 'Abdurahman Mulvi Tarakan';
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD || 'Tarakan11#';
```
Kredensial ini nangkring di source code — siapa pun yang dapat salinan project ini otomatis tahu password admin. `QUICK_START.txt` juga mendokumentasikan nilai yang sama sebagai contoh.

**Perbaikan:** kedua script sekarang WAJIB dapat `SEED_ADMIN_USERNAME`/`SEED_ADMIN_PASSWORD` dari `.env` — tidak ada default sama sekali, script berhenti dengan pesan jelas kalau belum diisi. `QUICK_START.txt` sudah discrub, tidak menampilkan kredensial asli lagi.

**⚠️ TINDAKAN YANG WAJIB KAMU LAKUKAN SENDIRI:** kalau password `Tarakan11#` ini PERNAH benar-benar dipakai untuk login admin di production, anggap sudah bocor — segera ganti lewat Admin Panel → Settings → Kredensial Admin, dan jangan pernah pakai password yang sama lagi di tempat lain.

## 🟠 Dependency rentan (SUDAH DIPERBAIKI)
- `sharp` `^0.33.5` → `^0.35.4` — versi lama kena beberapa CVE high-severity di libvips (image processing library yang langsung memproses gambar upload dari user).
- `qs`/`body-parser`/`express` — dibenerin lewat field `overrides` di `package.json` (express & body-parser pin `qs` ke range `~6.15.1` yang masih kena advisory, jadi dipaksa naik ke `^6.16.0`).
- `express-session` dihapus dari `package.json` — dependency mati, tidak dipakai sama sekali di kode (project pakai `cookie-session`).
- `engines.node` dinaikkan ke `>=18.17.0` (sharp 0.35 butuh Node 18+).
- Hasil `npm audit` sekarang: **0 vulnerabilities**.

Kalau deploy ulang, jalankan `npm install` dulu (bukan cuma pull kode) supaya `package-lock.json` ke-generate ulang sesuai versi baru.

## 🟠 Payment gateway Pakasir — tidak ada webhook (SUDAH DIPERBAIKI)
Sebelumnya Pakasir (gateway aktif) cuma diverifikasi lewat polling `/check-payment` yang dipicu browser. Kalau pembeli bayar lalu langsung tutup tab sebelum polling sempat nangkep status sukses, order nyangkut "pending" selamanya sampai admin cek manual — beda dengan GensPay yang sudah punya webhook.

**Perbaikan:** endpoint baru `POST /webhook/pakasir` ditambahkan. Didesain aman meski format signature resmi Pakasir belum sempat dipastikan ulang saat audit ini ditulis: webhook HANYA dipakai sebagai pemicu ("coba cek order ini"), status finalnya selalu di-double-check lewat API resmi Pakasir pakai API key kita sendiri sebelum order difinalisasi — jadi tetap aman walau ada yang kirim POST palsu ke endpoint ini.

**Tindakan yang perlu kamu lakukan:** buka dashboard Pakasir (app.pakasir.com) → project kamu → cari kolom Webhook/Callback URL (kalau tersedia) → isi dengan `https://domainkamu.com/webhook/pakasir`. Polling `/check-payment` tetap aktif sebagai fallback kalau fitur ini belum/tidak ada di Pakasir.

## 🟠 Race condition saldo & stok key lintas-instance Vercel (SUDAH DIPERBAIKI)
Vercel menjalankan banyak instance serverless yang tidak berbagi memori. Lock in-memory (`walletLocks`, `processingOrders`) cuma melindungi 1 instance — dua request nyaris bersamaan yang jatuh ke instance berbeda secara teori bisa lolos dan menyebabkan saldo terpotong/terkredit dua kali, atau key yang sama terjual dua kali.

**Perbaikan:** fungsi baru `atomicUpdate()` di `supabase.js` — compare-and-swap di level baris Postgres (baca fresh, ubah, tulis HANYA jika data belum berubah sejak dibaca; kalau konflik, otomatis retry). Diterapkan di:
- `/wallet/buy` — potong saldo
- `finalizeOrder()` — kredit saldo top up & potong stok key (dipakai bareng oleh `/check-payment`, `/webhook/genspay`, dan `/webhook/pakasir` yang baru)

## 🟡 Tidak ada `.gitignore` (SUDAH DIPERBAIKI)
Folder `database/*.json` (password hash user, nomor WA, riwayat transaksi) sebelumnya tidak dikecualikan — kalau project ini pernah di-push ke git repo, data itu ikut bocor. `.gitignore` baru sudah dibuat, mengecualikan `database/`, `.env`, `node_modules/`, dan folder upload lokal.

## 🟢 Minor — perbandingan SETUP_SECRET (SUDAH DIPERBAIKI)
`/franzzstore-setup` dan `/admin/migrate-images` sebelumnya pakai `!==` biasa untuk cek secret. Sekarang pakai `timingSafeStringEqual()` (berbasis `crypto.timingSafeEqual`) untuk mencegah timing attack, meski risikonya kecil karena endpoint ini cuma dipakai sekali/jarang.

---

## Belum/tidak dikerjakan (di luar scope audit ini)
- **UI/UX** — sesuai obrolan awal, difokuskan ke backend & keamanan dulu, bukan tampilan.
- **Migrasi dari model JSON blob ke tabel relasional** — `atomicUpdate` sudah menutup race condition tanpa perlu ubah skema, tapi kalau traffic makin besar, model "1 file = 1 kolom jsonb besar" ini pada akhirnya akan jadi bottleneck (`.eq('value', current)` pada `atomicUpdate` mengirim seluruh isi file lewat query — bisa jadi berat kalau `users.json`/`products.json` sudah sangat besar). Ini pertimbangan jangka panjang, bukan bug yang mendesak sekarang.
