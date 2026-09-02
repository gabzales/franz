# Progres Rebranding Angga/ViprneStore → Franzzstore

Referensi prompt asli: `prompt_rebranding_franzzstore.md` (di luar folder project ini).

## ✅ SEMUA ITEM TODO SELESAI

Rekap lengkap seluruh pekerjaan (gabungan sesi-sesi Claude sebelumnya + sesi ini):

1. **Aset logo** — `logo-franzzstore.png` & `favicon-franzzstore.png` sudah ada di `public/uploads/`.
2. **Rebrand nama & konten di `server.js`** — `siteName`/`gamePanelName` FRANZZSTORE, `about`/`marqueeText`, email kontak, `logoUrl`/`faviconUrl` — semua sudah diarahkan ke aset baru.
3. **Tema warna** — dark UI abu-abu (`#24272B`/`#2E3237`/dst) sudah aktif di `views/layout.ejs` (variabel CSS `--bg-main` dkk) dan `settings.theme` di `server.js`. Meta `theme-color` juga sudah `#24272B`.
4. **Kategori & banner default** — kategori "akun" (Jual Beli Akun) sudah menggantikan "sertifikat", teks banner default sudah tema Top Up & Jual Beli Akun.
5. **Form Top Up (ID Server/User ID + Nickname)**:
   - Backend `POST /create-order` mewajibkan `gameUserId` & `gameNickname` untuk semua produk kecuali kategori `akun`.
   - Field HTML di `buy.ejs` sudah ada, dan sekarang **disembunyikan total** kalau `product.category === 'akun'` (fix bug inkonsistensi sebelumnya).
   - Label Nickname sudah wajib (bukan lagi "opsional"), sesuai validasi backend.
   - `handleOrder()` di-guard null-safe + validasi kondisional berdasarkan `PCATEGORY`.
   - Ditampilkan di `invoice.ejs`, `admin.ejs` (card transaksi), dan `dashboard.ejs` (riwayat transaksi ringkas).
6. **Fitur "Jual Beli Akun" — backend & frontend lengkap**:
   - Routes backend: listing publik, detail, form submit, riwayat user, moderasi admin (approve/reject/sold/delete) — semua sudah ada dan sudah diverifikasi (`node -c server.js` OK).
   - `views/pages/jual-beli-akun.ejs` — grid listing + filter game. ✅
   - `views/pages/akun-detail.ejs` — detail akun + tombol WA ke penjual. ✅
   - `views/pages/jual-akun-form.ejs` — **(dibuat sesi ini)** form submit akun baru (game, judul, deskripsi, harga, WA, upload multi-foto via FormData), validasi client-side lengkap, redirect ke `/dashboard/jual-akun` setelah sukses. ✅
   - `views/pages/akun-saya.ejs` — **(dibuat sesi ini)** riwayat listing akun milik user dengan badge status (pending/approved/rejected+alasan/sold). ✅
   - **Section moderasi Admin Panel** — **(dibuat sesi ini)** `#pane-accounts` di `views/pages/admin.ejs` sekarang berisi list semua listing (filter Semua/Pending/Approved/Terjual) + tombol Approve, Reject (dengan input alasan), Tandai Terjual, Hapus — semua terhubung ke endpoint backend yang sudah ada, dengan update UI optimis (badge & tombol berubah tanpa reload).
7. **Ukuran & posisi logo** — semua halaman (`layout.ejs`, `buy.ejs`, `invoice.ejs`, `home.ejs`, `leaderboard.ejs`, `reseller.ejs`, `akun-detail.ejs`, `jual-beli-akun.ejs`) sekarang konsisten pakai `height:44px`. `login.ejs`/`register.ejs` sudah 56px (cukup besar, tidak diubah).
8. **Animasi banner ala pointgo.id — (dipoles sesi ini)**:
   - Ditambahkan aksen background diagonal stripes biru (`#carousel-wrap::before`, `repeating-linear-gradient` -45deg, warna brand `rgba(19,216,255,.05)`).
   - Ditambahkan efek shimmer/skeleton loading (`#carousel-skeleton`, animasi `shimmerSweep`) yang tampil saat banner masih fetch dari `/api/banners`, otomatis hilang begitu data siap.
9. **Rebrand teks yang tersisa di file lain — SEMUA SUDAH BERSIH**:
   - `seed-settings.js` — `SITE_NAME`, path logo, email, handle TikTok, `about`/`marqueeText` sudah disamakan dengan default `server.js`.
   - `seed.js` — testimonial dummy "anggavipstore" → "franzzstore".
   - Semua file di `views/` dicek dengan `grep -rni "angga\|viprne" views/ server.js supabase.js seed.js seed-settings.js package.json` → **hasil 0** (bersih total, terakhir diverifikasi sesi ini).
10. **`package.json`** — `name` → `franzzstore-backend`, `description` & `author` sudah Franzzstore.
11. **Card promosi "Jual Beli Akun" di `home.ejs`** — **(ditambahkan sesi ini)** section CTA baru (gaya sama seperti promo Reseller VIP) di antara section reseller dan footer, mengarah ke `/jual-beli-akun`.
12. **Navigasi ke fitur Jual Beli Akun** — link sudah ada di menu drawer (`layout.ejs`) + card promosi baru di homepage (poin 11).

## Validasi yang sudah dijalankan

- `node -c server.js` → **OK**, tidak ada syntax error.
- Cek keseimbangan tag `<% %>` di semua file EJS yang diedit sesi ini (`admin.ejs`, `home.ejs`, `buy.ejs`, `dashboard.ejs`, `jual-akun-form.ejs`, `akun-saya.ejs`, `akun-detail.ejs`, `jual-beli-akun.ejs`) → semua seimbang (mismatch 1 di `admin.ejs` sudah ada sejak sebelum sesi ini, bukan dari perubahan baru — kemungkinan false-positive dari karakter `%>` di dalam string JS, bukan bug fungsional).
- Grep menyeluruh sisa teks brand lama → 0 hasil relevan.

## Sisa yang disarankan sebelum production (bukan bug, tapi manual test)

Karena tidak ada akses server/browser di lingkungan pengerjaan ini, disarankan untuk test manual sebelum deploy:
1. Alur beli produk **top up game** — pastikan field ID Server/Nickname muncul & wajib diisi.
2. Alur beli/lihat **akun** (kategori `akun`) — pastikan field ID Server/Nickname **tidak muncul** sama sekali.
3. Alur **jual akun baru** dari `/jual-beli-akun-jual` — submit form, cek redirect ke `/dashboard/jual-akun`, cek status "pending" muncul di `akun-saya.ejs`.
4. Alur **admin approve/reject/sold/delete** di tab "Akun" — pastikan badge & tombol berubah sesuai aksi tanpa perlu reload halaman.
5. Cek tampilan carousel banner di homepage — skeleton shimmer muncul sekilas lalu banner asli muncul, dan aksen diagonal stripes terlihat halus di background.
