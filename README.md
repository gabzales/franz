# FRANZZ Orbit Web (Vercel, tanpa database)

Struktur: `public/` (halaman statis, dilayani CDN, tidak dihitung invocation), `api/[name].js` (satu function untuk semua
`/api/*`), `lib/` (logika), `vercel.json` (region, batas durasi, header keamanan). Tanpa dependensi npm dan tanpa database.

## Setup
1. Push proyek ini ke GitHub (repo private).
2. Vercel: Add New > Project > import repo. Framework Preset **Other**, Build Command kosong, Output Directory biarkan (otomatis `public`).
3. Environment Variables (Production), tandai **Sensitive**, lalu Deploy:

| Variabel | Wajib | Isi |
|---|---|---|
| `SESSION_SECRET` | Ya | Acak, minimal 32 karakter. Buat: `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Ya | Akun untuk masuk. Ganti password = ubah variabel, deploy ulang, semua sesi lama hangus |
| `GEMINI_API_KEY` | Ya (untuk fitur AI) | API key Gemini |
| `GEMINI_MODEL`, `GEMINI_FALLBACK_MODEL` | Tidak | Model utama dan cadangan. Cadangan dipakai otomatis bila model utama kena batas (429) |

4. Buka situs dan login dengan `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Tidak ada layar setup.
5. Aplikasi Android: login dengan alamat situs ini, username, dan password admin.

Kalau deploy gagal karena `regions`, hapus baris `"regions"` di `vercel.json` (isinya `sin1`, Singapura, terdekat dari Jakarta).

## Chat AI dan situs lain
- **Chat AI**: tombol "Chat AI" di bar atas. Percakapan multi-giliran (12 pesan terakhir dikirim ke AI), tidak disimpan di server.
  Kalau ada halaman terbuka (mode baca) atau datang dari bookmark Orbit, isinya bisa disertakan sebagai konteks (bisa dimatikan).
  Teks halaman diperlakukan sebagai data tidak tepercaya. Satu pesan = satu hitungan kuota harian pengguna biasa; admin tanpa batas.
- **Bookmark Orbit (situs apa saja)**: Pengaturan > "Pakai di situs lain", seret tombol **Orbit** ke bar bookmark. Di situs mana pun,
  termasuk yang butuh login atau dirender JavaScript, klik bookmark itu. Orbit membaca teks dan kolom isian di halaman (dari browser kamu sendiri,
  jadi sesi login ikut), membuka jendela Orbit dengan chat AI, dan tombol **Isi kolom di halaman**: AI menjawab dulu, kamu lihat jawabannya,
  lalu **Terapkan ke halaman** mengisi kolom (teks, pilihan tunggal/ganda, dropdown). Tombol Kirim di situs itu tetap kamu tekan sendiri.
- Jendela Orbit hanya menerima data dari halaman yang membukanya, dan jawaban hanya dikirim balik ke halaman itu setelah kamu menekan Terapkan.
- Batas: situs yang memblokir bookmarklet (CSP ketat) atau memutus hubungan antar jendela (COOP) tidak bisa; widget pilihan buatan sendiri
  (bukan input HTML biasa) tidak terdeteksi sebagai kolom, tapi isi halamannya tetap bisa ditanyakan lewat chat. Perlu izin popup. Hanya browser desktop.

## Mode tanpa database
Semua pengaturan ada di Environment Variables, jadi tidak ada layanan tambahan. Konsekuensinya:
- **Satu akun admin** (dari env). Tidak ada tambah pengguna, kuota per pengguna, atau panel Admin (tombol Admin disembunyikan).
- Sesi bertanda tangan dan diverifikasi tanpa penyimpanan. Berlaku 12 jam.
- Pengunci login (5 salah = kunci 5 menit) disimpan di memori instance, jadi sifatnya best effort. Pakai password yang kuat.
- Mau banyak pengguna atau pengaturan lewat panel: perlu penyimpanan tetap (database). Tidak dipasang di versi ini.

## Hemat kuota gratis
- Hobby: sekitar 1 juta invocation, 100 GB transfer, dan 4 jam CPU aktif per bulan; melewati batas tidak ditagih, project dijeda.
  **Hobby hanya untuk pemakaian pribadi non-komersial.** Untuk klien berbayar, pakai Pro.
- Halaman dan gambar adalah file statis (cache), bukan function. Satu function melayani semua API, `maxDuration` 30 detik.
- Jangan aktifkan Analytics/Speed Insights, Cron, atau Image Optimization kalau tidak perlu.
- Satu kali "Isi otomatis" memakai beberapa permintaan Gemini bila soalnya banyak (dipecah per 8 soal). Isi `GEMINI_FALLBACK_MODEL` agar tidak mentok 429.

## Keamanan
- Rahasia hanya di Environment Variables, tidak ada di kode atau repo. API key Gemini tidak pernah dikirim ke browser atau APK.
- Token sesi bertanda tangan (HMAC) dan terikat ke password admin: ganti `ADMIN_PASSWORD` mencabut semua sesi.
- Password yang diketik hanya dikirim lewat HTTPS saat login dan tidak disimpan. Token disimpan di browser (localStorage) / APK (Android Keystore).
- Header keamanan (vercel.json): Content-Security-Policy, X-Frame-Options DENY, nosniff, no-referrer.

## Lihat dan analisis halaman web apa saja
Tempel link situs apa saja di kolom atas (link Google Form tetap diisi otomatis):
- Kalau situs mengizinkan, halamannya tampil langsung di dalam FRANZZ Orbit.
- Kalau situs melarang ditampilkan di halaman lain (`X-Frame-Options` atau `frame-ancestors`), server mengambil isinya dan
  menampilkannya sebagai teks bacaan, lengkap dengan daftar kolom dan pertanyaan yang terdeteksi dari HTML-nya.
- Tombol **Analisis halaman (AI)** merangkum halaman dan menjawab pertanyaanmu tentang isinya. AI tidak menjawab soal ujian atau kuis bernilai.

Keamanan pengambil halaman: wajib login; hanya http/https di port 80/443/8080/8443; alamat internal (localhost, 10.x, 192.168.x,
169.254.x, dll.) ditolak termasuk lewat pengalihan dan DNS; ukuran maksimal 2 MB; batas waktu total 8 detik; maksimal 100 halaman per
pengguna per hari (admin tanpa batas). Analisis AI memakai kuota AI harian pengguna.

Batasan: halaman yang dirender dengan JavaScript atau butuh login hanya menampilkan sedikit teks; kolom form terdeteksi dari HTML
awal saja; isi otomatis di web tetap hanya untuk Google Forms. Untuk situs lain yang berisi form biasa, pakai aplikasi Android.

## Kecepatan
Mode berpikir Gemini diturunkan otomatis (Gemini 3: `thinkingLevel: low`, Gemini 2.x: `thinkingBudget: 0`;
diulang tanpa pengaturan itu bila model menolak). Soal lebih dari 8 dipecah dan dikirim paralel (maks 3 sekaligus).

## Batasan
- Hanya Google Forms publik di versi web. Situs lain: pakai aplikasi Android.
- Satu admin (dari env). Tidak ada kelola pengguna dan panel Admin karena tanpa database (lihat di atas).
- Tidak ada lanjut otomatis antar halaman di web.
- Parser membaca struktur internal Google Forms yang bisa berubah sewaktu-waktu.

## Tes lokal
`npm test` (data tiruan; belum diuji ke Vercel atau Google Forms asli).
