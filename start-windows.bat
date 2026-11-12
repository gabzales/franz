@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".env" (
  echo [!] File .env belum ada. Menyalin dari .env.example ...
  copy ".env.example" ".env" >nul
  echo [!] Buka file .env, isi SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY dan SESSION_SECRET, lalu jalankan file ini lagi.
  notepad ".env"
  pause
  exit /b
)
if not exist "node_modules" (
  echo [*] Install dependensi pertama kali, tunggu sebentar ...
  call npm install
)
echo [*] Menjalankan server ...
node server.js
pause
