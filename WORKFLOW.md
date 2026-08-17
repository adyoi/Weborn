# Weborn — Workflow Dokumentasi

## Setup Awal
1. Install dependensi: `pip install -r requirements.txt`
2. Jalankan panel: `python run.py`
3. Buka browser ke `http://localhost:2025`
4. Isi form setup wizard (buat akun admin pertama)
5. Login dengan akun yang baru dibuat

## Menu & Fitur

### 🏠 Dashboard (`/`)
- Ringkasan sistem: CPU, RAM, disk usage
- Status layanan utama (Nginx, MariaDB, Redis)

### 🌐 Web Hosting

#### Domain (`/domains`)
- **Tambah domain**: isi nama, document root, tipe app, port
- **Edit domain**: klik ✏️ → ubah document root / tipe app / port
- **SSL**: klik 🔒 → otomatis terbitkan Let's Encrypt
- **Toggle**: aktifkan/nonaktifkan domain
- **Hapus**: klik 🗑 → hapus domain + config Nginx

#### DNS (`/dns`)
- Kelola record A, CNAME, MX, TXT, NS
- Domain baru otomatis buat A record + CNAME www

#### File Manager (`/files`)
- Browse & edit file di `/var/www/<domain>`

### 📦 Layanan

#### Aplikasi (`/apps`)
- **Buat app**: pilih bahasa (Node/Python/PHP/Go/Ruby/Rust), framework, port
- **Edit app**: klik ✏️ → ubah perintah start
- **Control**: Start ⏸, Stop ⏹, Restart 🔄, Delete 🗑
- Setiap app punya: user OS, direktori, port, .env, unit systemd sendiri

#### Cron Jobs (`/cron`)
- Jadwalkan task otomatis (backup, cleanup, dll)

### 💾 Data

#### Backup (`/backup`)
- **Buat backup**: centang situs (/var/www) + database panel
- **Restore**: klik ↩ → restore situs + DB
- **Download**: klik ⬇ → unduh file backup
- **Hapus**: klik 🗑 → hapus backup

### 📊 Monitor

#### Logs (`/logs`)
- Lihat log Nginx, PHP-FPM, MySQL, sistem

#### Processes (`/processes`)
- Lihat & manage proses via psutil

#### Network (`/network`)
- Traffic monitor + firewall

### 🔐 Akses

#### Panel Accounts (`/panel-accounts`)
- Kelola akun panel (admin/user)
- **Catatan**: panel accounts terpisah dari OS accounts

#### SSH Users (`/ssh`)
- Kelola akses SSH ke server

#### Database (`/database`)
- Kelola MariaDB/MySQL

#### Firewall (`/firewall`)
- Atur rule firewall

### ⚙️ Sistem

#### Backup, Settings, AI Agent
- Pengaturan panel & integrasi AI

## Tips

### Port Default
- Panel: 2025
- Nginx: 80/443
- MariaDB: 3306
- App default: 8000-8999

### Password Panel
- Bisa diubah di menu Panel Accounts
- Tidak terkait dengan akun OS/Linux

### Backup Location
- File backup tersimpan di `data/backups/`
