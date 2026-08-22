# Weborn — Workflow Dokumentasi

## Setup Awal
1. Install dependensi: `pip install -r requirements.txt`
2. Build CSS: `npm install && npm run css:build`
3. Jalankan panel: `python weborn.py --reload --local`
4. Buka browser ke `http://localhost:2025`
5. Isi form setup wizard (buat akun admin pertama + Linux OS user)
6. Login dengan akun yang baru dibuat
7. Setelah setup, semua Linux user bisa login dengan password OS mereka (PAM fallback)

## Menu & Fitur

### 🏠 Dashboard (`/`)
- Ringkasan sistem: CPU, RAM, disk usage
- Statistik aplikasi: total, running, stopped, jumlah panel users
- Status layanan utama (Nginx, MariaDB, Redis) dengan start/stop/restart

### 🧩 Addon Store (`/addons`)
- 39 addon terbagi 7 kategori: Web Server, Database, Mail, Remote Access, Security, Runtime, Monitoring
- Filter berdasarkan kategori, status instalasi, pencarian
- Setiap addon: Install → Config → Update → Start/Stop/Restart → Uninstall

### 🌐 Web Server

#### Domain & DNS (`/domains`, `/dns`)
- **Tambah domain**: isi nama, document root, tipe app, port
- **Edit domain**: klik ✏️ → ubah document root / tipe app / port
- **SSL**: klik 🔒 → otomatis terbitkan Let's Encrypt
- **Toggle**: aktifkan/nonaktifkan domain
- **Hapus**: klik 🗑 → hapus domain + config Nginx

#### Nginx (`/nginx`)
- Manage Nginx config, start/stop/restart, view status

#### PHP-FPM (`/php`)
- Manage PHP-FPM versions, start/stop/restart

#### Cache (`/cache`)
- Redis & Memcached management

#### Reverse Proxy (`/reverse-proxy`)
- Buat reverse proxy ke port backend

### 🗄️ Database

#### MariaDB (`/mariadb`)
- User management, database CRUD, start/stop/restart

#### PostgreSQL (`/postgresql`)
- User management, database CRUD, start/stop/restart

#### MongoDB (`/mongodb`)
- NoSQL management

#### Redis (`/redis`)
- Cache & session store, start/stop/restart

#### Memcached (`/memcached`)
- Lightweight cache

### 📧 Mail Server

#### Overview (`/email`)
- Status semua komponen mail (Postfix, Dovecot, Rspamd, OpenDKIM, Roundcube, SpamAssassin)
- Setup Wizard: pilih domain → Install & Konfigurasi otomatis
- Quick actions: Start/Stop/Restart per service

#### Mailbox (`/email/accounts`)
- Create/delete mailboxes, change passwords
- Auto-creates Linux user + Maildir structure

#### Mail DNS (`/email/dns`)
- Auto-generate SPF, DKIM, DMARC, MX records

#### Webmail (`/email/webmail`)
- Install & manage Roundcube webmail
- Status detection via `/var/lib/roundcube` directory check

#### Spam & DKIM (`/email/security`)
- Install Rspamd, ClamAV, SpamAssassin, OpenDKIM stack
- Start/Stop/Restart per service

### 📦 Weborn (App Management)

#### WSGI Apps (`/apps/wsgi`)
- Buat app Python WSGI (Django, Flask, Pyramid, Bottle, Tornado)
- Gunicorn sync workers → unix socket

#### ASGI Apps (`/apps/asgi`)
- Buat app Python ASGI (FastAPI, Litestar, Sanic)
- Gunicorn + UvicornWorker → unix socket, atau Uvicorn standalone

#### App Edit (`/apps/{id}/edit`)
- Edit konfigurasi app: name, domain, port, framework, document root
- **Process Manager Config**: workers, timeout, worker class, max requests, graceful timeout, keep alive, access log
- **Resource Limits**: memory limit (MemoryMax), CPU quota (CPUQuota), nice, OOM score
- Quick actions: Start, Stop, Restart, Reload (SIGHUP)

#### Process Monitor (`/apps/monitor`)
- Worker status real-time (PID, CPU%, MEM%, uptime)
- Start / Stop / Restart / Reload controls
- **Trace Log**: Live xterm.js log streaming via WebSocket
- **Weborn Panel**: Self-monitoring (panel card → detail page)
- **Orphan Detection**: Rogue processes + kill APIs
- **Real-time WebSocket**: Auto-refresh via `/ws/apps/all-status` (3s interval)
- **Per-app WebSocket**: `/ws/apps/{id}/process-status` (2s interval)

### 📊 Monitoring

#### Logs (`/logs`)
- Lihat log Nginx, PHP-FPM, MySQL, sistem, panel

#### Proses (`/processes`)
- Lihat & manage proses via psutil

#### Network (`/network`)
- Traffic monitor

#### Paket (`/packages`)
- Lihat versi Python packages (uvicorn, gunicorn, fastapi, jinja2)
- Lihat versi Linux packages (Node.js, Nginx, MariaDB, PostgreSQL, PHP, Git)
- Status instalasi tiap paket

#### Cron (`/cron`)
- Jadwalkan task otomatis (backup, cleanup, dll)

### 🔐 Access & Security

#### Terminal (`/terminal`)
- WebSocket terminal (PTY-based) via xterm.js

#### File Explorer (`/files`)
- Browse & edit file, download/upload, chmod/chown

#### OS Users (`/users`)
- Manage Linux OS users, lock/unlock, SSH/SFTP/RDP/VNC/NFS/FTP access

#### Panel Users (`/panel-users`)
- Manage panel accounts (admin/user), change password, toggle active/inactive
- Session timeout: set idle timeout per user (default 300 detik)

#### Services (`/services`)
- System services status, start/stop/restart

#### Firewall (`/firewall`)
- UFW rules: allow/block ports, status

#### Fail2Ban (`/fail2ban`)
- Ban/unban IPs, jail status

#### ClamAV (`/clamav`)
- Antivirus scanning (system + mail)

#### Backup (`/backup`)
- Buat backup: centang situs (/var/www) + database panel
- Restore: restore situs + DB
- Download: unduh file backup
- Hapus: hapus backup

#### Settings (`/settings`)
- Panel settings, executor mode, .env config

### ℹ️ Info

#### About (`/info/about`)
- Info panel: versi, framework, Python, mode eksekusi

#### Changelog (`/info/changelog`)
- Riwayat perubahan versi (markdown → HTML via marked.js)

#### Test (`/info/test`)
- Test status Python packages (uvicorn, gunicorn, fastapi, jinja2)
- Test status Linux packages (Node.js, Nginx, MariaDB, PostgreSQL, PHP, Git, Disk, Memory)

## Keamanan

| Fitur | Deskripsi |
|-------|-----------|
| **CSRF** | HMAC-based tokens pada semua form POST + AJAX header |
| **JWT Auth** | Stateless HS256 tokens di HTTP-only cookies, 24h expiry |
| **WebSocket Auth** | JWT validation sebelum menerima koneksi |
| **Rate Limiting** | 5 percobaan login per IP per 5 menit |
| **Session Hardening** | `httponly`, `max_age=24h`, `secure` saat SSL |
| **Session Idle Lock** | Timeout per-user, auto-lock sesi tidak aktif |
| **Shell Injection** | `shlex.quote()` pada semua user input di bash commands |
| **Password Hashing** | PBKDF2-SHA256 (SQLite) + PAM shadow users |
| **Audit Trail** | Login logs dengan IP, timestamp, success/fail |

## Mode Eksekusi

| Mode | Deskripsi |
|------|-----------|
| `local` | Eksekusi langsung di Linux (butuh root) |
| `wsl` | Eksekusi via WSL distro (default: Debian) |
| `dry-run` | Simulasi tanpa eksekusi (Windows dev) |

Auto-detection: Linux → `local`, Windows → `dry-run`

```bash
export WEBORN_EXECUTOR_MODE=local
export WEBORN_EXECUTOR_MODE=wsl
export WEBORN_WSL_DISTRO=Debian
```

## Tips

### Port Default
- Panel: 2025
- Nginx: 80/443
- MariaDB: 3306
- App default: 8000-8999

### SSL
```bash
# Self-signed
python weborn.py --local --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem

# Let's Encrypt
certbot certonly --standalone -d yourdomain.com
python weborn.py --local --ssl-cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem --ssl-key /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

### PAM Authentication
- Panel user pertama dibuat via setup wizard
- Setelah itu, semua Linux user bisa login dengan password OS
- Root hanya bisa login setelah admin panel user sudah ada

### Backup Location
- File backup tersimpan di `data/backups/`

### Frontend Build
```bash
npm install
npm run css:build     # Build CSS
npm run css:watch     # Watch for changes
```
