# Weborn

<p align="center">
  <img src="assets/weborn-logo.png" alt="Weborn logo" width="620" />
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB" />
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Ready-009688" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-8A2BE2" />
  <img alt="GitHub Actions" src="https://github.com/adyoi/Weborn/workflows/CI/badge.svg" />
</p>

Weborn is a self-hosted control panel for running, securing, and managing server-side services from one clean dashboard. It provides a unified interface for application deployment, domain management, database administration, monitoring, security hardening, and system operations.

## Architecture

```
Client (Browser)
  │
  ├─ Nginx (Port 80/443) — Reverse Proxy + Static File Server
  │   ├─ Static files → direct serve
  │   ├─ PHP/Laravel → PHP-FPM (unix socket)
  │   ├─ Python WSGI → Gunicorn (sync workers) → Django/Flask
  │   ├─ Python ASGI → Gunicorn + UvicornWorker → FastAPI
  │   └─ Node.js → reverse proxy port
  │
  ├─ Gunicorn — Process Manager
  │   ├─ WSGI: gunicorn main:app -w 4 --bind unix:/run/gunicorn/{name}.sock
  │   └─ ASGI: gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:/run/gunicorn/{name}.sock
  │
  └─ Weborn Panel (Port 2025) — Control Panel UI
      ├─ WSGI mode: Nginx → Gunicorn → FastAPI app
      └─ ASGI mode: Nginx → Gunicorn (uvicorn workers) → FastAPI app
```

## What's New

- **Gunicorn as Process Manager** — All Python apps (WSGI/ASGI) run through Gunicorn for stable process management with async I/O
- **Browser Navigation Guard** — Prevents accidental page reload/close during running processes
- **Mail Server Stack** — Postfix + Dovecot + Rspamd + OpenDKIM + Roundcube with automated setup wizard
- **Web Server Management** — Nginx, PHP-FPM, Redis/Memcached control pages
- **Process Monitor** — Real-time Gunicorn worker status (PID, CPU%, MEM%, uptime)
- **Admin Setup Creates Linux User** — Setup wizard creates panel account + Linux OS user with sudo/SSH
- **Interactive WebSocket Terminal** — Real PTY shell via xterm.js
- **Addon Store with 35 Addons** — 7 categories × 5 addons each

## Key Features

### 🏠 Dashboard & System
- Real-time system monitoring (CPU, RAM, Disk)
- Service status overview
- OS information and package management

### 📦 Application Management
- Create isolated apps with dedicated user, directory, and socket
- **WSGI (Gunicorn sync workers)** — Django, Flask
- **ASGI (Gunicorn + UvicornWorker)** — FastAPI, Starlette
- **PHP (PHP-FPM)** — Laravel, WordPress
- **Node.js (direct process)** — Express, Next.js, Fastify
- **Static (Nginx direct)** — HTML/CSS/JS sites
- Framework presets with auto-generated Nginx configs
- Real-time log streaming via WebSocket

### 🌐 Web Server
- **Nginx** — Reverse proxy, static files, site config management
- **PHP-FPM** — FastCGI Process Manager for PHP apps
- **Cache** — Redis (object cache + sessions) and Memcached
- SSL/TLS via Let's Encrypt (Certbot)
- Reverse proxy support

### 🗄️ Database Management
- **MariaDB/MySQL** — User management, database CRUD
- **PostgreSQL** — Full management
- **MongoDB** — NoSQL management
- **Redis** — Cache & session store
- **Memcached** — Lightweight cache

### 📧 Mail Server
- **Postfix** (SMTP) — Port 25/587/465
- **Dovecot** (IMAP/POP3) — Port 143/993/110/995
- **Rspamd** — Modern anti-spam with ML scoring
- **SpamAssassin** — Legacy spam filter (alternative)
- **OpenDKIM** — DKIM signing for email authentication
- **SPF/DMARC** — DNS-based email authentication
- **Roundcube** — Web-based email client
- Automated setup wizard with DNS record generation

### 🔒 Security
- **UFW** — Firewall rule management
- **Fail2Ban** — Intrusion prevention
- **ClamAV** — Antivirus scanning (system + mail)
- **Backup** — System backup and restore

### 📊 Monitoring
- Centralized log viewer
- Process viewer (psutil)
- Cron job scheduling
- Network monitoring

### 💻 Remote Access
- WebSocket terminal (PTY-based)
- File explorer with edit/chown/chmod
- SSH user management
- OS user management

## Menu Structure

| Group | Items |
|-------|-------|
| **Beranda** | Dashboard, Aplikasi, Addon Store |
| **Web Server** | Domain & DNS, Nginx, PHP-FPM, Cache, Reverse Proxy |
| **Database** | MariaDB, PostgreSQL, MongoDB, Redis, Memcached |
| **Mail Server** | Overview, Mailbox, Mail DNS, Webmail, Spam & DKIM |
| **Weborn** | WSGI Apps, ASGI Apps, Process Monitor |
| **Monitoring** | Logs, Proses, Network, Paket, Cron |
| **Access & Security** | Terminal, File Explorer, Users, Services, Firewall, Fail2Ban, ClamAV, Backup, Settings |

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, SQLite, Jinja2
- **Frontend:** Tailwind CSS, xterm.js, WebSocket
- **Process Manager:** Gunicorn (WSGI) + UvicornWorker (ASGI)
- **Web Server:** Nginx (reverse proxy)
- **Mail:** Postfix + Dovecot + Rspamd + OpenDKIM + Roundcube
- **System:** systemd, psutil
- **Executor Modes:** Local (Linux), WSL, Dry-run (Windows dev)

## Requirements

- Python 3.10 or newer
- `pip`
- Linux or WSL recommended for full local execution
- Root access for privileged system tasks when using `--local`

## Quick Start

```bash
# 1 Clone the repository
git clone https://github.com/adyoi/Weborn.git
cd Weborn

# 2 Create and activate a virtual environment
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# 3 Install dependencies
pip install -r requirements.txt

# 4 (Optional) Build Tailwind CSS assets
npm install
npm run css:build

# 5 Run the dashboard
# Development / dry-run (works on Windows)
python run.py --reload --host 127.0.0.1 --port 2025

# Full system execution on Linux/WSL (requires sudo)
sudo python run.py --local --host 0.0.0.0 --port 2025
```

Open the dashboard in your browser:

```text
http://127.0.0.1:2025
```

## First-Time Setup

1. Open the panel in your browser
2. You'll be redirected to `/setup` (first-time wizard)
3. Enter username and password (min 6 characters)
4. Panel creates:
   - Panel admin account (SQLite)
   - Linux OS user with sudo/SSH access
5. Login with your new credentials

## App Deployment Flow

When you create an app through the panel:

```
1. Panel creates OS user (weborn-{name})
2. Panel creates directory (/var/www/{name})
3. Panel writes starter file (main.py, server.js, etc.)
4. Panel installs dependencies (pip install, npm install)
5. Panel writes .env config
6. Panel writes systemd unit (weborn-{name}.service)
7. Panel generates Nginx site config
8. Panel enables & starts the service
```

For Python apps, Gunicorn is the process manager:

```bash
# WSGI (Django/Flask)
gunicorn main:app -w 4 --bind unix:/run/gunicorn/{name}.sock

# ASGI (FastAPI)
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:/run/gunicorn/{name}.sock
```

## Executor Modes

| Mode | Description |
|------|-------------|
| `local` | Direct execution on Linux (requires root) |
| `wsl` | Execute via WSL distro (Debian default) |
| `dry-run` | Simulate commands without execution (Windows dev) |

Auto-detection: Linux → `local`, Windows → `dry-run`

Set via environment variable:
```bash
export WEBORN_EXECUTOR_MODE=local
# or
export WEBORN_EXECUTOR_MODE=wsl
export WEBORN_WSL_DISTRO=Debian
```

## Frontend Build

```bash
npm install
npm run css:build     # Build CSS
npm run css:watch     # Watch for changes
```

## Installer

On Debian/Ubuntu, install Weborn with:

```bash
sudo bash install.sh
```

- Installs the service under `/opt/weborn`
- Creates the required `data/backups` directory
- Adds a systemd unit (`weborn.service`) and reloads the daemon

To remove:

```bash
sudo bash uninstall.sh
```

## Security Note

Weborn creates Linux users with sudo privileges during setup. In production:
- Use strong passwords
- Configure SSH key authentication
- Enable firewall (UFW)
- Run behind a reverse proxy with HTTPS
- Regularly update packages

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes and ensure the code follows existing style (PEP 8)
4. Commit with a clear message
5. Open a Pull Request against the `main` branch

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
