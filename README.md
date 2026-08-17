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

Weborn is a self‑hosted control panel for running, securing, and managing server‑side services from one clean dashboard. It provides a unified interface for application deployment, domain management, database administration, monitoring, security hardening, and system operations.

## What's New (2026‑08‑17)

- **Admin Setup Creates Linux User** — Setup wizard now creates both panel account and Linux OS user with sudo/SSH access
- **Interactive WebSocket Terminal** — Real PTY shell via xterm.js, not just a form-based command runner
- **App Access Links** — Direct browser links after app installation (`http://localhost:{port}`)
- **App Log Streaming** — Real-time log monitoring via WebSocket for each application
- **WSGI/ASGI Runtime Support** — Gunicorn (WSGI) and Uvicorn (ASGI) app types
- **Addon Store with 35 Addons** — 7 categories × 5 addons each
- **Restructured Menu** — 10 organized groups for better navigation
- **Domain & App Edit Routes** — Full CRUD for domains and applications
- **Proper 404 Pages** — Custom error pages instead of JSON responses
- **Backup DB Restore** — Database checkbox included in backup restore
- **WORKFLOW.md** — Complete admin workflow documentation

## Why Weborn?

Weborn is built for system administrators and developers who want a single pane of glass for server management. Instead of juggling multiple tools for deployments, DNS, databases, monitoring, and security — Weborn brings everything together in one clean, modern interface.

## Key Features

### 🏠 Dashboard & System
- Real-time system monitoring (CPU, RAM, Disk)
- Service status overview (Nginx, Apache, MySQL, PostgreSQL, etc.)
- OS information and package management

### 📦 Application Management
- Create isolated apps with dedicated user, directory, and port
- Support for Node.js, Python, PHP, Ruby, Go, and Rust
- Framework presets: Express, FastAPI, Django, Flask, Laravel, Next.js, and more
- WSGI (Gunicorn) and ASGI (Uvicorn) runtime modes
- Real-time log streaming via WebSocket
- Direct browser access links

### 🌐 Web Hosting
- Domain management with Nginx config generation
- SSL/TLS via Let's Encrypt (Certbot)
- Reverse proxy and CDN support
- DNS record management (A, CNAME, MX, TXT, NS)

### 🗄️ Database Management
- MySQL/MariaDB administration
- PostgreSQL support via addons
- Redis, MongoDB, Memcached management

### 📧 Mail Services
- Postfix (MTA)
- Dovecot (IMAP/POP3)
- Exim mail transfer
- Roundcube webmail
- SpamAssassin filtering

### 🔒 Security
- Fail2Ban intrusion prevention
- ClamAV antivirus scanning
- AIDE file integrity checking
- Lynis security auditing
- UFW firewall management

### 📊 Monitoring
- Grafana dashboards
- Prometheus metrics
- Netdata real-time monitoring
- Glances system overview
- Centralized log viewer

### 🛠️ Addon Store
- 35 built-in addons across 7 categories
- One-click install/update/uninstall
- Configuration templates with live preview
- Third-party addon support (JSON manifests)
- Streaming SSE progress for operations

### 💻 Remote Access
- SSH user management
- OpenVPN server
- Cockpit web console
- FTP server (vsftpd)
- WebSocket terminal (PTY-based)

### ⚙️ System Administration
- Systemd service management
- Process viewer (psutil)
- Cron job scheduling
- File explorer with edit/chown/chmod
- Config file editor
- Package management

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, SQLite, Jinja2
- **Frontend:** Tailwind CSS, xterm.js, WebSocket
- **System:** systemd, Nginx, Let's Encrypt, psutil
- **Executor Modes:** Local (Linux), WSL, Dry-run (Windows dev)

## Requirements

- Python 3.10 or newer
- `pip`
- Linux or WSL recommended for full local execution
- Root access for privileged system tasks when using `--local`

## Quick Start

```bash
# 1️⃣ Clone the repository
git clone https://github.com/adyoi/Weborn.git
cd Weborn

# 2️⃣ Create and activate a virtual environment
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# 3️⃣ Install dependencies
pip install -r requirements.txt

# 4️⃣ (Optional) Build Tailwind CSS assets
npm install
npm run css:build

# 5️⃣ Run the dashboard
# • Development / dry-run (works on Windows)
python run.py --reload --host 127.0.0.1 --port 2025

# • Full system execution on Linux/WSL (requires sudo)
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

## Frontend Build

Weborn includes Tailwind CSS for the dashboard UI. Rebuild the generated CSS with:

```bash
npm install
npm run css:build
```

Watch for changes while developing:

```bash
npm run css:watch
```

## Installer

On Debian/Ubuntu, install Weborn with:

```bash
sudo bash install.sh
```

- Installs the service under `/opt/weborn`.
- Creates the required `data/backups` directory.
- Adds a systemd unit (`weborn.service`) and reloads the daemon.

To remove the installation:

```bash
sudo bash uninstall.sh
```

## Menu Structure

| Group | Items |
|-------|-------|
| **Beranda** | Dashboard, Aplikasi, Addon Store |
| **Web Server** | Server, Domain, Proxy, CDN, DNS |
| **Database** | MySQL, PostgreSQL, Redis, MongoDB, Memcached |
| **Mail** | Postfix, Dovecot, Exim, Roundcube, SpamAssassin |
| **Monitoring** | Logs, Grafana, Prometheus, Netdata, Glances |
| **Remote Access** | Akun OS, SSH, OpenVPN, Cockpit, FTP |
| **Runtime** | Node.js, Python, PHP, Ruby, Go |
| **Security** | Security, Fail2Ban, ClamAV, AIDE, Lynis |
| **System** | Systemd, Proses, Cron, Files, Terminal |
| **Config** | Settings, Akun Panel, Paket, Network, Backup |

## Executor Modes

| Mode | Description |
|------|-------------|
| `local` | Direct execution on Linux (requires root) |
| `wsl` | Execute via WSL distro (Debian default) |
| `dry-run` | Simulate commands without execution (Windows dev) |

Set via environment variable:
```bash
export WEBORN_EXECUTOR_MODE=local
# or
export WEBORN_EXECUTOR_MODE=wsl
export WEBORN_WSL_DISTRO=Debian
```

## Security Note

Weborn creates Linux users with sudo privileges during setup. In production:
- Use strong passwords
- Configure SSH key authentication
- Enable firewall (UFW)
- Run behind a reverse proxy with HTTPS
- Regularly update packages

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b my-feature`).
3. Make your changes and ensure the code follows existing style (PEP 8).
4. Commit with a clear message.
5. Open a Pull Request against the `main` branch.

## Dashboard Preview

<p align="center">
  <img src="assets/weborn-screenshot.png" alt="Weborn dashboard preview" width="1200" />
</p>

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
