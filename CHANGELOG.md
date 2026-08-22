# Changelog

All notable changes to Weborn will be documented in this file.

## [1.0.0] - 2026-08-21

### Added
- **Process Manager Config**: Edit worker count, timeout, worker class, max requests, graceful timeout, keep alive, access log per app
- **Resource Limits (systemd)**: MemoryMax, CPUQuota, Nice, OOMScoreAdjust per app
- **Process Config API**: `GET/POST /apps/{id}/process-config`, `POST /apps/{id}/limits`
- **Graceful Reload**: SIGHUP reload without restart (`POST /apps/{id}/reload`)
- **Process Status WebSocket**: `GET /ws/apps/{id}/process-status` (2s interval), `GET /ws/apps/all-status` (3s interval)
- **Process Manager UI**: Full edit page with process config + resource limits panels, worker count + timeout in apps list
- **Session Idle Lock**: Configurable per-user timeout (`session_timeout` column), idle check in `get_current_user()`, touch on login
- **Session Timeout UI**: Timeout column in panel accounts, ⏱️ modal to set timeout per user

### Fixed
- **Dashboard Downtime**: `_get_panel_start()` uses parent process creation time (uvicorn reloader) so `--reload` doesn't reset clock
- **Email Install Commands**: All `apt-get install` in `bash -c` now use `sudo` — previously silently failed with permission denied
- **Email Status Detection**: Fixed wrong binary names (`clamav-daemon`→`clamd`, `spamassassin`→`spamc`); roundcube uses directory check (`/var/lib/roundcube`)
- **Email Unit Names**: Roundcube service check uses `apache2` (not `roundcube` which doesn't exist on Debian)
- **Email Mailbox Creation**: Added `sudo` to `useradd`, `chpasswd`, `mkdir`, `chown` in account creation
- **Email Setup Wizard**: Added `sudo` to hostname, sed, mkdir, systemctl commands
- **Self-Deactivate Guard**: Panel users can't deactivate or delete themselves
- **Last Admin Guard**: Prevents deleting the last admin user
- **PostgreSQL CREATE USER**: Uses double quotes for identifiers instead of single quotes

### Changed
- **Bootstrap**: No longer auto-creates `admin`/`admin` OS user; only creates `www-data` service user
- **Executor Timeout**: Command timeout increased to 60s with 1MB output cap
- **Executor**: Uses `asyncio.wait_for` with kill on timeout

### Added
- **JWT Authentication**: Stateless JWT tokens replace Starlette session cookies — simpler decode, no DB session table needed for auth
- **Weborn Panel Card**: Status badge, PID, Trace Log button, detail page (`/apps/panel/monitor`)
- **Panel Self-Monitoring**: Detects own process (Gunicorn/Uvicorn/Python), shows workers, CPU, MEM
- **Orphan Detection**: Finds unmanaged gunicorn/uvicorn processes with recursive PID collection
- **Kill Orphan APIs**: Single kill (`POST /api/monitor/kill-orphan`) and Kill All (`POST /api/monitor/kill-all-orphans`)
- **WebSocket Auth**: JWT-based auth on all WebSocket endpoints (terminal, app logs, panel logs)
- **CSRF Protection**: CSRF token middleware + auto-inject in all POST forms via JavaScript
- **Rate Limiting**: Login rate limit — 5 failed attempts per IP per 5 minutes
- **Session Cookie Hardening**: `httponly`, `max_age=24h`, `secure` flag when SSL enabled
- **Shell Injection Fix**: `shlex.quote()` applied consistently to security.py, apps.py, email.py, managers/apps.py
- **Test Page Split**: Separated into Python Packages + Linux Packages tables with version detection
- **Changelog Markdown**: Renders CHANGELOG.md as HTML via marked.js CDN
- **SSL Support**: `--ssl-cert` / `--ssl-key` flags with automatic `secure` cookie flag
- **Port Auto-Kill**: `weborn.py` kills existing process on same port before starting

### Fixed
- **WebSocket Cookie Decode**: Use `TimestampSigner` + `base64` + `json.loads` (matches Starlette format)
- **Route Conflict**: `/apps/panel/monitor` registered before `/apps/{app_id}/monitor`
- **xterm.js Trace Log**: Removed `scale(.97)` CSS transform from modal — root cause of staircase text
- **Worker Detection**: Simplified to single-level `ps --ppid` — workers are children of bash (MainPID)
- **async def run_checks**: Fixed syntax error in info.py test route
- **CSS import fix**: csrf.py `from ..db` → `from .db`

### Changed
- **Route**: `/apps/monitor/{id}` → `/apps/{id}/monitor` (all template links updated)
- **Worker detection**: `get_process_status()` uses single-level `ps --ppid MainPID`
- **Removed mistune**: Changelog uses marked.js CDN instead of Python markdown library
- **Removed pty from requirements.txt**: Linux-only stdlib module, not installable via pip

### Removed
- **Starlette SessionMiddleware**: Replaced with JWT cookie auth (PyJWT)
- **itsdangerous**: No longer needed — JWT uses PyJWT instead

### Security
- **C1**: Shell injection — all user input in `bash -c` f-strings now uses `shlex.quote()`
- **C2/C3/C4**: WebSocket terminal, app logs, panel logs — all validate JWT before accepting
- **H1**: CSRF middleware validates tokens on all POST form submissions
- **H2**: JWT cookie `httponly`, `max_age=24h`, `secure` when SSL
- **H5**: Login rate limiting — 5 failed attempts per IP per 5 minutes
- **Auth**: Stateless JWT (HS256) — no server-side session storage needed

## [0.3.0] - 2026-08-18

### Added
- **Popular Frameworks**: Added 11 new frameworks
  - Python: Litestar, Sanic, Tornado, Pyramid, Bottle
  - PHP: Symfony, CodeIgniter, Slim
  - Node.js: NestJS, Hono, SvelteKit, Astro
- **Type Filtering**: Filter apps by WSGI/ASGI/Flask/Django/FastAPI/Node.js/Laravel
- **Duplicate Name Check**: Clear error message when app name already exists
- **Starter Files**: Added starter stubs for all new frameworks

### Fixed
- **UNIQUE constraint error**: App creation now checks for duplicate names before insert
- **Shell injection**: Email account creation uses `shlex.quote()` for security
- **Navigation guard**: Only blocks reload/close when process succeeds (not on failure)
- **run_raw() bug**: Replaced with `run()` in apps.py for log streaming

### Changed
- **App Types**: Added APP_TYPES for Litestar, Sanic, Tornado, Pyramid, Bottle
- **Framework Detection**: Updated `_app_type_for()` to handle all new frameworks

## [0.2.0] - 2026-08-17

### Added
- **Panel Accounts**: Change password modal, toggle active/inactive, login log
- **OS Users (Akun & Hak Akses)**: Added RDP/SFTP/VNC/NFS/FTP/Telnet access checkboxes
- **Settings**: File size display, .env badge, `/opt/weborn/.env` example
- **Error Handling**: `friendlyError()` mapper for permission denied, command not found, etc.
- **Dashboard**: App count from DB, Panel Users card, service table with start/stop/restart
- **Addon Store**: Status legend bar, UNKNOWN/FAILED explanations
- **5 New Addons**: Docker, Supervisor, UFW, Git, Logrotate (39 total)

### Fixed
- **weborn.action() undefined** → `weborn.simplePost()`
- **Email setup FormData not sent** → pass FormData to streamPost
- **testNginx calls wrong endpoint** → simplified, no longer uses `.then()`
- **Duplicate ufw** in LocalExecutor privileged set
- **Duplicate /apps** in sidebar

## [0.1.0] - 2026-08-16

### Added
- **Gunicorn Architecture**: `Nginx → Gunicorn → UvicornWorker/sync workers → app`
- **Web Server Management**: Nginx, PHP-FPM, Cache pages
- **App Monitor**: Worker status, log streaming
- **Security**: Firewall, Fail2Ban, ClamAV with progress modals
- **Email Stack**: Postfix + Dovecot + Rspamd + OpenDKIM + Roundcube
- **Email Setup Wizard**: StreamPost with FormData, progress modal
- **Webmail**: Install Roundcube action with progress modal
- **Email Service Control**: Start/stop/restart for all email services
- **Menu Restructured**: 7 groups (Beranda, Web Server, Database, Mail Server, Weborn, Monitoring, Access & Security)
- **Browser Navigation Guard**: Blocks reload/close when process running
- **Addons**: 35 builtin addons with manifest system
- **Setup Wizard**: Creates panel user + Linux OS user with sudo/SSH access
- **Terminal WebSocket**: Remote terminal access
- **App Logs**: Streaming via SSE/WebSocket

### Changed
- **Form Controls**: Compact padding, `.sm` variant
- **Status Indicators**: Active (green), inactive/stop (gray), failed/error (red)
- **All POST endpoints return JSON** (not redirects) for progress modals

### Fixed
- **Navigation guard**: Only blocks when process succeeds
- **Shell injection**: Email account creation uses `shlex.quote()`
- **Duplicate items**: Removed duplicate ufw, duplicate /apps link
