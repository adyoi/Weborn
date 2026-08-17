# Changelog

All notable changes to Weborn will be documented in this file.

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
