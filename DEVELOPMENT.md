# DEVELOPMENT.md

Panduan teknis untuk melanjutkan pengembangan Weborn — arsitektur, konvensi kode, cara menjalankan/menguji/deploy, dan jebakan (gotchas) penting.

## 1. Ringkasan Proyek

Weborn adalah control panel self-hosted untuk menjalankan & mengelola layanan server (app WSGI/ASGI/PHP/Node/static, domain, database, mail, keamanan, monitoring) lewat satu dashboard.

- **Backend:** Python 3.10+ · FastAPI · Jinja2 server-render · SQLite · PyJWT
- **Frontend:** Tailwind (built), HTMX-style utilitas kecil `panel.js`, xterm.js (terminal & log), chart sederhana
- **Process manager:** Gunicorn (WSGI) / Uvicorn (ASGI), systemd unit per app
- **Web server:** Nginx (reverse proxy + static)
- **Eksekutor:** abstraksi `LocalExecutor` (Linux) / `WslExecutor` / `DryRunExecutor` (Windows dev)

## 2. Struktur Direktori

```
weborn/
  main.py            # create_app(), lifespan, mount router, bootstrap www-data
  config.py          # konstanta: port 2025, path, WEB_ROOT, APP_TYPES, FRAMEWORKS
  db.py              # lapisan SQLite (users, apps, settings, audit, sessions)
  auth.py            # JWT HS256 cookie, RBAC, session idle lock, PAM fallback
  csrf.py            # CSRFMiddleware + generate/verify token (HMAC, terikat session)
  ratelimit.py       # sliding-window per key (login 5/5m)
  ui.py              # render() — inject csrf_token, user, menu, flash ke template
  executors/         # Local/Wsl/DryRun executor + redaksi password di audit log
  managers/          # domain logic: apps, accounts(OS user), backup, cron, nginx
  routers/           # endpoint HTTP+WS per fitur: apps, appmonitor, auth, accounts,
                     # addons, database, email, files, info, network, security,
                     # settings, system, terminal, webservers, ...
  templates/         # Jinja2 (extends base.html), id template: panel_*.html (JS util)
  static/js/panel.js # helper weborn.* : toast, modal, simplePost, streamPost
  static/css/        # style.css + tailwind.* (build via `npm run css:build`)
engine/ scripts/     # skrip pendukung (jalur instalasi/internal)
data/                # SQLite + log + backup (gitignore) — WAL mode
test/                # 5 file test unit (stdlib unittest) + run_tests.py
assets/              # logo SVG + weborn-shots/ (screenshot README)
install.sh update.sh uninstall.sh
```

## 3. Model Eksekusi (PENTING)

Semua operasi sistem (memulai service, instal paket, tulis file) **tidak pernah** dipanggil langsung dari router — selalu lewat `weborn.executors`:

```python
from ..executors import get_executor
ex = get_executor()                    # auto-deteksi: Linux→local, Windows→dry-run
r = await ex.run("systemctl", "start", unit)
r = await ex.write_file(path, content) # otomatis sudo -u owner untuk file app
```

- Executor di-set via env `WEBORN_EXECUTOR_MODE=local|wsl|dry-run`
- `DryRunExecutor` membungkus `cmdline` dengan `shlex.quote` (trace aman & teraudit)
- **Redaksi audit log:** pola password di `echo ... | chpasswd` otomatis disembunyikan; tambahkan pola baru di `executors/__init__.py` bila menambah command berisi kredensial.
- Konvensi argumen: jangan gabung jadi string bash lalu `sh -c`, kirim argv list ke `run(...)` (setara `subprocess.run(argv)`). Hanya untuk skrip kompleks boleh `bash -c` dengan `shlex.quote()` setiap variabel interpolasi.

## 4. Template & Frontend Conventions

- Semua template `{% extends "base.html" %}`; `base.html` menyuntik hidden input CSRF `<input name="_csrf_token">` secara global.
- Helper JS `weborn.*` di `static/js/panel.js`:
  - `weborn.simplePost(url, title, reload, body?)` — POST JSON + header `X-CSRF-Token`; body opsional (FormData/string).
  - `weborn.streamPost(url, title, reload, body?)` — POST dengan progress (SSE/stream).
  - `weborn.toast(msg, kind)`, `weborn.modal.open/close`, `weborn.confirmAction`.
- **Wajib:** JANGAN pakai `|tojson` di HTML — output JSON ber-delimiter `"` memotong atribut `onclick`/`data-*` (`Unexpected end of input`). Nilai dinamis untuk JS ditaruh di atribut `data-*` (autoescape `{{ x }}` aman di sana; dataset membacanya sebagai teks ter-decode) lalu handler di-bind via `addEventListener`. ID int aman tanpa filter.
- Route URL dinamis gunakan `{{ x|urlencode }}`; jangan interpolasi mentah. Di fetch client, encode dengan `encodeURIComponent()`.
- Nama input form konsisten dengan `request.form.get(...)`. Untuk POST fetch, kirim `FormData` (bukan JSON.stringify) agar cocok `form()`.

## 5. Keamanan (checklist commit)

- Path traversal: validasi `[A-Za-z0-9._-]+` pada name yang dipakai di path (site, mailbox, app name).
- Shell injection: `shlex.quote()` semua input user yang masuk bash.
- CSRF: semua POST form/fetch wajib token `X-CSRF-Token` (didapat dari hidden input). Endpoint `/ws/*` dichain CSRF (WebSocket pakai auth cookie sendiri).
- Session: cookie `weborn_session`, `httponly`, `samesite=lax`, `secure` bila SSL; idle lock per-user (`session_timeout`).
- Rate limit: login 5/5m/IP; API sensitif diattach `RateLimiter`.
- Password policy admin panel: ≥8 char + upper + lower + digit + simbol.
- Jangan pernah commit `data/weborn.db`, `.env`, isi `node_modules/`, `__pycache__`, `.tgrep/`, `.git-rewrite/`.

## 6. Menjalankan di Lingkungan Pengembangan

### Windows (dry-run)
```powershell
python weborn.py --host 127.0.0.1 --port 2025      # executor dry-run, operasi sistem disimulasikan
```

### Linux/WSL (full)
```bash
sudo python weborn.py --local --host 0.0.0.0 --port 2025
```

### Menjalankan suite unit (stdlib, tanpa pytest)
```bash
sudo -E ./.venv/bin/python test/run_tests.py        # 52 test
```

### Deploy ke /opt/weborn
```bash
sudo bash update.sh      # tar-sync (exclude .git, data, .venv*, __pycache__, node_modules, *.sqlite3) + pip install + restart service
sudo bash update.sh --no-restart
```

## 7. Verifikasi (lakukan sebelum commit)

```bash
# 1) Syntax check file Python yang diubah
python -m py_compile <file.py>  # di Windows cukup

# 2) Unit test di WSL (deploy dulu via update.sh)
wsl -d Debian -- sh -c "cd /opt/weborn && sudo -E ./.venv/bin/python test/run_tests.py"

# 3) Smoke test fungsional live (skrip di /tmp, jalankan sebagai root)
#    - login → GET /apps,/dashboard,/monitor/apps cek marker
#    - POST dengan header X-CSRF-Token → bukan 403
#    - WebSocket terminal /ws/term echo
```

Catatan khusus lingkungan uji (lihat AGENTS.md item gotchas).

## 8. Menambah Fitur Baru

1. **Router:** buat `weborn/routers/<fitur>.py` (APIRouter + depend `require_user/require_admin`), register di `main.py`.
2. **Manager `async def`:** taruh logika sistem di `weborn/managers/<fitur>.py`, return dict; router cukup parse → render.
   - Operasi blocking (baca proses, psutil) bungkus `await asyncio.to_thread(...)` agar tidak memblokir event loop.
3. **Template:** extends base.html; gunakan helper JS; nilai dinamis ke JS via atribut `data-*` + `addEventListener` (larang `|tojson`).
4. **Submit:** jika POST via fetch → sertakan header CSRF; bentuk FormData. Jika form HTML biasa → cukup `method=post` (CSRF auto-inject).
5. **Command lama:** jalankan lewat executor (bukan subprocess langsung) supaya mode dry-run & audit tetap bekerja.
6. **Test:** tambah kasus di `test/test_<fitur>*.py` mengikuti gaya unittest yang ada.

## 9. Gotchas yang Sudah Dialami

- **SQLite WAL:** koneksi read-only ke `data/weborn.db` gagal "attempt to write a readonly database" (butuh `-shm`/`-wal` writable). Selalu akses DB sebagai root pada deploy.
- **`create-native` lambat (>30s):** endpoint menciptakan venv+pip+systemctl; HTTP client timeout wajib ≥180s.
- **WSL networking (mirrored):** Windows **tidak** dapat menjangkau port WSL via localhost/LAN. Untuk akses dari Windows gunakan: `wsl -- sh -c "ssh -L ..."`, forward via Windows EXE dalam WSL, atau jalankan browser di dalam WSL (lihat AGENTS.md metode screenshot CDP).
- **`os._exit`:** branch child process (fork/exec) wajib `_exit`, jangan `exit()`.
- **Journalctl streaming:** gunakan `stderr=DEVNULL` agar pipe tidak tersumbat.
- **Upload/download biner:** jangan lewati `str`/`echo`; pakai `base64` + decouple response.
- **Aplikasi hasil delete:** folder `/var/www/<name>` sengaja dipertahankan (hanya unit/user/venv yang dihapus).
- **Autentikasi halaman untuk test/screenshot:** mint token lewat `weborn.auth.encode_jwt(1, "admin", "admin")` — tanpa perlu password (secret dari DB).
- **Dovecot 2.4:** plugin dikonfigurasi per-protocol (`mail_plugins { ... }`); blok `protocol lda` **menimpa** global — bila ingin kuota di LDA, sertakan `quota = yes` di dalamnya, bukan hanya global.
- **passwd-file kuota:** kolom extra `userdb_quota_storage_size=<Q>`; userdb username = alamat lengkap (`admin@localhost`) sehingga pipe LDA memakai `-d ${user}@${domain}`.
- **OpenDKIM (daemon root):** kunci & direktori harus owned `root` mode `0700` (bukan `opendkim:opendkim`) bila tidak → `key data is not secure` dan milter tempfail (451). Soket di `/var/spool/postfix/opendkim` perlu dir setgid grup `postfix` agar postfix (user `postfix`) bisa connect (kalau tidak: `Permission denied`, rantai milter dihentikan postfix).
- **`milter_default_action = accept`:** bila milter error/timeout, email TETAP diterima tanpa header DKIM/spam — selalu cek header saat verifikasi.
- **`opendkim-genkey`** menghasilkan `weborn.private` (prefix selector); rename ke `{domain}.weborn.private` agar cocok dengan `KeyTable` template.

## 10. Roadmap Terdekat (item terbuka)

- Eksekusi `bash -c` di `_write_unit` sudah dibungkus `shlex.quote(home)` — pantau room untuk komado app custom lain.
- Pertimbangkan registrasi addon penuh (API `addons/`) + tes integrasi.
- Pertimbangkan instalasi `D:\localhost\pyth-webapps` (FastAPI/PostgreSQL, port 8080) sebagai referensi vendor-integration.

## 11. Email Stack (Postfix + Dovecot) — Catatan Implementasi

Semua logika ada di `weborn/routers/email.py`; template UI `weborn/templates/email_*.html`; konfigurasi layanan dirender dari `weborn/addons/templates/` (`postfix-main.cf.j2`, `dovecot-*.j2`, `opendkim-*.j2`, `rspamd-local.conf.j2`, `opendkim.conf.j2`).

### Model multi-domain
- Daftar domain disimpan di setting `mail_domains` (JSON). `_apply_mail_domains(names)` menulis `virtual_mailbox_domains` + TLS ke `main.cf`; `localhost` selalu primary (ssl dir `/etc/ssl/mail.<primary>`).
- Menambah domain (`/email/domains/add`) → seed mailbox owner + insert DNS records (MX/A/SPF/DMARC); menghapus domain harus bersih dari mailbox (proteksi di `email_domain_delete`).
- Perangkap: relasi di `/etc/postfix/virtual` dievaluasi LEBIH dulu daripada mailbox (Postfix `virtual_alias` > mailbox lookup). Domain ber-catchall membutuhkan **alias identitas** `user@domain → user@domain` untuk tiap mailbox agar alamat asli tidak tertelan catch-all (`_write_virtual_map`).

### Virtual mailbox + kuota
- Penyimpanan: `passwd-file` — `email:{hash}:{uid}:{gid}::{home}:/usr/sbin/nologin[:userdb_quota_storage_size=...]`. Kuota di setting `mail_quota:<email>` (format `1G/500M/K`); `_apply_mail_quota_conf()` menulis `dovecot-90-quota.conf` + memastikan `10-mail.conf` memuat blok proteksi.
- Enforcement: `quota-status` (SMTP 552) hanya menolak sender non-mynetworks; sender lokal lolos `permit_mynetworks`. Pengiriman lewat LDA (`protocol lda` + plugin quota) menjamin lokal juga dibatasi.
- Autoresponder: sieve vacation di `.dovecot.sieve` per user (setting `mail_vacation:<email>` = JSON `{subject,message}`).

### Milter (DKIM + anti-spam)
- `smtpd_milters` di `postfix-main.cf.j2`: `local:opendkim/opendkim.sock inet:localhost:11332`.
- OpenDKIM: KeyTable/SigningTable per domain (`weborn._domainkey.<d>`), kunci `{domain}.weborn.private` (owner root — lihat gotcha), socket dir setgid `postfix`.
- Rspamd: `worker rspamd_proxy (11332)` milter = yes; threshold `add header` default 6.0; verifikasi tampak lewat `rspamc` atau log `rspamd.log` (`proxy_milter_finish_handler`).
- Klien port: submission `587` (STARTTLS) + submissions `465` (TLS wrap) disediakan `_ensure_postfix_master()` — SASL via dovecot `private/auth`.

### Publikasi DNS
- `/email/dns` menyimpan panduan di tabel `dns_records` (MX `10 mail.<d>`, A `mail.<d>`, SPF, DKIM `weborn._domainkey.<d>` TXT, DMARC). Setup otomatis mengisi MX/A/SPF/DMARC + DKIM TXT dari file `.txt` publik key. Publikasi ke DNS provider tetap manual oleh user.