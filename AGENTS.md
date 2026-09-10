# AGENTS.md — Panduan Agen AI (dan Developer) Kontinuitas

File ini dibuat agar developer (atau asisten AI seperti opencode) dapat **langsung melanjutkan** pekerjaan di repo ini tanpa kehilangan konteks. Baca lengkap — terutama bagian "Gotchas" — sebelum mengubah apa pun.

## Mulai Cepat (3 langkah verifikasi wajib)

```bash
# 1. Syntax (Windows OK, tanpa deps)
python -m py_compile weborn.py weborn/**/*.py

# 2. Unit test (WSL, deploy dulu dari repo ke /opt/weborn)
wsl -d Debian -- sh -c "cd /opt/weborn && sudo -E ./.venv/bin/python test/run_tests.py"

# 3. Smoke live (contoh skrip ada di DEVELOPMENT.md §7)
wsl -d Debian -- sh -c "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:2025/login"
```

Jangan commit sebelum 3 langkah di atas lolos. Ikuti pola commit repo: pesan singkat bermakna, satu konsep per commit.

## Peta Cepat File Penting

| File | Peran |
|------|-------|
| `weborn/main.py` | `create_app()`, lifespan (init_db + bootstrap www-data), mount routers |
| `weborn/config.py` | konstanta (port 2025, `SESSION_COOKIE=weborn_session`, `WEB_ROOT`, APP_TYPES) |
| `weborn/db.py` | SQLite (users, apps, settings, audit, sessions); `get_conn()`, dll |
| `weborn/auth.py` | JWT HS256 + cookie + `require_user/require_admin` + idle lock + PAM |
| `weborn/csrf.py` | `CSRFMiddleware` + `generate_csrf_token(jwt)` — header `X-CSRF-Token` |
| `weborn/executors/` | Local/Wsl/DryRun + redaksi password di audit |
| `weborn/managers/` | domain logic (apps, accounts, backup, cron, nginx) |
| `weborn/routers/` | endpoint per fitur |
| `weborn/static/js/panel.js` | helper `weborn.*` (simplePost punya param `body` opsional) |
| `test/run_tests.py` | suite unit (52 test, stdlib) |
| `update.sh` | deploy repo → `/opt/weborn` (tar-sync + pip + restart systemd) |
| `DEVELOPMENT.md` | arsitektur & cara menambah fitur |
| `API.md` | API untuk integrator 3rd party / vendor |
| `SKILL.md` | skill prompt untuk membangun/memanjangkan project |

## Aturan Kerja untuk Agen

1. **Baca sebelum edit.** Gunakan glob/grep dulu; kalau ragu, baca file penuh target.
2. **Jangan rombak yang sehat.** Fokus fix minimal-robust; hindari refactor kosmetik besar tanpa diminta.
3. **Template = nilai dinamis via atribut `data-*` + `addEventListener`;** jangan `|tojson` di HTML (memotong atribut) dan jangan `'{{ x }}'` di string JS.
4. **CSRF:** setiap POST fetch wajib `X-CSRF-Token`; form HTML biasa auto-inject.
5. **Jangan** commit: `data/*.db*`, `.env`, `.tgrep/`, `.git-rewrite/`, `node_modules/`, `__pycache__/`.
6. **Jangan pernah** taruh kredensial/secret di kode atau commit; gunakan env var / tabel settings.
7. Jika mengubah perilaku sistem (unit, nginx, accounts) → selalu uji live sebagai root.

## Gotchas Lingkungan (KRITIS — hemat waktu besar)

- **WSL tidak dapat dijangkau dari Windows** (mode network mirrored, IP sama 192.168.1.7). Akses ke port panel WSL dari Windows TIDAK berfungsi. Jalankan hal-hal yang butuh panel di DALAM WSL.
  - Panel: `http://127.0.0.1:2025` (hanya dari dalam WSL).
  - Screenshot README: chromium di WSL + CDP client Python (`websockets` dari venv `/opt/weborn/.venv`). Contoh: `C:\Users\uci\AppData\Local\Temp\opencode\shots_wsl.py` (pola: mint JWT via `weborn.auth.encode_jwt`, set cookie via CDP).
- **SQLite WAL:** akses DB read-only langsung gagal. Pakai `sudo -E ./.venv/bin/python` untuk query/scripts.
- **Skrip temp:** tulis di `C:\Users\uci\AppData\Local\Temp\opencode\` → `cp` ke `/tmp` WSL di **command yang sama** dengan eksekusi (jangan pisah command; /tmp tiap invocasi kadang tertimpa). Pakai heredoc `python - <<'PY'` untuk kesederhanaan.
- **PowerShell pasang jebakan kutip:** hindari nested double-quote di `wsl -- sh -c "..."`; pakai file .sh di /tmp.
- **`create-native` memakan >30s** — timeout klien HTTP/uji ≥180s.
- **Panel user id 1 = `admin`** (role admin). Password tidak disimpan; bila butuh sesi, mint JWT (bukan login).
- **Chrome/Chromium CDP** perlu `--no-sandbox --remote-allow-origins=*`.
- **Excel/eksekutor `ex.run(argv)`** = argumen list, jangan string bash (kecuali skrip kompleks + `shlex.quote`).

## Checklist Sebelum "Selesai"

- [ ] `py_compile` semua file Python yang disentuh.
- [ ] Unit test 52/52 hijau (deploy dulu via `update.sh`).
- [ ] Smoke live: login + GET utama 200 + POST CSRF bukan 403 + WS `/ws/term` echo.
- [ ] `git status` bersih dari artefak; tanpa secret.
- [ ] Bila fitur/dokumen berubah, refresh README/CHANGELOG/doc terkait.
- [ ] Commit + push hanya jika diminta user.

## Status Terakhir yang Diketahui

- Employ: panel aktif di WSL (`/opt/weborn`, unit `weborn.service`, port 2025, executor local).
- Semua fitur inti diuji: HTTP pages, port-busy 400, terminal WS (banner/echo/resize/exit/no-orphan), panel logs stream, app link (create/edit/monitor/delete).
- Audit keamanan + cleanup + logo SVG + screenshot baru + dokumen (README/DEVELOPMENT/API/SKILL/AGENTS) selesai; menunggu verifikasi akhir & commit/push.
- Item lama terbuka: instalasi `D:\localhost\pyth-webapps` (FastAPI/PostgreSQL:8080).