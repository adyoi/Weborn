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
| `weborn/routers/email.py` | mail stack (Postfix+Dovecot+Rspamd+OpenDKIM+Roundcube + DNS records); `.eml` étape |
| `weborn/static/js/panel.js` | helper `weborn.*` (simplePost punya param `body` opsional) |
| `test/run_tests.py` | suite unit (52 test, stdlib) |
| `update.sh` | deploy repo → `/opt/weborn` (tar-sync + pip + restart systemd) |
| `DEVELOPMENT.md` | arsitektur & cara menambah fitur |
| `WORKFLOW.md` | alur kerja per fitur (bagian email = sesuai menu final panel) |
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
- **OpenDKIM di Debian jalan sebagai root** → kunci harus `root:root` mode `0700` (selain itu: "key data is not secure" → tempfail 451) dan KeyTable menunjuk `{domain}.weborn.private` (rename hasil `opendkim-genkey`). Soket milter: dir `/var/spool/postfix/opendkim` wajib `opendkim:postfix` + setgid `2775` — jika pemilik salah, rantai milter postfix berhenti (DKIM & rspamd tidak diproses). Verifikasi tanda tangan pakai `dkimpy` (bukan `opendkim-testmsg` yang hanya menandatangani); `dnsfunc(name)` mengembalikan satu string nilai TXT.
- **Rspamd via milter proxy** `localhost:11332` + `milter_default_action=accept` (milter error → email tetap diterima, tanpa header). Threshold `Add header` rspamd = 6.0 → mail round-trip normal (skor <6) TIDAK diberi header spam; bukan bug. Uji deteksi manual: `echo ... | rspamc -h 127.0.0.1:11333`.
- **Klien email kirim via 587 STARTTLS / 465 TLS wrap** (SASL Dovecot). Port 25 hanya untuk penerimaan; dari luar WSL tidak ada akses SMTP.
- **DKIM TXT panjang (420 char)** — value di tabel `email_dns.html` di-**slice** (20 char + ellipsis) dengan tooltip `title` nilai utuh; nilai lengkap tampil di kartu "DNS Records yang Dibutuhkan" (`textarea` readonly, tanpa whitespace). Regenerasi kunci: POST `/email/dns/dkim/generate` (opendkim-genkey → rename `{domain}.weborn.*` → root:root 0700 → upsert TXT `weborn._domainkey.{domain}` → restart opendkim) — record DNS di-update otomatis.
- **Roundcube menolak alamat tanpa domain bertitik**: `rcube_check_email` (program/js/common.js) mensyaratkan `local@domain.tld` (TLD ≥2 char). Alamat `user@localhost` dianggap invalid → saat kirim di compose muncul **"Please enter at least one recipient"** (padahal To terisi). Bukan bug panel; untuk uji kirim webmail gunakan domain beneran (mis. `@test.example.com`). Seed `admin@localhost` hanya untuk log-in panel.

## Checklist Sebelum "Selesai"

- [ ] `py_compile` semua file Python yang disentuh.
- [ ] Unit test 55/55 hijau (deploy dulu via `update.sh`).
- [ ] Smoke live: login + GET utama 200 + POST CSRF bukan 403 + WS `/ws/term` echo.
- [ ] `git status` bersih dari artefak; tanpa secret.
- [ ] Bila fitur/dokumen berubah, refresh README/CHANGELOG/doc terkait.
- [ ] Commit + push hanya jika diminta user.

## Status Terakhir yang Diketahui

- Employ: panel aktif di WSL (`/opt/weborn`, unit `weborn.service`, port 2025, executor local); smoke live 3 langkah & unit test 52/52 hijau.
- Semua fitur inti diuji (HTTP pages, port-busy 400, terminal WS echo/resize/exit/no-orphan, panel logs, app link CRUD).
- Mail stack (email.py) live-tested: kirim/terima via 25/587/465, DKIM sign + crypto-verify (dkimpy True), Rspamd milter scan aktif, virtual mailboxes multi-domain + kuota + autoresponder + catch-all, DNS records MX/A/SPF/DMARC/DKIM-TXT tampil di panel.
- **Alias/Catch-all/List/Forwarder telah di-test ulang pasca-reset** (baseline: 1 domain `localhost`, mailbox `admin@localhost`, alias `root`/`postmaster`; 13/13 OK — deliver di verifikasi via Maildir + journal postfix). Temuan & perbaikan: (1) mailbox **baru** di domain ber-catch-all kini langsung dapat alias identitas (`_catchall_identity_entries` dipakai `_create_mailbox` + `_write_virtual_map`) — sebelumnya tertangkap catch-all; (2) entry sistem `root@`/`postmaster@` & identity `x@→x@` diklasifikasi `identity` dan **tidak muncul** di halaman Alias/List/Forwarder (anti-noise & anti-hapus-sengaja); (3) `_delete_mailbox` hapus settings sebelum tulis ulang map → tak ada residu identity; (4) `catchall/clear` ikut membersihkan identity sisa. Catatan: `postmap` cukup (Postfix auto-reload map, "table … has changed -- restarting").
- **SpamAssassin dihapus** dari overview & Mail Security — Rspamd anti-spam tunggal (addon store `spamassassin.json` tetap ada).
- Dokumentasi (README, DEVELOPMENT §11, API Panel Mail, WORKFLOW email = menu final, CHANGELOG, AGENTS) diperbarui menyusul fitur email.
- **Mailbox auto-login webmail selesai & settle**: `/email/accounts/webmail/{user}` melakukan login Roundcube server-side (password Fernet tersimpan), mengembalikan `roundcube_sessid` + `roundcube_sessauth` sebagai `Set-Cookie` (HttpOnly, SameSite=Lax, Secure bila HTTPS), redirect ke `/roundcube/` — E2E browser teruji (masuk `?_task=mail&_mbox=INBOX`, tanpa form login). Unit `test/test_webmail.py` (HTTP server lokal, tanpa deps) — 55/55 test (bertambah 3).
- Screenshot README kini 4 halaman mail via CDP (`assets/weborn-shots/mail_*.png`; kunci: chromium headless + CDP, mint JWT `weborn.auth.encode_jwt`, set cookie via `Network.setCookie`, screenshot `Page.captureScreenshot`).
- Belum dieksekusi (opsional): item lama instalasi `D:\localhost\pyth-webapps` (FastAPI/PostgreSQL:8080).