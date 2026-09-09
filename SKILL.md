# SKILL.md — Skill Prompt: Membangun Project Weborn

Gunakan skill ini sebagai panduan (prompt) ketika membuat, memperbaiki, atau memperluas proyek **Weborn** atau project web-hosting panel yang serupa. Bacalah dokumen pendamping: `DEVELOPMENT.md`, `API.md`, `AGENTS.md`.

## Identitas Skill

- **Nama:** `weborn-dev`
- **Deskripsi:** Control-panel "web hosting self-hosted" berbasis FastAPI + SQLite + Jinja2 + Tailwind, men-deploy & mengelola app WSGI/ASGI/PHP/Node/static, domain, database, mail, firewall, monitoring via satu dashboard root.
- **Konteks pemakaian:** pembuatan awal, refactor, code-audit keamanan, tambah fitur, dan penulisan dokumentasi pelengkap.

## Prinsip Arsitektur yang Harus Dipertahankan

1. **Abstraksi executor** — semua operasi sistem lewat `executors/` (Local/Wsl/DryRun), bukan subprocess langsung di router. Mode dry-run harus tetap berfungsi penuh di Windows.
2. **FastAPI + Jinja2 server-render** — UI minimal-JS; helper `weborn.*` kecil di `static/js/panel.js` (simplePost/streamPost/toast/modal). Perintah eksekusi panjang memakai streaming `streamPost`.
3. **Security by default:**
   - CSRF HMAC (header `X-CSRF-Token` atau form hidden input) untuk semua POST; `/ws/*` memakai auth cookie sendiri.
   - JWT HS256 cookie `weborn_session` + RBAC admin/user + session idle lock.
   - `shlex.quote()` semua input bash; path name divalidasi regex ketat (`^[A-Za-z0-9._-]+$`).
   - Password admin policy ≥8 karakter (upper/lower/digit/simbol).
4. **Template process per app:** user OS `weborn-<name>` → dir `/var/www/<name>` → scaffold → deps → `.env` → systemd unit → nginx config → enable.
5. **Audit trail & rate limit** login (5/5m) melekat sebagai fitur inti, jangan dihapus.

## Pola Kode yang Dipakai

```python
# router
@router.get("/apps", response_class=HTMLResponse)
async def apps_page(request: Request, user=Depends(require_user)):
    if hasattr(user, "headers"): return user          # pattern unify redirect/403
    apps = await list_apps(executor)
    return render(request, "apps.html", {"apps": apps})
```

```python
# manager async (blocking dibungkus to_thread)
async def list_apps(ex):
    data = await asyncio.to_thread(_collect, ex)
    return sorted(data, key=lambda a: (a.get("port") or 0))
```

```html
<!-- template: nilai dinamis di JS SELALU tojson -->
<button onclick="viewSite({{ site|tojson }})">
```

## Checklist Audit Ulang (dipakai tiap iterasi)

- [ ] Semua file Python di-`python -m py_compile`.
- [ ] Unit test `test/run_tests.py` hijau (52 test, stdlib only).
- [ ] Tidak ada `'{{ x }}'` di dalam string JS/onclick (harus `|tojson`).
- [ ] Semua POST fetch mengirim `X-CSRF-Token`.
- [ ] Biner tidak lewat `str`/`echo`; gunakan base64.
- [ ] Fork/exec child memakai `os._exit`.
- [ ] Streaming journalctl memakai `stderr=DEVNULL`.
- [ ] Tidak ada import mati, tidak ada template mati, tidak ada dict/dead code.
- [ ] `git status` bersih dari `node_modules/`, `.git-rewrite/`, `.tgrep/`, `data/*.db`, `__pycache__`.

## Cara Kerja Standar

1. Audit struktur via `glob`+`grep` dulu, baru baca file target (jangan asal edit).
2. Terapkan fix terkecil yang robust; jangan rombak kosmetik.
3. Verifikasi: py_compile → unit test (WSL deploy `/opt/weborn` via `update.sh`) → smoke test fungsional → commit & push.
4. Dokumentasi: update `README.md`, `CHANGELOG.md`, dan doc terkait tiap fitur signifikan.

## Jebakan Lingkungan

- WSL networking mirrored: Windows tidak bisa akses port WSL → browser/screenshot dijalankan DI DALAM WSL (chromium + CDP `websockets`).
- DB SQLite WAL: baca DB harus sebagai root (atau writable shm).
- `create-native` harus timeout ≥180s.
- Halaman screenshot autentikasi: mint JWT via `weborn.auth.encode_jwt(1, "admin", "admin")` (tanpa password), set cookie `weborn_session` via CDP.