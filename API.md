# API.md — Referensi API untuk Integrator (3rd Party / Vendor)

Dokumentasi ini menjelaskan HTTP & WebSocket API yang diekspos Weborn untuk keperluan integrasi eksternal, otomatisasi (CI/CD), atau tooling vendor. Semua endpoint berada di bawah origin panel Weborn (`http://<host>:2025`).

## 1. Basis Autentikasi

Weborn memakai **JWT (HS256)** dalam cookie `weborn_session` (httponly, samesite=lax, max-age 24h).

### 1.1 Masuk lewat GUI (mendapatkan cookie)

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=<user>&password=<pass>&_csrf_token=<token-dari-halaman-login>
```

Respons sukses: **303** → cookie `Set-Cookie: weborn_session=<jwt>; HttpOnly; Path=/; SameSite=Lax`.

### 1.2 CSRF untuk semua POST dari klien

Setiap request POST (kecuali `/ws/*`) wajib header:

```http
X-CSRF-Token: <generate_csrf_token(jwt_cookie_value)>
```

Token dihitung **sama persis** dengan implementasi internal Weborn:

```python
import hmac, hashlib, base64, json
from datetime import datetime, timezone, timedelta

jwt_cookie = "<nilai cookie weborn_session>"

# 1) Verifikasi JWT (lib PyJWT di sisi server; untuk vendor gunakan algoritma HS256)
# secret = weborn.db.get_secret_key()  # tersimpan di tabel settings (key='secret_key')

# 2) payload JWT → session proof = b64url(payload) bagian tengah (signature diabaikan utk proof)
proof = jwt_cookie.split(".")[1]

# 3) HMAC token dengan TTL 900 detik (format: <ts>.<sig>)
ts = int(datetime.now(timezone.utc).timestamp())
sig = hmac.new(secret.encode(), f"csrf:{proof}:{ts}".encode(), hashlib.sha256).hexdigest()
token = f"{ts}.{sig}"
```

Implementasi resmi: `weborn/csrf.py` (`generate_csrf_token` / `CSRFMiddleware`). Sederhananya — ambil nilai dari hidden input `<input name="_csrf_token">` pada halaman panel mana pun, lalu kirim sebagai `X-CSRF-Token`.

### 1.3 Session idle lock

Jika user dikonfigurasi `session_timeout > 0`, session yang tidak aktif otomatis dipaksa logout. Kirim request berkala (mis. heartbeat GET `/api/ping`) atau lakukan ulang login.

## 2. Format Umum

- **Kesuksesan (JSON):** `{"ok": true, ...data}`
- **Kegagalan:** `{"ok": false, "error": "...", "output": "..."}` — HTTP codes: `400` (validasi/port sibuk), `401/403` (auth/CSRF), `404`, `422` (parameter).
- Endpoint streamed menggunakan **SSE** semantics via POST (`streamPost`) atau **WebSocket**.
- Rate limit: login `5` percobaan per `5 menit` per IP.

## 3. Endpoint HTTP Utama

### Aplikasi (Weborn Core)

| Method | Path | Keterangan |
|--------|------|------------|
| GET | `/apps` | Daftar apps (render HTML — gunakan `/api` bila perlu JSON) |
| POST | `/apps/create` | Buat app. Form: `name, app_type, framework, python_version, root_path, command, port, workers, worker_class, module, app` |
| POST | `/apps/create-native` | Buat app dengan runtime venv mandiri (LAMBAT ≥30s) |
| POST | `/apps/{id}/start` · `/stop` · `/restart` | Kontrol service (gunicorn/uvicorn/php-fpm/node) |
| POST | `/apps/{id}/delete` | Hapus app (unit+user+venv; **folder tetap`**) |
| GET | `/apps/{id}/edit` | Halaman edit konfigurasi |
| GET | `/monitor/apps` | Halaman monitor + worker + orphan detection |

### Monitoring & Proses

| Method | Path | Keterangan |
|--------|------|------------|
| GET | `/dashboard` | Dashboard (stats sistem, service status) |
| POST | `/api/monitor/kill-orphan` | Body JSON `{"pid": <int>}` — kill orphan gunicorn/uvicorn |
| GET | `/processes` | Daftar proses (CPU/MEM) |
| GET | `/logs?source=<key>&lines=<n>` | Log viewer: `system, auth, nginx, mysql, panel, ...` |
| POST | `/logs/{source}/clear` | Bersihkan log sumber |

### Pengguna & Panel

| Method | Path | Keterangan |
|--------|------|------------|
| GET | `/panel-accounts` | Daftar akun panel |
| POST | `/panel-accounts/{id}/password` | Ubah password (form: `current_password, password`) |
| POST | `/panel-accounts/{id}/role` | Ubah role (`role=admin|user`) |
| POST | `/panel-accounts/{id}/timeout` | Set idle timeout `timeout=<detik>; 0=nonaktif` |
| POST | `/panel-accounts/{id}/delete` | Hapus akun panel |
| POST | `/accounts/create` | Buat user OS: `username, password, privilege, services[]` |

### Web Server, Firewall, Fail2Ban

| Method | Path | Keterangan |
|--------|------|------------|
| POST | `/web-server/nginx/test` · `/reload` · `/restart` | Nginx control |
| POST | `/web-server/apache/test` · `/reload` · `/restart` | Apache control |
| GET | `/web-server/nginx/site/{name}` | Isi config site (JSON) |
| POST | `/web-server/nginx/site/{name}/delete` | Hapus site |
| POST | `/security/firewall/allow` | Form `port, proto` — buka port UFW |
| POST | `/security/firewall/block` | Form `port, proto` — tutup port UFW |
| POST | `/security/firewall/toggle` | Toggle UFW on/off |
| POST | `/security/firewall/{allow\|block}/{port}` | Aturan cepat |
| POST | `/security/fail2ban/ban` | Form `ip` — ban IP |
| POST | `/security/fail2ban/unban` | Form `ip, jail` — unban |

### File & Terminal

| Method | Path | Keterangan |
|--------|------|------------|
| GET | `/files/list?path=...` | List direktori |
| GET | `/files/read?path=...` | Isi file |
| POST | `/files/write` | Write file (bentuk form: `path, content, chmod`) |
| POST | `/files/chmod` · `/files/chown` | Ubah permission/owner |
| POST | `/files/compress` | Tar.gz path (async, BackgroundTask) |
| GET | `/files/download?path=...` | Unduh file (biner aman via base64 internal) |

## 4. WebSocket Endpoint

Semua WS divalidasi via cookie session (`ws_require_admin`/`ws_require_user`).

| Path | Format | Keterangan |
|------|--------|------------|
| `/ws/term` | Text (JSON) | Terminal PTY: kirim `{"op":"input","data":"..."}`; respon `{"op":"output","data":"..."}`; `{"op":"resize","cols":N,"rows":N}`; `{"op":"exit"}` |
| `/ws/panel/logs` | Text lines | Stream `journalctl -u weborn -f` |
| `/ws/apps/{id}/logs` | Text lines | Stream `journalctl -u weborn-{name} -f` |
| `/ws/panel/trace` | Text lines | Trace panel |
| `/ws/apps/{id}/trace` | Text lines | Trace app |

Contoh terminal (Python + `websockets`):

```python
import asyncio, json, websockets
from weborn.auth import encode_jwt   # atau gunakan cookie hasil login

async def main():
    async with websockets.connect("ws://127.0.0.1:2025/ws/term") as ws:
        await ws.send(json.dumps({"op": "input", "data": "echo hi\n"}))
        print(await ws.recv())
        await ws.send(json.dumps({"op": "exit"}))

asyncio.run(main())
```

## 5. Catatan Integrasi Vendor

- **CI/CD:** gunakan endpoint `/apps` + `/apps/create` dengan CSRF header; tunggu status `active` dari `/monitor/apps` sebelum healthcheck.
- **Entity/OSS:** pola management paket (install → config → start → uninstall) bisa dibuat idempotent dengan memanfaatkan update/uninstall cover di `/addons/*`.
- **Monitoring eksternal:** konsumsi `/logs`, `/processes`, `/dashboard` (render HTML) atau WS trace; belum tersedia API JSON lengkap — tambahkan bila butuh.
- **Import modul internal untuk integrasi berbasis Python:** `weborn.csrf.generate_csrf_token`, `weborn.auth.encode_jwt`, `weborn.executors.get_executor`, `weborn.managers.*`.
- **Keamanan produksi:** aktifkan SSL (`WEBORN_SSL_CERT/KEY`) agar cookie `secure`; jalankan di balik reverse proxy HTTPS; jangan expose port 2025 ke publik.