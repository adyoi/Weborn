"""Weborn Engine - webserver mandiri (ASGI, siap uvicorn/gunicorn).

Engine tetap berfungsi sebagai webserver walau dijalankan memakai uvicorn
(async) atau gunicorn (-k uvicorn.workers.UvicornWorker). Kemampuan:
  1. Serve file statis (root WEB_ROOT) dengan security headers, cache, gzip,
     index.html, dan proteksi path traversal.
  2. Reverse proxy berbasis host/domain ATAU prefix path ke backend app
     (Node.js, PHP, Python) - app sync/async apa pun, cukup HTTP.
  3. Mount panel GUI Weborn di /panel (opsional).

Konfigurasi proxy (default: {root}/.weborn/engine.json):
  {"routes": [{"host": "example.com", "target": "http://127.0.0.1:8000"},
              {"path": "/api", "target": "http://127.0.0.1:8001"}]}

Jika file config tidak ada, engine otomatis membaca tabel `domains`
(proxy_target) dari DB panel sebagai route berbasis host.
"""
import json
import mimetypes
import os
import asyncio
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response

from weborn.config import DB_PATH, WEB_ROOT

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "1; mode=block",
}

CACHE_RULES = {
    ".css": "max-age=3600, public",
    ".js": "max-age=3600, public",
    ".jpg": "max-age=86400, public",
    ".jpeg": "max-age=86400, public",
    ".png": "max-age=86400, public",
    ".gif": "max-age=86400, public",
    ".svg": "max-age=86400, public",
    ".ico": "max-age=86400, public",
    ".woff": "max-age=2592000, public",
    ".woff2": "max-age=2592000, public",
}

INDEX_FILES = ("index.html", "index.htm")


def _load_proxy_config(root: str) -> list[dict]:
    """Route dari engine.json, lalu merge dengan domain panel (proxy_target)."""
    routes = []
    cfg_path = os.path.join(root, ".weborn", "engine.json")
    try:
        with open(cfg_path, encoding="utf-8") as f:
            data = json.load(f)
        routes = list(data.get("routes") or [])
    except (OSError, ValueError):
        pass

    # Route domain panel: domains enabled + proxy_target (SSL/HTTP sama saja).
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT name, proxy_target FROM domains "
            "WHERE enabled = 1 AND proxy_target IS NOT NULL AND proxy_target != ''"
        ).fetchall()
        conn.close()
        known_hosts = {r.get("host") for r in routes if r.get("host")}
        for row in rows:
            if row["name"] not in known_hosts:
                routes.append({"host": row["name"], "target": row["proxy_target"]})
    except Exception:
        pass
    return routes


def _resolve(root: str, path: str):
    """Path aman dalam root (tolak traversal & symlink keluar)."""
    rel = path.lstrip("/")
    target = os.path.realpath(os.path.join(root, rel))
    real_root = os.path.realpath(root)
    if target == real_root or target.startswith(real_root + os.sep):
        return target
    return None


def _static_response(root: str, request: Request, path: str):
    resolved = _resolve(root, path)
    if resolved is None:
        return Response("Forbidden", status_code=403)
    if os.path.isdir(resolved):
        for idx in INDEX_FILES:
            candidate = os.path.join(resolved, idx)
            if os.path.isfile(candidate):
                resolved = candidate
                break
        else:
            return Response("Directory listing disabled", status_code=403)
    if not os.path.isfile(resolved):
        return Response("Not Found", status_code=404)
    headers = dict(SECURITY_HEADERS)
    _, ext = os.path.splitext(resolved)
    if ext.lower() in CACHE_RULES:
        headers["Cache-Control"] = CACHE_RULES[ext.lower()]
    ctype, _ = mimetypes.guess_type(resolved)
    if ctype:
        headers["Content-Type"] = ctype
    return FileResponse(resolved, headers=headers)


async def _proxy(request: Request, target: str, path: str):
    """Forward request ke backend app (sync/async apa pun) via http.client."""
    parts = urlsplit(target)
    if not parts.hostname or not parts.port:
        return Response("target backend tidak valid", status_code=502)

    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()

    def _forward(body: bytes):
        import http.client
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=30)
        qs = request.url.query
        url = path if not qs else f"{path}?{qs}"
        headers = {}
        for k, v in request.headers.items():
            if k.lower() in ("host", "connection", "transfer-encoding", "content-length"):
                continue
            headers[k] = v
        try:
            conn.request(request.method, url, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            out_headers = [(k, v) for k, v in resp.getheaders()
                           if k.lower() not in ("transfer-encoding", "connection")]
            return resp.status, out_headers, data
        except Exception:
            return 502, [], b"bad gateway"
        finally:
            conn.close()

    status, out_headers, data = await asyncio.to_thread(_forward, body)
    return Response(content=data, status_code=status, headers=dict(out_headers))


def create_engine(static_root: str | None = None, config: str | None = None,
                  panel: bool = True) -> FastAPI:
    root = static_root or WEB_ROOT
    app = FastAPI(title="Weborn Engine", docs_url=None, redoc_url=None, openapi_url=None)

    if panel:
        from weborn.main import app as panel_app
        app.mount("/panel", panel_app, name="panel-gui")

    routes = _load_proxy_config(config or root)

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT",
                                            "PATCH", "DELETE", "OPTIONS"])
    async def handler(request: Request, path: str):
        host = (request.headers.get("host") or "").split(":")[0]

        # 1. proxy berbasis host (domain) — prioritas tertinggi
        for route in routes:
            if route.get("host") and host == route["host"]:
                return await _proxy(request, route["target"], "/" + path)
        # 2. proxy berbasis prefix path
        for route in routes:
            prefix = (route.get("path") or "").strip("/")
            if prefix and path.startswith(prefix):
                rest = path[len(prefix):] or "/"
                return await _proxy(request, route["target"], rest)
        # 3. statis
        if request.method in ("GET", "HEAD"):
            return _static_response(root, request, path)
        return Response("Method Not Allowed", status_code=405)

    return app


# Akses langsung: `uvicorn engine.asgi:app` / `gunicorn -k uvicorn.workers.UvicornWorker engine.asgi:app`
app = create_engine()
