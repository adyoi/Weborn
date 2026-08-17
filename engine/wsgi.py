"""Weborn Engine - WSGI application.

Siap dijalankan dengan gunicorn:
    gunicorn engine.wsgi:application -b 0.0.0.0:8080 -w 4
    gunicorn engine.wsgi:application -b unix:/run/weborn-engine.sock -w 4

Atau dengan uWSGI:
    uwsgi --http :8080 --wsgi-file engine/wsgi.py --callable application

Fitur:
  1. Serve file statis dengan security headers, cache, gzip
  2. Reverse proxy berbasis host/domain ATAU prefix path ke backend
  3. Path traversal protection
  4. Index file support (index.html, index.htm)

Konfigurasi proxy: {root}/.weborn/engine.json
  {"routes": [{"host": "example.com", "target": "http://127.0.0.1:8000"},
              {"path": "/api", "target": "http://127.0.0.1:8001"}]}
"""
import gzip
import io
import json
import mimetypes
import os
import sqlite3
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

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

GZIP_MIN_SIZE = 500
GZIP_EXCLUDE = frozenset({".jpg", ".jpeg", ".png", ".gif", ".zip", ".gz", ".mp3", ".mp4", ".webp"})


class WebornWSGI:
    """WSGI application untuk Weborn Engine."""

    def __init__(self, static_root: str | None = None, config_path: str | None = None):
        self.root = os.path.realpath(static_root or WEB_ROOT)
        self.routes = _load_proxy_config(config_path or self.root)
        os.makedirs(self.root, exist_ok=True)

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        host = environ.get("SERVER_NAME", "")
        query = environ.get("QUERY_STRING", "")
        content_length = int(environ.get("CONTENT_LENGTH") or 0)

        body = environ["wsgi.input"].read(content_length) if content_length else b""

        # 1. Proxy berbasis host (domain)
        for route in self.routes:
            if route.get("host") and host == route["host"]:
                return self._proxy(environ, start_response, route["target"],
                                   "/" + path, query, method, body, environ)

        # 2. Proxy berbasis prefix path
        for route in self.routes:
            prefix = (route.get("path") or "").strip("/")
            if prefix and path.startswith("/" + prefix):
                rest = path[len(prefix) + 1:] or "/"
                return self._proxy(environ, start_response, route["target"],
                                   rest, query, method, body, environ)

        # 3. Static files
        if method in ("GET", "HEAD"):
            return self._static(environ, start_response, path)

        return _error_response(start_response, 405, "Method Not Allowed")

    def _static(self, environ, start_response, path: str):
        resolved = _resolve(self.root, path)
        if resolved is None:
            return _error_response(start_response, 403, "Forbidden")

        if os.path.isdir(resolved):
            for idx in INDEX_FILES:
                candidate = os.path.join(resolved, idx)
                if os.path.isfile(candidate):
                    resolved = candidate
                    break
            else:
                return _error_response(start_response, 403, "Directory listing disabled")

        if not os.path.isfile(resolved):
            return _error_response(start_response, 404, "Not Found")

        headers = dict(SECURITY_HEADERS)

        _, ext = os.path.splitext(resolved)
        if ext.lower() in CACHE_RULES:
            headers["Cache-Control"] = CACHE_RULES[ext.lower()]

        ctype, _ = mimetypes.guess_type(resolved)
        if ctype:
            headers["Content-Type"] = ctype

        with open(resolved, "rb") as f:
            data = f.read()

        # GZIP compression
        accept_encoding = environ.get("HTTP_ACCEPT_ENCODING", "")
        if ("gzip" in accept_encoding and ext.lower() not in GZIP_EXCLUDE
                and len(data) >= GZIP_MIN_SIZE):
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(data)
            data = buf.getvalue()
            headers["Content-Encoding"] = "gzip"

        headers["Content-Length"] = str(len(data))
        status = "200 OK"
        header_list = list(headers.items())

        start_response(status, header_list)
        return [data]

    def _proxy(self, environ, start_response, target: str, path: str,
               query: str, method: str, body: bytes, wsgi_env: dict):
        parts = urlsplit(target)
        hostname = parts.hostname
        scheme = parts.scheme or "http"
        port = parts.port or (443 if scheme == "https" else 80)

        if not hostname:
            return _error_response(start_response, 502, "Bad Gateway")

        url = path
        if query:
            url += "?" + query

        headers = {}
        for key in ("HTTP_ACCEPT", "HTTP_ACCEPT_ENCODING", "HTTP_ACCEPT_LANGUAGE",
                     "HTTP_USER_AGENT", "HTTP_REFERER", "CONTENT_TYPE"):
            val = wsgi_env.get(key)
            if val:
                hkey = key.replace("HTTP_", "").replace("_", "-").title()
                headers[hkey] = val

        full_url = f"{scheme}://{hostname}:{port}{url}"

        try:
            req = urllib.request.Request(
                full_url,
                data=body if method in ("POST", "PUT", "PATCH") else None,
                headers=headers,
                method=method,
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = resp.read()
                resp_status = f"{resp.status} OK"
                resp_headers = [
                    (k, v) for k, v in resp.getheaders()
                    if k.lower() not in ("transfer-encoding", "connection", "content-length")
                ]
                resp_headers.append(("Content-Length", str(len(resp_data))))

            start_response(resp_status, resp_headers)
            return [resp_data]

        except urllib.error.HTTPError as e:
            resp_data = e.read()
            resp_headers = [
                ("Content-Length", str(len(resp_data))),
                ("Content-Type", "text/plain"),
            ]
            start_response(f"{e.code} Error", resp_headers)
            return [resp_data]

        except Exception:
            return _error_response(start_response, 502, "Bad Gateway")


def _resolve(root: str, path: str) -> str | None:
    rel = path.lstrip("/")
    target = os.path.realpath(os.path.join(root, rel))
    real_root = os.path.realpath(root)
    if target == real_root or target.startswith(real_root + os.sep):
        return target
    return None


def _load_proxy_config(root: str) -> list[dict]:
    routes = []
    cfg_path = os.path.join(root, ".weborn", "engine.json")
    try:
        with open(cfg_path, encoding="utf-8") as f:
            data = json.load(f)
        routes = list(data.get("routes") or [])
    except (OSError, ValueError):
        pass

    try:
        conn = sqlite3.connect(str(DB_PATH))
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


def _error_response(start_response, code: int, message: str):
    body = message.encode()
    status_map = {
        403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        502: "502 Bad Gateway",
    }
    status = status_map.get(code, f"{code} Error")
    headers = [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(body))),
    ] + list(SECURITY_HEADERS.items())
    start_response(status, headers)
    return [body]


application = WebornWSGI()
