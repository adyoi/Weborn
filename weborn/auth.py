"""Autentikasi panel: JWT cookie + RBAC dasar + PAM fallback.

Alur login:
  1. Cari user di panel DB (SQLite).
  2. Jika ditemukan → verifikasi password hash → login.
  3. Jika tidak ditemukan atau password salah → coba PAM (Linux auth via /etc/shadow).
  4. Jika PAM berhasil → buat user shadow di panel → login.
  5. Gate: root hanya boleh login bila sudah ada admin panel.
"""
import os
import platform

import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse, RedirectResponse

from . import db
from .config import SESSION_COOKIE, USE_PAM

JWT_EXPIRY_HOURS = 24

# Linux-only modules (not available on Windows)
_crypt = None
_spwd = None
if platform.system() == "Linux":
    try:
        import crypt as _crypt
        import spwd as _spwd
    except ImportError:
        pass


# ── JWT helpers ─────────────────────────────────────────────────────────────

def _get_jwt_secret() -> str:
    return db.get_secret_key()


def encode_jwt(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def decode_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, _get_jwt_secret(), algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def _set_jwt_cookie(response, token: str):
    is_secure = os.environ.get("WEBORN_SSL_CERT") is not None
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=JWT_EXPIRY_HOURS * 3600,
    )


def _clear_jwt_cookie(response):
    response.delete_cookie(SESSION_COOKIE)


# ── PAM via /etc/shadow ─────────────────────────────────────────────────────

def _pam_authenticate(username: str, password: str) -> bool:
    if not USE_PAM:
        return False
    if platform.system() != "Linux":
        return False
    if not _crypt or not _spwd:
        return False

    try:
        shadow = _spwd.getspnam(username)
        stored_hash = shadow.sp_pwd
        if not stored_hash or stored_hash in ("!", "*", "!!"):
            return False
        return _crypt.crypt(password, stored_hash) == stored_hash
    except (KeyError, PermissionError):
        return False


# ── Panel auth ──────────────────────────────────────────────────────────────

def login(request: Request, username: str, password: str):
    """Login dengan fallback: panel DB → PAM.

    Returns RedirectResponse on success, None on failure.
    """
    ip = request.client.host if request.client else ""

    # ── Step 1: Coba panel DB ──
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if row and db.verify_password(password, row["password_hash"]):
        row_dict = dict(row)
        if not row_dict.get("is_active", 1):
            db.log_login(0, username, ip, False)
            return None
        token = encode_jwt(row["id"], row["username"], row["role"])
        resp = RedirectResponse("/", status_code=303)
        _set_jwt_cookie(resp, token)
        db.log_login(row["id"], username, ip, True)
        return resp

    # ── Step 2: Fallback ke PAM (/etc/shadow) ──
    if _pam_authenticate(username, password):
        if username == "root" and not _has_admin():
            db.log_login(0, username, ip, False)
            return None

        role = "admin" if username == "root" else "user"
        user_id = db.create_shadow_user(username, role=role)
        if not user_id:
            db.log_login(0, username, ip, False)
            return None

        with db.get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row and not dict(row).get("is_active", 1):
            db.log_login(0, username, ip, False)
            return None

        token = encode_jwt(row["id"], row["username"], row["role"])
        resp = RedirectResponse("/", status_code=303)
        _set_jwt_cookie(resp, token)
        db.log_login(user_id, username, ip, True)
        return resp

    # ── Step 3: Gagal ──
    db.log_login(0, username, ip, False)
    return None


def _has_admin() -> bool:
    with db.get_conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    return row is not None


def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        payload = decode_jwt(token)
        if payload:
            db.delete_session(str(payload.get("user_id", "")))


def get_current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    payload = decode_jwt(token)
    if not payload:
        return None
    user_id = payload.get("user_id")
    if not user_id:
        return None
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    user = dict(row)
    if not user.get("is_active", 1):
        return None
    return user


def require_user(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return user


def require_admin(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return JSONResponse(
            {"ok": False, "error": "akses ditolak: dibutuhkan admin (root)"},
            status_code=403,
        )
    return user


# ── WebSocket auth ──────────────────────────────────────────────────────────

def get_ws_user(websocket: WebSocket):
    cookie_header = websocket.headers.get("cookie", "")
    if not cookie_header:
        return None
    cookies = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    raw_token = cookies.get(SESSION_COOKIE, "")
    if not raw_token:
        return None
    payload = decode_jwt(raw_token)
    if not payload:
        return None
    user_id = payload.get("user_id")
    if not user_id:
        return None
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    user = dict(row)
    if not user.get("is_active", 1):
        return None
    return user


async def ws_require_admin(websocket: WebSocket) -> dict | None:
    await websocket.accept()
    user = get_ws_user(websocket)
    if not user:
        await websocket.close(code=4001, reason="unauthenticated")
        return None
    return user


async def ws_require_user(websocket: WebSocket) -> dict | None:
    await websocket.accept()
    user = get_ws_user(websocket)
    if not user:
        await websocket.close(code=4001, reason="unauthenticated")
        return None
    return user
