"""Autentikasi panel: sesi berbasis cookie + RBAC dasar."""
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import db
from .config import SESSION_COOKIE


def login(request: Request, username: str, password: str) -> bool:
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not db.verify_password(password, row["password_hash"]):
        ip = request.client.host if request.client else ""
        db.log_login(0, username, ip, False)
        return False
    row_dict = dict(row)
    if not row_dict.get("is_active", 1):
        return False
    token = db.create_session(row["id"])
    request.session[SESSION_COOKIE] = token
    ip = request.client.host if request.client else ""
    db.log_login(row["id"], username, ip, True)
    return True


def logout(request: Request):
    token = request.session.get(SESSION_COOKIE)
    if token:
        db.delete_session(token)
        request.session.pop(SESSION_COOKIE, None)


def get_current_user(request: Request):
    token = request.session.get(SESSION_COOKIE)
    return db.get_user_from_session(token)


def require_user(request: Request):
    """Dependency: redirect ke /login bila belum login."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return user


def require_admin(request: Request):
    """Dependency: untuk operasi yang butuh otorisasi root/admin.

    Mengembalikan 403 untuk non-admin; dipakai pada route yang menjalankan
    perintah tingkat sistem (apt, systemctl, useradd, dll).
    """
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.get("role") != "admin":
        return JSONResponse(
            {"ok": False, "error": "akses ditolak: dibutuhkan admin (root)"},
            status_code=403,
        )
    return user
