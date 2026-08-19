"""Autentikasi panel: sesi berbasis cookie + RBAC dasar + PAM fallback.

Alur login:
  1. Cari user di panel DB (SQLite).
  2. Jika ditemukan → verifikasi password hash → login.
  3. Jika tidak ditemukan atau password salah → coba PAM (Linux auth via /etc/shadow).
  4. Jika PAM berhasil → buat user shadow di panel → login.
  5. Gate: root hanya boleh login bila sudah ada admin panel.
"""
import platform

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import db
from .config import SESSION_COOKIE, USE_PAM

# Linux-only modules (not available on Windows)
_crypt = None
_spwd = None
if platform.system() == "Linux":
    try:
        import crypt as _crypt
        import spwd as _spwd
    except ImportError:
        pass


# ── PAM via /etc/shadow ─────────────────────────────────────────────────────
# Panel berjalan dengan sudo → bisa baca /etc/shadow langsung.
# Tidak perlu ctypes atau pip package tambahan.

def _pam_authenticate(username: str, password: str) -> bool:
    """Autentikasi user Linux via /etc/shadow.

    Returns True jika password cocok, False jika ditolak atau tidak tersedia.
    """
    if not USE_PAM:
        return False
    if platform.system() != "Linux":
        return False
    if not _crypt or not _spwd:
        return False

    try:
        shadow = _spwd.getspnam(username)
        stored_hash = shadow.sp_pwd
        # Hash kosong atau '!' atau '*' = akun terkunci/no password
        if not stored_hash or stored_hash in ("!", "*", "!!"):
            return False
        return _crypt.crypt(password, stored_hash) == stored_hash
    except (KeyError, PermissionError):
        # KeyError = user tidak ada, PermissionError = tidak punya akses shadow
        return False


# ── Panel auth ──────────────────────────────────────────────────────────────

def login(request: Request, username: str, password: str) -> bool:
    """Login dengan fallback: panel DB → PAM.

    Alur:
      1. Cari user di panel DB, verifikasi password.
      2. Jika tidak ditemukan/salah → coba PAM.
      3. Jika PAM berhasil → auto-create shadow user → login.
      4. Gate: root hanya boleh login bila sudah ada admin panel.
    """
    ip = request.client.host if request.client else ""

    # ── Step 1: Coba panel DB ──
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if row and db.verify_password(password, row["password_hash"]):
        row_dict = dict(row)
        if not row_dict.get("is_active", 1):
            db.log_login(0, username, ip, False)
            return False
        token = db.create_session(row["id"])
        request.session[SESSION_COOKIE] = token
        db.log_login(row["id"], username, ip, True)
        return True

    # ── Step 2: Fallback ke PAM (/etc/shadow) ──
    if _pam_authenticate(username, password):
        # Gate: root hanya boleh login bila sudah ada admin
        if username == "root" and not _has_admin():
            db.log_login(0, username, ip, False)
            return False

        # Auto-create shadow user jika belum ada di panel
        role = "admin" if username == "root" else "user"
        user_id = db.create_shadow_user(username, role=role)
        if not user_id:
            db.log_login(0, username, ip, False)
            return False

        # Check is_active
        with db.get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row and not dict(row).get("is_active", 1):
            db.log_login(0, username, ip, False)
            return False

        token = db.create_session(user_id)
        request.session[SESSION_COOKIE] = token
        db.log_login(user_id, username, ip, True)
        return True

    # ── Step 3: Gagal ──
    db.log_login(0, username, ip, False)
    return False


def _has_admin() -> bool:
    """Cek apakah sudah ada user admin di panel DB."""
    with db.get_conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    return row is not None


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
