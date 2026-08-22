"""Manajemen akun panel Weborn (bukan akun OS Linux)."""
import re as _re
import shlex

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..db import (create_panel_user, delete_panel_user, get_login_logs,
                  hash_password, list_panel_users, toggle_panel_user_active,
                  update_panel_user)
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Panel Users"])

_PASSWORD_RE = _re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,}$')


@router.get("/panel-accounts", response_class=HTMLResponse)
async def panel_accounts_page(request: Request, msg: str = "",
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    accounts = list_panel_users()
    logs = get_login_logs(50)
    return render(request, "panel_accounts.html", {
        "user": user,
        "accounts": accounts,
        "logs": logs,
        "msg": msg,
        "active": "panel-accounts",
    })


@router.post("/panel-accounts/create")
async def panel_accounts_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    user: dict = Depends(require_admin),
):
    if hasattr(user, "headers"):
        return user
    if len(username) < 3:
        return RedirectResponse("/panel-accounts?msg=Username%20minimal%203%20karakter",
                                status_code=303)
    if not _PASSWORD_RE.match(password):
        return RedirectResponse("/panel-accounts?msg=Password%20minimal%208%20karakter%20dengan%20huruf%20besar%2C%20kecil%2C%20angka%2C%20dan%20simbol",
                                status_code=303)
    ok = create_panel_user(username, password, role)
    if not ok:
        return RedirectResponse("/panel-accounts?msg=Username%20sudah%20digunakan",
                                status_code=303)

    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        try:
            if _re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
                check = await ex.run("bash", "-c",
                                     f"id {shlex.quote(username)} >/dev/null 2>&1 && echo exists || echo new")
                if "new" in check.stdout:
                    await ex.run("useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username)
                    await ex.run("bash", "-c",
                                 f"echo {shlex.quote(username + ':' + password)} | sudo chpasswd")
                    await ex.run("usermod", "-aG", "ssh-user", username)
                else:
                    await ex.run("bash", "-c",
                                 f"echo {shlex.quote(username + ':' + password)} | sudo chpasswd")
        except Exception as e:
            return RedirectResponse(f"/panel-accounts?msg=Gagal%20buat%20user%20OS:%20{str(e)[:50]}",
                                    status_code=303)

    return RedirectResponse("/panel-accounts?msg=Akun%20panel%20dibuat", status_code=303)


@router.post("/panel-accounts/{user_id}/password")
async def panel_accounts_password(
    user_id: int,
    current_password: str = Form(""),
    password: str = Form(...),
    user: dict = Depends(require_admin),
):
    if hasattr(user, "headers"):
        return user
    if len(password) < 8 or not _PASSWORD_RE.match(password):
        return RedirectResponse("/panel-accounts?msg=Password%20baru%20minimal%208%20karakter%20dengan%20huruf%20besar%2C%20kecil%2C%20angka%2C%20dan%20simbol",
                                status_code=303)
    from ..db import get_conn, verify_password
    if user_id == user.get("id"):
        if not current_password:
            return RedirectResponse("/panel-accounts?msg=Password%20sekarang%20wajib%20diisi",
                                    status_code=303)
        with get_conn() as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE id = ?",
                               (user_id,)).fetchone()
        if not row or not verify_password(current_password, row["password_hash"]):
            return RedirectResponse("/panel-accounts?msg=Password%20sekarang%20salah",
                                    status_code=303)
    with get_conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (hash_password(password), user_id))
        row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.commit()

    username = row["username"] if row else ""
    ex = get_executor()
    if ex.mode in ("local", "wsl") and username:
        try:
            if _re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
                check = await ex.run("bash", "-c",
                                     f"id {shlex.quote(username)} >/dev/null 2>&1 && echo exists || echo new")
                if "exists" in check.stdout:
                    await ex.run("bash", "-c",
                                 f"echo {shlex.quote(username + ':' + password)} | sudo chpasswd")
        except Exception:
            pass  # Password panel sudah diupdate, sync OS gagal tapi tidak kritis

    return RedirectResponse("/panel-accounts?msg=Password%20diperbarui", status_code=303)


@router.post("/panel-accounts/{user_id}/toggle")
async def panel_accounts_toggle(user_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    # Prevent self-deactivate
    if user_id == user.get("id"):
        return RedirectResponse("/panel-accounts?msg=Tidak%20bisa%20nonaktifkan%20akun%20sendiri",
                                status_code=303)
    # Prevent deactivate last admin
    from ..db import list_panel_users
    accounts = list_panel_users()
    active_admins = [a for a in accounts if a["role"] == "admin" and a.get("is_active", 1)]
    target = next((a for a in accounts if a["id"] == user_id), None)
    if target and target["role"] == "admin" and len(active_admins) <= 1:
        return RedirectResponse("/panel-accounts?msg=Tidak%20bisa%20nonaktifkan%20admin%20terakhir",
                                status_code=303)
    toggle_panel_user_active(user_id)
    return RedirectResponse("/panel-accounts?msg=Akun%20diaktifkan/dinonaktifkan",
                            status_code=303)


@router.post("/panel-accounts/{user_id}/role")
async def panel_accounts_role(user_id: int, role: str = Form("user"),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if role not in ("admin", "user"):
        return RedirectResponse("/panel-accounts?msg=Role%20tidak%20valid",
                                status_code=303)
    from ..db import get_conn
    with get_conn() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
    return RedirectResponse("/panel-accounts?msg=Role%20diperbarui", status_code=303)


@router.post("/panel-accounts/{user_id}/timeout")
async def panel_accounts_timeout(user_id: int, timeout: int = Form(300),
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    timeout = max(0, min(timeout, 86400))  # 0 = disabled, max 24h
    from ..db import update_session_timeout
    update_session_timeout(user_id, timeout)
    label = "nonaktif" if timeout == 0 else f"{timeout // 60} menit"
    return RedirectResponse(f"/panel-accounts?msg=Session%20timeout%20diatur%20ke%20{label}",
                            status_code=303)


@router.post("/panel-accounts/{user_id}/delete")
async def panel_accounts_delete(user_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    # Prevent self-delete
    if user_id == user.get("id"):
        return RedirectResponse("/panel-accounts?msg=Tidak%20bisa%20hapus%20akun%20sendiri",
                                status_code=303)
    # Prevent delete last admin
    accounts = list_panel_users()
    target = next((a for a in accounts if a["id"] == user_id), None)
    if target and target["role"] == "admin":
        admin_count = sum(1 for a in accounts if a["role"] == "admin")
        if admin_count <= 1:
            return RedirectResponse("/panel-accounts?msg=Tidak%20bisa%20hapus%20admin%20terakhir",
                                    status_code=303)
    delete_panel_user(user_id)
    return RedirectResponse("/panel-accounts?msg=Akun%20panel%20dihapus", status_code=303)
