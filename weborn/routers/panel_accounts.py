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
    if len(password) < 6:
        return RedirectResponse("/panel-accounts?msg=Password%20minimal%206%20karakter",
                                status_code=303)
    ok = create_panel_user(username, password, role)
    if not ok:
        return RedirectResponse("/panel-accounts?msg=Username%20sudah%20digunakan",
                                status_code=303)

    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        if _re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
            check = await ex.run("bash", "-c",
                                 f"id {shlex.quote(username)} >/dev/null 2>&1 && echo exists || echo new")
            if "new" in check.stdout:
                await ex.run("useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username)
                await ex.run("bash", "-c",
                             f"echo {shlex.quote(username + ':' + password)} | chpasswd")
                await ex.run("usermod", "-aG", "ssh-user", username)
            else:
                await ex.run("bash", "-c",
                             f"echo {shlex.quote(username + ':' + password)} | chpasswd")

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
    if len(password) < 6:
        return RedirectResponse("/panel-accounts?msg=Password%20baru%20minimal%206%20karakter",
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
        if _re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
            check = await ex.run("bash", "-c",
                                 f"id {shlex.quote(username)} >/dev/null 2>&1 && echo exists || echo new")
            if "exists" in check.stdout:
                await ex.run("bash", "-c",
                             f"echo {shlex.quote(username + ':' + password)} | chpasswd")

    return RedirectResponse("/panel-accounts?msg=Password%20diperbarui", status_code=303)


@router.post("/panel-accounts/{user_id}/toggle")
async def panel_accounts_toggle(user_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
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


@router.post("/panel-accounts/{user_id}/delete")
async def panel_accounts_delete(user_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    delete_panel_user(user_id)
    return RedirectResponse("/panel-accounts?msg=Akun%20panel%20dihapus", status_code=303)
