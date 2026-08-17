"""Manajemen akun panel Weborn (bukan akun OS Linux)."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..db import (create_panel_user, delete_panel_user, list_panel_users,
                  update_panel_user)
from ..ui import render

router = APIRouter()


@router.get("/panel-accounts", response_class=HTMLResponse)
async def panel_accounts_page(request: Request, msg: str = "",
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    return render(request, "panel_accounts.html", {
        "user": user,
        "accounts": list_panel_users(),
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
    return RedirectResponse("/panel-accounts?msg=Akun%20panel%20dibuat", status_code=303)


@router.post("/panel-accounts/{user_id}/password")
async def panel_accounts_password(
    user_id: int,
    password: str = Form(...),
    role: str = Form("user"),
    user: dict = Depends(require_admin),
):
    if hasattr(user, "headers"):
        return user
    if len(password) < 6:
        return RedirectResponse("/panel-accounts?msg=Password%20minimal%206%20karakter",
                                status_code=303)
    update_panel_user(user_id, password, role)
    return RedirectResponse("/panel-accounts?msg=Password%20diperbarui", status_code=303)


@router.post("/panel-accounts/{user_id}/delete")
async def panel_accounts_delete(user_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    delete_panel_user(user_id)
    return RedirectResponse("/panel-accounts?msg=Akun%20panel%20dihapus", status_code=303)
