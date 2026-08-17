"""Manajemen akun OS: dibuat setara privilege server sehingga langsung bisa
dipakai untuk SSH, FTP, Telnet, dll."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..managers.accounts import AccountManager, PRIVILEGE_LEVELS
from ..ui import render

router = APIRouter()
SERVICE_NAMES = {
    "ssh": "SSH", "sftp": "SFTP", "rdp": "RDP",
    "vnc": "VNC", "nfs": "NFS", "ftp": "FTP", "telnet": "Telnet",
}


@router.get("/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request, msg: str = "",
                        user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    manager = AccountManager(get_executor())
    accounts = await manager.list_users()
    return render(request, "accounts.html", {
        "user": user,
        "accounts": accounts,
        "levels": PRIVILEGE_LEVELS,
        "services": SERVICE_NAMES,
        "msg": msg,
        "active": "accounts",
    })


@router.post("/accounts/create")
async def accounts_create(request: Request, username: str = Form(...),
                          password: str = Form(...), privilege: str = Form("user"),
                          shell: str = Form("/bin/bash"),
                          user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    form = await request.form()
    services = form.getlist("services")
    result = await AccountManager(get_executor()).create(
        username, password, privilege, services, shell)
    return RedirectResponse(
        f"/accounts?msg={_msg(result, 'Akun dibuat')}", status_code=303)


@router.post("/accounts/{username}/delete")
async def accounts_delete(username: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await AccountManager(get_executor()).delete(username)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Akun dihapus')}", status_code=303)


@router.post("/accounts/{username}/password")
async def accounts_password(username: str, password: str = Form(...),
                            user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await AccountManager(get_executor()).set_password(username, password)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Password diganti')}", status_code=303)


@router.post("/accounts/{username}/lock")
async def accounts_lock(username: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await AccountManager(get_executor()).set_locked(username, True)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Akun dikunci')}", status_code=303)


@router.post("/accounts/{username}/unlock")
async def accounts_unlock(username: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await AccountManager(get_executor()).set_locked(username, False)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Akun dibuka')}", status_code=303)


@router.post("/accounts/{username}/privilege")
async def accounts_privilege(username: str, level: str = Form(...),
                             user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await AccountManager(get_executor()).set_privilege(username, level)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Privilege diubah')}", status_code=303)


@router.post("/accounts/{username}/services")
async def accounts_services(request: Request, username: str,
                            user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    form = await request.form()
    services = form.getlist("services")
    result = await AccountManager(get_executor()).set_services(username, services)
    return RedirectResponse(f"/accounts?msg={_msg(result, 'Akses layanan diubah')}", status_code=303)


def _msg(result: dict, ok_text: str) -> str:
    if result.get("ok"):
        return ok_text.replace(" ", "%20")
    return "Gagal:%20" + result.get("error", result.get("output", "unknown")).replace(" ", "%20")
