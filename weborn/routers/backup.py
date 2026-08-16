"""Backup & restore situs + database panel."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..managers.backup import BackupManager
from ..ui import render

router = APIRouter()


@router.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, msg: str = "",
                      user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "backup.html", {
        "user": user,
        "backups": BackupManager().list_backups(),
        "msg": msg,
        "active": "backup",
    })


@router.post("/backup/create")
async def backup_create(include_www: int = Form(1), include_db: int = Form(1),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    info = BackupManager().create(bool(include_www), bool(include_db))
    size_mb = info["size"] / 1024 / 1024
    return RedirectResponse(
        f"/backup?msg=Backup%20{info['name']}%20dibuat%20({size_mb:.1f}MB)"
        f"%20-%20situs%20{'ok' if info['www'] else 'kosong'}%20DB%20{'ok' if info['db'] else 'kosong'}",
        status_code=303)


@router.get("/backup/download/{name}")
async def backup_download(name: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    try:
        path = BackupManager().safe_name(name)
    except FileNotFoundError:
        return RedirectResponse("/backup?msg=Arsip%20tidak%20ditemukan", status_code=303)
    return FileResponse(path, filename=path.name)


@router.post("/backup/{name}/delete")
async def backup_delete(name: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    try:
        path = BackupManager().safe_name(name)
        path.unlink()
    except FileNotFoundError:
        pass
    return RedirectResponse("/backup?msg=Backup%20dihapus", status_code=303)


@router.post("/backup/{name}/restore")
async def backup_restore(name: str, restore_www: int = Form(1),
                         restore_db: int = Form(0),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    try:
        res = BackupManager().restore(name, bool(restore_www), bool(restore_db))
    except FileNotFoundError:
        return RedirectResponse("/backup?msg=Arsip%20tidak%20ditemukan", status_code=303)
    except ValueError as e:
        return RedirectResponse(f"/backup?msg={str(e)[:80]}", status_code=303)
    return RedirectResponse(
        f"/backup?msg=Restore%20selesai%20-%20situs%20{'ok' if res['www'] else 'skip'}%20"
        f"DB%20{'ok' if res['db'] else 'skip'}", status_code=303)
