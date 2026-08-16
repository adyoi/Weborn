"""Manajemen database MySQL/MariaDB (list, buat, hapus, buat user)."""
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..ui import render

router = APIRouter()

DB_NAME_RE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


async def _db_info(ex):
    """Daftar database + pengecekan keberadaan mysql client."""
    installed = await ex.run("bash", "-c", "command -v mysql && echo yes || echo no")
    if "yes" not in installed.stdout:
        return [], False
    r = await ex.run("mysql", "-uroot", "-N", "-e", "SHOW DATABASES;")
    dbs = [line.strip() for line in r.stdout.splitlines() if line.strip() and
           line.strip() not in ("information_schema", "performance_schema", "mysql", "sys")]
    return sorted(dbs), True


@router.get("/database", response_class=HTMLResponse)
async def database_page(request: Request, msg: str = "",
                        user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    dbs, has_mysql = [], True
    if ex.mode in ("local", "wsl"):
        dbs, has_mysql = await _db_info(ex)
    else:  # dry-run
        dbs, has_mysql = ["weborn_prod", "blog_example"], True
    return render(request, "database.html", {
        "user": user, "dbs": dbs, "has_mysql": has_mysql,
        "msg": msg, "active": "database",
    })


@router.post("/database/create")
async def database_create(name: str = Form(...),
                          user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    db = name.strip()
    if not DB_NAME_RE.match(db):
        return RedirectResponse("/database?msg=Nama%20database%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mysql", "-uroot", "-e", f"CREATE DATABASE `{db}` CHARACTER SET utf8mb4;")
        ok = r.ok
    else:
        ok = True
    return RedirectResponse("/database?msg=Database%20dibuat" if ok
                            else "/database?msg=Gagal%20membuat", status_code=303)


@router.post("/database/{db}/drop")
async def database_drop(db: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if not DB_NAME_RE.match(db):
        return RedirectResponse("/database?msg=Nama%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mysql", "-uroot", "-e", f"DROP DATABASE `{db}`;")
        ok = r.ok
    else:
        ok = True
    return RedirectResponse("/database?msg=Database%20dihapus" if ok
                            else "/database?msg=Gagal%20menghapus", status_code=303)
