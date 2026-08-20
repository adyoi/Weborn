"""Manajemen cron job."""
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..db import add_cron, delete_cron, get_conn, list_crons, set_cron_enabled
from ..executors import get_executor
from ..managers.cron import CronManager, valid_schedule
from ..ui import render

router = APIRouter(tags=["Monitoring"])

USER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$")


async def _apply():
    await CronManager(get_executor()).apply(list_crons())


@router.get("/cron", response_class=HTMLResponse)
async def cron_page(request: Request, msg: str = "",
                    user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "cron.html", {
        "user": user,
        "crons": list_crons(),
        "cron_file": CronManager(get_executor()).build_file(list_crons()),
        "msg": msg,
        "active": "cron",
    })


@router.post("/cron/add")
async def cron_add(request: Request, name: str = Form(...),
                   schedule: str = Form(...), user: str = Form("root"),
                   command: str = Form(...),
                   admin: dict = Depends(require_admin)):
    if hasattr(admin, "headers"):
        return admin
    if not valid_schedule(schedule):
        return RedirectResponse("/cron?msg=Format%20jadwal%20salah%20(5%20kolom%20cron)",
                                status_code=303)
    if not command.strip():
        return RedirectResponse("/cron?msg=Perintah%20tidak%20boleh%20kosong",
                                status_code=303)
    uname = user.strip() or "root"
    if not USER_RE.match(uname):
        return RedirectResponse("/cron?msg=Nama%20user%20tidak%20valid",
                                status_code=303)
    try:
        add_cron(name.strip(), schedule.strip(), uname, command.strip())
    except Exception:
        return RedirectResponse("/cron?msg=Nama%20cron%20sudah%20ada", status_code=303)
    await _apply()
    return RedirectResponse("/cron?msg=Cron%20ditambahkan", status_code=303)


@router.post("/cron/{cron_id}/delete")
async def cron_delete(cron_id: int, admin: dict = Depends(require_admin)):
    if hasattr(admin, "headers"):
        return admin
    delete_cron(cron_id)
    await _apply()
    return RedirectResponse("/cron?msg=Cron%20dihapus", status_code=303)


@router.post("/cron/{cron_id}/toggle")
async def cron_toggle(cron_id: int, admin: dict = Depends(require_admin)):
    if hasattr(admin, "headers"):
        return admin
    with get_conn() as conn:
        row = conn.execute("SELECT enabled FROM crons WHERE id = ?",
                           (cron_id,)).fetchone()
        if row:
            set_cron_enabled(cron_id, 1 - row["enabled"])
    await _apply()
    return RedirectResponse("/cron?msg=Status%20diubah", status_code=303)
