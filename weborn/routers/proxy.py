"""Reverse Proxy & CDN."""
import re
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..db import get_conn
from ..executors import get_executor
from ..managers.nginx import NginxManager
from ..ui import render
from starlette.responses import JSONResponse

router = APIRouter(tags=["Web Server"])

_PROXY_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*$')
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')
_PATH_RE = re.compile(r'^(/[a-zA-Z0-9_\-./]*)?$')


def _list_proxies(kind: str | None = None):
    with get_conn() as conn:
        if kind:
            rows = conn.execute("SELECT * FROM proxies WHERE type = ? ORDER BY id DESC",
                                (kind,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM proxies ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


@router.get("/reverse-proxy", response_class=HTMLResponse)
async def proxy_page(request: Request, msg: str = "",
                     user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "proxy.html", {
        "user": user,
        "proxies": _list_proxies(),
        "kind": "reverse",
        "msg": msg,
        "active": "proxy",
    })


@router.get("/cdn", response_class=HTMLResponse)
async def cdn_page(request: Request, msg: str = "",
                   user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "proxy.html", {
        "user": user,
        "proxies": _list_proxies("cdn"),
        "kind": "cdn",
        "msg": msg,
        "active": "cdn",
    })


@router.post("/proxies/add")
async def proxies_add(request: Request, name: str = Form(...),
                      source: str = Form(...), target: str = Form(...),
                      ptype: str = Form("reverse"), cache: int = Form(0),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if ptype not in ("reverse", "cdn"):
        return JSONResponse({"ok": False, "error": "tipe tidak dikenal"}, status_code=400)
    name = name.strip()
    if not _PROXY_NAME_RE.match(name):
        dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
        return RedirectResponse(f"{dest}?msg=Nama%20proxy%20tidak%20valid", status_code=303)
    source = source.strip()
    if not _DOMAIN_RE.match(source):
        dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
        return RedirectResponse(f"{dest}?msg=Source%20harus%20domain%20valid", status_code=303)
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
        return RedirectResponse(f"{dest}?msg=Target%20harus%20URL%20valid%20(http/https)", status_code=303)
    if parsed.path and not _PATH_RE.match(parsed.path):
        dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
        return RedirectResponse(f"{dest}?msg=Path%20target%20tidak%20valid", status_code=303)
    try:
        with get_conn() as conn:
            conn.execute(
                """INSERT INTO proxies(name, source, target, type, cache, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (name, source, target, ptype, cache, datetime.now().isoformat()),
            )
            conn.commit()
    except Exception:
        dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
        return RedirectResponse(f"{dest}?msg=Nama%20proxy%20sudah%20ada", status_code=303)
    nginx = NginxManager(get_executor())
    nginx.apply_proxy(name, source, target, bool(cache))
    await nginx._deploy(name)
    dest = "/reverse-proxy" if ptype == "reverse" else "/cdn"
    return RedirectResponse(f"{dest}?msg=Proxy%20ditambahkan", status_code=303)


@router.post("/proxies/{proxy_id}/delete")
async def proxies_delete(proxy_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    kind = "reverse"
    with get_conn() as conn:
        row = conn.execute("SELECT name, type FROM proxies WHERE id = ?",
                           (proxy_id,)).fetchone()
        if row:
            kind = row["type"] if row["type"] in ("reverse", "cdn") else "reverse"
            conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
            conn.commit()
    if row:
        await NginxManager(get_executor())._remove(row["name"])
    dest = "/reverse-proxy" if kind == "reverse" else "/cdn"
    return RedirectResponse(f"{dest}?msg=Proxy%20dihapus", status_code=303)
