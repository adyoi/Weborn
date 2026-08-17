"""Manajemen domain & subdomain."""
import socket
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..config import APP_TYPES
from ..db import get_conn
from ..executors import get_executor
from ..managers.nginx import NginxManager
from ..ui import render

router = APIRouter()


def _get_server_ip() -> str:
    """Dapatkan IP publik server."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _list_domains():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM domains ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


@router.get("/domains", response_class=HTMLResponse)
async def domains_page(request: Request, msg: str = "",
                       user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "domains.html", {
        "user": user,
        "domains": _list_domains(),
        "app_types": APP_TYPES,
        "msg": msg,
        "active": "domains",
    })


@router.post("/domains/add")
async def domains_add(request: Request, name: str = Form(...),
                      document_root: str = Form("/var/www"),
                      app_type: str = Form("static"),
                      app_port: str = Form("8000"),
                      ssl: int = Form(0),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if app_type not in APP_TYPES:
        return RedirectResponse("/domains?msg=Tipe%20aplikasi%20tidak%20dikenal", status_code=303)
    try:
        port_int = int((app_port or "8000").strip())
    except ValueError:
        return RedirectResponse("/domains?msg=Port%20harus%20angka", status_code=303)
    # app dinamis (django/fastapi/nodejs/laravel) -> reverse proxy ke port app
    proxy_target = None
    if app_type in ("django", "fastapi", "nodejs", "laravel"):
        proxy_target = f"http://127.0.0.1:{port_int}"
    try:
        with get_conn() as conn:
            conn.execute(
                """INSERT INTO domains(name, document_root, app_type, app_port, ssl, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (name, document_root, app_type, port_int, ssl,
                 datetime.now().isoformat()),
            )
            conn.commit()
    except Exception:
        return RedirectResponse("/domains?msg=Domain%20sudah%20ada", status_code=303)
    # Auto-create DNS records
    server_ip = _get_server_ip()
    now = datetime.now().isoformat()
    with get_conn() as conn:
        # A record untuk domain utama
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (name, "A", server_ip, 300, now))
        # CNAME untuk www
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (f"www.{name}", "CNAME", name, 300, now))
        conn.commit()
    nginx = NginxManager(get_executor())
    nginx.apply_domain(name, document_root, proxy_target, bool(ssl))
    await nginx._deploy(name)
    return RedirectResponse("/domains?msg=Domain%20ditambahkan%20+%20DNS%20records%20dibuat",
                            status_code=303)


@router.post("/domains/{domain_id}/delete")
async def domains_delete(domain_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    row = None
    with get_conn() as conn:
        row = conn.execute("SELECT name FROM domains WHERE id = ?", (domain_id,)).fetchone()
        conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        conn.commit()
    if row:
        await NginxManager(get_executor())._remove(row["name"])
    return RedirectResponse("/domains?msg=Domain%20dihapus", status_code=303)


@router.post("/domains/{domain_id}/toggle")
async def domains_toggle(domain_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        conn.execute("UPDATE domains SET enabled = 1 - enabled WHERE id = ?", (domain_id,))
        conn.commit()
    return RedirectResponse("/domains?msg=Status%20diubah", status_code=303)


@router.post("/domains/{domain_id}/ssl")
async def domains_ssl(domain_id: int, user: dict = Depends(require_admin)):
    """Terbitkan sertifikat Let's Encrypt via certbot, lalu aktifkan HTTPS."""
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?",
                           (domain_id,)).fetchone()
    if not row:
        return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
    d = dict(row)
    ex = get_executor()
    # pastikan certbot terpasang
    check = await ex.run("bash", "-c", "command -v certbot && echo yes || echo no")
    if "yes" not in check.stdout:
        await ex.run("apt-get", "install", "-y", "-qq", "certbot",
                     "python3-certbot-nginx")
    res = await ex.run("certbot", "certonly", "--nginx", "-d", d["name"],
                       "--non-interactive", "--agree-tos",
                       "--register-unsafely-without-email",
                       "--keep-until-expiring")
    if not res.ok:
        return RedirectResponse("/domains?msg=Gagal%20terbitkan%20SSL", status_code=303)
    with get_conn() as conn:
        conn.execute("UPDATE domains SET ssl = 1 WHERE id = ?", (domain_id,))
        conn.commit()
    nginx = NginxManager(ex)
    proxy = d["proxy_target"] or (
        f"http://127.0.0.1:{d['app_port']}" if d["app_type"] in
        ("django", "fastapi", "nodejs", "laravel") else None)
    nginx.apply_domain(d["name"], d["document_root"], proxy, ssl=True)
    await nginx._deploy(d["name"])
    return RedirectResponse("/domains?msg=SSL%20terpasang", status_code=303)
