"""Manajemen domain, subdomain & path-based routing."""
import json
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


def _parent_domains():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name FROM domains WHERE kind='domain' ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def _get_locations(domain_id: int) -> list[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT locations FROM domains WHERE id = ?", (domain_id,)
        ).fetchone()
    if not row or not row["locations"]:
        return []
    try:
        return json.loads(row["locations"])
    except Exception:
        return []


def _save_locations(domain_id: int, locations: list[dict]):
    with get_conn() as conn:
        conn.execute(
            "UPDATE domains SET locations = ? WHERE id = ?",
            (json.dumps(locations), domain_id),
        )
        conn.commit()


@router.get("/domains", response_class=HTMLResponse)
async def domains_page(request: Request, msg: str = "",
                       user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _list_domains()
    parent_map = {d["id"]: d["name"] for d in domains if d["kind"] == "domain"}
    return render(request, "domains.html", {
        "user": user,
        "domains": domains,
        "app_types": APP_TYPES,
        "parent_map": parent_map,
        "msg": msg,
        "active": "domains",
    })


@router.post("/domains/add")
async def domains_add(request: Request, name: str = Form(...),
                      kind: str = Form("domain"),
                      parent_id: str = Form(""),
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
    proxy_target = None
    if app_type in ("django", "fastapi", "nodejs", "laravel"):
        proxy_target = f"http://127.0.0.1:{port_int}"
    parent = int(parent_id) if parent_id and parent_id.isdigit() else None
    kind = "subdomain" if parent else "domain"
    try:
        with get_conn() as conn:
            conn.execute(
                """INSERT INTO domains(name, kind, parent, document_root, app_type,
                   app_port, ssl, locations, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, kind, parent, document_root, app_type, port_int, ssl,
                 "[]", datetime.now().isoformat()),
            )
            conn.commit()
    except Exception:
        return RedirectResponse("/domains?msg=Domain%20sudah%20ada", status_code=303)
    if kind == "domain":
        server_ip = _get_server_ip()
        now = datetime.now().isoformat()
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                (name, "A", server_ip, 300, now))
            conn.execute(
                "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                (f"www.{name}", "CNAME", name, 300, now))
            conn.commit()
    nginx = NginxManager(get_executor())
    nginx.apply_domain(name, document_root, proxy_target, bool(ssl))
    await nginx._deploy(name)
    return RedirectResponse(
        "/domains?msg=Domain%20ditambahkan" + ("%20+%20DNS" if kind == "domain" else ""),
        status_code=303)


@router.get("/domains/{domain_id}/edit", response_class=HTMLResponse)
async def domains_edit_page(request: Request, domain_id: int,
                            user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if not row:
        return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
    return render(request, "domain_edit.html", {
        "user": user,
        "domain": dict(row),
        "app_types": APP_TYPES,
        "locations": _get_locations(domain_id),
        "active": "domains",
    })


@router.post("/domains/{domain_id}/edit")
async def domains_edit(request: Request, domain_id: int,
                       document_root: str = Form("/var/www"),
                       app_type: str = Form("static"),
                       app_port: str = Form("8000"),
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if app_type not in APP_TYPES:
        return RedirectResponse(f"/domains/{domain_id}/edit?msg=Tipe%20tidak%20dikenal",
                                status_code=303)
    try:
        port_int = int((app_port or "8000").strip())
    except ValueError:
        return RedirectResponse(f"/domains/{domain_id}/edit?msg=Port%20harus%20angka",
                                status_code=303)
    proxy_target = None
    if app_type in ("django", "fastapi", "nodejs", "laravel"):
        proxy_target = f"http://127.0.0.1:{port_int}"
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
        if not row:
            return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
        conn.execute(
            "UPDATE domains SET document_root=?, app_type=?, app_port=?, proxy_target=? WHERE id=?",
            (document_root, app_type, port_int, proxy_target, domain_id))
        conn.commit()
        name = row["name"]
    nginx = NginxManager(get_executor())
    locations = _get_locations(domain_id)
    nginx.apply_domain(name, document_root, proxy_target, bool(row["ssl"]), locations=locations)
    await nginx._deploy(name)
    return RedirectResponse("/domains?msg=Domain%20diperbarui", status_code=303)


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
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?",
                           (domain_id,)).fetchone()
    if not row:
        return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
    d = dict(row)
    ex = get_executor()
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
    locations = _get_locations(domain_id)
    nginx.apply_domain(d["name"], d["document_root"], proxy, ssl=True, locations=locations)
    await nginx._deploy(d["name"])
    return RedirectResponse("/domains?msg=SSL%20terpasang", status_code=303)


# ───────────────────────────────── Path Locations ──────────────────────────────

@router.post("/domains/{domain_id}/locations/add")
async def location_add(domain_id: int,
                       path: str = Form("/api"),
                       location_type: str = Form("proxy"),
                       target: str = Form(""),
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if not row:
        return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
    locations = _get_locations(domain_id)
    loc = {"path": path.rstrip("/") or "/", "type": location_type, "target": target}
    locations.append(loc)
    _save_locations(domain_id, locations)
    d = dict(row)
    nginx = NginxManager(get_executor())
    proxy = d["proxy_target"]
    nginx.apply_domain(d["name"], d["document_root"], proxy, bool(d["ssl"]),
                       locations=locations)
    await nginx._deploy(d["name"])
    return RedirectResponse(f"/domains/{domain_id}/edit?msg=Location%20ditambahkan",
                            status_code=303)


@router.post("/domains/{domain_id}/locations/delete")
async def location_delete(domain_id: int, index: int = Form(...),
                          user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if not row:
        return RedirectResponse("/domains?msg=Domain%20tidak%20ditemukan", status_code=303)
    locations = _get_locations(domain_id)
    if 0 <= index < len(locations):
        locations.pop(index)
    _save_locations(domain_id, locations)
    d = dict(row)
    nginx = NginxManager(get_executor())
    proxy = d["proxy_target"]
    nginx.apply_domain(d["name"], d["document_root"], proxy, bool(d["ssl"]),
                       locations=locations)
    await nginx._deploy(d["name"])
    return RedirectResponse(f"/domains/{domain_id}/edit?msg=Location%20dihapus",
                            status_code=303)
