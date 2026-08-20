"""Modul sistem Weborn: services, proses, network, logs, packages, settings, DNS."""
import asyncio
import json as _json
import os
import time as _time
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..config import BASE_DIR
from ..db import get_conn, get_setting, set_setting
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["System"])

SYSTEMD_ACTIONS = ("start", "stop", "restart", "reload", "enable", "disable")

CONFIG_FILES = {
    "SSH": {
        "path": "/etc/ssh/sshd_config",
        "desc": "Konfigurasi server SSH (port, izin root, PasswordAuthentication)",
    },
    "Nginx": {
        "path": "/etc/nginx/nginx.conf",
        "desc": "Konfigurasi utama server web nginx",
    },
    "Apache": {
        "path": "/etc/apache2/apache2.conf",
        "desc": "Konfigurasi utama Apache",
    },
    "Hosts": {
        "path": "/etc/hosts",
        "desc": "Pemetaan hostname statis",
    },
    "Hostname": {
        "path": "/etc/hostname",
        "desc": "Nama host server",
    },
    "sysctl": {
        "path": "/etc/sysctl.conf",
        "desc": "Parameter kernel (net.ipv4.ip_forward, dll)",
    },
    "resolv": {
        "path": "/etc/resolv.conf",
        "desc": "Konfigurasi DNS resolver",
    },
    "fstab": {
        "path": "/etc/fstab",
        "desc": "Mount sistem file",
    },
    "PHP": {
        "path": "/etc/php/8.2/apache2/php.ini",
        "desc": "Konfigurasi PHP (fallback bila ada)",
    },
    "MySQL": {
        "path": "/etc/mysql/my.cnf",
        "desc": "Konfigurasi MySQL/MariaDB",
    },
    "Panel Env": {
        "path": "/opt/weborn/.env",
        "desc": "Variabel lingkungan panel Weborn",
    },
}


# ---------------------------------------------------------------- services
@router.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    units: dict[str, dict] = {}
    if ex.mode in ("local", "wsl"):
        r = await ex.run("systemctl", "list-unit-files", "--type=service",
                         "--no-pager", "--plain", "--no-legend")
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                units[parts[0]] = {"enabled": parts[1]}
        r2 = await ex.run("systemctl", "list-units", "--type=service", "--all",
                          "--no-pager", "--plain", "--no-legend")
        for line in r2.stdout.splitlines():
            parts = line.split(maxsplit=4)
            if len(parts) >= 4:
                name, load, active, sub = parts[:4]
                desc = parts[4] if len(parts) > 4 else ""
                units.setdefault(name, {})["load"] = load
                units[name]["active"] = active
                units[name]["sub"] = sub
                units[name]["desc"] = desc
    else:  # dry-run
        for name in ("nginx.service", "apache2.service", "mysql.service",
                     "ssh.service", "vsftpd.service", "weborn.service"):
            units[name] = {"enabled": "disabled", "active": "inactive", "sub": "dead",
                           "desc": "contoh (dry-run)"}
    services = [{"name": n, **v} for n, v in units.items()]
    services.sort(key=lambda s: s["name"])
    return render(request, "services.html", {"user": user, "services": services,
                                             "active": "services"})


@router.post("/services/{unit}/{action}")
async def service_action(unit: str, action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in SYSTEMD_ACTIONS:
        return JSONResponse({"ok": False, "error": "aksi tidak dikenal"}, status_code=400)
    r = await get_executor().systemctl(action, unit)
    return {"ok": r.ok, "action": action, "unit": unit, "output": r.output}


# ---------------------------------------------------------------- processes
@router.get("/processes", response_class=HTMLResponse)
async def processes_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    procs = []
    if psutil:
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
            try:
                info = p.info
                procs.append({
                    "pid": info["pid"], "name": info["name"][:40],
                    "user": info["username"] or "?", "cpu": round(info["cpu_percent"] or 0, 1),
                    "mem": round(info["memory_percent"] or 0, 1), "status": info["status"],
                })
            except Exception:
                continue
    if not procs:
        procs = [{"pid": 1, "name": "init", "user": "root", "cpu": 0, "mem": 0, "status": "running"}]
    procs.sort(key=lambda x: -x["cpu"])
    total = len(procs)
    procs = procs[:200]
    return render(request, "processes.html", {"user": user, "processes": procs,
                                              "total": total, "active": "processes"})


@router.post("/processes/{pid}/kill")
async def kill_process(pid: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    r = await get_executor().run("kill", "-9", str(pid))
    return {"ok": r.ok, "pid": pid, "output": r.output}


# ---------------------------------------------------------------- network
@router.get("/network", response_class=HTMLResponse)
async def network_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    interfaces, listeners, connections = [], [], []
    if psutil:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family.name == "AF_INET":
                        interfaces.append({"name": name, "addr": a.address, "netmask": a.netmask})
            for c in psutil.net_connections("tcp"):
                if c.status == "LISTEN" and c.laddr:
                    connections.append({"type": "listen", "addr": f"{c.laddr.ip}:{c.laddr.port}",
                                        "pid": c.pid})
                elif c.status == "ESTABLISHED" and c.raddr:
                    connections.append({"type": "conn",
                                        "addr": f"{c.laddr.ip}:{c.laddr.port} → {c.raddr.ip}:{c.raddr.port}",
                                        "pid": c.pid})
        except Exception:
            pass
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("ss", "-ltnp")
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                listeners.append({"proto": parts[0], "listen": parts[3],
                                  "process": parts[5] if len(parts) > 5 else ""})
    stats = {"interfaces": len(interfaces), "listeners": len(listeners or connections),
             "conns": sum(1 for c in connections if c["type"] == "conn")}
    return render(request, "network.html", {"user": user, "interfaces": interfaces,
                                            "listeners": listeners, "connections": connections[:120],
                                            "stats": stats, "active": "network"})


# ---------------------------------------------------------------- SIEM/security
def _parse_bruteforce(text: str, limit: int = 10):
    """Count 'Failed password for ... from <ip>' per IP dari auth.log."""
    from collections import Counter
    ip_counts: Counter[str, int] = Counter()
    last = {}
    for line in text.splitlines():
        if "Failed password" in line:
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok == "from" and i + 1 < len(parts):
                    ip = parts[i + 1].rstrip(":")
                    ip_counts[ip] += 1
                    last[ip] = line[:80]
    top = ip_counts.most_common(limit)
    return [{"ip": ip, "attempts": n, "last": last.get(ip, "")} for ip, n in top]


# ---------------------------------------------------------------- logs
LOG_SOURCES = {
    "system": ("journalctl", "Log sistem (journalctl -xe)"),
    "auth": ("auth", "Login & autentikasi (/var/log/auth.log)"),
    "nginx": ("nginx", "Error log nginx"),
    "mysql": ("mysql", "Error log MySQL/MariaDB"),
    "apache": ("apache", "Error log Apache"),
    "panel": ("panel", "Log & audit Weborn"),
}


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, source: str = "system", lines: int = 120,
                    user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    output, ok = "", True
    if ex.mode in ("local", "wsl"):
        if source == "panel":
            r = await ex.run("bash", "-c",
                             f"tail -n {lines} {BASE_DIR}/data/logs/panel.log 2>/dev/null || true")
        elif source == "system":
            r = await ex.run("journalctl", "-xe", "-n", str(lines), "--no-pager")
        elif source == "auth":
            r = await ex.run("bash", "-c", f"tail -n {lines} /var/log/auth.log 2>/dev/null || true")
        elif source == "nginx":
            r = await ex.run("bash", "-c", f"tail -n {lines} /var/log/nginx/error.log 2>/dev/null || true")
        elif source == "mysql":
            r = await ex.run("bash", "-c", f"tail -n {lines} /var/log/mysql/error.log 2>/dev/null || true")
        elif source == "apache":
            r = await ex.run("bash", "-c", f"tail -n {lines} /var/log/apache2/error.log 2>/dev/null || true")
        output, ok = r.output, r.ok
    else:
        output = f"[dry-run] log {source} ({lines} baris)"
    return render(request, "logs.html", {"user": user, "source": source, "lines": lines,
                                         "output": output, "ok": ok, "sources": LOG_SOURCES,
                                         "active": "logs"})


# ---------------------------------------------------------------- packages & OS
@router.get("/packages", response_class=HTMLResponse)
async def packages_page(request: Request, q: str = "", user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    packages = []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c",
                         "dpkg-query -W -f='${Package} ${Version} ${Section}\\n' 2>/dev/null | head -3000")
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1],
                                 "section": parts[2] if len(parts) > 2 else ""})
    else:
        packages = [{"name": "nginx", "version": "1.26.3", "section": "httpd"},
                    {"name": "python3", "version": "3.13.5", "section": "python"},
                    {"name": "mysql-server", "version": "8.0.36", "section": "database"}]
    if q:
        packages = [p for p in packages if q.lower() in p["name"].lower() or q.lower() in p["version"].lower()]
    total = len(packages)
    return render(request, "packages.html", {"user": user, "packages": packages[:400],
                                              "total": total, "q": q, "active": "packages"})


async def _apt_stream(cmd: str):
    """Generator for apt command streaming via SSE."""
    import asyncio as _aio
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        yield f"data: [dry-run] {cmd}\n\n"
        yield "data: [DONE]\n\n"
        return
    proc = await _aio.create_subprocess_exec(
        "bash", "-c", cmd,
        stdout=_aio.subprocess.PIPE,
        stderr=_aio.subprocess.STDOUT,
    )
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\n")
        if text:
            yield f"data: {text}\n\n"
    await proc.wait()
    yield f"data: [DONE] exit={proc.returncode}\n\n"


@router.post("/packages/update")
async def packages_update(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from starlette.responses import StreamingResponse
    return StreamingResponse(
        _apt_stream("sudo apt update 2>&1"),
        media_type="text/event-stream",
    )


@router.post("/packages/upgrade")
async def packages_upgrade(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from starlette.responses import StreamingResponse
    return StreamingResponse(
        _apt_stream("sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1"),
        media_type="text/event-stream",
    )



async def os_update_info(ex):
    """Info OS + update tersedia + jumlah paket (dipakai dashboard)."""
    if ex.mode not in ("local", "wsl"):
        return {"os": "Debian/Ubuntu (dry-run)", "updates": 0, "packages": 0,
                "uptime": None}
    r = await ex.run("bash", "-c", "grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'")
    os_name = r.stdout.strip() or "Linux"
    r2 = await ex.run("bash", "-c", "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l")
    updates = int(r2.stdout.strip() or "0")
    r3 = await ex.run("bash", "-c", "dpkg-query -W 2>/dev/null | wc -l")
    pkg = int(r3.stdout.strip() or "0")
    return {"os": os_name, "updates": updates, "packages": pkg, "uptime": None}


async def os_update_info_cached(ex, ttl: int = 600):
    """os_update_info dengan cache (ttl detik) + timeout supaya dashboard tetap cepat."""
    now = _time.time()
    try:
        ts = float(get_setting("os_info_ts", "0"))
    except (TypeError, ValueError):
        ts = 0.0
    cached = get_setting("os_info_cache", "")
    if cached and (now - ts) < ttl:
        try:
            return _json.loads(cached)
        except ValueError:
            pass
    try:
        result = await asyncio.wait_for(os_update_info(ex), timeout=8)
    except Exception:
        result = {"os": "Linux", "updates": 0, "packages": 0}
    set_setting("os_info_cache", _json.dumps(result))
    set_setting("os_info_ts", str(now))
    return result


# ---------------------------------------------------------------- settings (config GUI)
@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, path: str = "", user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    current, content = None, ""
    if path:
        current = next((c for c in CONFIG_FILES.values() if c["path"] == path), None)
        if current:
            r = await ex.read_file(path)
            content = r.stdout
    return render(request, "settings.html", {"user": user, "configs": CONFIG_FILES,
                                             "current": current, "content": content,
                                             "active": "settings"})


@router.post("/settings/save")
async def settings_save(path: str = Form(...), content: str = Form(""),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    known = any(c["path"] == path for c in CONFIG_FILES.values())
    if not known:
        return JSONResponse({"ok": False, "error": "file tidak dalam daftar aman"}, status_code=400)
    r = await get_executor().write_file(path, content)
    return RedirectResponse(f"/settings?path={path}&saved={'ok' if r.ok else 'gagal'}",
                            status_code=303)


# ---------------------------------------------------------------- DNS
@router.get("/dns", response_class=HTMLResponse)
async def dns_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        records = [dict(r) for r in conn.execute(
            "SELECT * FROM dns_records ORDER BY name").fetchall()]
    ex = get_executor()
    resolv = ""
    if ex.mode in ("local", "wsl"):
        r = await ex.read_file("/etc/resolv.conf")
        resolv = r.stdout
    else:
        resolv = "[dry-run] resolv.conf"
    return render(request, "dns.html", {"user": user, "records": records,
                                        "resolv": resolv, "active": "dns"})


@router.post("/dns/add")
async def dns_add(name: str = Form(...), type: str = Form("A"), value: str = Form(...),
                  ttl: int = Form(300), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (name.strip(), type.upper(), value.strip(), ttl, datetime.now().isoformat()))
    return RedirectResponse("/dns?added=1", status_code=303)


@router.post("/dns/{rid}/delete")
async def dns_delete(rid: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        conn.execute("DELETE FROM dns_records WHERE id = ?", (rid,))
    return RedirectResponse("/dns?deleted=1", status_code=303)
