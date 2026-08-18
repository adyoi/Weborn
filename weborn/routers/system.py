"""Modul sistem Weborn: services, proses, network, SIEM/security, log,
file explorer, terminal, DNS, paket terinstall, dan editor config server."""
import asyncio
import json as _json
import os
import re
import stat
import time as _time
from datetime import datetime
from pathlib import Path

if os.name == "posix":
    import grp
    import pwd
else:
    grp = pwd = None

from fastapi import APIRouter, Depends, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..config import BASE_DIR, WEB_ROOT
from ..db import get_conn, get_setting, set_setting
from ..executors import get_executor
from ..ui import render

router = APIRouter()

ALLOWED_FS_ROOTS = ("/var/www", "/etc", "/opt", "/home", "/srv", "/usr/share",
                    "/srv/www", str(BASE_DIR), "/mnt/d/Documents")

SYSTEMD_ACTIONS = ("start", "stop", "restart", "reload", "enable", "disable")

OWNER_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}(:[a-zA-Z0-9_.-]{1,32})?$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")

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
    try:
        import psutil
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
    except Exception:
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
    try:
        import psutil
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


# ---------------------------------------------------------------- files
def _resolve_fs_path(raw: str) -> Path | None:
    """Resolve path & pastikan masih dalam akar yang diizinkan."""
    p = Path(raw).resolve()
    if p.is_absolute():
        for root in ALLOWED_FS_ROOTS:
            if str(p) == root or str(p).startswith(root + os.sep):
                return p
    return None


def _owner_of(st: os.stat_result) -> tuple:
    """Nama owner:group untuk sebuah stat (fallback ke uid/gid)."""
    if pwd is None:
        return "?", "?"
    try:
        oname = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        oname = str(st.st_uid)
    try:
        gname = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        gname = str(st.st_gid)
    return oname, gname


@router.get("/files", response_class=HTMLResponse)
async def files_page(request: Request, path: str = "", user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    default_root = WEB_ROOT if ex.mode in ("local", "wsl") else str(BASE_DIR)
    if not path:
        path = default_root
    resolved = _resolve_fs_path(path)
    error, entries = None, []
    if resolved is None:
        error = f"Path di luar izin (akar: {', '.join(ALLOWED_FS_ROOTS)})"
        resolved = Path(default_root)
    try:
        for child in sorted(resolved.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                st = child.stat()
                oname, gname = _owner_of(st)
                entries.append({
                    "name": child.name,
                    "dir": child.is_dir(),
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "mode": stat.filemode(st.st_mode),
                    "mode_num": "%03o" % stat.S_IMODE(st.st_mode),
                    "owner": oname,
                    "group": gname,
                })
            except OSError:
                continue
    except OSError as e:
        error = str(e)
    users = await _os_users(ex)
    groups = await _os_groups(ex)
    return render(request, "files.html", {"user": user, "path": str(resolved), "entries": entries,
                                          "error": error, "active": "files",
                                          "users": users, "groups": groups})


async def _os_users(ex) -> list:
    """Daftar user OS untuk dropdown chown (root, system & user uid>=1000)."""
    users = ["root", "www-data"]
    if ex.mode in ("local", "wsl"):
        r = await ex.run("getent", "passwd")
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                if uid == 0 or uid >= 1000:
                    users.append(parts[0])
    seen, out = set(), []
    for u in users:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def _os_groups(ex) -> list:
    """Daftar group OS untuk dropdown chown."""
    groups = ["root", "www-data", "sudo"]
    if ex.mode in ("local", "wsl"):
        r = await ex.run("getent", "group")
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                groups.append(parts[0])
    seen, out = set(), []
    for g in groups:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


@router.get("/files/download")
async def files_download(path: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None or not resolved.is_file():
        return JSONResponse({"error": "file tidak valid"}, status_code=400)
    return FileResponse(resolved, filename=resolved.name)


@router.post("/files/save")
async def files_save(path: str = Form(...), content: str = Form(""),
                     user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    r = await get_executor().write_file(str(resolved), content)
    return RedirectResponse(f"/files?path={resolved.parent}&saved={r.ok}", status_code=303)


@router.post("/files/delete")
async def files_delete(path: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    if resolved.is_file():
        resolved.unlink()
        ok = True
    elif resolved.is_dir():
        try:
            resolved.rmdir()
            ok = True
        except OSError:
            ok = False
    else:
        ok = False
    return RedirectResponse(f"/files?path={resolved.parent}&deleted={ok}", status_code=303)


@router.post("/files/chown")
async def files_chown(path: str = Form(...), owner: str = Form(...),
                      group: str = Form(""), recursive: str = Form(""),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    owner = owner.strip()
    group = group.strip()
    if not owner or not OWNER_RE.match(owner) or (group and not OWNER_RE.match(group)):
        return JSONResponse({"ok": False, "error": "user/group tidak valid"}, status_code=400)
    spec = f"{owner}:{group}" if group else owner
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        args = ["chown"]
        if recursive == "1":
            args.append("-R")
        args += [spec, str(resolved)]
        r = await ex.run(*args)
        ok = r.ok
    else:
        ok = True
    return RedirectResponse(f"/files?path={resolved.parent}&chown={ok}", status_code=303)


@router.post("/files/chmod")
async def files_chmod(path: str = Form(...), mode: str = Form(...),
                      recursive: str = Form(""), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    mode = mode.strip()
    if not mode or not MODE_RE.match(mode):
        return JSONResponse({"ok": False, "error": "mode tidak valid (contoh: 644, 755)"},
                            status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        args = ["chmod"]
        if recursive == "1":
            args.append("-R")
        args += [mode, str(resolved)]
        r = await ex.run(*args)
        ok = r.ok
    else:
        ok = True
    return RedirectResponse(f"/files?path={resolved.parent}&chmod={ok}", status_code=303)


@router.post("/files/create")
async def files_create(path: str = Form(...), name: str = Form(...),
                       kind: str = Form("file"), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    name = name.strip()
    if not name or "/" in name or name in (".", ".."):
        return JSONResponse({"ok": False, "error": "nama tidak valid"}, status_code=400)
    target = resolved / name
    if target.exists():
        return JSONResponse({"ok": False, "error": f"'{name}' sudah ada"}, status_code=400)
    ex = get_executor()
    if kind == "dir":
        if ex.mode in ("local", "wsl"):
            r = await ex.run("mkdir", "-p", str(target))
            ok = r.ok
        else:
            target.mkdir(parents=True, exist_ok=True)
            ok = True
    else:
        if ex.mode in ("local", "wsl"):
            r = await ex.run("touch", str(target))
            ok = r.ok
        else:
            target.touch()
            ok = True
    return RedirectResponse(f"/files?path={resolved}&created={ok}", status_code=303)


@router.get("/files/edit")
async def files_edit_get(path: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None or not resolved.is_file():
        return JSONResponse({"ok": False, "error": "file tidak valid"}, status_code=400)
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    return JSONResponse({"ok": True, "content": content, "path": str(resolved)})


@router.post("/files/mkdir")
async def files_mkdir(path: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    if resolved.exists():
        return JSONResponse({"ok": False, "error": "sudah ada"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mkdir", "-p", str(resolved))
        ok = r.ok
    else:
        resolved.mkdir(parents=True, exist_ok=True)
        ok = True
    return RedirectResponse(f"/files?path={resolved.parent}&created={ok}", status_code=303)


# ---------------------------------------------------------------- terminal
@router.get("/terminal", response_class=HTMLResponse)
async def terminal_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "terminal.html", {"user": user, "active": "terminal"})


@router.post("/terminal/run")
async def terminal_run(cmd: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if len(cmd) > 4000:
        return JSONResponse({"ok": False, "error": "perintah terlalu panjang"}, status_code=400)
    r = await get_executor().run("bash", "-c", cmd)
    return {"ok": r.ok, "returncode": r.returncode, "output": r.output}


@router.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    await websocket.accept()
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        await websocket.send_text("[error] Terminal WebSocket hanya tersedia di mode local/WSL\r\n")
        await websocket.close()
        return
    try:
        import pty
        import fcntl
        import struct
        import termios
        master_fd, slave_fd = pty.openpty()
        # Set non-blocking
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        pid = os.fork()
        if pid == 0:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            os.execvp("/bin/bash", ["/bin/bash", "--login"])
        os.close(slave_fd)
        await websocket.send_text("\033[1;32m[Terminal Weborn]\033[0m Siap.\r\n")
        async def read_pty():
            while True:
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        await websocket.send_text(data.decode("utf-8", errors="replace"))
                except (OSError, BlockingIOError):
                    await asyncio.sleep(0.01)
        async def read_ws():
            while True:
                data = await websocket.receive_text()
                if data.startswith("\x1b["):
                    # Resize event: \x1b[rows;colsR
                    import re as _re
                    m = _re.match(r"\x1b\[(\d+);(\d+)R", data)
                    if m:
                        rows, cols = int(m.group(1)), int(m.group(2))
                        winsize = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
                        continue
                os.write(master_fd, data.encode("utf-8"))
        done, pending = await asyncio.wait(
            [asyncio.create_task(read_pty()), asyncio.create_task(read_ws())],
            return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n[error] {e}\r\n")
        except Exception:
            pass
    finally:
        try:
            os.close(master_fd)
        except Exception:
            pass


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
