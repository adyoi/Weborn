"""Router aplikasi: kelola environment app (Node/PHP/Python/Go/Ruby/Rust)."""
import shlex

from fastapi import APIRouter, Depends, Form, Request, WebSocket
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import JSONResponse

from ..auth import require_admin, require_user
from ..config import FRAMEWORKS, RUNTIMES
from ..db import get_app, set_app_status
from ..executors import get_executor
from ..managers.apps import AppManager
from ..ui import render

router = APIRouter(tags=["Weborn Apps"])


@router.get("/apps", response_class=HTMLResponse)
async def apps_page(request: Request, user: dict = Depends(require_user),
                    type: str = ""):
    if hasattr(user, "headers"):
        return user
    manager = AppManager(get_executor())
    apps = manager.list()
    # Filter by type (wsgi, asgi, flask, django, fastapi, etc.)
    if type:
        apps = [a for a in apps if a.get("app_type") == type]
    return render(request, "apps.html", {
        "user": user,
        "apps": apps,
        "runtimes": RUNTIMES,
        "frameworks": FRAMEWORKS,
        "active": "apps",
        "app_type_filter": type,
    })


@router.get("/apps/api/check-dir")
async def api_check_dir(path: str = "", user: dict = Depends(require_admin)):
    """Check if a directory path exists, is a directory, and is writable."""
    if hasattr(user, "headers"):
        return user
    if not path.strip():
        return JSONResponse({"ok": False, "error": "path kosong"})
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        qpath = shlex.quote(path)
        r = await ex.run("bash", "-c",
                         f"if [ -d {qpath} ]; then "
                         f"  echo EXISTS; "
                         f"  sudo ls -1 {qpath} 2>/dev/null | head -20; "
                         f"  echo '---'; "
                         f"  sudo test -w {qpath} && echo WRITABLE || echo NOWRIT; "
                         f"else "
                         f"  echo MISSING; "
                         f"  pdir=$(dirname {qpath}); "
                         f"  [ -d \"$pdir\" ] && sudo test -w \"$pdir\" && echo PARENT_WRITABLE || echo PARENT_NOWRIT; "
                         f"fi")
        out = r.stdout.strip()
        lines = out.splitlines()
        exists = lines[0] == "EXISTS" if lines else False
        writable = "WRITABLE" in out and "NOWRIT" not in out
        files = []
        if exists:
            files = [l for l in lines[1:] if l and l != "---" and not l.startswith("WRITABLE") and not l.startswith("NOWRIT")]
        parent_writable = "PARENT_WRITABLE" in out
        return JSONResponse({
            "ok": True, "exists": exists, "writable": writable,
            "parent_writable": parent_writable, "files": files,
            "message": ("Direktori ada, bisa ditulis" if exists and writable
                        else "Direktori ada, TIDAK bisa ditulis" if exists
                        else "Direktori belum ada, parent bisa ditulis" if parent_writable
                        else "Direktori belum ada, parent TIDAK bisa ditulis"),
        })
    return JSONResponse({"ok": True, "exists": False, "writable": False,
                         "files": [], "message": "[dry-run] cek direktori"})


@router.get("/apps/api/validate-module")
async def api_validate_module(dir: str = "", module: str = "", app_name: str = "",
                               user: dict = Depends(require_admin)):
    """Validate module:app — check if module exists and app_name is callable."""
    if hasattr(user, "headers"):
        return user
    if not module.strip():
        return JSONResponse({"ok": False, "error": "module kosong"})
    ex = get_executor()
    # Extract module filename (e.g. "main" from "main:app")
    mod_name = module.split(":")[0].strip().split(".")[0].strip()
    if not mod_name:
        return JSONResponse({"ok": False, "error": "format module salah"})
    # Validate: module and app_name must be valid Python identifiers
    import re as _re
    if not _re.fullmatch(r"[A-Za-z_]\w*", mod_name):
        return JSONResponse({"ok": False, "error": "nama module tidak valid"})
    clean_app = app_name.strip()
    if clean_app and not _re.fullmatch(r"[A-Za-z_]\w*", clean_app):
        return JSONResponse({"ok": False, "error": "nama app tidak valid"})
    if ex.mode in ("local", "wsl"):
        check_dir = dir.strip() or "/tmp"
        qdir = shlex.quote(check_dir)
        qmod = shlex.quote(mod_name)
        r = await ex.run("bash", "-c",
                         f"cd {qdir} 2>/dev/null && "
                         f"python3 -c \""
                         f"import importlib.util, sys; "
                         f"spec = importlib.util.find_spec({qmod}); "
                         f"exit(0 if spec else 1)"
                         f"\" 2>/dev/null && echo MODULE_OK || echo MODULE_MISSING")
        mod_ok = "MODULE_OK" in r.stdout
        if not mod_ok:
            return JSONResponse({
                "ok": True, "valid": False,
                "error": f"Module '{mod_name}.py' tidak ditemukan di {check_dir}",
                "message": f"❌ Module '{mod_name}' tidak ditemukan",
            })
        if clean_app:
            qapp = shlex.quote(clean_app)
            r2 = await ex.run("bash", "-c",
                              f"cd {qdir} 2>/dev/null && "
                              f"python3 -c \""
                              f"from {qmod} import {qapp}; "
                              f"import inspect; "
                              f"assert callable({qapp}) or hasattr({qapp}, '__call__') or hasattr({qapp}, 'app') or hasattr({qapp}, 'get') or hasattr({qapp}, 'route')"
                              f"\" 2>/dev/null && echo APP_OK || echo APP_MISSING")
            app_ok = "APP_OK" in r2.stdout
            if not app_ok:
                return JSONResponse({
                    "ok": True, "valid": False,
                    "error": f"'{app_name}' tidak ditemukan atau bukan callable di module '{mod_name}'",
                    "message": f"❌ '{app_name}' tidak ditemukan di module '{mod_name}'",
                })
            return JSONResponse({
                "ok": True, "valid": True,
                "message": f"✅ Module '{mod_name}' + app '{app_name}' valid",
            })
        return JSONResponse({
            "ok": True, "valid": True,
            "message": f"✅ Module '{mod_name}' ditemukan",
        })
    return JSONResponse({"ok": True, "valid": True, "message": "[dry-run] validasi module"})


# ── Config file whitelist ──────────────────────────────────────────────────────
import re as _re

_NGINX_VERSION_RE = _re.compile(r"^/etc/nginx/[\w.\-]+$")
_PHP_VERSION_RE = _re.compile(r"^/etc/php/\d+\.\d+/fpm/[\w.\-/]+$")
_APP_DIR_RE = _re.compile(r"^/var/www/[\w\-]+/[\w.\-]+$")


def _is_config_path_allowed(path: str) -> bool:
    """Check if a config file path is whitelisted for editing."""
    p = path.strip()
    if _NGINX_VERSION_RE.match(p):
        return True
    if _PHP_VERSION_RE.match(p):
        return True
    if _APP_DIR_RE.match(p):
        return True
    return False


def _resolve_config_path(config_type: str, config_name: str,
                         app_name: str = "") -> str:
    """Resolve a config selector value to an absolute file path."""
    if config_type == "nginx":
        return f"/etc/nginx/{config_name}"
    if config_type == "php-fpm":
        import glob as _glob
        candidates = sorted(_glob.glob("/etc/php/*/fpm"), reverse=True)
        ver_dir = candidates[0] if candidates else "/etc/php/8.2/fpm"
        if config_name == "php.ini":
            return f"{ver_dir}/php.ini"
        if config_name == "www.conf":
            return f"{ver_dir}/pool.d/www.conf"
        if config_name == "php-fpm.conf":
            return f"{ver_dir}/php-fpm.conf"
        return f"{ver_dir}/{config_name}"
    if config_type == "node":
        slug = app_name.replace("/", "").replace("..", "") or "app"
        return f"/var/www/{slug}/{config_name}"
    return ""


@router.get("/apps/api/config-file")
async def api_config_file_read(config_type: str = "", config_name: str = "",
                               app_name: str = "", path: str = "",
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if path:
        resolved = path.strip()
    else:
        resolved = _resolve_config_path(config_type, config_name, app_name)
    if not resolved or not _is_config_path_allowed(resolved):
        return JSONResponse({"ok": False, "error": "path tidak diizinkan"})
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.read_file(resolved)
        if not r.ok and not r.stdout:
            return JSONResponse({"ok": False, "error": r.stderr or "file tidak ditemukan"})
        return JSONResponse({"ok": True, "path": resolved, "content": r.stdout})
    return JSONResponse({"ok": True, "path": resolved, "content": "# [dry-run] content simulasi"})


@router.post("/apps/api/config-file")
async def api_config_file_save(request: Request,
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    body = await request.json()
    path = (body.get("path") or "").strip()
    content = body.get("content", "")
    if not path or not _is_config_path_allowed(path):
        return JSONResponse({"ok": False, "error": "path tidak diizinkan"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.write_file(path, content)
        if not r.ok:
            return JSONResponse({"ok": False, "error": r.stderr or "gagal menulis file"})
        return JSONResponse({"ok": True, "path": path})
    return JSONResponse({"ok": True, "path": path, "output": "[dry-run] file disimpan"})


@router.get("/apps/{app_id}/edit", response_class=HTMLResponse)
async def apps_edit_page(request: Request, app_id: int,
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return RedirectResponse("/apps?msg=App%20tidak%20ditemukan", status_code=303)
    from ..managers.apps import _detect_pm, _app_type_for, AppManager as _AM
    pm = _detect_pm(app.get("command", ""))
    stored = app.get("app_type", "")
    app_type = stored if stored else _app_type_for(app["language"], app.get("framework", ""))
    process_config = _AM.parse_process_config(app.get("command", ""))
    return render(request, "app_edit.html", {
        "user": user,
        "app": app,
        "runtimes": RUNTIMES,
        "process_manager": pm,
        "app_type": app_type,
        "process_config": process_config,
        "active": "apps",
    })


@router.post("/apps/{app_id}/edit")
async def apps_edit(request: Request, app_id: int,
                    command: str = Form(...),
                    user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return RedirectResponse("/apps?msg=App%20tidak%20ditemukan", status_code=303)
    from ..db import get_conn
    with get_conn() as conn:
        conn.execute("UPDATE apps SET command = ? WHERE id = ?", (command, app_id))
        conn.commit()
    return RedirectResponse("/apps?msg=App%20diperbarui", status_code=303)


@router.post("/apps/create")
async def apps_create(name: str = Form(...), language: str = Form(...),
                      framework: str = Form(""), port: str = Form("0"),
                      webserver: str = Form("nginx"),
                      webserver_port: str = Form(""),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    try:
        port_int = int((port or "0").strip())
    except ValueError:
        return JSONResponse({"ok": False, "error": "port harus berupa angka"},
                            status_code=400)
    try:
        result = await AppManager(get_executor()).create(
            name.strip(), language, framework.strip(), port_int)
    except Exception as e:  # mis. nama duplikat (UNIQUE constraint)
        return JSONResponse({"ok": False, "error": f"gagal membuat app: {e}"},
                            status_code=400)
    if not result.get("ok"):
        return JSONResponse({"ok": False, "error": result.get("error")}, status_code=400)

    ws_port = int(webserver_port) if webserver_port and webserver_port.isdigit() else 0
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        slug = name.strip().lower().replace(" ", "-")[:63]
        home = result.get("home_dir", f"/var/www/{slug}")
        upstream = f"http://127.0.0.1:{result.get('port', 8000)}"
        if webserver == "apache":
            from ..managers.apache import ApacheManager
            apache = ApacheManager(ex)
            apache.apply_domain(slug, home, upstream, port=ws_port or 80)
            await apache._deploy(slug)
        elif webserver == "caddy":
            from ..managers.nginx import NginxManager
            nginx = NginxManager(ex)
            nginx.apply_domain(slug, home, upstream, port=ws_port or 443)
            await nginx._deploy(slug)
        elif webserver == "lighttpd":
            from ..managers.nginx import NginxManager
            nginx = NginxManager(ex)
            nginx.apply_domain(slug, home, upstream, port=ws_port or 80)
            await nginx._deploy(slug)
        else:
            from ..managers.nginx import NginxManager
            nginx = NginxManager(ex)
            nginx.apply_domain(slug, home, upstream)
            await nginx._deploy(slug)

    port = result.get("port", 8000)
    return RedirectResponse(f"/apps?created=1&port={port}", status_code=303)


@router.post("/apps/create-native")
async def apps_create_native(name: str = Form(...), app_type: str = Form("wsgi"),
                              launcher: str = Form("gunicorn"), module_app: str = Form("main:app"),
                              workers: str = Form("4"), host: str = Form("0.0.0.0"),
                              port: str = Form("8000"), dir_path: str = Form(""),
                              webserver: str = Form("nginx"),
                              webserver_port: str = Form(""),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    try:
        port_int = int((port or "8000").strip())
    except ValueError:
        return JSONResponse({"ok": False, "error": "port harus angka"}, status_code=400)
    try:
        workers_int = int((workers or "4").strip())
    except ValueError:
        workers_int = 4

    # Build command from user selections
    import re as _re
    mod = module_app.strip() or "main:app"
    h = (host.strip() or "0.0.0.0")
    if not _re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*:[a-zA-Z_][a-zA-Z0-9_]*$', mod):
        return JSONResponse({"ok": False, "error": "module_app format: module:obj (contoh: main:app)"}, status_code=400)
    if not _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', h):
        return JSONResponse({"ok": False, "error": "host harus IP address (contoh: 0.0.0.0)"}, status_code=400)
    if app_type == "wsgi":
        if launcher == "gunicorn":
            command = f"python3 -m gunicorn -w {workers_int} {mod} --bind {h}:{port_int}"
        else:
            command = f"python3 -m uvicorn {mod} --interface wsgi --host {h} --port {port_int}"
    else:
        if launcher == "gunicorn":
            command = f"python3 -m gunicorn -w {workers_int} -k uvicorn.workers.UvicornWorker {mod} --bind {h}:{port_int}"
        else:
            command = f"python3 -m uvicorn {mod} --host {h} --port {port_int} --workers {workers_int}"

    try:
        result = await AppManager(get_executor()).create_native(
            name.strip(), app_type, command, port_int,
            dir_path=dir_path.strip())
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"gagal membuat app: {e}"},
                            status_code=400)
    if not result.get("ok"):
        return JSONResponse({"ok": False, "error": result.get("error")}, status_code=400)

    ex = get_executor()
    ws_port = int(webserver_port) if webserver_port and webserver_port.isdigit() else 0
    if ex.mode in ("local", "wsl"):
        slug = name.strip().lower().replace(" ", "-")[:63]
        home = result.get("home_dir", dir_path.strip() or f"/var/www/{slug}")
        upstream = f"http://127.0.0.1:{port_int}"
        if webserver == "apache":
            from ..managers.apache import ApacheManager
            apache = ApacheManager(ex)
            apache.apply_domain(slug, home, upstream, port=ws_port or 80)
            await apache._deploy(slug)
        elif webserver in ("caddy", "lighttpd"):
            from ..managers.nginx import NginxManager
            nginx = NginxManager(ex)
            nginx.apply_domain(slug, home, upstream, port=ws_port or (443 if webserver == "caddy" else 80))
            await nginx._deploy(slug)
        else:
            from ..managers.nginx import NginxManager
            nginx = NginxManager(ex)
            nginx.apply_domain(slug, home, upstream)
            await nginx._deploy(slug)

    return RedirectResponse(f"/apps?created=1&port={port_int}", status_code=303)


@router.get("/apps/{app_id}/process-config")
async def apps_get_process_config(app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return JSONResponse({"ok": False, "error": "app tidak ditemukan"}, status_code=404)
    config = AppManager.parse_process_config(app.get("command", ""))
    return JSONResponse({"ok": True, "config": config})


@router.post("/apps/{app_id}/process-config")
async def apps_process_config(app_id: int, request: Request,
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    body = await request.json()
    config = {
        "workers": int(body.get("workers", 4)),
        "timeout": int(body.get("timeout", 120)),
        "worker_class": body.get("worker_class", ""),
        "access_log": bool(body.get("access_log", False)),
        "max_requests": int(body.get("max_requests", 0)),
        "graceful_timeout": int(body.get("graceful_timeout", 30)),
        "keepalive": int(body.get("keepalive", 5)),
    }
    config["workers"] = max(1, min(config["workers"], 32))
    config["timeout"] = max(10, min(config["timeout"], 600))
    config["max_requests"] = max(0, min(config["max_requests"], 100000))
    result = await AppManager(get_executor()).update_process_config(app_id, config)
    return JSONResponse(result)


@router.post("/apps/{app_id}/limits")
async def apps_limits(app_id: int, request: Request,
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    body = await request.json()
    import re as _re
    _MEM_RE = re.compile(r'^\d+[KMG]?$')
    _CPU_RE = re.compile(r'^\d+(\.\d+)?%?$')
    _NICE_RE = re.compile(r'^-?\d{1,2}$')
    _OOM_RE = re.compile(r'^-?\d{1,4}$')

    ml = body.get("memory_limit", "")
    cq = body.get("cpu_quota", "")
    ni = body.get("nice", "")
    oo = body.get("oom_score_adjust", "")

    if ml and not _MEM_RE.match(ml):
        return JSONResponse({"ok": False, "error": "memory_limit format: angka + K/M/G (contoh: 512M)"}, status_code=400)
    if cq and not _CPU_RE.match(cq):
        return JSONResponse({"ok": False, "error": "cpu_quota format: angka + % (contoh: 50%)"}, status_code=400)
    if ni and not _NICE_RE.match(ni):
        return JSONResponse({"ok": False, "error": "nice: -20 s/d 19"}, status_code=400)
    if oo and not _OOM_RE.match(oo):
        return JSONResponse({"ok": False, "error": "oom_score_adjust: -1000 s/d 1000"}, status_code=400)

    limits = {
        "memory_limit": ml,
        "cpu_quota": cq,
        "nice": ni,
        "oom_score_adjust": oo,
    }
    result = await AppManager(get_executor()).update_limits(app_id, limits)
    return JSONResponse(result)


@router.post("/apps/{app_id}/{action}")
async def apps_control(app_id: int, action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "restart", "delete", "reload"):
        return JSONResponse({"ok": False, "error": "aksi tidak dikenal"}, status_code=400)
    if action == "delete":
        result = await AppManager(get_executor()).delete(app_id)
        return JSONResponse(result)
    result = await AppManager(get_executor()).control(app_id, action)
    return JSONResponse(result)


@router.get("/apps/{app_id}/logs", response_class=HTMLResponse)
async def apps_logs_page(request: Request, app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return RedirectResponse("/apps?msg=App%20tidak%20ditemukan", status_code=303)
    return render(request, "app_logs.html", {
        "user": user, "app": app, "active": "apps",
    })


@router.get("/apps/{app_id}/logs/stream")
async def apps_logs_stream(app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return JSONResponse({"ok": False}, status_code=404)
    from fastapi.responses import StreamingResponse
    async def gen():
        ex = get_executor()
        if ex.mode in ("local", "wsl"):
            result = await ex.run("bash", "-c",
                                  f"journalctl -u {app['unit']} --no-pager -n 100 2>/dev/null || echo 'no logs'")
            yield result.stdout or result.stderr or "no logs"
        else:
            yield "[dry-run] journal logs simulasi\n"
    return StreamingResponse(gen(), media_type="text/plain")


@router.websocket("/ws/apps/{app_id}/logs")
async def apps_logs_ws(websocket: WebSocket, app_id: int):
    from ..auth import ws_require_admin
    user = await ws_require_admin(websocket)
    if not user:
        return
    app = get_app(app_id)
    if not app:
        await websocket.send_text("[error] App tidak ditemukan\n")
        await websocket.close()
        return
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        await websocket.send_text("[dry-run] Log simulasi\n")
        await websocket.close()
        return
    try:
        import asyncio
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-u", app["unit"], "-f", "--no-pager", "-n", "50",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            await websocket.send_text(line.decode("utf-8", errors="replace"))
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
