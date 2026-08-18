"""Router aplikasi: kelola environment app (Node/PHP/Python/Go/Ruby/Rust)."""
from fastapi import APIRouter, Depends, Form, Request, WebSocket
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import JSONResponse

from ..auth import require_admin, require_user
from ..config import FRAMEWORKS, RUNTIMES
from ..db import get_app, set_app_status
from ..executors import get_executor
from ..managers.apps import AppManager
from ..ui import render

router = APIRouter()


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
        r = await ex.run("bash", "-c",
                         f"if [ -d '{path}' ]; then "
                         f"  echo EXISTS; "
                         f"  sudo ls -1 '{path}' 2>/dev/null | head -20; "
                         f"  echo '---'; "
                         f"  sudo test -w '{path}' && echo WRITABLE || echo NOWRIT; "
                         f"else "
                         f"  echo MISSING; "
                         f"  pdir=$(dirname '{path}'); "
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
    if ex.mode in ("local", "wsl"):
        check_dir = dir.strip() or "/tmp"
        r = await ex.run("bash", "-c",
                         f"cd '{check_dir}' 2>/dev/null && "
                         f"python3 -c \""
                         f"import importlib.util, sys; "
                         f"spec = importlib.util.find_spec('{mod_name}'); "
                         f"exit(0 if spec else 1)"
                         f"\" 2>/dev/null && echo MODULE_OK || echo MODULE_MISSING")
        mod_ok = "MODULE_OK" in r.stdout
        if not mod_ok:
            return JSONResponse({
                "ok": True, "valid": False,
                "error": f"Module '{mod_name}.py' tidak ditemukan di {check_dir}",
                "message": f"❌ Module '{mod_name}' tidak ditemukan",
            })
        if app_name.strip():
            r2 = await ex.run("bash", "-c",
                              f"cd '{check_dir}' 2>/dev/null && "
                              f"python3 -c \""
                              f"from {mod_name} import {app_name.strip()}; "
                              f"import inspect; "
                              f"assert callable({app_name.strip()}) or hasattr({app_name.strip()}, '__call__') or hasattr({app_name.strip()}, 'app') or hasattr({app_name.strip()}, 'get') or hasattr({app_name.strip()}, 'route')"
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


@router.get("/apps/{app_id}/edit", response_class=HTMLResponse)
async def apps_edit_page(request: Request, app_id: int,
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return RedirectResponse("/apps?msg=App%20tidak%20ditemukan", status_code=303)
    return render(request, "app_edit.html", {
        "user": user,
        "app": app,
        "runtimes": RUNTIMES,
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
    port = result.get("port", 8000)
    return RedirectResponse(f"/apps?created=1&port={port}", status_code=303)


@router.post("/apps/create-native")
async def apps_create_native(name: str = Form(...), app_type: str = Form("wsgi"),
                              launcher: str = Form("gunicorn"), module_app: str = Form("main:app"),
                              workers: str = Form("4"), host: str = Form("0.0.0.0"),
                              port: str = Form("8000"), dir_path: str = Form(""),
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
    mod = module_app.strip() or "main:app"
    h = (host.strip() or "0.0.0.0")
    if app_type == "wsgi":
        if launcher == "gunicorn":
            command = f"gunicorn -w {workers_int} {mod} --bind {h}:{port_int}"
        else:
            command = f"uvicorn {mod} --host {h} --port {port_int}"
    else:
        if launcher == "gunicorn":
            command = f"gunicorn -w {workers_int} -k uvicorn.workers.UvicornWorker {mod} --bind {h}:{port_int}"
        else:
            command = f"uvicorn {mod} --host {h} --port {port_int} --workers {workers_int}"

    try:
        result = await AppManager(get_executor()).create_native(
            name.strip(), app_type, command, port_int,
            dir_path=dir_path.strip())
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"gagal membuat app: {e}"},
                            status_code=400)
    if not result.get("ok"):
        return JSONResponse({"ok": False, "error": result.get("error")}, status_code=400)
    return RedirectResponse(f"/apps?created=1&port={port_int}", status_code=303)


@router.post("/apps/{app_id}/{action}")
async def apps_control(app_id: int, action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "restart", "delete"):
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
    await websocket.accept()
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
        await websocket.close()
