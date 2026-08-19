"""Router App Monitor: Gunicorn process monitoring & Nginx upstream status."""
import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin
from ..config import APP_TYPES, GUNICORN_SOCK_DIR
from ..db import get_app, list_apps
from ..executors import get_executor
from ..managers.apps import AppManager, _app_type_for, _detect_pm, _slug
from ..ui import render

router = APIRouter()


@router.get("/apps/monitor", response_class=HTMLResponse)
async def apps_monitor_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    apps = list_apps()
    ex = get_executor()
    manager = AppManager(ex)

    # Enrich app data with Gunicorn status
    for a in apps:
        stored = a.get("app_type", "")
        a["app_type"] = stored if stored else _app_type_for(a["language"], a.get("framework", ""))
        if a.get("command"):
            a["process_manager"] = _detect_pm(a["command"])
        else:
            a["process_manager"] = APP_TYPES.get(a["app_type"], {}).get("process_manager", "direct")
        a["slug"] = _slug(a["name"])

        if a["process_manager"] in ("gunicorn", "uvicorn") and ex.mode in ("local", "wsl"):
            status = await manager.get_process_status(a["name"])
            a["gunicorn_status"] = status.get("status", "unknown")
            a["master_pid"] = status.get("master_pid", "")
            a["workers"] = status.get("workers", [])
        else:
            a["gunicorn_status"] = a.get("status", "unknown")
            a["master_pid"] = ""
            a["workers"] = []

    return render(request, "app_monitor.html", {
        "user": user,
        "apps": apps,
        "active": "app-monitor",
    })


@router.get("/apps/monitor/{app_id}", response_class=HTMLResponse)
async def apps_monitor_detail(request: Request, app_id: int,
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return HTMLResponse("App tidak ditemukan", status_code=404)

    ex = get_executor()
    manager = AppManager(ex)

    stored = app.get("app_type", "")
    app["app_type"] = stored if stored else _app_type_for(app["language"], app.get("framework", ""))
    if app.get("command"):
        app["process_manager"] = _detect_pm(app["command"])
    else:
        app["process_manager"] = APP_TYPES.get(app["app_type"], {}).get("process_manager", "direct")
    app["slug"] = _slug(app["name"])

    # Process status
    gstatus = {"status": "unknown", "master_pid": "", "workers": []}
    if app["process_manager"] in ("gunicorn", "uvicorn") and ex.mode in ("local", "wsl"):
        gstatus = await manager.get_process_status(app["name"])
    elif ex.mode in ("local", "wsl"):
        # For non-gunicorn, check systemd status
        r = await ex.run("bash", "-c",
                         f"systemctl is-active {app['unit']} 2>/dev/null || echo stopped")
        gstatus["status"] = r.stdout.strip()

    # Get resource usage from /proc if running
    resource_info = {}
    if gstatus.get("master_pid") and gstatus["master_pid"].isdigit():
        pid = gstatus["master_pid"]
        r = await ex.run("bash", "-c",
                         f"cat /proc/{pid}/status 2>/dev/null | grep -E '^(VmRSS|VmSize|Threads|Name)' || echo none")
        if r.ok and "none" not in r.stdout:
            for line in r.stdout.strip().splitlines():
                k, _, v = line.partition(":")
                resource_info[k.strip()] = v.strip()

    # Memory/CPU summary from all workers
    total_cpu = 0.0
    total_mem = 0.0
    for w in gstatus.get("workers", []):
        try:
            total_cpu += float(w.get("cpu", "0"))
        except ValueError:
            pass
        try:
            total_mem += float(w.get("mem", "0"))
        except ValueError:
            pass

    return render(request, "app_monitor_detail.html", {
        "user": user,
        "app": app,
        "gstatus": gstatus,
        "resource_info": resource_info,
        "total_cpu": total_cpu,
        "total_mem": total_mem,
        "active": "app-monitor",
    })


@router.get("/apps/{app_id}/status")
async def app_status(app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return JSONResponse({"ok": False, "error": "app tidak ditemukan"}, status_code=404)

    ex = get_executor()
    manager = AppManager(ex)
    status = await manager.get_process_status(app["name"])
    status["app"] = app["name"]
    status["ok"] = True
    return JSONResponse(status)
