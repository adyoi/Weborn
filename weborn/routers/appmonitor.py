"""Router App Monitor: Gunicorn process monitoring & Nginx upstream status."""
import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin
from ..config import APP_TYPES, GUNICORN_SOCK_DIR
from ..db import list_apps
from ..executors import get_executor
from ..managers.apps import AppManager, _app_type_for, _slug
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
        a["app_type"] = _app_type_for(a["language"], a.get("framework", ""))
        a["process_manager"] = APP_TYPES.get(a["app_type"], {}).get("process_manager", "direct")
        a["slug"] = _slug(a["name"])

        if a["process_manager"] == "gunicorn" and ex.mode in ("local", "wsl"):
            status = await manager.get_gunicorn_status(a["name"])
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


@router.get("/apps/{app_id}/status")
async def app_status(app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from ..db import get_app
    app = get_app(app_id)
    if not app:
        return JSONResponse({"ok": False, "error": "app tidak ditemukan"}, status_code=404)

    ex = get_executor()
    manager = AppManager(ex)
    status = await manager.get_gunicorn_status(app["name"])
    status["app"] = app["name"]
    status["ok"] = True
    return JSONResponse(status)
