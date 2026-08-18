from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from datetime import datetime

from ..auth import require_user
from ..db import list_apps, list_panel_users
from ..executors import get_executor
from ..managers.accounts import AccountManager
from ..ui import render

router = APIRouter()


def system_stats() -> dict:
    try:
        import psutil
        vmem = psutil.virtual_memory()
        dsk = psutil.disk_usage("/")
        boot = psutil.boot_time()
        now = datetime.now().timestamp()
        uptime_sec = int(now - boot)
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        mins = (uptime_sec % 3600) // 60
        if days > 0:
            uptime_str = f"{days} hari {hours} jam {mins} menit"
        elif hours > 0:
            uptime_str = f"{hours} jam {mins} menit"
        else:
            uptime_str = f"{mins} menit"
        GB = 1024 ** 3
        return {
            "cpu": psutil.cpu_percent(interval=0.2),
            "cores": psutil.cpu_count(),
            "ram": vmem.percent,
            "ram_used": round(vmem.used / GB, 1),
            "ram_total": round(vmem.total / GB, 1),
            "disk": dsk.percent,
            "disk_used": round(dsk.used / GB, 1),
            "disk_total": round(dsk.total / GB, 1),
            "uptime_str": uptime_str,
        }
    except Exception:
        return {"cpu": 0, "cores": 0, "ram": 0, "ram_used": 0,
                "ram_total": 0, "disk": 0, "disk_used": 0, "disk_total": 0,
                "uptime_str": "—"}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    from ..addons import AddonManager
    from ..routers.system import os_update_info_cached
    manager = AddonManager(get_executor())

    all_addons = manager.list_addons()
    services = []
    installed_count = 0
    for addon in all_addons:
        try:
            status = await manager.status(addon)
        except Exception:
            status = {"installed": False, "active": False, "status": "unknown"}
        status["addon"] = addon
        if status["installed"]:
            installed_count += 1
            services.append(status)

    apps = list_apps()
    apps_running = sum(1 for a in apps if a.get("status") == "running")
    apps_stopped = sum(1 for a in apps if a.get("status") != "running")

    panel_users = list_panel_users()
    ex = get_executor()
    updates = await os_update_info_cached(ex)
    stats = system_stats()

    services_running = sum(1 for s in services if s.get("active"))
    services_stopped = installed_count - services_running

    return render(request, "dashboard.html", {
        "user": user,
        "stats": stats,
        "services": services,
        "services_running": services_running,
        "services_stopped": services_stopped,
        "apps_total": len(apps),
        "apps_running": apps_running,
        "apps_stopped": apps_stopped,
        "panel_users_count": len(panel_users),
        "installed_count": installed_count,
        "total_addons": len(all_addons),
        "os": updates["os"],
        "updates": updates["updates"],
        "packages_total": updates["packages"],
        "active": "dashboard",
    })
