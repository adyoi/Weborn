from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from datetime import datetime

from ..auth import require_user
from ..executors import get_executor
from ..managers.accounts import AccountManager
from ..ui import render

router = APIRouter()


def system_stats() -> dict:
    try:
        import psutil
        return {
            "cpu": psutil.cpu_percent(interval=0.2),
            "cores": psutil.cpu_count(),
            "ram": psutil.virtual_memory().percent,
            "ram_used": round(psutil.virtual_memory().used / 1e9, 2),
            "ram_total": round(psutil.virtual_memory().total / 1e9, 2),
            "disk": psutil.disk_usage("/").percent,
            "uptime": int(psutil.boot_time()),
        }
    except Exception:
        return {"cpu": 0, "cores": 0, "ram": 0, "ram_used": 0,
                "ram_total": 0, "disk": 0, "uptime": None}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):  # RedirectResponse dari dependency
        return user
    from ..addons import AddonManager
    from ..routers.system import os_update_info_cached
    manager = AddonManager(get_executor())
    ids = ("nginx", "apache", "mysql", "postgresql", "dovecot", "ssh")
    services = []
    for addon_id in ids:
        addon = manager.get(addon_id)
        if addon:
            status = await manager.status(addon)
            status["addon"] = addon
            services.append(status)
    accounts = await AccountManager(get_executor()).list_users()
    ex = get_executor()
    updates = await os_update_info_cached(ex)
    stats = system_stats()
    return render(request, "dashboard.html", {
        "user": user,
        "stats": stats,
        "uptime_days": int((datetime.now().timestamp() - stats["uptime"]) // 86400) if stats["uptime"] else 0,
        "services": services,
        "account_count": len(accounts),
        "os": updates["os"],
        "updates": updates["updates"],
        "packages_total": updates["packages"],
        "active": "dashboard",
    })
