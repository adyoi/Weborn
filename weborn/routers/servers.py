from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..managers.nginx import NginxManager
from ..ui import render

router = APIRouter()


@router.get("/web-server", response_class=HTMLResponse)
async def web_server(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    nginx = NginxManager(get_executor())
    status = await nginx.status()
    configs = nginx.list_configs()
    return render(request, "servers.html", {
        "user": user,
        "nginx": status,
        "configs": configs,
        "active": "web-server",
    })


@router.post("/web-server/nginx/install")
async def nginx_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await NginxManager(get_executor()).install()
    return JSONResponse({"ok": result.get("ok"), "output": result.get("output")})


@router.post("/web-server/nginx/{action}")
async def nginx_action(action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "reload", "restart", "test"):
        return JSONResponse({"ok": False, "error": "aksi tidak dikenal"})
    nginx = NginxManager(get_executor())
    if action == "test":
        result = await nginx.test()
    elif action == "start":
        result = await nginx.start()
    elif action == "stop":
        result = await nginx.stop()
    elif action == "restart":
        result = await nginx.restart()
    else:
        result = await nginx.reload()
    ok = result.get("ok", False) if isinstance(result, dict) else result.ok
    output = result.get("output", result.get("error", "")) if isinstance(result, dict) else result.output
    return JSONResponse({"ok": ok, "output": output})
