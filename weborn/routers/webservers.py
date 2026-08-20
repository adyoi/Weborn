"""Router Web Server: Nginx, PHP-FPM, Cache management."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin, require_user
from ..config import APP_TYPES
from ..db import list_apps
from ..executors import get_executor
from ..managers.apps import _app_type_for
from ..managers.nginx import NginxManager
from ..ui import render

router = APIRouter(tags=["Web Server"])


# ── Main web-server page ────────────────────────────────────────────────────

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
    return JSONResponse({"ok": result.ok, "output": result.output})


# ── Nginx detail ────────────────────────────────────────────────────────────

@router.get("/web-server/nginx", response_class=HTMLResponse)
async def nginx_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    nginx_status = "unknown"
    nginx_version = ""
    sites = []

    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "systemctl is-active nginx 2>/dev/null || echo stopped")
        nginx_status = r.stdout.strip()
        r2 = await ex.run("bash", "-c", "nginx -v 2>&1 | head -1")
        nginx_version = r2.stderr.strip() or r2.stdout.strip()
        r3 = await ex.run("bash", "-c",
                          "ls /etc/nginx/sites-enabled/ 2>/dev/null || ls /etc/nginx/conf.d/ 2>/dev/null || echo ''")
        sites = [s.strip() for s in r3.stdout.strip().splitlines() if s.strip()]

    apps = list_apps()
    for a in apps:
        a["app_type"] = _app_type_for(a["language"], a.get("framework", ""))

    return render(request, "webserver_nginx.html", {
        "user": user,
        "nginx_status": nginx_status,
        "nginx_version": nginx_version,
        "sites": sites,
        "apps": apps,
        "active": "ws-nginx",
    })


# ── PHP-FPM ──────────────────────────────────────────────────────────────────

@router.get("/web-server/php", response_class=HTMLResponse)
async def php_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    php_status = "unknown"
    php_version = ""
    fpm_status = "unknown"
    pools = []

    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "php -v 2>/dev/null | head -1")
        php_version = r.stdout.strip()
        r2 = await ex.run("bash", "-c",
                          "systemctl is-active php*-fpm 2>/dev/null || echo stopped")
        fpm_status = r2.stdout.strip()
        r3 = await ex.run("bash", "-c",
                          "ls /etc/php/*/fpm/pool.d/ 2>/dev/null || echo ''")
        pools = [p.strip() for p in r3.stdout.strip().splitlines() if p.strip()]

    return render(request, "webserver_php.html", {
        "user": user,
        "php_version": php_version,
        "php_status": php_status,
        "fpm_status": fpm_status,
        "pools": pools,
        "active": "ws-php",
    })


# ── Cache (Redis/Memcached) ─────────────────────────────────────────────────

@router.get("/web-server/cache", response_class=HTMLResponse)
async def cache_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    redis_status = "unknown"
    redis_info = ""
    memcached_status = "unknown"

    if ex.mode in ("local", "wsl"):
        r1 = await ex.run("bash", "-c", "systemctl is-active redis-server 2>/dev/null || echo stopped")
        redis_status = r1.stdout.strip()
        r2 = await ex.run("bash", "-c", "redis-cli INFO server 2>/dev/null | head -20 || echo ''")
        redis_info = r2.stdout.strip()
        r3 = await ex.run("bash", "-c", "systemctl is-active memcached 2>/dev/null || echo stopped")
        memcached_status = r3.stdout.strip()

    return render(request, "webserver_cache.html", {
        "user": user,
        "redis_status": redis_status,
        "redis_info": redis_info,
        "memcached_status": memcached_status,
        "active": "ws-cache",
    })


# ── Service control actions ──────────────────────────────────────────────────

@router.post("/web-server/{service}/{action}")
async def webserver_control(service: str, action: str,
                            user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "restart", "reload"):
        return {"ok": False, "error": "aksi tidak dikenal"}

    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return {"ok": True, "output": f"[dry-run] systemctl {action} {service}"}

    if service == "nginx":
        # nginx uses reload for config changes
        cmd = f"sudo systemctl {action} nginx"
    elif service == "php-fpm":
        cmd = f"sudo systemctl {action} php*-fpm 2>/dev/null || sudo systemctl {action} php8.2-fpm"
    elif service == "redis":
        cmd = f"sudo systemctl {action} redis-server"
    elif service == "memcached":
        cmd = f"sudo systemctl {action} memcached"
    else:
        return {"ok": False, "error": f"service '{service}' tidak dikenal"}

    r = await ex.run("bash", "-c", cmd)
    return {"ok": r.ok, "output": r.stdout + r.stderr}
