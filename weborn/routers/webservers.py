"""Router Web Server: Nginx, Apache, PHP-FPM, Cache management."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..managers.apache import ApacheManager
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


# ── Nginx ────────────────────────────────────────────────────────────────────

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

    return render(request, "webserver_nginx.html", {
        "user": user,
        "nginx_status": nginx_status,
        "nginx_version": nginx_version,
        "sites": sites,
        "active": "ws-nginx",
    })


@router.get("/web-server/nginx/site/{site_name}")
async def nginx_site_read(site_name: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    import re as _re
    if not _re.match(r'^[A-Za-z0-9._-]+$', site_name):
        return JSONResponse({"ok": False, "error": "nama site tidak valid"}, status_code=400)
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return JSONResponse({"ok": True, "content": "[dry-run] site config"})
    import shlex as _shlex
    qname = _shlex.quote(site_name)
    r = await ex.run("bash", "-c",
                     f"cat /etc/nginx/sites-enabled/{qname} 2>/dev/null || "
                     f"cat /etc/nginx/conf.d/{qname} 2>/dev/null || echo ''")
    return JSONResponse({"ok": True, "content": r.stdout, "name": site_name})


@router.post("/web-server/nginx/site/{site_name}/delete")
async def nginx_site_delete(site_name: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    import shlex as _shlex
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return JSONResponse({"ok": True, "output": f"[dry-run] hapus site {site_name}"})
    qname = _shlex.quote(site_name)
    r = await ex.run("bash", "-c",
                     f"sudo rm -f /etc/nginx/sites-enabled/{qname} "
                     f"/etc/nginx/sites-available/{qname} "
                     f"/etc/nginx/conf.d/{qname} && "
                     f"sudo nginx -t 2>&1 && sudo nginx -s reload")
    return JSONResponse({"ok": r.ok, "output": r.stdout + r.stderr})


# ── Apache ───────────────────────────────────────────────────────────────────

@router.post("/web-server/apache/install")
async def apache_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await ApacheManager(get_executor()).install()
    return JSONResponse({"ok": result.get("ok"), "output": result.get("output")})


@router.post("/web-server/apache/test")
async def apache_test(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    result = await ApacheManager(get_executor()).test()
    return JSONResponse({"ok": result.ok, "output": result.output})


@router.post("/web-server/apache/{action}")
async def apache_action(action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "reload", "restart"):
        return JSONResponse({"ok": False, "error": "aksi tidak dikenal"})
    apache = ApacheManager(get_executor())
    if action == "start":
        result = await apache.start()
    elif action == "stop":
        result = await apache.stop()
    elif action == "restart":
        result = await apache.restart()
    else:
        result = await apache.reload()
    return JSONResponse({"ok": result.ok, "output": result.output})


@router.get("/web-server/apache", response_class=HTMLResponse)
async def apache_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    apache_status = "unknown"
    apache_version = ""
    sites = []
    modules = []

    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "systemctl is-active apache2 2>/dev/null || echo stopped")
        apache_status = r.stdout.strip()
        r2 = await ex.run("bash", "-c", "apache2 -v 2>&1 | head -1")
        apache_version = r2.stdout.strip() or r2.stderr.strip()
        r3 = await ex.run("bash", "-c",
                          "ls /etc/apache2/sites-enabled/ 2>/dev/null || echo ''")
        sites = [s.strip() for s in r3.stdout.strip().splitlines() if s.strip()]
        r4 = await ex.run("bash", "-c",
                          "apache2ctl -M 2>/dev/null | awk '{print $1}' | head -30 || echo ''")
        modules = [m.strip() for m in r4.stdout.strip().splitlines()
                   if m.strip() and m.strip() != '']

    return render(request, "webserver_apache.html", {
        "user": user,
        "apache_status": apache_status,
        "apache_version": apache_version,
        "sites": sites,
        "modules": modules,
        "active": "ws-apache",
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
        # Detect actual PHP-FPM unit (e.g. php8.2-fpm)
        r_ver = await ex.run("bash", "-c",
                             "ls /etc/php/ 2>/dev/null | sort -V | tail -1 || echo ''")
        fpm_ver = r_ver.stdout.strip()
        fpm_unit = f"php{fpm_ver}-fpm" if fpm_ver else ""
        if fpm_unit:
            r2 = await ex.run("bash", "-c",
                              f"systemctl is-active {fpm_unit} 2>/dev/null || echo stopped")
        else:
            r2 = await ex.run("bash", "-c", "echo stopped")
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


# ── Service control actions (catch-all) ──────────────────────────────────────

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
        cmd = f"sudo systemctl {action} nginx"
    elif service == "apache":
        cmd = f"sudo systemctl {action} apache2"
    elif service == "php-fpm":
        r_ver = await ex.run("bash", "-c",
                             "ls /etc/php/ 2>/dev/null | sort -V | tail -1 || echo 8.2")
        fpm_ver = r_ver.stdout.strip() or "8.2"
        cmd = f"sudo systemctl {action} php{fpm_ver}-fpm"
    elif service == "redis":
        cmd = f"sudo systemctl {action} redis-server"
    elif service == "memcached":
        cmd = f"sudo systemctl {action} memcached"
    else:
        return {"ok": False, "error": f"service '{service}' tidak dikenal"}

    r = await ex.run("bash", "-c", cmd)
    return {"ok": r.ok, "output": r.stdout + r.stderr}
