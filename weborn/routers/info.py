"""Info pages: test connectivity, update, changelog, about, status."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..auth import require_admin, require_user
from ..config import BASE_DIR, VERSION
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Info"])


@router.get("/info/status", response_class=HTMLResponse)
async def info_status_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    from datetime import datetime
    ex = get_executor()
    info = {"hostname": "—", "kernel": "—", "os": "—", "uptime": "—",
            "cpu_model": "—", "cores": 0, "ram": "—", "disk": "—",
            "ip_lan": "—", "ip_pub": "—", "python": "—", "node": "—",
            "nginx": "—", "mariadb": "—", "postgresql": "—", "redis": "—"}
    if ex.mode in ("local", "wsl"):
        cmds = {
            "hostname": "hostname -f 2>/dev/null || hostname",
            "kernel": "uname -r",
            "os": "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'\"' -f2",
            "uptime": "uptime -p 2>/dev/null || uptime",
            "cpu_model": "lscpu 2>/dev/null | grep 'Model name' | sed 's/.*:\\s*//'",
            "cores": "nproc",
            "ram": "free -h | awk '/Mem/{print $2}'",
            "disk": "df -h / | awk 'NR==2{print $2\" total, \"$3\" used, \"$4\" avail\"}'",
            "ip_lan": "hostname -I 2>/dev/null | awk '{print $1}'",
            "python": "python3 --version 2>&1",
            "node": "node -v 2>&1",
            "nginx": "nginx -v 2>&1",
            "mariadb": "mariadb --version 2>&1 | head -1",
            "postgresql": "psql --version 2>&1",
            "redis": "redis-server --version 2>&1 | awk '{print $3}'",
        }
        for key, cmd in cmds.items():
            r = await ex.run("bash", "-c", cmd)
            out = (r.stdout.strip() or r.stderr.strip()) if r.ok else "—"
            if key == "cores":
                info[key] = int(out) if out.isdigit() else 0
            else:
                info[key] = out
        r = await ex.run("bash", "-c", "curl -s --max-time 3 https://api.ipify.org 2>/dev/null")
        info["ip_pub"] = r.stdout.strip() if r.ok and r.stdout.strip() else "—"
    return render(request, "info_status.html", {
        "user": user, "active": "info-status", "info": info, "version": VERSION,
    })


@router.get("/info/test", response_class=HTMLResponse)
async def info_test_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "info_test.html", {"user": user, "active": "info-test"})


@router.post("/info/test/run")
async def info_test_run(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()

    python_checks = [
        ("Python", "python3 -V", "sys"),
        ("FastAPI", "pip3 show fastapi 2>/dev/null | grep Version || echo not installed", "fastapi"),
        ("Uvicorn", "pip3 show uvicorn 2>/dev/null | grep Version || echo not installed", "uvicorn"),
        ("Gunicorn", "pip3 show gunicorn 2>/dev/null | grep Version || echo not installed", "gunicorn"),
        ("Jinja2", "pip3 show jinja2 2>/dev/null | grep Version || echo not installed", "jinja2"),
        ("python-multipart", "pip3 show python-multipart 2>/dev/null | grep Version || echo not installed", "multipart"),
        ("PyJWT", "pip3 show PyJWT 2>/dev/null | grep Version || echo not installed", "jwt"),
        ("psutil", "pip3 show psutil 2>/dev/null | grep Version || echo not installed", "psutil"),
        ("websockets", "pip3 show websockets 2>/dev/null | grep Version || echo not installed", "websockets"),
    ]

    linux_checks = [
        ("Node.js", "node -v", ""),
        ("Nginx", "nginx -v", ""),
        ("MariaDB", "mariadb --version", ""),
        ("PostgreSQL", "psql --version", ""),
        ("PHP", "php -v | head -1", ""),
        ("Git", "git --version", ""),
        ("Disk Space", "df -h / | tail -1", ""),
        ("Memory", "free -h | grep Mem", ""),
    ]

    async def run_one(item):
        label, cmd = item[0], item[1]
        module = item[2] if len(item) > 2 else ""
        if ex.mode in ("local", "wsl"):
            r = await ex.run("bash", "-c", cmd)
            return {
                "label": label,
                "ok": r.ok,
                "output": (r.stdout or r.stderr or "not found").strip(),
                "module": module,
            }
        return {"label": label, "ok": True, "output": "[dry-run] available", "module": module}

    import asyncio
    py_results, linux_results = await asyncio.gather(
        asyncio.gather(*(run_one(c) for c in python_checks)),
        asyncio.gather(*(run_one(c) for c in linux_checks)),
    )

    return JSONResponse({
        "ok": True,
        "python": list(py_results),
        "linux": list(linux_results),
    })


@router.get("/info/update", response_class=HTMLResponse)
async def info_update_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "info_update.html", {
        "user": user, "active": "info-update", "version": VERSION,
    })


@router.post("/info/update/check")
async def info_update_check(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"cd {BASE_DIR} && git fetch origin 2>&1")
        if r.stdout.strip():
            lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            for l in lines:
                if "error" in l.lower() or "fatal" in l.lower() or "unable" in l.lower():
                    return JSONResponse({
                        "ok": False, "error": l,
                        "current": VERSION,
                    })
        r2 = await ex.run("bash", "-c", f"cd {BASE_DIR} && git log HEAD..origin/main --oneline 2>/dev/null")
        lines = [l.strip() for l in r2.stdout.strip().splitlines() if l.strip()]
        return JSONResponse({
            "ok": True,
            "current": VERSION,
            "commits": len(lines),
            "changes": lines[:20],
            "has_update": len(lines) > 0,
        })
    return JSONResponse({"ok": True, "current": VERSION, "commits": 0, "changes": [], "has_update": False})


@router.post("/info/update/install")
async def info_update_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"cd {BASE_DIR} && git pull origin main 2>&1")
        return JSONResponse({"ok": r.ok, "output": r.stdout + r.stderr})
    return JSONResponse({"ok": False, "output": "[dry-run] not applicable"})


@router.get("/info/changelog", response_class=HTMLResponse)
async def info_changelog_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    changelog = ""
    cl_path = BASE_DIR / "CHANGELOG.md"
    if cl_path.exists():
        changelog = cl_path.read_text(encoding="utf-8")
    return render(request, "info_changelog.html", {
        "user": user, "active": "info-changelog", "changelog": changelog,
    })


@router.get("/info/about", response_class=HTMLResponse)
async def info_about_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    os_info = ""
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "cat /etc/os-release 2>/dev/null | head -5")
        os_info = r.stdout.strip()
    return render(request, "info_about.html", {
        "user": user, "active": "info-about", "version": VERSION, "os_info": os_info,
    })
