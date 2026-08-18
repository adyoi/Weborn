"""Info pages: test connectivity, update, changelog, about."""
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..auth import require_admin, require_user
from ..config import BASE_DIR, VERSION
from ..executors import get_executor
from ..ui import render

router = APIRouter()


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
    results = []
    checks = [
        ("Python", "python3 -V"),
        ("Node.js", "node -v"),
        ("Nginx", "nginx -v"),
        ("MariaDB", "mariadb --version"),
        ("PostgreSQL", "psql --version"),
        ("PHP", "php -v | head -1"),
        ("Gunicorn", "gunicorn --version"),
        ("Git", "git --version"),
        ("Disk Space", "df -h / | tail -1"),
        ("Memory", "free -h | grep Mem"),
    ]
    for label, cmd in checks:
        if ex.mode in ("local", "wsl"):
            r = await ex.run("bash", "-c", cmd)
            results.append({
                "label": label,
                "ok": r.ok,
                "output": (r.stdout or r.stderr or "not found").strip(),
            })
        else:
            results.append({"label": label, "ok": True, "output": "[dry-run] available"})
    return JSONResponse({"ok": True, "results": results})


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
        r = await ex.run("bash", "-c", f"cd {BASE_DIR} && git fetch origin 2>&1 && git log HEAD..origin/main --oneline")
        lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
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
