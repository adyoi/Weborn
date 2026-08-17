"""Router aplikasi: kelola environment app (Node/PHP/Python/Go/Ruby/Rust)."""
from fastapi import APIRouter, Depends, Form, Request
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
async def apps_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    manager = AppManager(get_executor())
    return render(request, "apps.html", {
        "user": user,
        "apps": manager.list(),
        "runtimes": RUNTIMES,
        "frameworks": FRAMEWORKS,
        "active": "apps",
    })


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
    return RedirectResponse("/apps?created=1", status_code=303)


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
