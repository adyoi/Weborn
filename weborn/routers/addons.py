"""Addon Store: install, config, update, dan run semua layanan/plugin."""
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.responses import JSONResponse

from ..addons import AddonManager, get_addon_manager
from ..auth import require_admin, require_user
from ..ui import render

router = APIRouter()


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _stream_install(manager: AddonManager, addon_id: str, op: str) -> StreamingResponse:
    addon = manager.get(addon_id)

    async def gen():
        if addon is None:
            yield _sse("error", {"ok": False, "error": "addon tidak ditemukan"})
            return
        steps = {"install": manager.install_steps,
                 "update": manager.update_steps,
                 "uninstall": manager.uninstall_steps}[op](addon)
        async for step in steps:
            if not step.get("ok", True):
                yield _sse("error", step)
                return
            yield _sse("step", step)
        yield _sse("done", {"ok": True})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/addons", response_class=HTMLResponse)
async def addons_page(request: Request, category: str | None = None,
                      user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addons = manager.list_addons(category)
    statuses = {}
    for a in addons:
        statuses[a.id] = await manager.status(a)
    return render(request, "addons.html", {
        "user": user,
        "addons": addons,
        "statuses": statuses,
        "categories": manager.categories(),
        "current_category": category,
        "active": "addons",
    })


@router.get("/addons/{addon_id}", response_class=HTMLResponse)
async def addon_detail(addon_id: str, request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"error": "addon tidak ditemukan"}, status_code=404)
    status = await manager.status(addon)
    preview = ""
    try:
        preview = await addon.render_config()
    except Exception:
        preview = "(gagal render template)"
    return render(request, "addon_detail.html", {
        "user": user,
        "addon": addon,
        "status": status,
        "values": addon.config_values(),
        "preview": preview,
        "active": "addons",
    })


@router.post("/addons/{addon_id}/install")
async def addon_install(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"ok": False, "error": "tidak ditemukan"})
    result = await manager.install(addon)
    return JSONResponse(result)


@router.post("/addons/{addon_id}/install/stream")
async def addon_install_stream(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    return _stream_install(get_addon_manager(), addon_id, "install")


@router.post("/addons/{addon_id}/update/stream")
async def addon_update_stream(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    return _stream_install(get_addon_manager(), addon_id, "update")


@router.post("/addons/{addon_id}/uninstall/stream")
async def addon_uninstall_stream(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    return _stream_install(get_addon_manager(), addon_id, "uninstall")


@router.post("/addons/{addon_id}/update")
async def addon_update(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"ok": False, "error": "tidak ditemukan"})
    result = await manager.update(addon)
    return JSONResponse(result)


@router.post("/addons/{addon_id}/uninstall")
async def addon_uninstall(addon_id: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"ok": False, "error": "tidak ditemukan"})
    result = await manager.uninstall(addon)
    return JSONResponse(result)


@router.post("/addons/{addon_id}/config")
async def addon_config(addon_id: str, request: Request,
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"ok": False, "error": "tidak ditemukan"})
    form = await request.form()
    values = {f["name"]: form.get(f["name"], f.get("default", "")) for f in addon.fields}
    result = await manager.apply_config(addon, values)
    return JSONResponse(result)


@router.post("/addons/{addon_id}/{action}")
async def addon_action(addon_id: str, action: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if action not in ("start", "stop", "restart", "enable", "disable"):
        return JSONResponse({"ok": False, "error": "aksi tidak dikenal"})
    manager = get_addon_manager()
    addon = manager.get(addon_id)
    if addon is None:
        return JSONResponse({"ok": False, "error": "tidak ditemukan"})
    result = await manager.action(addon, action)
    return JSONResponse(result)
