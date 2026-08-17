"""Setup wizard: buat akun panel pertama kali."""
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..db import create_panel_user, has_panel_users
from ..ui import render

router = APIRouter()


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if has_panel_users():
        return RedirectResponse("/", status_code=303)
    return render(request, "setup.html", {"error": None})


@router.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if has_panel_users():
        return RedirectResponse("/", status_code=303)
    if len(username) < 3:
        return render(request, "setup.html", {"error": "Username minimal 3 karakter"})
    if len(password) < 6:
        return render(request, "setup.html", {"error": "Password minimal 6 karakter"})
    if password != password_confirm:
        return render(request, "setup.html", {"error": "Konfirmasi password tidak cocok"})
    ok = create_panel_user(username, password, role="admin")
    if not ok:
        return render(request, "setup.html", {"error": "Username sudah digunakan"})
    return RedirectResponse("/login", status_code=303)
