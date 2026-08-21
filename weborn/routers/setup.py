"""Setup wizard: buat akun admin pertama + user Linux OS."""
import shlex

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..db import create_panel_user, has_panel_users
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Setup"])


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

    # 1) Buat panel user
    ok = create_panel_user(username, password, role="admin")
    if not ok:
        return render(request, "setup.html", {"error": "Username sudah digunakan"})

    # 2) Buat Linux OS user (admin, bisa SSH/sudo)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        import re as _re
        if not _re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
            return RedirectResponse("/login", status_code=303)

        # Cek apakah user sudah ada di OS
        check = await ex.run("bash", "-c", f"id {shlex.quote(username)} >/dev/null 2>&1 && echo exists || echo new")
        if "new" in check.stdout:
            await ex.run("useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username)
            await ex.run("bash", "-c",
                         f"echo {shlex.quote(username + ':' + password)} | sudo chpasswd")
            await ex.run("usermod", "-aG", "ssh-user", username)
        else:
            await ex.run("bash", "-c",
                         f"echo {shlex.quote(username + ':' + password)} | sudo chpasswd")

    return RedirectResponse("/login?msg=Akun+admin+dan+user+Linux+dibuat", status_code=303)
