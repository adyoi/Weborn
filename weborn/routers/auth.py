import time
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth
from ..config import SESSION_COOKIE
from ..db import get_conn, has_panel_users
from ..ui import render

router = APIRouter(tags=["Auth"])

_RATE_LIMIT_MAX = 5
_RATE_LIMIT_WINDOW = 300


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with get_conn() as conn:
        conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?",
                     (now - _RATE_LIMIT_WINDOW,))
        count = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ?",
                             (ip,)).fetchone()[0]
        conn.commit()
    return count >= _RATE_LIMIT_MAX


def _record_failed(ip: str):
    with get_conn() as conn:
        conn.execute("INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)",
                     (ip, time.time()))
        conn.commit()


def _clear_attempts(ip: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
        conn.commit()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not has_panel_users():
        return RedirectResponse("/setup", status_code=303)
    if auth.get_current_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": None})


@router.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not has_panel_users():
        return RedirectResponse("/setup", status_code=303)

    ip = request.client.host if request.client else "unknown"

    if _is_rate_limited(ip):
        return render(request, "login.html", {"error": "Terlalu banyak percobaan. Coba lagi dalam 5 menit."})

    resp = auth.login(request, username, password)
    if not resp:
        _record_failed(ip)
        return render(request, "login.html", {"error": "Username atau password salah"})

    _clear_attempts(ip)
    return resp


@router.post("/logout")
async def logout_action(request: Request):
    auth.logout(request)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
