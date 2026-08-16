from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth
from ..ui import render

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if auth.get_current_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": None})


@router.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not auth.login(request, username, password):
        return render(request, "login.html", {"error": "Username atau password salah"})
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
async def logout_action(request: Request):
    auth.logout(request)
    return RedirectResponse("/login", status_code=303)
