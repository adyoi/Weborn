"""Halaman generik/placeholder yang menunggu modul lengkap."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ..auth import require_user
from ..ui import render

router = APIRouter()

PLACEHOLDERS = {
    "ai": "AI Agent (Gemini)",
}


@router.get("/{page}", response_class=HTMLResponse)
async def placeholder(page: str, request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    title = PLACEHOLDERS.get(page)
    if title is None:
        return render(request, "404.html", {
            "user": user,
            "page": page,
            "active": "",
        })
    return render(request, "placeholder.html", {
        "user": user,
        "page": page,
        "title": title,
        "active": page,
    })
