"""Bundling UI: Jinja2 templates + helper render."""
from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import SESSION_COOKIE, TEMPLATES_DIR, VERSION

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["version"] = VERSION


def render(request: Request, name: str, context: dict | None = None):
    ctx = dict(context or {})
    from .csrf import generate_csrf_token
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    ctx["csrf_token"] = generate_csrf_token(raw_token) if raw_token else ""
    return templates.TemplateResponse(request, name, ctx)
