"""Bundling UI: Jinja2 templates + helper render."""
from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import TEMPLATES_DIR, VERSION

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["version"] = VERSION


def render(request: Request, name: str, context: dict | None = None):
    ctx = dict(context or {})
    return templates.TemplateResponse(request, name, ctx)
