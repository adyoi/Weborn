"""Bundling UI: Jinja2 templates + helper render."""
from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import SESSION_COOKIE, TEMPLATES_DIR, VERSION

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["version"] = VERSION


def _csrf_token_global(request: Request):
    """Jinja2 context processor: inject csrf_token into all templates."""
    from .csrf import generate_csrf_token
    session_id = request.session.get(SESSION_COOKIE, "")
    return {"csrf_token": generate_csrf_token(session_id) if session_id else ""}


templates.env.globals["csrf_token"] = _csrf_token_global


def render(request: Request, name: str, context: dict | None = None):
    ctx = dict(context or {})
    # Inject CSRF token for all templates
    from .csrf import generate_csrf_token
    session_id = request.session.get(SESSION_COOKIE, "")
    ctx["csrf_token"] = generate_csrf_token(session_id) if session_id else ""
    return templates.TemplateResponse(request, name, ctx)
