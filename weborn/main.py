"""Weborn Control Panel - entry point FastAPI."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from .config import SESSION_COOKIE, STATIC_DIR
from .csrf import CSRFMiddleware
from .db import get_secret_key, has_panel_users, init_db
from .executors import get_executor
from .managers.accounts import AccountManager
from .routers import (accounts, addons, apps, appmonitor, auth, backup, cron,
                      dashboard, database, domains, email, info, misc, panel_accounts,
                      proxy, servers, security, setup, system, webservers)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await AccountManager(get_executor()).bootstrap()
    yield


def _csrf_token_context(request):
    """Jinja2 context processor: inject csrf_token into all templates."""
    from .csrf import generate_csrf_token
    session_id = request.session.get(SESSION_COOKIE, "")
    return {"csrf_token": generate_csrf_token(session_id) if session_id else ""}


def create_app() -> FastAPI:
    init_db()
    app = FastAPI(title="Weborn Engine", version="1.0.0", lifespan=lifespan)

    is_secure = os.environ.get("WEBORN_SSL_CERT") is not None
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=get_secret_key(),
        same_site="lax",
        session_cookie="session",
        max_age=60 * 60 * 24,  # 24 hours
        https_only=is_secure,
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    for router in (setup.router, auth.router, panel_accounts.router,
                   dashboard.router, servers.router, domains.router,
                   proxy.router, addons.router, accounts.router, apps.router,
                   appmonitor.router, webservers.router, system.router,
                   cron.router, database.router, backup.router,
                   security.router, email.router, info.router, misc.router):
        app.include_router(router)
    return app


app = create_app()
