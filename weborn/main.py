"""Weborn Control Panel - entry point FastAPI."""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse

from .config import BASE_DIR, SESSION_COOKIE, STATIC_DIR
from .csrf import CSRFMiddleware
from .db import get_secret_key, has_panel_users, init_db
from .executors import get_executor
from .managers.accounts import AccountManager
from .routers import (accounts, addons, apps, appmonitor, auth, backup, cron,
                      dashboard, database, domains, email, files, info, misc,
                      panel_accounts, proxy, security, setup, system, terminal,
                      webservers)


class SecurityHeadersMiddleware:
    """Add security headers to all responses. Pure ASGI (no BaseHTTPMiddleware)
    to avoid breaking StreamingResponse."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                for name, value in [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-xss-protection", b"1; mode=block"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]:
                    headers.append((name, value))
                message["headers"] = headers
            await send(message)

        return await self.app(scope, receive, send_with_headers)


def _setup_logging():
    log_dir = BASE_DIR / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "panel.log"

    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(str(log_file), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(fh)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(fh)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await AccountManager(get_executor()).bootstrap()
    yield


def create_app() -> FastAPI:
    _setup_logging()
    init_db()
    app = FastAPI(title="Weborn Engine", version="1.0.0", lifespan=lifespan)

    app.add_middleware(CSRFMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    for router in (setup.router, auth.router, panel_accounts.router,
                   dashboard.router, domains.router,
                   proxy.router, addons.router, accounts.router, apps.router,
                   appmonitor.router, webservers.router, system.router,
                   files.router, terminal.router,
                   cron.router, database.router, backup.router,
                   security.router, email.router, info.router, misc.router):
        app.include_router(router)
    return app


app = create_app()
