"""Weborn Control Panel - entry point FastAPI."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse

from .config import SESSION_COOKIE, STATIC_DIR
from .csrf import CSRFMiddleware
from .db import get_secret_key, has_panel_users, init_db
from .executors import get_executor
from .managers.accounts import AccountManager
from .routers import (accounts, addons, apps, appmonitor, auth, backup, cron,
                      dashboard, database, domains, email, files, info, misc,
                      panel_accounts, proxy, security, setup, system, terminal,
                      webservers)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await AccountManager(get_executor()).bootstrap()
    yield


def create_app() -> FastAPI:
    init_db()
    app = FastAPI(title="Weborn Engine", version="1.0.0", lifespan=lifespan)

    app.add_middleware(CSRFMiddleware)
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
