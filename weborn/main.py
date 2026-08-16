"""Weborn Control Panel - entry point FastAPI."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import STATIC_DIR
from .db import get_secret_key, init_db
from .executors import get_executor
from .managers.accounts import AccountManager
from .routers import (accounts, addons, apps, auth, backup, cron, dashboard,
                      database, domains, misc, proxy, servers, system)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await AccountManager(get_executor()).bootstrap()
    yield


def create_app() -> FastAPI:
    init_db()  # pastikan schema ada sebelum SessionMiddleware ambil secret key
    app = FastAPI(title="Weborn Control Panel", version="0.1.0", lifespan=lifespan)
    app.add_middleware(SessionMiddleware, secret_key=get_secret_key(), same_site="lax")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    for router in (auth.router, dashboard.router, servers.router, domains.router,
                   proxy.router, addons.router, accounts.router, apps.router,
                   system.router, cron.router, database.router, backup.router,
                   misc.router):
        app.include_router(router)
    return app


app = create_app()
