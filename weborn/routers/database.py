"""Manajemen database: MySQL/MariaDB + PostgreSQL + Redis/MongoDB/Memcached."""
import re
import shlex

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..db import get_conn
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Database"])

DB_NAME_RE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")
USER_RE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


# ───────────────────────────────── MySQL / MariaDB ──────────────────────────────

async def _mysql_installed(ex) -> bool:
    r = await ex.run("bash", "-c", "command -v mysql && echo yes || echo no")
    return "yes" in r.stdout


async def _mysql_databases(ex) -> list:
    r = await ex.run("mysql", "-uroot", "-N", "-e", "SHOW DATABASES;")
    return sorted(line.strip() for line in r.stdout.splitlines()
                  if line.strip() and line.strip() not in
                  ("information_schema", "performance_schema", "mysql", "sys"))


async def _mysql_users(ex) -> list[dict]:
    r = await ex.run("mysql", "-uroot", "-N", "-e",
                     "SELECT user, host FROM mysql.user WHERE user NOT IN "
                     "('root','mysql.sys','mysql.session','debian-sys-maint') ORDER BY user;")
    users = []
    for line in r.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            users.append({"user": parts[0], "host": parts[1]})
    return users


async def _mysql_user_dbs(ex, user: str) -> list:
    r = await ex.run("mysql", "-uroot", "-N", "-e",
                     f"SELECT DISTINCT db FROM mysql.db WHERE user='{user}' ORDER BY db;")
    return sorted(line.strip() for line in r.stdout.splitlines() if line.strip())


@router.get("/database", response_class=HTMLResponse)
async def database_page(request: Request, msg: str = "",
                        user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed = await _mysql_installed(ex) if ex.mode in ("local", "wsl") else True
    dbs, users, user_dbs_map = [], [], {}
    if installed:
        if ex.mode in ("local", "wsl"):
            dbs = await _mysql_databases(ex)
            users = await _mysql_users(ex)
            for u in users:
                user_dbs_map[u["user"]] = await _mysql_user_dbs(ex, u["user"])
        else:
            dbs = ["weborn_prod", "blog_example"]
            users = [{"user": "weborn", "host": "localhost"}, {"user": "admin", "host": "%"}]
            user_dbs_map = {"weborn": ["weborn_prod"], "admin": ["weborn_prod", "blog_example"]}
    return render(request, "database.html", {
        "user": user, "dbs": dbs, "users": users, "user_dbs_map": user_dbs_map,
        "installed": installed, "msg": msg, "active": "database",
    })


@router.post("/database/create")
async def database_create(name: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    db = name.strip()
    if not DB_NAME_RE.match(db):
        return RedirectResponse("/database?msg=Nama%20database%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mysql", "-uroot", "-e", f"CREATE DATABASE `{db}` CHARACTER SET utf8mb4;")
        ok = r.ok
    else:
        ok = True
    return RedirectResponse("/database?msg=Database%20dibuat" if ok
                            else "/database?msg=Gagal%20membuat", status_code=303)


@router.post("/database/{db}/drop")
async def database_drop(db: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if not DB_NAME_RE.match(db):
        return RedirectResponse("/database?msg=Nama%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mysql", "-uroot", "-e", f"DROP DATABASE `{db}`;")
        ok = r.ok
    else:
        ok = True
    return RedirectResponse("/database?msg=Database%20dihapus" if ok
                            else "/database?msg=Gagal%20menghapus", status_code=303)


@router.post("/database/user/create")
async def database_user_create(username: str = Form(...), password: str = Form(...),
                               host: str = Form("localhost"),
                               privileges: list = Form(default=[]),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    username = username.strip()
    if not USER_RE.match(username):
        return RedirectResponse("/database?msg=Nama%20user%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("mysql", "-uroot", "-e",
                         f"CREATE USER {shlex.quote(username)}@{shlex.quote(host)} "
                         f"IDENTIFIED BY {shlex.quote(password)};")
        if not r.ok:
            return RedirectResponse(f"/database?msg=Gagal%20buat%20user%3A%20{r.stderr[:80]}",
                                    status_code=303)
        if privileges:
            for db in privileges:
                await ex.run("mysql", "-uroot", "-e",
                             f"GRANT ALL PRIVILEGES ON `{db}`.* TO "
                             f"{shlex.quote(username)}@{shlex.quote(host)};")
            await ex.run("mysql", "-uroot", "-e", "FLUSH PRIVILEGES;")
    return RedirectResponse("/database?msg=User%20MySQL%20dibuat", status_code=303)


@router.post("/database/user/{username}/grant")
async def database_user_grant(username: str, db: str = Form(...),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("mysql", "-uroot", "-e",
                     f"GRANT ALL PRIVILEGES ON `{db}`.* TO "
                     f"{shlex.quote(username)}@'localhost'; FLUSH PRIVILEGES;")
    return RedirectResponse("/database?msg=Privilege%20ditambahkan", status_code=303)


@router.post("/database/user/{username}/delete")
async def database_user_delete(username: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("mysql", "-uroot", "-e",
                     f"DROP USER {shlex.quote(username)}@'localhost'; FLUSH PRIVILEGES;")
    return RedirectResponse("/database?msg=User%20dihapus", status_code=303)


# ───────────────────────────────── PostgreSQL ──────────────────────────────────

@router.get("/database/pg", response_class=HTMLResponse)
async def pg_page(request: Request, msg: str = "",
                  user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed = True
    databases, users = [], []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v psql && echo yes || echo no")
        installed = "yes" in r.stdout
        if installed:
            r = await ex.run("sudo", "-u", "postgres", "psql", "-t", "-A", "-c",
                             "SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname;")
            databases = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            r2 = await ex.run("sudo", "-u", "postgres", "psql", "-t", "-A", "-c",
                              "SELECT usename FROM pg_user WHERE usename NOT IN ('postgres') ORDER BY usename;")
            users = [l.strip() for l in r2.stdout.splitlines() if l.strip()]
    else:
        databases = ["weborn_db", "wordpress"]
        users = ["weborn", "wp_user"]
    return render(request, "database_pg.html", {
        "user": user, "dbs": databases, "users": users,
        "installed": installed, "msg": msg, "active": "db-pg",
    })


@router.post("/database/pg/create")
async def pg_create(name: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    name = name.strip()
    if not DB_NAME_RE.match(name):
        return RedirectResponse("/database/pg?msg=Nama%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("sudo", "-u", "postgres", "psql", "-c",
                     f"CREATE DATABASE {name};")
    return RedirectResponse("/database/pg?msg=Database%20dibuat", status_code=303)


@router.post("/database/pg/{db}/drop")
async def pg_drop(db: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if not DB_NAME_RE.match(db):
        return RedirectResponse("/database/pg?msg=Nama%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("sudo", "-u", "postgres", "psql", "-c",
                     f"DROP DATABASE IF EXISTS {shlex.quote(db)};")
    return RedirectResponse("/database/pg?msg=Database%20dihapus", status_code=303)


@router.post("/database/pg/user/create")
async def pg_user_create(username: str = Form(...), password: str = Form(...),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    username = username.strip()
    if not USER_RE.match(username):
        return RedirectResponse("/database/pg?msg=Nama%20user%20tidak%20valid", status_code=303)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("sudo", "-u", "postgres", "psql", "-c",
                     f"CREATE USER {shlex.quote(username)} WITH PASSWORD {shlex.quote(password)};")
    return RedirectResponse("/database/pg?msg=User%20dibuat", status_code=303)


@router.post("/database/pg/user/{username}/delete")
async def pg_user_delete(username: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("sudo", "-u", "postgres", "psql", "-c",
                     f"DROP USER IF EXISTS {shlex.quote(username)};")
    return RedirectResponse("/database/pg?msg=User%20dihapus", status_code=303)


@router.post("/database/pg/user/{username}/grant")
async def pg_user_grant(username: str, db: str = Form(...),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("sudo", "-u", "postgres", "psql", "-c",
                     f"GRANT ALL PRIVILEGES ON DATABASE {shlex.quote(db)} TO {shlex.quote(username)};")
    return RedirectResponse("/database/pg?msg=Privilege%20ditambahkan", status_code=303)


# ───────────────────────────────── Redis ───────────────────────────────────────

@router.get("/database/redis", response_class=HTMLResponse)
async def redis_page(request: Request, msg: str = "",
                     user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    info_lines = []
    installed = True
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v redis-cli && echo yes || echo no")
        installed = "yes" in r.stdout
        if installed:
            r = await ex.run("redis-cli", "INFO", "server")
            info_lines = r.stdout.splitlines()[:30]
    return render(request, "database_redis.html", {
        "user": user, "info": info_lines,
        "installed": installed, "msg": msg, "active": "db-redis",
    })


# ───────────────────────────────── MongoDB ─────────────────────────────────────

@router.get("/database/mongodb", response_class=HTMLResponse)
async def mongo_page(request: Request, msg: str = "",
                     user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed = True
    databases = []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v mongosh && echo yes || echo no")
        installed = "yes" in r.stdout
        if installed:
            r = await ex.run("mongosh", "--quiet", "--eval", "db.adminCommand({listDatabases:1}).databases.map(d=>d.name)")
            databases = [l.strip().strip('"') for l in r.stdout.splitlines()
                         if l.strip() and l.strip() not in ('[', ']', 'undefined')]
    return render(request, "database_mongodb.html", {
        "user": user, "dbs": databases,
        "installed": installed, "msg": msg, "active": "db-mongo",
    })


# ───────────────────────────────── Memcached ───────────────────────────────────

@router.get("/database/memcached", response_class=HTMLResponse)
async def memcached_page(request: Request, msg: str = "",
                         user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed = True
    stats = []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v memcached && echo yes || echo no")
        installed = "yes" in r.stdout
    return render(request, "database_memcached.html", {
        "user": user, "stats": stats,
        "installed": installed, "msg": msg, "active": "db-memcached",
    })
