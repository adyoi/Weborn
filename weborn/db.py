"""SQLite storage untuk metadata panel.

Membedakan dua jenis penyimpanan:
- DB ini = metadata panel (user, sesi, domain, app, konfigurasi)
- Managed DB (postgres/mysql) = layanan yang dikelola lewat managers/db.py
"""
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL UNIQUE,
    kind           TEXT NOT NULL DEFAULT 'domain',       -- domain | subdomain
    parent         INTEGER REFERENCES domains(id),        -- untuk subdomain
    document_root  TEXT,
    app_type       TEXT NOT NULL DEFAULT 'static',        -- static | django | fastapi | laravel
    app_port       INTEGER,
    proxy_target   TEXT,                                  -- http://127.0.0.1:8000 dst.
    ssl            INTEGER NOT NULL DEFAULT 0,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    source       TEXT NOT NULL,                           -- domain / path
    target       TEXT NOT NULL,                           -- http://127.0.0.1:port
    type         TEXT NOT NULL DEFAULT 'reverse',         -- reverse | cdn
    cache        INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'A',      -- A | AAAA | CNAME | MX | TXT | NS | SRV
    value      TEXT NOT NULL,
    ttl        INTEGER NOT NULL DEFAULT 300,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    language   TEXT NOT NULL,                  -- nodejs | php | python | golang | ruby | rust
    framework  TEXT NOT NULL DEFAULT '',
    user       TEXT NOT NULL,                  -- user OS terisolasi per app
    home_dir   TEXT NOT NULL,                  -- /var/www/<name>
    port       INTEGER NOT NULL UNIQUE,
    command    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'stopped',-- stopped | running | error
    env_file   TEXT NOT NULL,                  -- <home_dir>/.env
    unit       TEXT NOT NULL,                  -- nama unit systemd weborn-<name>.service
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crons (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    schedule   TEXT NOT NULL,                  -- 5 kolom cron: "*/5 * * * *"
    user       TEXT NOT NULL DEFAULT 'root',   -- user OS yang menjalankan
    command    TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

DEFAULT_ADMIN = "admin"
DEFAULT_PASSWORD = "weborn"


def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires),
        )
    return token


def get_user_from_session(token: str):
    if not token:
        return None
    with get_conn() as conn:
        row = conn.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ? AND s.expires_at > ?""",
            (token, datetime.now().isoformat()),
        ).fetchone()
    return dict(row) if row else None


def delete_session(token: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        user = conn.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN,)).fetchone()
        if not user:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (DEFAULT_ADMIN, hash_password(DEFAULT_PASSWORD), datetime.now().isoformat()),
            )
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES ('secret_key', ?)",
            (secrets.token_urlsafe(48),),
        )
        conn.commit()


def get_secret_key() -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'secret_key'").fetchone()
    return row["value"] if row else secrets.token_urlsafe(48)


def get_setting(key: str, default: str = "") -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def create_panel_user(username: str, password: str, role: str = "user") -> bool:
    """Buat user panel (bukan OS user). role: admin | user."""
    if role not in ("admin", "user"):
        raise ValueError("role harus admin atau user")
    with get_conn() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            return False
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, datetime.now().isoformat()),
        )
        conn.commit()
    return True


def list_apps() -> list[dict]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM apps ORDER BY name").fetchall()]


def add_app(data: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO apps(name, language, framework, user, home_dir, port,
                                command, status, env_file, unit, created_at)
               VALUES (:name,:language,:framework,:user,:home_dir,:port,
                       :command,:status,:env_file,:unit,:created_at)""",
            data,
        )
        conn.commit()


def get_app(app_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM apps WHERE id = ?", (app_id,)).fetchone()
    return dict(row) if row else None


def get_app_by_port(port: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM apps WHERE port = ?", (port,)).fetchone()
    return dict(row) if row else None


def set_app_status(app_id: int, status: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE apps SET status = ? WHERE id = ?", (status, app_id))
        conn.commit()


def delete_app(app_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))
        conn.commit()


def list_crons() -> list[dict]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM crons ORDER BY id DESC").fetchall()]


def add_cron(name: str, schedule: str, user: str, command: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO crons(name, schedule, user, command, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, schedule, user, command, datetime.now().isoformat()),
        )
        conn.commit()


def delete_cron(cron_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM crons WHERE id = ?", (cron_id,))
        conn.commit()


def set_cron_enabled(cron_id: int, enabled: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE crons SET enabled = ? WHERE id = ?", (enabled, cron_id))
        conn.commit()
