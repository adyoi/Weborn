from pathlib import Path

VERSION = "0.3.1"

BASE_DIR = Path(__file__).resolve().parent.parent

WEBORN_DIR = BASE_DIR / "data"
DB_PATH = WEBORN_DIR / "weborn.db"
CONFIG_DIR = WEBORN_DIR / "configs"
LOG_DIR = WEBORN_DIR / "logs"
BACKUP_DIR = WEBORN_DIR / "backups"
ADDONS_DIR = WEBORN_DIR / "addons"          # addon 3rd party (manifest .json)
BUILTIN_ADDONS_DIR = Path(__file__).resolve().parent / "addons" / "builtin"
CONF_TEMPLATES_DIR = Path(__file__).resolve().parent / "addons" / "templates"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Target deployment (linux)
WEB_ROOT = "/var/www"
GUNICORN_SOCK_DIR = "/run/gunicorn"

# Port panel
PANEL_HTTP_PORT = 2025
PANEL_HTTPS_PORT = 2043

SESSION_COOKIE = "weborn_session"

# ─────────────────────────────────────────────────────────────────────────────
# PAM — Autentikasi Linux user via Pluggable Authentication Modules
# Aktifkan bila ingin user Linux bisa login ke panel dengan akun mereka.
# Root login diizinkan hanya bila sudah ada admin panel (gate).
# ─────────────────────────────────────────────────────────────────────────────
USE_PAM = True

import os as _os
import platform as _platform

_env_mode = _os.environ.get("WEBORN_EXECUTOR_MODE", "").strip().lower()
if _env_mode in ("dry-run", "local", "wsl"):
    EXECUTOR_MODE = _env_mode
elif _platform.system() == "Linux":
    EXECUTOR_MODE = "local"
else:
    EXECUTOR_MODE = "dry-run"

WSL_DISTRO = _os.environ.get("WEBORN_WSL_DISTRO", "Debian")

# ─────────────────────────────────────────────────────────────────────────────
# APP TYPES — Arsitektur Gunicorn sebagai process manager
#
# WSGI (Django/Flask):
#   Nginx → Gunicorn (sync workers) → Django/Flask
#   gunicorn main:app -w 4 --bind unix:/run/gunicorn/{name}.sock
#
# ASGI (FastAPI/Starlette):
#   Nginx → Gunicorn (uvicorn workers) → FastAPI/Starlette
#   gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:/run/gunicorn/{name}.sock
#
# Static: Nginx langsung serve file
# PHP: Nginx → PHP-FPM
# Node.js: Nginx → Node process (reverse proxy)
# ─────────────────────────────────────────────────────────────────────────────

APP_TYPES = {
    # ── Python WSGI ──
    "wsgi": {
        "label": "WSGI (Python)",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "django": {
        "label": "Django",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "flask": {
        "label": "Flask",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },

    # ── Python ASGI ──
    "asgi": {
        "label": "ASGI (Python)",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "fastapi": {
        "label": "FastAPI",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "litestar": {
        "label": "Litestar",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "sanic": {
        "label": "Sanic",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "tornado": {
        "label": "Tornado",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "pyramid": {
        "label": "Pyramid",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "bottle": {
        "label": "Bottle",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },

    # ── PHP (via PHP-FPM) ──
    "laravel": {
        "label": "Laravel (PHP)",
        "runtime": "php",
        "process_manager": "php-fpm",
        "command": None,  # served by Nginx → PHP-FPM
    },
    "php": {
        "label": "PHP",
        "runtime": "php",
        "process_manager": "php-fpm",
        "command": None,
    },

    # ── Node.js ──
    "nodejs": {
        "label": "Node.js",
        "runtime": "nodejs",
        "process_manager": "direct",
        "command": "node server.js",
    },

    # ── Static ──
    "static": {
        "label": "Static Site",
        "runtime": None,
        "process_manager": None,
        "command": None,  # Nginx serves directly
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# RUNTIMES — Bahasa yang dikelola panel
# ─────────────────────────────────────────────────────────────────────────────

RUNTIMES = {
    "python": {
        "label": "Python",
        "addon": "python3",
        "pkg": "pip",
        "version_cmd": "python3 -V",
        "wsgi_server": "gunicorn",
        "asgi_server": "gunicorn+uvicorn",
        "install_cmd": "pip install gunicorn uvicorn",
        "default": {
            "wsgi": "gunicorn main:app -w {workers} --bind unix:{sock}",
            "asgi": "gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock}",
        },
    },
    "php": {
        "label": "PHP",
        "addon": "php",
        "pkg": "composer",
        "version_cmd": "php -v | head -1",
        "fpm_sock": "/run/php/php{version}-fpm.sock",
        "default": {
            "serve": "Nginx → PHP-FPM (no direct process)",
        },
    },
    "nodejs": {
        "label": "Node.js",
        "addon": "nodejs",
        "pkg": "npm",
        "version_cmd": "node -v && npm -v",
        "default": {
            "serve": "node server.js",
        },
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORKS — Preset scaffold per bahasa
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORKS = {
    "python": [
        {"id": "django", "label": "Django", "app_type": "django",
         "pkg": "pip install django gunicorn uvicorn",
         "start": "gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "fastapi", "label": "FastAPI", "app_type": "fastapi",
         "pkg": "pip install fastapi uvicorn gunicorn",
         "start": "gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "flask", "label": "Flask", "app_type": "flask",
         "pkg": "pip install flask gunicorn",
         "start": "gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "litestar", "label": "Litestar", "app_type": "asgi",
         "pkg": "pip install litestar uvicorn gunicorn",
         "start": "gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "sanic", "label": "Sanic", "app_type": "asgi",
         "pkg": "pip install sanic gunicorn uvicorn",
         "start": "gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "tornado", "label": "Tornado", "app_type": "wsgi",
         "pkg": "pip install tornado gunicorn",
         "start": "gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "pyramid", "label": "Pyramid", "app_type": "wsgi",
         "pkg": "pip install pyramid gunicorn",
         "start": "gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "bottle", "label": "Bottle", "app_type": "wsgi",
         "pkg": "pip install bottle gunicorn",
         "start": "gunicorn main:app -w 4 --bind unix:{sock}"},
    ],
    "php": [
        {"id": "laravel", "label": "Laravel", "app_type": "laravel",
         "pkg": "composer create-project laravel/laravel .",
         "serve": "Nginx → PHP-FPM"},
        {"id": "wordpress", "label": "WordPress", "app_type": "php",
         "pkg": "wp core download",
         "serve": "Nginx → PHP-FPM"},
        {"id": "symfony", "label": "Symfony", "app_type": "laravel",
         "pkg": "composer create-project symfony/skeleton .",
         "serve": "Nginx → PHP-FPM"},
        {"id": "codeigniter", "label": "CodeIgniter", "app_type": "laravel",
         "pkg": "composer create-project codeigniter4/appstarter .",
         "serve": "Nginx → PHP-FPM"},
        {"id": "slim", "label": "Slim", "app_type": "laravel",
         "pkg": "composer create-project slim/slim-skeleton .",
         "serve": "Nginx → PHP-FPM"},
    ],
    "nodejs": [
        {"id": "express", "label": "Express", "app_type": "nodejs",
         "pkg": "npm install express",
         "start": "node server.js"},
        {"id": "next", "label": "Next.js", "app_type": "nodejs",
         "pkg": "npx create-next-app@latest . --js",
         "start": "npm run dev"},
        {"id": "fastify", "label": "Fastify", "app_type": "nodejs",
         "pkg": "npm install fastify",
         "start": "node server.js"},
        {"id": "nest", "label": "NestJS", "app_type": "nodejs",
         "pkg": "npm i -g @nestjs/cli && nest new .",
         "start": "npm run start:dev"},
        {"id": "hono", "label": "Hono", "app_type": "nodejs",
         "pkg": "npm install hono",
         "start": "node server.js"},
        {"id": "sveltekit", "label": "SvelteKit", "app_type": "nodejs",
         "pkg": "npx sv create . --template minimal --types ts --no-add-ons --no-install",
         "start": "npm run dev"},
        {"id": "astro", "label": "Astro", "app_type": "nodejs",
         "pkg": "npm create astro@latest . -- --template basics",
         "start": "npm run dev"},
    ],
}
