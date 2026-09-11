from pathlib import Path

VERSION = "1.0.0"

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

# Virtualenv untuk app Python. Dua lokasi didukung:
#   - di dalam home_dir  -> {home_dir}/.venv
#   - di luar home_dir   -> VENV_ROOT/<slug>
VENV_ROOT = "/opt/weborn/venvs"

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
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "django": {
        "label": "Django",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "flask": {
        "label": "Flask",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },

    # ── Python ASGI ──
    "asgi": {
        "label": "ASGI (Python)",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "fastapi": {
        "label": "FastAPI",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "litestar": {
        "label": "Litestar",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "sanic": {
        "label": "Sanic",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} -k uvicorn.workers.UvicornWorker --bind unix:{sock} --timeout 120",
        "workers_default": 4,
    },
    "tornado": {
        "label": "Tornado",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "pyramid": {
        "label": "Pyramid",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
        "workers_default": 4,
    },
    "bottle": {
        "label": "Bottle",
        "runtime": "python",
        "process_manager": "gunicorn",
        "command": "python3 -m gunicorn main:app -w {workers} --bind unix:{sock} --timeout 120 --access-logfile -",
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

    # ── Deno ──
    "deno": {
        "label": "Deno",
        "runtime": "deno",
        "process_manager": "direct",
        "command": "deno run --allow-net --allow-env main.ts",
    },

    # ── Bun ──
    "bun": {
        "label": "Bun",
        "runtime": "bun",
        "process_manager": "direct",
        "command": "bun run main.ts",
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
# APP TYPE GROUPS — Filter daftar aplikasi (chips di halaman Application)
# ─────────────────────────────────────────────────────────────────────────────

APP_TYPE_GROUPS = {
    "wsgi": "WSGI",
    "asgi": "ASGI",
    "js": "JavaScript",
    "php": "PHP",
}

APP_TYPES_IN_GROUP = {
    "wsgi": {"wsgi", "django", "flask", "tornado", "pyramid", "bottle"},
    "asgi": {"asgi", "fastapi", "litestar", "sanic"},
    "js": {"nodejs", "deno", "bun"},
    "php": {"php", "laravel"},
}

# Setiap app_type di APP_TYPES yang tidak tercantum di atas (mis. "static")
# hanya muncul pada chip "Semua" — grup filter tidak memilikinya.
ALL_GROUPED_TYPES = frozenset(t for group in APP_TYPES_IN_GROUP.values() for t in group)

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
    "deno": {
        "label": "Deno",
        "addon": "deno",
        "pkg": "deno",
        "version_cmd": "deno --version | head -1",
        "install_cmd": "curl -fsSL https://deno.land/install.sh | sh && "
                       "sudo cp \"$HOME/.deno/bin/deno\" /usr/local/bin/deno && deno --version",
        "default": {
            "serve": "deno run --allow-net --allow-env main.ts",
        },
    },
    "bun": {
        "label": "Bun",
        "addon": "bun",
        "pkg": "bun",
        "version_cmd": "bun --version",
        "install_cmd": "curl -fsSL https://bun.sh/install | bash && "
                       "sudo cp \"$HOME/.bun/bin/bun\" /usr/local/bin/bun && bun --version",
        "default": {
            "serve": "bun run main.ts",
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
         "start": "python3 -m gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "fastapi", "label": "FastAPI", "app_type": "fastapi",
         "pkg": "pip install fastapi uvicorn gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "flask", "label": "Flask", "app_type": "flask",
         "pkg": "pip install flask gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "litestar", "label": "Litestar", "app_type": "asgi",
         "pkg": "pip install litestar uvicorn gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "sanic", "label": "Sanic", "app_type": "asgi",
         "pkg": "pip install sanic gunicorn uvicorn",
         "start": "python3 -m gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind unix:{sock}"},
        {"id": "tornado", "label": "Tornado", "app_type": "wsgi",
         "pkg": "pip install tornado gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "pyramid", "label": "Pyramid", "app_type": "wsgi",
         "pkg": "pip install pyramid gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 --bind unix:{sock}"},
        {"id": "bottle", "label": "Bottle", "app_type": "wsgi",
         "pkg": "pip install bottle gunicorn",
         "start": "python3 -m gunicorn main:app -w 4 --bind unix:{sock}"},
    ],
    "php": [
        {"id": "laravel", "label": "Laravel", "app_type": "laravel",
         "pkg": "composer create-project laravel/laravel .",
         "serve": "Nginx → PHP-FPM"},
        {"id": "spiral", "label": "Spiral", "app_type": "php",
         "pkg": "composer create-project spiral/app .",
         "serve": "Nginx → PHP-FPM"},
        {"id": "yii3", "label": "Yii3", "app_type": "php",
         "pkg": "composer create-project yiisoft/app .",
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
    "deno": [
        {"id": "fresh", "label": "Fresh", "app_type": "deno",
         "pkg": "deno run -A -r https://fresh.deno.dev .",
         "start": "deno run -A main.ts"},
        {"id": "hono-deno", "label": "Hono", "app_type": "deno",
         "pkg": "deno add npm:hono",
         "start": "deno run --allow-net --allow-env main.ts"},
        {"id": "oak", "label": "Oak", "app_type": "deno",
         "pkg": "deno add npm:oak",
         "start": "deno run --allow-net --allow-env main.ts"},
        {"id": "deno-http", "label": "Deno std/http", "app_type": "deno",
         "pkg": "",
         "start": "deno run --allow-net --allow-env main.ts"},
    ],
    "bun": [
        {"id": "elysia", "label": "Elysia", "app_type": "bun",
         "pkg": "bun add elysia",
         "start": "bun run main.ts"},
        {"id": "hono-bun", "label": "Hono", "app_type": "bun",
         "pkg": "bun add hono",
         "start": "bun run main.ts"},
        {"id": "bun-express", "label": "Express", "app_type": "bun",
         "pkg": "bun add express",
         "start": "bun run main.ts"},
        {"id": "bun-http", "label": "Bun.serve", "app_type": "bun",
         "pkg": "",
         "start": "bun run main.ts"},
    ],
}
