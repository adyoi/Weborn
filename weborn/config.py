from pathlib import Path

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

# Target deployment (linux) — dipakai untuk generate konfigurasi layanan
WEB_ROOT = "/var/www"

# Port panel
PANEL_HTTP_PORT = 2025
PANEL_HTTPS_PORT = 2043

# Nama cookie sesi
SESSION_COOKIE = "weborn_session"

# Mode eksekusi: "dry-run" (dev/Windows), "local" (linux), atau "wsl" (WSL distro).
# Bisa dioverride lewat env WEBORN_EXECUTOR_MODE (untuk tes WSL/Debian).
import os as _os

EXECUTOR_MODE = _os.environ.get("WEBORN_EXECUTOR_MODE", "dry-run").strip().lower()
if EXECUTOR_MODE not in ("dry-run", "local", "wsl"):
    EXECUTOR_MODE = "dry-run"

# Distro WSL default untuk mode "wsl"
WSL_DISTRO = _os.environ.get("WEBORN_WSL_DISTRO", "Debian")

APP_TYPES = {
    "static": {"label": "Static Site", "command": None},
    "django": {"label": "Django", "command": "uvicorn main:app"},
    "fastapi": {"label": "FastAPI", "command": "uvicorn main:app"},
    "laravel": {"label": "Laravel (PHP)", "command": "php artisan serve"},
    "nodejs": {"label": "Node.js", "command": "npm start"},
}

# ---------------------------------------------------------------- Runtime apps
# Bahasa runtime yang dikelola panel. Setiap bahasa butuh addon runtime (Addon Store)
# yang menginstall interpreter/compiler-nya.
RUNTIMES = {
    "nodejs": {
        "label": "Node.js",
        "addon": "nodejs",                 # addon runtime di Addon Store
        "pkg": "npm",
        "version_cmd": "node -v && npm -v",
        "run_dir": "app",
        "default": {"file": "server.js", "cmd": "node server.js"},
    },
    "php": {
        "label": "PHP",
        "addon": "php",
        "pkg": "composer",
        "version_cmd": "php -v | head -1",
        "run_dir": "public",
        "default": {"file": "index.php", "cmd": "php -S 0.0.0.0:{port} -t public"},
    },
    "python": {
        "label": "Python",
        "addon": "python",
        "pkg": "pip",
        "version_cmd": "python3 -V",
        "run_dir": "app",
        "default": {"file": "main.py", "cmd": "python3 -m uvicorn main:app --host 0.0.0.0 --port {port}"},
    },
}

# Framework populer per bahasa (preset untuk scaffold starter app).
FRAMEWORKS = {
    "nodejs": [
        {"id": "express", "label": "Express", "pkg": "npm install express",
         "start": "node server.js"},
        {"id": "next", "label": "Next.js", "pkg": "npx create-next-app@latest . --js",
         "start": "npm run dev"},
        {"id": "nuxt", "label": "Nuxt", "pkg": "npx create-nuxt-app", "start": "npm run dev"},
        {"id": "nest", "label": "NestJS", "pkg": "npm i -g @nestjs/cli && nest new .",
         "start": "npm run start:dev"},
        {"id": "fastify", "label": "Fastify", "pkg": "npm install fastify",
         "start": "node server.js"},
    ],
    "php": [
        {"id": "laravel", "label": "Laravel", "pkg": "composer create-project laravel/laravel .",
         "start": "php artisan serve --port {port}"},
        {"id": "wordpress", "label": "WordPress", "pkg": "wp core download",
         "start": "php -S 0.0.0.0:{port} -t ."},
        {"id": "codeigniter", "label": "CodeIgniter 4",
         "pkg": "composer create-project codeigniter4/appstarter .",
         "start": "php spark serve --port {port}"},
        {"id": "symfony", "label": "Symfony", "pkg": "composer create-project symfony/skeleton .",
         "start": "php -S 0.0.0.0:{port} -t public"},
        {"id": "lumen", "label": "Lumen", "pkg": "composer create-project laravel/lumen .",
         "start": "php -S 0.0.0.0:{port} -t public"},
    ],
    "python": [
        {"id": "django", "label": "Django", "pkg": "pip install django && django-admin startproject weborn .",
         "start": "python3 manage.py runserver 0.0.0.0:{port}"},
        {"id": "fastapi", "label": "FastAPI", "pkg": "pip install fastapi uvicorn",
         "start": "python3 -m uvicorn main:app --host 0.0.0.0 --port {port}"},
        {"id": "flask", "label": "Flask", "pkg": "pip install flask",
         "start": "python3 -m flask run --host 0.0.0.0 --port {port}"},
        {"id": "tornado", "label": "Tornado", "pkg": "pip install tornado",
         "start": "python3 main.py"},
    ],
}
