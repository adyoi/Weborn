"""Manager aplikasi Weborn: environment bare-metal terisolasi per app.

Arsitektur:
  - WSGI/ASGI (Python): Gunicorn sebagai process manager
    Nginx → Gunicorn (unix socket) → app
    Command: gunicorn main:app -w N -k uvicorn.workers.UvicornWorker --bind unix:/run/gunicorn/<name>.sock

  - PHP: Nginx → PHP-FPM (socket)

  - Node.js: Nginx → Node process (reverse proxy port)

  - Static: Nginx langsung serve file

Setiap aplikasi mendapat:
- user OS sendiri (weborn-<name>)
- direktori sendiri (WEB_ROOT/<name>)
- socket/port unik
- file .env sendiri
- unit systemd sendiri (weborn-<name>.service)
"""
import re
from datetime import datetime

from ..config import APP_TYPES, FRAMEWORKS, GUNICORN_SOCK_DIR, RUNTIMES, WEB_ROOT
from ..db import add_app, delete_app, get_app, get_app_by_name, get_app_by_port, list_apps, set_app_status

# Stub starter per framework
STUBS = {
    "express": ("server.js",
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/', (req, res) => res.json({ ok: true }));\n"
        "app.listen(process.env.PORT || 8000, () => console.log('listening'));\n"),
    "fastify": ("server.js",
        "const fastify = require('fastify')({ logger: true });\n"
        "fastify.get('/', async () => ({ ok: true }));\n"
        "fastify.listen({ port: process.env.PORT || 8000, host: '0.0.0.0' });\n"),
    "nest": ("src/main.ts",
        "import { NestFactory } from '@nestjs/core';\n"
        "import { AppModule } from './app.module';\n"
        "async function bootstrap() {\n"
        "  const app = await NestFactory.create(AppModule);\n"
        "  await app.listen(process.env.PORT || 3000);\n"
        "}\n"
        "bootstrap();\n"),
    "hono": ("server.js",
        "const { Hono } = require('hono');\n"
        "const app = new Hono();\n"
        "app.get('/', (c) => c.json({ ok: true }));\n"
        "require('node:http').createServer(app.fetch).listen(process.env.PORT || 8000);\n"),
    "sveltekit": ("src/routes/+page.svelte",
        "<script>\n"
        "  export let data;\n"
        "</script>\n"
        "<h1>Welcome to {data.name}</h1>\n"),
    "astro": ("src/pages/index.astro",
        "---\n"
        "const name = '{name}';\n"
        "---\n"
        "<html><body><h1>Welcome to {name}</h1></body></html>\n"),
    "fastapi": ("main.py",
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title='{name}')\n\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return {'app': '{name}', 'ok': True}\n"),
    "flask": ("main.py",
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/')\n"
        "def home():\n"
        "    return {'app': '{name}', 'ok': True}\n"),
    "django": ("main.py",
        "import os\n"
        "import django\n"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')\n"
        "django.setup()\n"
        "from django.core.wsgi import get_wsgi_application\n"
        "app = get_wsgi_application()\n"),
    "litestar": ("main.py",
        "from litestar import Litestar, get\n\n"
        "@get('/')\n"
        "def home() -> dict:\n"
        "    return {'app': '{name}', 'ok': True}\n\n"
        "app = Litestar(route_handlers=[home])\n"),
    "sanic": ("main.py",
        "from sanic import Sanic\n"
        "from sanic.response import json\n\n"
        "app = Sanic('{name}')\n\n"
        "@app.get('/')\n"
        "async def home(request):\n"
        "    return json({'app': '{name}', 'ok': True})\n"),
    "tornado": ("main.py",
        "import tornado.ioloop\n"
        "import tornado.web\n\n"
        "class MainHandler(tornado.web.RequestHandler):\n"
        "    def get(self):\n"
        "        self.write({'app': '{name}', 'ok': True})\n\n"
        "app = tornado.web.Application([(r'/', MainHandler)])\n"
        "app.listen(8000)\n"
        "tornado.ioloop.IOLoop.current().start()\n"),
    "pyramid": ("main.py",
        "from wsgiref.simple_server import make_server\n"
        "from pyramid.config import Configurator\n"
        "from pyramid.response import Response\n\n"
        "def home(request):\n"
        "    return Response(json_body={'app': '{name}', 'ok': True})\n\n"
        "with Configurator() as config:\n"
        "    config.add_route('home', '/')\n"
        "    config.add_view(home, route_name='home')\n"
        "    app = config.make_wsgi_app()\n"),
    "bottle": ("main.py",
        "from bottle import Bottle, response\n"
        "import json\n\n"
        "app = Bottle()\n\n"
        "@app.route('/')\n"
        "def home():\n"
        "    response.content_type = 'application/json'\n"
        "    return json.dumps({'app': '{name}', 'ok': True})\n"),
}

LANG_STUB = {
    "nodejs": ("server.js",
        "const http = require('http');\n"
        "http.createServer((req, res) => {\n"
        "  res.writeHead(200, {'Content-Type': 'application/json'});\n"
        "  res.end(JSON.stringify({ app: '{name}', ok: true }));\n"
        "}).listen(process.env.PORT || 8000, '0.0.0.0');\n"),
    "php": ("public/index.php",
        "<?php header('Content-Type: application/json');\n"
        "echo json_encode(['app' => '{name}', 'ok' => true]);\n"),
}


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return s or "app"


def _app_type_for(language: str, framework: str) -> str:
    """Determine app type from language + framework."""
    fw_lower = (framework or "").lower()
    lang_lower = (language or "").lower()
    if fw_lower in ("django", "flask"):
        return fw_lower
    if fw_lower in ("fastapi", "litestar", "sanic"):
        return "asgi"
    if fw_lower in ("tornado", "pyramid", "bottle"):
        return "wsgi"
    if fw_lower in ("laravel", "wordpress", "codeigniter", "symfony", "slim"):
        return "laravel"
    if fw_lower in ("express", "next", "nuxt", "fastify", "nest", "hono", "sveltekit", "astro"):
        return "nodejs"
    if lang_lower == "php":
        return "laravel"
    if lang_lower == "python":
        return "wsgi"
    if lang_lower == "nodejs":
        return "nodejs"
    return "static"


class AppManager:
    def __init__(self, ex):
        self.ex = ex

    # ----------------------------------------------------------------- helpers
    async def _ensure_dirs(self, name: str):
        """Create log + socket dirs."""
        await self.ex.run("bash", "-c",
                          f"sudo mkdir -p {GUNICORN_SOCK_DIR} /var/log/gunicorn "
                          f"/var/log/nginx /run/php /var/log/php-fpm")
        await self.ex.run("bash", "-c", f"sudo mkdir -p /var/log/{name}")

    # ---------------------------------------------------------------- port alloc
    async def alloc_port(self) -> int:
        used = {a["port"] for a in list_apps()}
        busy = set()
        if self.ex.mode in ("local", "wsl"):
            r = await self.ex.run("bash", "-c",
                                  "ss -tln | awk 'NR>1{print $4}' | sed 's/.*://' | sort -u")
            for tok in r.stdout.split():
                if tok.isdigit():
                    busy.add(int(tok))
        for port in range(8000, 9000):
            if port not in used and port not in busy:
                return port
        raise RuntimeError("tidak ada port bebas (8000-8999 habis)")

    # ---------------------------------------------------------------- create
    async def create(self, name: str, language: str, framework: str = "",
                     port: int = 0) -> dict:
        lang = RUNTIMES.get(language)
        if not lang:
            return {"ok": False, "error": f"bahasa '{language}' tidak dikenal"}

        fw = None
        if framework:
            fw = next((f for f in FRAMEWORKS.get(language, []) if f["id"] == framework), None)
            if not fw:
                return {"ok": False, "error": f"framework '{framework}' tidak dikenal"}

        slug = _slug(name)
        app_type = _app_type_for(language, framework)
        type_info = APP_TYPES.get(app_type, {})

        # Check for duplicate name
        existing = get_app_by_name(name)
        if existing:
            return {"ok": False, "error": f"nama app '{name}' sudah dipakai"}

        if not port:
            try:
                port = await self.alloc_port()
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
        if get_app_by_port(port):
            return {"ok": False, "error": f"port {port} sudah dipakai app lain"}

        home = f"{WEB_ROOT}/{slug}"
        os_user = f"weborn-{slug}"[:32]
        unit = f"weborn-{slug}.service"
        env_file = f"{home}/.env"
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"
        log_dir = f"/var/log/{slug}"

        # ── Build command based on app_type ──
        workers = type_info.get("workers_default", 4)
        pm = type_info.get("process_manager", "direct")

        if pm == "gunicorn":
            command = type_info["command"].format(
                workers=workers, sock=sock, port=port, name=slug)
        elif pm == "php-fpm":
            command = None  # Nginx → PHP-FPM handles this
            sock = None
        elif pm == "direct":
            command = (fw or {}).get("start") or type_info.get("command", "")
            command = command.replace("{port}", str(port))
        else:
            command = None

        # ── Stub starter file ──
        stub = None
        if fw and fw["id"] in STUBS:
            stub = STUBS[fw["id"]]
        elif not fw:
            stub = LANG_STUB.get(language)

        steps, failed = [], None
        if self.ex.mode in ("local", "wsl"):
            await self._ensure_dirs(slug)

            deps = (fw or {}).get("pkg") or ""
            if deps and language == "python":
                deps = deps.replace("pip install",
                                    "python3 -m pip install --break-system-packages")

            steps += [
                ("mkdir", f"mkdir -p {home}/{lang.get('run_dir', '.')}"),
                ("user", f"id {os_user} >/dev/null 2>&1 || "
                         f"useradd -r -M -d {home} -s /bin/false {os_user}"),
            ]

            if stub:
                fname, content = stub
                steps.append(("stub",
                    f"mkdir -p {home}/{lang.get('run_dir', '.')} && "
                    f"cat > {home}/{fname} <<'WEBORN_EOF'\n"
                    f"{content.replace('{name}', name)}\nWEBORN_EOF"))

            if deps:
                steps.append(("deps", f"cd {home} && {deps}"))

            steps += [
                ("env", self._write_env(home, port, app_type, name)),
                ("unit", self._write_unit(unit, os_user, home, command, app_type)),
            ]

            if pm == "gunicorn":
                steps += [
                    ("glog", f"sudo mkdir -p {log_dir} && sudo chown {os_user}:{os_user} {log_dir}"),
                ]
            elif pm == "php-fpm":
                steps += [
                    ("fpm", f"sudo mkdir -p /etc/php/fpm/pool.d && "
                            f"sudo chown www-data:www-data {home}/public 2>/dev/null || true"),
                ]

            steps += [
                ("chown", f"sudo chown -R {os_user}:{os_user} {home}"),
                ("start", f"sudo systemctl enable --now {unit}"),
            ]

            for step, cmd in steps:
                r = await self.ex.run("bash", "-c", cmd)
                if not r.ok and failed is None:
                    if step not in ("deps", "stub"):
                        failed = step
        else:
            steps = [
                ("mkdir", f"mkdir -p {home}"),
                ("user", f"useradd -r -M -d {home} -s /bin/false {os_user}"),
                ("env", f".env written (PORT={port}, TYPE={app_type})"),
                ("unit", f"unit {unit} written"),
                ("start", f"systemctl enable --now {unit}"),
            ]

        add_app({
            "name": name, "language": language, "framework": framework or "",
            "user": os_user, "home_dir": home, "port": port,
            "command": command or f"Nginx → {pm}",
            "status": "running" if failed is None else "error",
            "env_file": env_file, "unit": unit,
            "created_at": datetime.now().isoformat(),
        })
        return {
            "ok": failed is None,
            "error": f"langkah '{failed}' gagal" if failed else None,
            "port": port, "user": os_user, "home_dir": home,
            "unit": unit, "command": command, "env_file": env_file, "steps": steps,
        }

    # ----------------------------------------------------------------- create native
    async def create_native(self, name: str, app_type: str, command: str,
                             port: int = 0) -> dict:
        """Create a native app with user-specified command (no framework stub)."""
        slug = _slug(name)

        existing = get_app_by_name(name)
        if existing:
            return {"ok": False, "error": f"nama app '{name}' sudah dipakai"}

        if not port:
            try:
                port = await self.alloc_port()
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
        if get_app_by_port(port):
            return {"ok": False, "error": f"port {port} sudah dipakai app lain"}

        home = f"{WEB_ROOT}/{slug}"
        os_user = f"weborn-{slug}"[:32]
        unit = f"weborn-{slug}.service"
        env_file = f"{home}/.env"
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"

        steps, failed = [], None
        if self.ex.mode in ("local", "wsl"):
            await self._ensure_dirs(slug)

            steps += [
                ("mkdir", f"mkdir -p {home}"),
                ("user", f"id {os_user} >/dev/null 2>&1 || "
                         f"useradd -r -M -d {home} -s /bin/false {os_user}"),
                ("env", self._write_env(home, port, app_type, name)),
                ("unit", self._write_unit(unit, os_user, home, command, app_type)),
                ("glog", f"sudo mkdir -p /var/log/{slug} && sudo chown {os_user}:{os_user} /var/log/{slug}"),
                ("chown", f"sudo chown -R {os_user}:{os_user} {home}"),
                ("start", f"sudo systemctl enable --now {unit}"),
            ]

            for step, cmd in steps:
                r = await self.ex.run("bash", "-c", cmd)
                if not r.ok and failed is None:
                    failed = step
        else:
            steps = [
                ("mkdir", f"mkdir -p {home}"),
                ("user", f"useradd -r -M -d {home} -s /bin/false {os_user}"),
                ("env", f".env written (PORT={port}, TYPE={app_type})"),
                ("unit", f"unit {unit} written"),
                ("start", f"systemctl enable --now {unit}"),
            ]

        add_app({
            "name": name, "language": "python", "framework": "",
            "user": os_user, "home_dir": home, "port": port,
            "command": command,
            "status": "running" if failed is None else "error",
            "env_file": env_file, "unit": unit,
            "created_at": datetime.now().isoformat(),
        })
        return {
            "ok": failed is None,
            "error": f"langkah '{failed}' gagal" if failed else None,
            "port": port, "user": os_user, "home_dir": home,
            "unit": unit, "command": command, "env_file": env_file, "steps": steps,
        }

    # ----------------------------------------------------------------- env/unit
    @staticmethod
    def _write_env(home: str, port: int, app_type: str, name: str) -> str:
        slug = _slug(name)
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"
        lines = [
            f"PORT={port}",
            f"APP_DIR={home}",
            f"APP_TYPE={app_type}",
            f"GUNICORN_SOCK={sock}",
        ]
        return f"cat > {home}/.env <<'WEBORN_EOF'\n" + "\n".join(lines) + "\nWEBORN_EOF"

    @staticmethod
    def _write_unit(unit: str, os_user: str, home: str, command: str | None,
                    app_type: str) -> str:
        slug = _slug(unit.replace("weborn-", "").replace(".service", ""))
        if command:
            exec_line = f"ExecStart=/bin/bash -c 'cd {home} && {command}'"
        else:
            # PHP-FPM or static: unit just ensures directory perms
            exec_line = f"ExecStart=/bin/true"
        return (
            f"cat > /etc/systemd/system/{unit} <<'WEBORN_EOF'\n"
            "[Unit]\n"
            f"Description=Weborn app ({app_type})\n"
            "After=network.target\n\n"
            "[Service]\n"
            f"User={os_user}\n"
            f"Group={os_user}\n"
            f"WorkingDirectory={home}\n"
            f"EnvironmentFile={home}/.env\n"
            f"{exec_line}\n"
            "Restart=on-failure\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
            "WEBORN_EOF"
        )

    # ---------------------------------------------------------------- actions
    async def control(self, app_id: int, action: str) -> dict:
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if action in ("start", "stop", "restart"):
            if self.ex.mode in ("local", "wsl"):
                r = await self.ex.run("bash", "-c",
                                      f"sudo systemctl {action} {app['unit']}")
                if r.ok:
                    set_app_status(app_id, "running" if action != "stop" else "stopped")
                return {"ok": r.ok, "output": r.stdout + r.stderr}
            set_app_status(app_id, "running" if action != "stop" else "stopped")
            return {"ok": True, "output": f"[dry-run] systemctl {action} {app['unit']}"}
        return {"ok": False, "error": "aksi tidak dikenal"}

    async def delete(self, app_id: int) -> dict:
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if self.ex.mode in ("local", "wsl"):
            steps = [
                ("stop", f"sudo systemctl disable --now {app['unit']} 2>/dev/null || true"),
                ("rmunit", f"sudo rm -f /etc/systemd/system/{app['unit']}"),
                ("sock", f"sudo rm -f {GUNICORN_SOCK_DIR}/{_slug(app['name'])}.sock"),
                ("rmdir", f"sudo rm -rf {app['home_dir']}"),
                ("rmuser", f"sudo userdel {app['user']} 2>/dev/null || true"),
            ]
            for _, cmd in steps:
                await self.ex.run("bash", "-c", cmd)
        delete_app(app_id)
        return {"ok": True, "output": f"app {app['name']} dihapus"}

    def list(self) -> list[dict]:
        apps = list_apps()
        for a in apps:
            lang_info = RUNTIMES.get(a["language"], {})
            a["language_label"] = lang_info.get("label", a["language"])
            a["app_type"] = _app_type_for(a["language"], a.get("framework", ""))
            a["process_manager"] = APP_TYPES.get(a["app_type"], {}).get("process_manager", "direct")
        return apps

    # -------------------------------------------------------------- status
    async def get_gunicorn_status(self, name: str) -> dict:
        """Get Gunicorn worker status for an app."""
        slug = _slug(name)
        unit = f"weborn-{slug}.service"
        if self.ex.mode not in ("local", "wsl"):
            return {"status": "dry-run", "workers": []}

        # Get systemd status
        r = await self.ex.run("bash", "-c",
                              f"systemctl is-active {unit} 2>/dev/null || echo stopped")
        status = r.stdout.strip()

        # Get Gunicorn master PID
        r2 = await self.ex.run("bash", "-c",
                               f"systemctl show {unit} --property=MainPID --value 2>/dev/null")
        master_pid = r2.stdout.strip()

        # Get worker count from ps
        workers = []
        if master_pid and master_pid.isdigit() and int(master_pid) > 0:
            r3 = await self.ex.run("bash", "-c",
                                   f"ps --ppid {master_pid} -o pid,pcpu,pmem,etime,cmd --no-headers 2>/dev/null")
            for line in r3.stdout.strip().splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    workers.append({
                        "pid": parts[0],
                        "cpu": parts[1],
                        "mem": parts[2],
                        "uptime": parts[3],
                        "cmd": parts[4],
                    })

        return {
            "status": status,
            "master_pid": master_pid,
            "workers": workers,
        }
