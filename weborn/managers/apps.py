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
import shlex
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


def _detect_pm(command: str) -> str:
    """Detect process manager from command string."""
    c = command.strip().lower()
    if "gunicorn" in c:
        return "gunicorn"
    if "uvicorn" in c:
        return "uvicorn"
    if "php-fpm" in c or "php_fpm" in c:
        return "php-fpm"
    return "direct"


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
        import shlex
        await self.ex.run("bash", "-c",
                          f"sudo mkdir -p {GUNICORN_SOCK_DIR} /var/log/gunicorn "
                          f"/var/log/nginx /run/php /var/log/php-fpm")
        await self.ex.run("bash", "-c", f"sudo mkdir -p /var/log/{shlex.quote(name)}")

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
        # Skip stubs for scaffolding frameworks (create-project / npx create-* / nest new)
        # These generate their own project structure
        _scaffold_keywords = ("create-project", "create-next-app", "nest new",
                              "sv create", "create astro", "wp core")
        _is_scaffold = fw and any(kw in ((fw or {}).get("pkg") or "")
                                  for kw in _scaffold_keywords)
        stub = None
        if not _is_scaffold:
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
                ("mkdir", f"sudo mkdir -p {home}/{lang.get('run_dir', '.')}"),
                ("user", f"id {os_user} >/dev/null 2>&1 || "
                         f"sudo useradd -r -M -d {home} -s /bin/false {os_user}"),
            ]

            if stub:
                import base64
                fname, content = stub
                resolved_content = content.replace('{name}', name)
                b64 = base64.b64encode(resolved_content.encode()).decode()
                steps.append(("stub",
                    f"mkdir -p {home}/{lang.get('run_dir', '.')} && "
                    f"echo {b64} | base64 -d | sudo tee {home}/{fname} > /dev/null"))

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
                ("reload", "sudo systemctl daemon-reload"),
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
            "app_type": app_type,
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
                             port: int = 0, dir_path: str = "") -> dict:
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

        # Use custom dir or default
        if dir_path and dir_path.startswith("/"):
            home = dir_path.rstrip("/")
        else:
            home = f"{WEB_ROOT}/{slug}"
        os_user = f"weborn-{slug}"[:32]
        unit = f"weborn-{slug}.service"
        env_file = f"{home}/.env"
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"

        steps, failed = [], None
        if self.ex.mode in ("local", "wsl"):
            await self._ensure_dirs(slug)

            qhome = shlex.quote(home)
            quser = shlex.quote(os_user)

            steps += [
                ("mkdir", f"sudo mkdir -p {qhome}"),
                ("user", f"id {os_user} >/dev/null 2>&1 || "
                         f"sudo useradd -r -M -d {qhome} -s /bin/false {os_user}"),
            ]

            # Auto-install gunicorn + uvicorn if not present
            steps.append(("deps",
                "python3 -c 'import gunicorn' 2>/dev/null || "
                "sudo python3 -m pip install --break-system-packages gunicorn uvicorn 2>/dev/null"))

            # Write sample app if directory is empty
            steps.append(("sample", self._write_sample_app(home, app_type)))

            steps += [
                ("env", self._write_env(home, port, app_type, name)),
                ("unit", self._write_unit(unit, os_user, home, command, app_type)),
                ("glog", f"sudo mkdir -p /var/log/{slug} && sudo chown {os_user}:{os_user} /var/log/{slug}"),
                ("chown", f"sudo chown -R {quser}:{quser} {qhome}"),
                ("reload", "sudo systemctl daemon-reload"),
                ("start", f"sudo systemctl enable --now {unit}"),
            ]

            for step, cmd in steps:
                r = await self.ex.run("bash", "-c", cmd)
                if not r.ok and failed is None:
                    if step not in ("deps", "sample"):
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
            "app_type": app_type,
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

    @staticmethod
    def _write_sample_app(home: str, app_type: str) -> str:
        """Write sample main.py if directory is empty."""
        if app_type == "asgi":
            content = (
                "from fastapi import FastAPI\n"
                "import os, datetime\n\n"
                "app = FastAPI()\n\n"
                "@app.get('/')\n"
                "async def root():\n"
                "    return {\n"
                "        'app': os.getenv('APP_DIR', 'unknown'),\n"
                "        'type': 'asgi',\n"
                "        'port': os.getenv('PORT', '8000'),\n"
                "        'time': datetime.datetime.now().isoformat(),\n"
                "        'status': 'running',\n"
                "    }\n"
                "\n"
                "@app.get('/health')\n"
                "async def health():\n"
                "    return {'status': 'ok'}\n"
            )
            pkg = "fastapi uvicorn"
        else:
            content = (
                "from flask import Flask, jsonify\n"
                "import os, datetime\n\n"
                "app = Flask(__name__)\n\n"
                "@app.route('/')\n"
                "def root():\n"
                "    return jsonify({\n"
                "        'app': os.getenv('APP_DIR', 'unknown'),\n"
                "        'type': 'wsgi',\n"
                "        'port': os.getenv('PORT', '8000'),\n"
                "        'time': datetime.datetime.now().isoformat(),\n"
                "        'status': 'running',\n"
                "    })\n"
                "\n"
                "@app.route('/health')\n"
                "def health():\n"
                "    return jsonify({'status': 'ok'})\n"
            )
            pkg = "flask gunicorn"
        import base64
        b64 = base64.b64encode(content.encode()).decode()
        # Only write if main.py doesn't exist
        return (f"[ -f {home}/main.py ] || "
                f"(echo {b64} | base64 -d | sudo tee {home}/main.py > /dev/null && "
                f"sudo python3 -m pip install --break-system-packages {pkg} 2>/dev/null)")

    # ----------------------------------------------------------------- env/unit
    @staticmethod
    def _write_env(home: str, port: int, app_type: str, name: str) -> str:
        slug = _slug(name)
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"
        content = (
            f"PORT={port}\n"
            f"APP_DIR={home}\n"
            f"APP_TYPE={app_type}\n"
            f"GUNICORN_SOCK={sock}\n"
        )
        import base64
        b64 = base64.b64encode(content.encode()).decode()
        return (f"echo {b64} | base64 -d | sudo tee {home}/.env > /dev/null && "
                f"sudo chown root:root {home}/.env")

    @staticmethod
    def _write_unit(unit: str, os_user: str, home: str, command: str | None,
                    app_type: str, limits: dict | None = None) -> str:
        slug = _slug(unit.replace("weborn-", "").replace(".service", ""))
        if command:
            exec_line = f"ExecStart=/bin/bash -c 'cd {home} && {command}'"
        else:
            # PHP-FPM or static: unit just ensures directory perms
            exec_line = f"ExecStart=/bin/true"
        limits = limits or {}
        limit_lines = ""
        mem_limit = limits.get("memory_limit", "")
        if mem_limit:
            limit_lines += f"MemoryMax={mem_limit}\n"
            limit_lines += f"MemoryHigh={mem_limit}\n"
        cpu_quota = limits.get("cpu_quota", "")
        if cpu_quota:
            limit_lines += f"CPUQuota={cpu_quota}\n"
        nice = limits.get("nice", "")
        if nice:
            limit_lines += f"Nice={nice}\n"
        oom_score = limits.get("oom_score_adjust", "")
        if oom_score:
            limit_lines += f"OOMScoreAdjust={oom_score}\n"
        content = (
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
            "RestartSec=5\n"
        )
        if limit_lines:
            content += limit_lines
        content += (
            "\n[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        import base64
        b64 = base64.b64encode(content.encode()).decode()
        return (f"echo {b64} | base64 -d | sudo tee /etc/systemd/system/{unit} > /dev/null && "
                f"sudo chmod 644 /etc/systemd/system/{unit}")

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
        if action == "reload":
            return await self.reload(app_id)
        return {"ok": False, "error": "aksi tidak dikenal"}

    async def reload(self, app_id: int) -> dict:
        """Graceful reload: send SIGHUP to master process."""
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if self.ex.mode not in ("local", "wsl"):
            return {"ok": True, "output": "[dry-run] reload"}
        slug = _slug(app["name"])
        unit = f"weborn-{slug}.service"
        r = await self.ex.run("bash", "-c",
                              f"sudo systemctl show {unit} --property=MainPID --value 2>/dev/null")
        pid = r.stdout.strip()
        if not pid or not pid.isdigit() or int(pid) <= 0:
            return await self.control(app_id, "restart")
        r2 = await self.ex.run("bash", "-c", f"kill -HUP {pid} 2>/dev/null")
        return {"ok": r2.ok, "output": f"Sent SIGHUP to PID {pid}"}

    async def update_process_config(self, app_id: int, config: dict) -> dict:
        """Update process manager config (workers, timeout, etc.) and rebuild unit."""
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        stored = app.get("app_type", "")
        app_type = stored if stored else _app_type_for(app["language"], app.get("framework", ""))
        type_info = APP_TYPES.get(app_type, {})
        pm = type_info.get("process_manager", "gunicorn")
        if pm not in ("gunicorn", "uvicorn"):
            return {"ok": False, "error": "hanya app gunicorn/uvicorn yang bisa dikonfigurasi"}
        new_command = self.build_process_command(app_type, config, app["name"])
        # Update DB
        from ..db import get_conn
        with get_conn() as conn:
            conn.execute("UPDATE apps SET command = ? WHERE id = ?", (new_command, app_id))
            conn.commit()
        # Rewrite systemd unit
        if self.ex.mode in ("local", "wsl"):
            slug = _slug(app["name"])
            unit_cmd = self._write_unit(app["unit"], app["user"], app["home_dir"],
                                        new_command, app_type)
            await self.ex.run("bash", "-c", unit_cmd)
            await self.ex.run("bash", "-c", "sudo systemctl daemon-reload")
            # Restart app with new config
            await self.ex.run("bash", "-c", f"sudo systemctl restart {app['unit']}")
        return {"ok": True, "command": new_command, "output": f"Config updated, restarted {app['unit']}"}

    async def update_limits(self, app_id: int, limits: dict) -> dict:
        """Update resource limits for an app (memory, CPU, etc.) and rebuild unit."""
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        stored = app.get("app_type", "")
        app_type = stored if stored else _app_type_for(app["language"], app.get("framework", ""))
        if self.ex.mode in ("local", "wsl"):
            unit_cmd = self._write_unit(app["unit"], app["user"], app["home_dir"],
                                        app["command"], app_type, limits=limits)
            await self.ex.run("bash", "-c", unit_cmd)
            await self.ex.run("bash", "-c", "sudo systemctl daemon-reload")
            await self.ex.run("bash", "-c", f"sudo systemctl restart {app['unit']}")
        return {"ok": True, "output": f"Limits updated, restarted {app['unit']}"}

    async def delete(self, app_id: int) -> dict:
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if self.ex.mode in ("local", "wsl"):
            qunit = shlex.quote(app['unit'])
            qsock = shlex.quote(f"{GUNICORN_SOCK_DIR}/{_slug(app['name'])}.sock")
            qhome = shlex.quote(app['home_dir'])
            quser = shlex.quote(app['user'])
            steps = [
                ("stop", f"sudo systemctl disable --now {qunit} 2>/dev/null || true"),
                ("rmunit", f"sudo rm -f /etc/systemd/system/{qunit}"),
                ("sock", f"sudo rm -f {qsock}"),
                ("rmdir", f"sudo rm -rf {qhome}"),
                ("rmuser", f"sudo userdel {quser} 2>/dev/null || true"),
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
            # Use stored app_type if available, else compute
            stored = a.get("app_type", "")
            a["app_type"] = stored if stored else _app_type_for(a["language"], a.get("framework", ""))
            if a.get("command"):
                a["process_manager"] = _detect_pm(a["command"])
                # Parse worker count from command
                cfg = self.parse_process_config(a["command"])
                a["workers"] = cfg.get("workers", 0)
                a["timeout"] = cfg.get("timeout", 0)
            else:
                a["process_manager"] = APP_TYPES.get(a["app_type"], {}).get("process_manager", "direct")
                a["workers"] = 0
                a["timeout"] = 0
        return apps

    # ---------------------------------------------------- process config
    @staticmethod
    def parse_process_config(command: str) -> dict:
        """Parse gunicorn/uvicorn command into config dict."""
        import shlex as _shlex
        config = {
            "workers": 4,
            "timeout": 120,
            "worker_class": "",
            "bind": "",
            "access_log": False,
            "max_requests": 0,
            "graceful_timeout": 30,
            "keepalive": 5,
        }
        if not command:
            return config
        try:
            parts = _shlex.split(command)
        except ValueError:
            return config
        pm = _detect_pm(command)
        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ("-w", "--workers") and i + 1 < len(parts):
                try: config["workers"] = int(parts[i + 1])
                except ValueError: pass
                i += 2
            elif p in ("-t", "--timeout") and i + 1 < len(parts):
                try: config["timeout"] = int(parts[i + 1])
                except ValueError: pass
                i += 2
            elif p in ("-k", "--worker-class") and i + 1 < len(parts):
                config["worker_class"] = parts[i + 1]
                i += 2
            elif p in ("--bind",) and i + 1 < len(parts):
                config["bind"] = parts[i + 1]
                i += 2
            elif p in ("--access-logfile",) and i + 1 < len(parts):
                config["access_log"] = parts[i + 1] != "-"
                i += 2
            elif p == "--access-logfile -":
                config["access_log"] = True
                i += 1
            elif p in ("--max-requests",) and i + 1 < len(parts):
                try: config["max_requests"] = int(parts[i + 1])
                except ValueError: pass
                i += 2
            elif p in ("--graceful-timeout",) and i + 1 < len(parts):
                try: config["graceful_timeout"] = int(parts[i + 1])
                except ValueError: pass
                i += 2
            elif p in ("--keep-alive",) and i + 1 < len(parts):
                try: config["keepalive"] = int(parts[i + 1])
                except ValueError: pass
                i += 2
            elif p.startswith("--workers="):
                try: config["workers"] = int(p.split("=", 1)[1])
                except ValueError: pass
                i += 1
            elif p.startswith("--timeout="):
                try: config["timeout"] = int(p.split("=", 1)[1])
                except ValueError: pass
                i += 1
            else:
                i += 1
        # Detect worker class from command if not set
        if not config["worker_class"]:
            if "uvicorn.workers.UvicornWorker" in command:
                config["worker_class"] = "uvicorn.workers.UvicornWorker"
            elif "gevent" in command:
                config["worker_class"] = "gevent"
            elif "gthread" in command:
                config["worker_class"] = "gthread"
        return config

    @staticmethod
    def build_process_command(app_type: str, config: dict, name: str = "") -> str:
        """Rebuild gunicorn/uvicorn command from config dict."""
        slug = _slug(name) if name else "app"
        sock = f"{GUNICORN_SOCK_DIR}/{slug}.sock"
        type_info = APP_TYPES.get(app_type, {})
        pm = type_info.get("process_manager", "gunicorn")
        if pm == "uvicorn":
            parts = ["python3", "-m", "uvicorn", "main:app"]
            parts.append(f"--workers {config.get('workers', 4)}")
            parts.append(f"--host 0.0.0.0")
            port = config.get("port", 0)
            if port:
                parts.append(f"--port {port}")
            timeout = config.get("timeout", 120)
            if timeout:
                parts.append(f"--timeout {timeout}")
            return " ".join(parts)
        parts = ["python3", "-m", "gunicorn"]
        parts.append(f"-w {config.get('workers', 4)}")
        wc = config.get("worker_class", "")
        if wc:
            parts.append(f"-k {wc}")
        parts.append(f"--bind unix:{sock}")
        timeout = config.get("timeout", 120)
        if timeout:
            parts.append(f"--timeout {timeout}")
        max_req = config.get("max_requests", 0)
        if max_req:
            parts.append(f"--max-requests {max_req}")
        gt = config.get("graceful_timeout", 30)
        if gt and gt != 30:
            parts.append(f"--graceful-timeout {gt}")
        ka = config.get("keepalive", 5)
        if ka and ka != 5:
            parts.append(f"--keep-alive {ka}")
        if config.get("access_log"):
            parts.append("--access-logfile -")
        parts.append("main:app")
        return " ".join(parts)

    # -------------------------------------------------------------- status
    async def get_process_status(self, name: str) -> dict:
        """Get process status for an app (gunicorn or uvicorn).

        Process tree: systemd → bash (MainPID) → master → workers
        We walk the full tree to find all descendants.
        """
        slug = _slug(name)
        unit = f"weborn-{slug}.service"
        if self.ex.mode not in ("local", "wsl"):
            return {"status": "dry-run", "workers": []}

        # Get systemd status
        r = await self.ex.run("bash", "-c",
                              f"systemctl is-active {unit} 2>/dev/null || echo stopped")
        status = r.stdout.strip()

        # Get MainPID (this is the bash wrapper from ExecStart)
        r2 = await self.ex.run("bash", "-c",
                               f"systemctl show {unit} --property=MainPID --value 2>/dev/null")
        master_pid = r2.stdout.strip()

        # Walk process tree: find ALL descendants of MainPID
        # Level 1: direct children of bash (master process)
        # Level 2+: grandchildren (workers)
        workers = []
        if master_pid and master_pid.isdigit() and int(master_pid) > 0:
            r3 = await self.ex.run("bash", "-c",
                                   f"ps -eo pid,ppid,pcpu,pmem,etime,cmd --no-headers 2>/dev/null")
            ppid_map = {}
            for line in r3.stdout.strip().splitlines():
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    pid, ppid = parts[0], parts[1]
                    ppid_map[pid] = (ppid, parts[2], parts[3], parts[4], parts[5])

            # BFS from master_pid to find all descendants
            queue = [master_pid]
            seen = {master_pid}
            while queue:
                current = queue.pop(0)
                for pid, (pp, cpu, mem, uptime, cmd) in ppid_map.items():
                    if pp == current and pid not in seen:
                        seen.add(pid)
                        queue.append(pid)
                        workers.append({
                            "pid": pid,
                            "cpu": cpu,
                            "mem": mem,
                            "uptime": uptime,
                            "cmd": cmd,
                        })

        return {
            "status": status,
            "master_pid": master_pid,
            "workers": workers,
        }
