"""Manager aplikasi Weborn: environment bare-metal terisolasi per app.

Setiap aplikasi mendapat:
- user OS sendiri (weborn-<name>)
- direktori sendiri (WEB_ROOT/<name>)
- port unik (auto-alokasi 8000-8999, cek DB + port aktif)
- file .env sendiri
- unit systemd sendiri (weborn-<name>.service)

Fokus bahasa: Python (utama), Node.js & PHP (terkait web stack).
"""
import re
from datetime import datetime

from ..config import FRAMEWORKS, RUNTIMES, WEB_ROOT
from ..db import add_app, delete_app, get_app, get_app_by_port, list_apps, set_app_status

# Stub starter per framework (ditulis otomatis bila framework butuh file minimal
# agar langsung bisa start; framework dengan scaffold (next/nuxt/django dst.)
# memakai perintah pkg-nya sendiri).
STUBS = {
    "express": ("server.js",
        "const express = require('express');\n"
        "const app = express();\n"
        "const port = process.env.PORT || 8000;\n"
        "app.get('/', (req, res) => res.json({ ok: true }));\n"
        "app.listen(port, () => console.log('listening on ' + port));\n"),
    "fastify": ("server.js",
        "const fastify = require('fastify')({ logger: true });\n"
        "const port = process.env.PORT || 8000;\n"
        "fastify.get('/', async () => ({ ok: true }));\n"
        "fastify.listen({ port, host: '0.0.0.0' });\n"),
    "fastapi": ("main.py",
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title='{name}')\n\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return {'app': '{name}', 'ok': True}\n"),
    "flask": ("app.py",
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/')\n"
        "def home():\n"
        "    return {'app': '{name}', 'ok': True}\n\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='0.0.0.0', port=int(__import__('os').environ.get('PORT', 8000)))\n"),
    "tornado": ("main.py",
        "import os\n"
        "from tornado.web import Application, RequestHandler\n\n"
        "class Main(RequestHandler):\n"
        "    def get(self):\n"
        "        self.write({'app': '{name}', 'ok': True})\n\n"
        "app = Application([(r'/', Main)])\n\n"
        "if __name__ == '__main__':\n"
        "    import tornado.ioloop\n"
        "    app.listen(int(os.environ.get('PORT', 8000)))\n"
        "    tornado.ioloop.IOLoop.current().start()\n"),
}

# Stub default per bahasa (bila framework tak punya stub & tak di-scaffold).
LANG_STUB = {
    "nodejs": ("server.js",
        "const http = require('http');\n"
        "const port = process.env.PORT || 8000;\n"
        "http.createServer((req, res) => {\n"
        "  res.writeHead(200, {'Content-Type': 'application/json'});\n"
        "  res.end(JSON.stringify({ app: '{name}', ok: true }));\n"
        "}).listen(port, '0.0.0.0');\n"),
    "php": ("public/index.php",
        "<?php header('Content-Type: application/json');\n"
        "echo json_encode(['app' => '{name}', 'ok' => true]);\n"),
}


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return s or "app"


class AppManager:
    def __init__(self, ex):
        self.ex = ex

    # ------------------------------------------------------------- port alloc
    async def alloc_port(self) -> int:
        used = {a["port"] for a in list_apps()}
        busy = set()
        if self.ex.mode in ("local", "wsl"):
            r = await self.ex.run("bash", "-c", "ss -tln | awk 'NR>1{print $4}' | sed 's/.*://' | sort -u")
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
        if not port:
            try:
                port = await self.alloc_port()
            except RuntimeError as e:
                return {"ok": False, "error": str(e)}
        if get_app_by_port(port):
            return {"ok": False, "error": f"port {port} sudah dipakai app lain"}
        if self.ex.mode in ("local", "wsl"):
            r = await self.ex.run("bash", "-c", f"ss -tln | grep ':{port} ' >/dev/null 2>&1 && echo busy || echo free")
            if "busy" in r.stdout:
                return {"ok": False, "error": f"port {port} sedang aktif dipakai OS"}

        home = f"{WEB_ROOT}/{slug}"
        os_user = f"weborn-{slug}"[:32]
        unit = f"weborn-{slug}.service"
        env_file = f"{home}/.env"

        start = (fw or {}).get("start") or lang["default"]["cmd"]
        command = start.replace("{port}", str(port))

        # Stub starter bila framework butuh file minimal.
        stub = None
        if fw and fw["id"] in STUBS:
            stub = STUBS[fw["id"]]
        elif not fw:
            stub = LANG_STUB.get(language)
        stub_cmd = ""
        if stub:
            fname, content = stub
            stub_cmd = (f"mkdir -p {home}/{lang['run_dir']} && "
                        f"cat > {home}/{fname} <<'WEBORN_EOF'\n{content.replace('{name}', name)}\nWEBORN_EOF")

        steps, failed = [], None
        if self.ex.mode in ("local", "wsl"):
            deps = (fw or {}).get("pkg")
            if deps and language == "python":
                # Debian 13 (PEP 668): pakai --break-system-packages
                deps = deps.replace("pip install",
                                    "python3 -m pip install --break-system-packages")
            steps += [
                ("mkdir", f"mkdir -p {home}/{lang['run_dir']}"),
                ("user", f"id {os_user} >/dev/null 2>&1 || useradd -r -M -d {home} -s /bin/false {os_user}"),
            ]
            if stub_cmd:
                steps.append(("stub", stub_cmd))
            if deps:
                steps.append(("deps", f"cd {home} && {deps}"))
            steps += [
                ("env", self._write_env(home, port)),
                ("unit", self._write_unit(unit, os_user, home, command)),
                ("chown", f"chown -R {os_user}:{os_user} {home}"),
                ("start", f"systemctl enable --now {unit}"),
            ]
            for step, cmd in steps:
                r = await self.ex.run("bash", "-c", cmd)
                if not r.ok and failed is None:
                    # deps (instal dependency) tidak mematikan pembuatan app
                    if step not in ("deps",):
                        failed = step
        else:  # dry-run: catat alur tanpa eksekusi
            steps = [
                ("mkdir", f"mkdir -p {home}/{lang['run_dir']}"),
                ("user", f"useradd -r -M -d {home} -s /bin/false {os_user}"),
                ("stub", stub_cmd or "starter ditulis"),
                ("env", f".env ditulis (PORT={port}, APP_DIR={home})"),
                ("unit", f"unit {unit} ditulis"),
                ("start", f"systemctl enable --now {unit}"),
            ]

        add_app({
            "name": name, "language": language, "framework": framework or "",
            "user": os_user, "home_dir": home, "port": port, "command": command,
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
    def _write_env(home: str, port: int) -> str:
        return (f"cat > {home}/.env <<'WEBORN_EOF'\n"
                f"PORT={port}\nAPP_DIR={home}\n"
                "WEBORN_EOF")

    @staticmethod
    def _write_unit(unit: str, os_user: str, home: str, command: str) -> str:
        return (f"cat > /etc/systemd/system/{unit} <<'WEBORN_EOF'\n"
                "[Unit]\nDescription=Weborn app\nAfter=network.target\n\n"
                "[Service]\n"
                f"User={os_user}\nGroup={os_user}\n"
                f"WorkingDirectory={home}\n"
                f"EnvironmentFile={home}/.env\n"
                f"ExecStart=/bin/bash -c 'cd {home} && {command}'\n"
                "Restart=on-failure\n\n"
                "[Install]\nWantedBy=multi-user.target\n"
                "WEBORN_EOF")

    # ---------------------------------------------------------------- actions
    async def control(self, app_id: int, action: str) -> dict:
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if action in ("start", "stop", "restart"):
            if self.ex.mode in ("local", "wsl"):
                r = await self.ex.systemctl(action, app["unit"])
                if r.ok:
                    set_app_status(app_id, "running" if action != "stop" else "stopped")
                return {"ok": r.ok, "output": r.output}
            set_app_status(app_id, "running" if action != "stop" else "stopped")
            return {"ok": True, "output": f"[dry-run] systemctl {action} {app['unit']}"}
        return {"ok": False, "error": "aksi tidak dikenal"}

    async def delete(self, app_id: int) -> dict:
        app = get_app(app_id)
        if not app:
            return {"ok": False, "error": "app tidak ditemukan"}
        if self.ex.mode in ("local", "wsl"):
            steps = [
                ("stop", f"systemctl disable --now {app['unit']} 2>/dev/null || true"),
                ("rmunit", f"rm -f /etc/systemd/system/{app['unit']}"),
                ("rmdir", f"rm -rf {app['home_dir']}"),
                ("rmuser", f"userdel {app['user']} 2>/dev/null || true"),
            ]
            for _, cmd in steps:
                await self.ex.run("bash", "-c", cmd)
        delete_app(app_id)
        return {"ok": True, "output": f"app {app['name']} dihapus"}

    def list(self) -> list[dict]:
        apps = list_apps()
        for a in apps:
            a["language_label"] = RUNTIMES.get(a["language"], {}).get("label", a["language"])
        return apps
