"""Sistem Addon terpadu Weborn.

Prinsip: SEMUA yang dikelola panel (nginx, caddy, mysql, dovecot, grafana,
wordpress, weborn-engine, plugin apapun) adalah sebuah ADDON yang punya satu
siklus hidup seragam:

    install -> config -> update -> run (start/stop/restart/status)

- Manifest addon dalam JSON (builtin di weborn/addons/builtin, 3rd party
  cukup di-drop ke data/addons/*.json).
- Semua operasi dieksekusi via Executor (local systemctl/apt/pip/git/docker
  di linux, atau dry-run di Windows/dev).
- Konfigurasi digenerate dari template Jinja2 (weborn/addons/templates).
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from fastapi.templating import Jinja2Templates

from ..config import ADDONS_DIR, BUILTIN_ADDONS_DIR, CONF_TEMPLATES_DIR, CONFIG_DIR
from ..db import get_setting, set_setting
from ..executors import get_executor

CONF_TEMPLATES = Jinja2Templates(directory=str(CONF_TEMPLATES_DIR))

# apt-get (terutama install AIDE: postinst hash seluruh filesystem) bisa
# berjalan beberapa menit — jauh melebihi COMMAND_TIMEOUT eksekutor (60s).
APT_TIMEOUT = 1800
# Tanpa DEBIAN_FRONTEND=noninteractive, debconf bisa menunggu input selamanya
# (karena panel tidak punya tty interaktif) → instalasi terlihat macet.
APT_ENV = {
    "DEBIAN_FRONTEND": "noninteractive",
    "PATH": os.environ.get("PATH",
                           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
}


@dataclass
class Addon:
    id: str
    name: str
    description: str = ""
    category: str = "other"          # web-server | database | mail | remote-access | runtime | monitoring | other
    type: str = "system"             # system | runtime | app | plugin | builtin
    packages: list = field(default_factory=list)     # paket apt/pip/npm
    systemd_unit: str | None = None
    bin: str | None = None
    version_args: list = field(default_factory=lambda: ["--version"])
    ports: list = field(default_factory=list)
    config: dict = field(default_factory=dict)       # {path, template}
    fields: list = field(default_factory=list)       # [{name,label,default}]
    repo: str | None = None                          # untuk type app: git url
    icon: str = "🛠️"
    source: str = "builtin"                          # builtin | user

    @property
    def unit(self) -> str:
        return self.systemd_unit or self.id

    def config_values(self) -> dict:
        try:
            raw = get_setting(f"addon:{self.id}", "{}")
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def save_config_values(self, values: dict):
        allowed = {f["name"]: values.get(f["name"], f.get("default", ""))
                   for f in self.fields}
        set_setting(f"addon:{self.id}", json.dumps(allowed))

    async def render_config(self) -> str:
        template_name = self.config.get("template")
        if not template_name:
            return ""
        template = CONF_TEMPLATES.get_template(template_name)
        return template.render(
            addon=self,
            values=self.config_values(),
            config_path=self.config.get("path", ""),
        )


class AddonManager:
    """Registri + operator addon. Semua op async via Executor."""

    def __init__(self, executor=None):
        self.executor = executor or get_executor()
        self._addons: dict[str, Addon] = {}
        self.load_builtin()
        self.load_user_addons()

    # ---------- loading ----------
    def load_builtin(self):
        for path in sorted(BUILTIN_ADDONS_DIR.glob("*.json")):
            self.register_manifest(path, source="builtin")

    def load_user_addons(self):
        ADDONS_DIR.mkdir(parents=True, exist_ok=True)
        for path in sorted(ADDONS_DIR.glob("*.json")):
            self.register_manifest(path, source="user")

    def register_manifest(self, path: Path, source: str = "user") -> Addon | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        addon = Addon(source=source, **data)
        self._addons[addon.id] = addon
        return addon

    def list_addons(self, category: str | None = None) -> list[Addon]:
        addons = list(self._addons.values())
        if category:
            addons = [a for a in addons if a.category == category]
        return sorted(addons, key=lambda a: (a.category, a.id))

    def categories(self) -> list[str]:
        return sorted({a.category for a in self._addons.values()})

    def get(self, addon_id: str) -> Addon | None:
        return self._addons.get(addon_id)

    # ---------- deteksi status ----------
    async def _binary_exists(self, addon: Addon) -> bool:
        if not addon.bin:
            return False
        result = await self.executor.run("which", addon.bin)
        return result.ok

    async def installed(self, addon: Addon) -> bool:
        if addon.type == "builtin":
            return True
        if addon.type == "plugin":
            # Plugin dijalankan via container — dicek dari keberadaan image,
            # bukan binary host (bin di dalam container, mis. grafana-server).
            return addon.packages and await self._image_present(addon.packages[0])
        if addon.type == "system":
            if not addon.bin:
                return False
            return await self._binary_exists(addon)
        if addon.bin:
            return await self._binary_exists(addon)
        return False

    async def _docker_ready(self) -> bool:
        return (await self.executor.run("which", "docker")).ok

    async def _image_present(self, img: str) -> bool:
        if not await self._docker_ready():
            return False
        return (await self.executor.run("docker", "image", "inspect", img)).ok

    async def _ensure_docker(self):
        """Pastikan Docker tersedia; kalau belum, install addon Docker dulu."""
        if await self._docker_ready():
            return
        docker_addon = self._addons.get("docker")
        if docker_addon is None:
            yield {"ok": False, "error": "Addon Docker tidak tersedia — plugin butuh Docker"}
            return
        yield {"ok": True, "step": "Docker belum terpasang — menginstall Docker dulu…"}
        async for s in self.install_steps(docker_addon):
            yield s
            if s.get("error") and not s.get("ok", True):
                return

    async def version(self, addon: Addon) -> str:
        if not addon.bin:
            return "—"
        result = await self.executor.run(addon.bin, *addon.version_args)
        out = result.stdout.strip() or result.stderr.strip()
        first = out.splitlines() or ["—"]
        return first[0][:64]

    async def status(self, addon: Addon) -> dict:
        """Kembalikan dict status: installed, active, state, version."""
        installed = await self.installed(addon)
        if not installed:
            return {"installed": False, "active": False, "state": "not-installed",
                    "version": "—"}
        active, state = False, "unknown"
        if addon.type in ("system", "app") and addon.systemd_unit:
            result = await self.executor.systemctl("is-active", addon.systemd_unit)
            active = result.ok
            state = result.stdout.strip() or "inactive"
        version = "—"
        if addon.type == "plugin" and addon.packages and await self._docker_ready():
            r = await self.executor.run("docker", "images", "--format",
                                        "{{.Repository}}:{{.Tag}}", addon.packages[0])
            parts = [ln for ln in r.stdout.strip().splitlines() if ln]
            version = parts[0] if parts else "—"
        else:
            version = await self.version(addon)
        return {"installed": True, "active": active, "state": state, "version": version}

    # ---------- lifecycle ----------
    def _commands_for(self, op: str, addon: Addon) -> list[tuple[str, list]]:
        """Daftar (label, cmd) untuk sebuah operasi — dipakai instalasi streaming."""
        cmds: list[tuple[str, list]] = []
        if op == "install":
            if addon.type == "system":
                if addon.packages:
                    cmds.append(("Menginstall paket: " + ", ".join(addon.packages),
                                 ["apt-get", "install", "-y", *addon.packages]))
                if addon.systemd_unit:
                    cmds.append((f"Mengaktifkan systemd unit {addon.systemd_unit}",
                                 ["systemctl", "enable", addon.systemd_unit]))
            elif addon.type == "runtime":
                if addon.packages:
                    cmds.append(("Menginstall runtime: " + ", ".join(addon.packages),
                                 ["apt-get", "install", "-y", *addon.packages]))
            elif addon.type == "app":
                if addon.repo:
                    cmds.append(("Clone repository", ["git", "clone", addon.repo]))
            elif addon.type == "plugin":
                if addon.packages:
                    cmds.append(("Pull image docker: " + ", ".join(addon.packages),
                                 ["docker", "pull", *addon.packages]))
        elif op == "update":
            if addon.type == "system":
                if addon.packages:
                    cmds.append(("Mengupdate paket: " + ", ".join(addon.packages),
                                 ["apt-get", "install", "-y", "--only-upgrade", *addon.packages]))
            elif addon.type == "app":
                cmds.append(("Git pull", ["git", "-C", ".", "pull"]))
            elif addon.type == "plugin":
                if addon.packages:
                    cmds.append(("Pull image docker: " + ", ".join(addon.packages),
                                 ["docker", "pull", *addon.packages]))
        elif op == "uninstall":
            if addon.type == "plugin" and addon.packages:
                cmds.append(("Menghapus image Docker: " + ", ".join(addon.packages),
                             ["docker", "rmi", *addon.packages]))
            elif addon.packages and addon.type != "builtin":
                cmds.append(("Menghapus paket: " + ", ".join(addon.packages),
                             ["apt-get", "remove", "-y", *addon.packages]))
        return cmds

    async def install_steps(self, addon: Addon):
        """Async generator: yield dict per-langkah {ok, step, output?, error?}."""
        if await self.installed(addon):
            yield {"ok": True, "step": f"{addon.name} sudah terpasang"}
            return
        if addon.type == "builtin":
            yield {"ok": True, "step": "Addon bawaan, selalu tersedia"}
            return
        if addon.type == "plugin":
            # Plugin dijalankan lewat container → pastikan Docker ada dulu.
            async for s in self._ensure_docker():
                yield s
                if s.get("error") and not s.get("ok", True):
                    return
            if not await self._docker_ready():
                yield {"ok": False, "error": "Docker tidak tersedia — install addon Docker dulu"}
                return
        installed_packages = False
        for label, cmd in self._commands_for("install", addon):
            yield {"ok": True, "step": f"{label} — sedang berjalan…"}
            result = await self._exec(cmd)
            if cmd[0:2] == ["apt-get", "install"]:
                installed_packages = True
            yield {"ok": result.ok, "step": label, "output": result.output}
            if not result.ok:
                if installed_packages and addon.type == "system":
                    yield {"ok": True, "step": "Rollback: menghapus paket yang gagal install...",
                           "output": "(partial install)"}
                    await self._exec(("apt-get", "remove", "-y", *addon.packages))
                yield {"ok": False, "error": result.output}
                return
        conf_path = addon.config.get("path")
        if conf_path and installed_packages and self.executor.mode in ("local", "wsl"):
            r = await self.executor.run("bash", "-c", f"test -f {conf_path} && echo yes || echo no")
            if "no" in (r.stdout or ""):
                yield {"ok": True, "step": f"Restoring config {conf_path}"}
                await self._exec(("apt-get", "install", "--reinstall", "-y", *addon.packages))
        yield {"ok": True, "step": "Instalasi selesai ✓"}

    async def _exec(self, cmd):
        """Jalankan perintah addon; apt pakai env noninteractive + timeout besar."""
        kwargs = {}
        if tuple(cmd[:1]) == ("apt-get",):
            kwargs = {"timeout": APT_TIMEOUT, "env": APT_ENV}
        return await self.executor.run(*cmd, **kwargs)

    async def update_steps(self, addon: Addon):
        if addon.type == "builtin":
            yield {"ok": True, "step": "Addon bawaan tidak perlu diupdate"}
            return
        for label, cmd in self._commands_for("update", addon):
            yield {"ok": True, "step": f"{label} — sedang berjalan…"}
            result = await self._exec(cmd)
            yield {"ok": result.ok, "step": label, "output": result.output}
            if not result.ok:
                yield {"ok": False, "error": result.output}
                return
        yield {"ok": True, "step": "Update selesai ✓"}

    async def uninstall_steps(self, addon: Addon):
        if addon.type == "builtin":
            yield {"ok": True, "step": "Addon bawaan tidak bisa di-uninstall"}
            return
        if addon.type in ("system", "app") and addon.systemd_unit:
            result = await self.executor.systemctl("stop", addon.unit)
            yield {"ok": True, "step": f"Stop {addon.unit}", "output": result.output}
            result = await self.executor.systemctl("disable", addon.unit)
            yield {"ok": True, "step": f"Disable {addon.unit}", "output": result.output}
        for label, cmd in self._commands_for("uninstall", addon):
            yield {"ok": True, "step": f"{label} — sedang berjalan…"}
            result = await self._exec(cmd)
            yield {"ok": result.ok, "step": label, "output": result.output}
            if not result.ok:
                yield {"ok": False, "error": result.output}
                return
        conf_path = addon.config.get("path")
        if conf_path and addon.type not in ("system",) and self.executor.mode in ("local", "wsl"):
            result = await self.executor.run("bash", "-c",
                                             f"test -f {conf_path} && sudo rm -f {conf_path} && echo removed || echo skip")
            yield {"ok": True, "step": f"Hapus config {conf_path}", "output": result.output}
        if addon.systemd_unit and self.executor.mode in ("local", "wsl"):
            unit_file = f"/etc/systemd/system/{addon.unit}.service"
            result = await self.executor.run("bash", "-c",
                                             f"test -f {unit_file} && sudo rm -f {unit_file} && sudo systemctl daemon-reload && echo removed || echo skip")
            yield {"ok": True, "step": f"Hapus unit file {addon.unit}", "output": result.output}
        if addon.type in ("system", "app") and addon.packages and self.executor.mode in ("local", "wsl"):
            result = await self._exec(("apt-get", "autoremove", "-y"))
            yield {"ok": result.ok, "step": "Autoremove unused packages", "output": result.output}
        yield {"ok": True, "step": "Penghapusan selesai ✓"}

    async def install(self, addon: Addon) -> dict:
        return await self._run_collect(self.install_steps(addon))

    async def update(self, addon: Addon) -> dict:
        return await self._run_collect(self.update_steps(addon))

    async def uninstall(self, addon: Addon) -> dict:
        return await self._run_collect(self.uninstall_steps(addon))

    async def _run_collect(self, gen) -> dict:
        output = []
        ok = True
        async for step in gen:
            line = step.get("step", "")
            if step.get("output"):
                line += "\n" + step["output"]
            output.append(line)
            if not step.get("ok", True):
                ok = False
        return {"ok": ok, "output": "\n".join(output) or "(tidak ada langkah)"}

    # ---------- runtime control ----------
    async def action(self, addon: Addon, action: str) -> dict:
        if action not in ("start", "stop", "restart", "enable", "disable"):
            return {"ok": False, "error": f"aksi tidak dikenal: {action}"}
        if addon.type == "builtin":
            return {"ok": True, "output": "Addon bawaan tidak punya systemd unit"}
        result = await self.executor.systemctl(action, addon.unit)
        return {"ok": result.ok, "output": result.output}

    # ---------- konfigurasi ----------
    async def apply_config(self, addon: Addon, values: dict) -> dict:
        addon.save_config_values(values)
        content = await addon.render_config()
        if not content:
            return {"ok": True, "output": "Addon ini tidak punya template konfigurasi"}

        target = CONFIG_DIR / addon.id
        target.mkdir(parents=True, exist_ok=True)
        local = target / "current.conf"
        local.write_text(content, encoding="utf-8")

        result = {"ok": True, "output": f"Konfigurasi digenerate:\n{content}"}
        if self.executor.mode in ("local", "wsl"):
            conf_path = addon.config.get("path")
            if conf_path:
                copy = await self.executor.run("install", "-m", "640", "-o", "root", "-g", "root",
                                               str(local), conf_path)
                result["output"] += f"\n\nDitulis ke {conf_path}: rc={copy.returncode}"
                if not copy.ok:
                    return {"ok": False, "output": result["output"]}
            if addon.systemd_unit:
                reload = await self.executor.systemctl("reload", addon.unit)
                result["output"] += f"\nReload {addon.unit}: rc={reload.returncode}"
        return result


def get_addon_manager() -> AddonManager:
    return AddonManager(get_executor())
