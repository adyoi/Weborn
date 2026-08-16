"""Abstraksi eksekusi perintah untuk semua fitur panel.

Semua perintah OS (systemctl, nginx, iptables, dovecot, dst.) WAJIB lewat
executor ini, bukan dieksekusi langsung — supaya bisa:
  - di-allow-list / disanitasi,
  - di-audit log,
  - di-dry-run di environment dev (Windows) tanpa perlu linux.
"""
import asyncio
import os
import shlex
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..config import LOG_DIR


@dataclass
class ExecResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str = ""
    cmd: str = ""

    @property
    def output(self):
        return (self.stdout + "\n" + self.stderr).strip()


class Executor:
    """Base executor. Implementasi subclass harus async (non-blocking)."""

    def __init__(self, mode: str = "local"):
        self.mode = mode

    async def run(self, *cmd: str) -> ExecResult:
        raise NotImplementedError

    async def systemctl(self, action: str, service: str) -> ExecResult:
        return await self.run("systemctl", action, service)

    async def read_file(self, path: str) -> ExecResult:
        return await self.run("cat", path)

    async def write_file(self, path: str, content: str) -> ExecResult:
        script = f"cat > {shlex.quote(path)} <<'WEBORN_EOF'\n{content}\nWEBORN_EOF"
        return await self.run("sh", "-c", script)

    def _audit(self, cmd: str, result: ExecResult):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        line = f"[{datetime.now().isoformat()}] {cmd} -> rc={result.returncode} ok={result.ok}"
        try:
            with open(LOG_DIR / "audit.log", "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


class LocalExecutor(Executor):
    """Menjalankan perintah langsung (linux production)."""

    def __init__(self, mode: str = "local"):
        super().__init__(mode)

    async def run(self, *cmd: str) -> ExecResult:
        cmdline = " ".join(shlex.quote(c) for c in cmd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result = ExecResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            cmd=cmdline,
        )
        self._audit(cmdline, result)
        return result


class DryRunExecutor(Executor):
    """Simulasi: perintah dicatat, tidak benar-benar dijalankan (dev/Windows)."""

    def __init__(self, mode: str = "dry-run"):
        super().__init__(mode)

    async def run(self, *cmd: str) -> ExecResult:
        cmdline = " ".join(cmd)
        result = ExecResult(ok=True, returncode=0, cmd=cmdline, stdout=f"[dry-run] {cmdline}")
        self._audit(cmdline, result)
        return result


class WSLExecutor(Executor):
    """Jalankan perintah DI DALAM distro WSL (mis. Debian).

    Mode: "wsl". Semua command dieksekusi via `wsl.exe -d <distro>`.
    Path Windows (D:\\...) otomatis diterjemahkan ke /mnt/d/....
    Operasi yang butuh root memakai `-u root`.
    """

    def __init__(self, distro: str | None = None, root: bool = True):
        super().__init__("wsl")
        self.distro = distro or os.environ.get("WEBORN_WSL_DISTRO", "Debian")
        self.root = root

    def _wslpath(self, p: str) -> str:
        if isinstance(p, Path):
            p = str(p)
        if os.name == "nt" and ":" in p and p[1] == ":":
            drive = p[0].lower()
            rest = p[2:].replace("\\", "/")
            return f"/mnt/{drive}{rest}"
        return p

    async def run(self, *cmd: str, root: bool = False) -> ExecResult:
        argv = ["wsl", "-d", self.distro]
        if root or self.root:
            argv += ["-u", "root"]
        argv += ["--exec"] + [self._wslpath(c) for c in cmd]
        cmdline = " ".join(shlex.quote(c) for c in argv)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result = ExecResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            cmd=cmdline,
        )
        self._audit(cmdline, result)
        return result

    async def systemctl(self, action: str, service: str) -> ExecResult:
        return await self.run("systemctl", action, service)


def get_executor(mode: str | None = None):
    from ..config import EXECUTOR_MODE

    mode = mode or EXECUTOR_MODE
    if mode == "local":
        return LocalExecutor(mode)
    if mode == "wsl":
        return WSLExecutor()
    return DryRunExecutor(mode)
