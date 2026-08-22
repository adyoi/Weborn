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
        """Write content to a file via sudo (needs root for system paths)."""
        import base64
        b64 = base64.b64encode(content.encode("utf-8")).decode()
        cmd = ("sudo", "-n", "-S", "bash", "-c",
               f"echo '{b64}' | base64 -d > {shlex.quote(path)}")
        cmdline = " ".join(shlex.quote(c) for c in cmd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=b"")
        result = ExecResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            cmd=cmdline,
        )
        self._audit(cmdline, result)
        return result

    def _audit(self, cmd: str, result: ExecResult):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        import re as _re
        sanitized = cmd
        # Redact password-bearing patterns before logging
        sanitized = _re.sub(
            r"(chpasswd\s+.*)",
            "[REDACTED chpasswd]",
            sanitized, count=1, flags=_re.IGNORECASE)
        sanitized = _re.sub(
            r"(password\s*=\s*).{6,}",
            r"\1[REDACTED]",
            sanitized, flags=_re.IGNORECASE)
        sanitized = _re.sub(
            r"(-p\s+)([^ ]{6,})",
            r"\1[REDACTED]",
            sanitized)
        line = f"[{datetime.now().isoformat()}] {sanitized} -> rc={result.returncode} ok={result.ok}"
        try:
            with open(LOG_DIR / "audit.log", "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


class LocalExecutor(Executor):
    """Menjalankan perintah langsung (linux production) dengan sudo."""

    COMMAND_TIMEOUT = 60  # seconds
    MAX_OUTPUT = 1024 * 1024  # 1MB

    def __init__(self, mode: str = "local"):
        super().__init__(mode)

    async def run(self, *cmd: str, timeout: int | None = None) -> ExecResult:
        # Prepend sudo untuk perintah yang butuh root
        privileged = {"apt-get", "apt", "systemctl", "ufw", "certbot",
                      "fail2ban-client", "freshclam", "clamscan", "useradd",
                      "userdel", "chpasswd", "chown", "ln", "nginx"}
        if cmd and cmd[0] in privileged:
            cmd = ("sudo", "-n", "-S", *cmd)  # -n = no password prompt, -S = read from stdin

        cmdline = " ".join(shlex.quote(c) for c in cmd)
        effective_timeout = timeout or self.COMMAND_TIMEOUT
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=b""),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return ExecResult(ok=False, returncode=-1, stdout="", stderr="timeout", cmd=cmdline)
            # Cap output size
            stdout_str = stdout.decode(errors="replace")[:self.MAX_OUTPUT]
            stderr_str = stderr.decode(errors="replace")[:self.MAX_OUTPUT]
        except Exception as e:
            return ExecResult(ok=False, returncode=-1, stdout="", stderr=str(e), cmd=cmdline)
        result = ExecResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout_str,
            stderr=stderr_str,
            cmd=cmdline,
        )
        # Detect sudo failure (password required but NOPASSWD not configured)
        if "password is required" in stderr_str.lower() or "a password is required" in stderr_str.lower():
            result = ExecResult(ok=False, returncode=proc.returncode,
                                stdout=stdout_str,
                                stderr="Sudo NOPASSWD belum dikonfigurasi. Jalankan: sudo visudo -f /etc/sudoers.d/weborn && tambahkan: admin ALL=(ALL) NOPASSWD: ALL",
                                cmd=cmdline)
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
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            self._audit(cmdline, ExecResult(ok=False, returncode=-1, stdout="", stderr="timeout"))
            return ExecResult(ok=False, returncode=-1, stdout="", stderr="timeout", cmd=cmdline)
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
