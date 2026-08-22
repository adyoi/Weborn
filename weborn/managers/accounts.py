"""Manajemen Akun Sistem Operasi (OS users).

Akun ini disamakan levelnya dengan privilege OS server, sehingga langsung
bisa dipakai untuk SSH, FTP, Telnet, dll.

Tingkat privilege:
  - root    : UID 0
  - admin   : anggota group sudo/wheel (hak sudo penuh)
  - user    : akun reguler biasa
  - service : akun sistem (www-data, dll) - shell nologin

Default yang dijamin ada (bootstrap): `admin` (hak root) dan `www-data`.
"""
import os
import re
import shlex

from ..executors import get_executor

PRIVILEGE_LEVELS = ["root", "admin", "user", "service"]
SERVICE_GROUPS = {  # layanan -> group OS yang dipakai untuk mengizinkan akses
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
}
SUDO_GROUPS = ("sudo", "wheel")


class Account:
    def __init__(self, username: str, uid: str, gid: str, home: str,
                 shell: str, groups: list, locked: bool = False):
        self.username = username
        self.uid = int(uid or -1)
        self.gid = int(gid or -1)
        self.home = home
        self.shell = shell
        self.groups = groups or []
        self.locked = locked

    @property
    def privilege(self) -> str:
        if self.uid == 0:
            return "root"
        if any(g in SUDO_GROUPS for g in self.groups):
            return "admin"
        if self.uid < 1000 and self.shell == "/usr/sbin/nologin":
            return "service"
        return "user"

    @property
    def services(self) -> list:
        return [s for s, g in SERVICE_GROUPS.items() if g in self.groups]


class AccountManager:
    def __init__(self, executor=None):
        self.executor = executor or get_executor()

    # ---------- membaca daftar akun ----------
    def _read_local_users(self) -> list[dict]:
        """Baca langsung /etc/passwd + /etc/group (posix) atau pengguna lokal (win)."""
        if os.name == "posix":
            try:
                import pwd
                import grp
                group_map = {g.gr_gid: g.gr_name for g in grp.getgrall()}
                users = []
                for p in pwd.getpwall():
                    groups = [g.gr_name for g in grp.getgrall() if p.pw_name in g.gr_mem]
                    if p.pw_gid in group_map:
                        groups.append(group_map[p.pw_gid])
                    locked = p.pw_passwd in ("*", "!", "!!", "x")
                    users.append({
                        "username": p.pw_name, "uid": p.pw_uid, "gid": p.pw_gid,
                        "home": p.pw_dir, "shell": p.pw_shell, "groups": groups,
                        "locked": locked,
                    })
                return users
            except Exception:
                return []
        username = os.getenv("USERNAME") or os.getenv("USER") or "admin"
        return [{
            "username": username, "uid": 1000, "gid": 1000,
            "home": os.path.expanduser("~"), "shell": "demo",
            "groups": ["sudo", "users"], "locked": False,
        }]

    async def list_users(self) -> list[Account]:
        if self.executor.mode in ("local", "wsl"):
            result = await self.executor.run("getent", "passwd")
            passwd_lines = result.stdout.strip().splitlines()
            result2 = await self.executor.run("getent", "group")
            raw = result2.stdout.strip().splitlines()
            # parse sederhana
            accounts = []
            for line in passwd_lines:
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                name, _, uid, gid, _, home, shell = parts[:7]
                groups = []
                for gl in raw:
                    gp = gl.split(":")
                    if len(gp) >= 4 and name in gp[3].split(","):
                        groups.append(gp[0])
                locked = parts[1] in ("*", "!", "!!", "x")
                accounts.append(Account(name, uid, gid, home, shell, groups, locked))
            return accounts
        return [Account(**u) for u in self._read_local_users()]

    def find(self, username: str) -> Account | None:
        if self.executor.mode in ("local", "wsl"):
            return None  # baca via executor
        for u in self._read_local_users():
            if u["username"] == username:
                return Account(**u)
        return None

    # ---------- lifecycle akun ----------
    async def create(self, username: str, password: str, privilege: str = "user",
                     services: list | None = None, shell: str = "/bin/bash") -> dict:
        services = services or []
        if not re.match(r"^[a-z_][a-z0-9_-]{2,31}$", username):
            return {"ok": False, "error": "username tidak valid"}
        if privilege not in PRIVILEGE_LEVELS:
            return {"ok": False, "error": "level privilege tidak dikenal"}
        if self.executor.mode in ("local", "wsl"):
            groups = set(SERVICE_GROUPS[s] for s in services if s in SERVICE_GROUPS)
            if privilege == "admin":
                groups.add("sudo")
            if privilege == "service":
                shell = "/usr/sbin/nologin"
            cmds = [
                ["useradd", "-m", "-s", shell,
                 *(f"-G{','.join(sorted(groups))}" if groups else ()),
                 username],
                ["bash", "-c",
                 f"echo {shlex.quote(username + ':' + password)} | chpasswd"],
            ]
            output = []
            for cmd in cmds:
                r = await self.executor.run(*cmd)
                output.append(f"$ {' '.join(cmd)}\n{r.output}")
                if not r.ok:
                    return {"ok": False, "output": "\n".join(output)}
            return {"ok": True, "output": "\n".join(output)}
        return {"ok": True, "output": f"(dry-run) useradd {username} + chpasswd + group {services}"}

    async def delete(self, username: str) -> dict:
        if username in ("root", "admin"):
            return {"ok": False, "error": "akun inti tidak boleh dihapus"}
        if self.executor.mode in ("local", "wsl"):
            r = await self.executor.run("userdel", "-r", username)
            return {"ok": r.ok, "output": r.output}
        return {"ok": True, "output": f"(dry-run) userdel -r {username}"}

    async def set_password(self, username: str, password: str) -> dict:
        if self.executor.mode in ("local", "wsl"):
            r = await self.executor.run("bash", "-c",
                                        f"echo {shlex.quote(username + ':' + password)} | chpasswd")
            return {"ok": r.ok, "output": r.output}
        return {"ok": True, "output": f"(dry-run) chpasswd {username}"}

    async def set_locked(self, username: str, locked: bool) -> dict:
        flag = "-L" if locked else "-U"
        if self.executor.mode in ("local", "wsl"):
            r = await self.executor.run("usermod", flag, username)
            return {"ok": r.ok, "output": r.output}
        return {"ok": True, "output": f"(dry-run) usermod {flag} {username}"}

    async def set_privilege(self, username: str, level: str) -> dict:
        if level not in PRIVILEGE_LEVELS:
            return {"ok": False, "error": "level tidak dikenal"}
        if self.executor.mode in ("local", "wsl"):
            cmds = []
            for g in SUDO_GROUPS:  # hapus dari sudo/wheel dulu
                cmds.append(["gpasswd", "-d", username, g])
            if level == "admin":
                cmds.append(["usermod", "-aG", ",".join(SUDO_GROUPS), username])
            if level == "service":
                cmds.append(["usermod", "-s", "/usr/sbin/nologin", username])
            output = []
            for cmd in cmds:
                r = await self.executor.run(*cmd)
                output.append(f"$ {' '.join(cmd)}\n{r.output}")
            return {"ok": True, "output": "\n".join(output)}
        return {"ok": True, "output": f"(dry-run) set privilege {username} -> {level}"}

    async def set_services(self, username: str, services: list) -> dict:
        if self.executor.mode in ("local", "wsl"):
            groups = ",".join(SERVICE_GROUPS[s] for s in services if s in SERVICE_GROUPS)
            r = await self.executor.run("usermod", "-aG", groups, username)
            return {"ok": r.ok, "output": r.output}
        return {"ok": True, "output": f"(dry-run) usermod -aG {services} {username}"}

    # ---------- default accounts ----------
    async def bootstrap(self) -> dict:
        """Cek apakah www-data ada (untuk service web). Admin dibuat via setup wizard."""
        results = []
        www = self.find("www-data")
        if www is None:
            # Buat www-data tanpa password (service account, nologin)
            if self.executor.mode in ("local", "wsl"):
                r = await self.executor.run("useradd", "-r", "-s", "/usr/sbin/nologin", "www-data")
                results.append({"ok": r.ok, "output": r.output})
        return {"ok": all(r.get("ok", True) for r in results),
                "output": "\n".join(r.get("output", r.get("error", "")) for r in results)}


def get_account_manager() -> AccountManager:
    return AccountManager(get_executor())
