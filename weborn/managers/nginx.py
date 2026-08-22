"""Manajemen Nginx: status via AddonManager + generator konfigurasi situs.

Supports path-based multi-location routing (e.g. /api → Django, / → Express).
"""
import re
import shlex
from pathlib import Path

from ..config import CONFIG_DIR
from ..executors import get_executor

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$")


class NginxManager:
    def __init__(self, executor=None):
        self.executor = executor or get_executor()
        self.conf_dir = CONFIG_DIR / "nginx"
        self.conf_dir.mkdir(parents=True, exist_ok=True)

    def _addon(self):
        from ..addons import AddonManager
        return AddonManager(self.executor).get("nginx")

    async def status(self):
        from ..addons import AddonManager
        manager = AddonManager(self.executor)
        addon = manager.get("nginx")
        return await manager.status(addon)

    async def install(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).install(self._addon())

    async def start(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).action(self._addon(), "start")

    async def stop(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).action(self._addon(), "stop")

    async def restart(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).action(self._addon(), "restart")

    async def reload(self):
        return await self.executor.run("nginx", "-s", "reload")

    async def test(self):
        return await self.executor.run("nginx", "-t")

    def _write(self, name: str, content: str) -> Path:
        if not _DOMAIN_RE.fullmatch(name):
            raise ValueError(f"nama config tidak valid: {name}")
        path = self.conf_dir / f"{name}.conf"
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------------- deploy
    async def _deploy(self, name: str):
        """Tulis config ke /etc/nginx + symlink + test + reload."""
        if not _DOMAIN_RE.fullmatch(name):
            return
        if self.executor.mode not in ("local", "wsl"):
            return
        src = self.conf_dir / f"{name}.conf"
        if not src.exists():
            return
        ok = await self.executor.run("bash", "-c",
                                     "test -d /etc/nginx/sites-available && echo yes || echo no")
        if "yes" not in ok.stdout:
            return
        remote = f"/etc/nginx/sites-available/{name}.conf"
        await self.executor.write_file(remote, src.read_text(encoding="utf-8"))
        qname = shlex.quote(name)
        await self.executor.run("bash", "-c",
                                f"ln -sf {qname}.conf /etc/nginx/sites-enabled/{qname}.conf")
        r = await self.executor.run("nginx", "-t")
        if r.ok:
            await self.executor.run("nginx", "-s", "reload")
        else:
            await self.executor.run("bash", "-c",
                                    f"rm -f /etc/nginx/sites-enabled/{qname}.conf")

    async def _remove(self, name: str):
        if not _DOMAIN_RE.fullmatch(name):
            return
        if self.executor.mode not in ("local", "wsl"):
            return
        qname = shlex.quote(name)
        await self.executor.run("bash", "-c",
            f"rm -f /etc/nginx/sites-available/{qname}.conf /etc/nginx/sites-enabled/{qname}.conf; "
            f"nginx -s reload 2>/dev/null || true")

    def _build_location(self, loc: dict) -> list[str]:
        """Generate a single location block."""
        path = loc.get("path", "/")
        loc_type = loc.get("type", "static")
        target = loc.get("target", "")
        lines = [f"    location {path} {{"]
        if loc_type == "proxy":
            target = target.rstrip("/")
            lines += [
                f"        proxy_pass {target};",
                "        proxy_set_header Host $host;",
                "        proxy_set_header X-Real-IP $remote_addr;",
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                "        proxy_set_header X-Forwarded-Proto $scheme;",
                "        proxy_http_version 1.1;",
                "        proxy_set_header Upgrade $http_upgrade;",
                '        proxy_set_header Connection "upgrade";',
            ]
        elif loc_type == "static":
            lines.append(f"        alias {target};")
            lines.append("        try_files $uri $uri/ =404;")
        elif loc_type == "return":
            lines.append(f"        return {target};")
        lines.append("    }")
        return lines

    def build_site_conf(self, domain: str, root: str, proxy_target: str | None,
                        ssl: bool = False, locations: list[dict] | None = None,
                        ssl_redirect: bool = False, port: int = 0) -> str:
        locations = locations or []
        lines = [
            f"# Generated by Weborn - {domain}",
        ]

        listen_port = port if port else (443 if ssl else 80)

        # HTTP → HTTPS redirect server block
        if ssl and ssl_redirect:
            lines += [
                "server {",
                "    listen 80;",
                f"    server_name {domain};",
                f"    return 301 https://{domain}$request_uri;",
                "}",
                "",
            ]

        listen = f"{listen_port} ssl" if ssl else str(listen_port)
        lines += [
            "server {",
            f"    listen {listen};",
            f"    server_name {domain};",
        ]
        if ssl:
            lines += [
                f"    ssl_certificate     /etc/letsencrypt/live/{domain}/fullchain.pem;",
                f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    ssl_prefer_server_ciphers on;",
            ]

        if locations:
            # Has explicit locations: put them as sub-blocks
            if proxy_target:
                # Root location proxies; explicit locations override
                root_loc = {"path": "/", "type": "proxy", "target": proxy_target}
                explicit_paths = {l["path"].rstrip("/") for l in locations}
                if "/" not in explicit_paths:
                    lines += self._build_location(root_loc)
            else:
                lines += [
                    f"    root {root};",
                    "    index index.php index.html;",
                ]
            for loc in locations:
                lines += self._build_location(loc)
        else:
            # Default single location
            if proxy_target:
                lines += [
                    "    location / {",
                    f"        proxy_pass {proxy_target};",
                    "        proxy_set_header Host $host;",
                    "        proxy_set_header X-Real-IP $remote_addr;",
                    "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                    "        proxy_set_header X-Forwarded-Proto $scheme;",
                    "        proxy_http_version 1.1;",
                    "        proxy_set_header Upgrade $http_upgrade;",
                    '        proxy_set_header Connection "upgrade";',
                    "    }",
                ]
            else:
                lines += [
                    f"    root {root};",
                    "    index index.php index.html;",
                ]
        lines += ["}"]
        return "\n".join(lines)

    def apply_domain(self, domain: str, root: str, proxy_target: str | None = None,
                     ssl: bool = False, locations: list[dict] | None = None,
                     port: int = 0):
        conf = self.build_site_conf(domain, root, proxy_target, ssl, locations, port=port)
        return self._write(domain, conf)

    def apply_proxy(self, name: str, source: str, target: str, cache: bool = False):
        conf = [
            f"# Generated by Weborn - proxy {name}",
            "server {",
            f"    server_name {source};",
            "    location / {",
            f"        proxy_pass {target};",
            "        proxy_set_header Host $host;",
        ]
        if cache:
            conf += [
                "        proxy_cache weborn_cache;",
                "        proxy_cache_valid 200 60m;",
            ]
        conf += [
            "    }",
            "}",
        ]
        return self._write(name, "\n".join(conf))

    def list_configs(self):
        return sorted(p.name for p in self.conf_dir.glob("*.conf"))
