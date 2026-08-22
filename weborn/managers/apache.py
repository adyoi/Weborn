"""Manajemen Apache: status via AddonManager + generator VirtualHost."""
import re
import shlex
from pathlib import Path

from ..config import CONFIG_DIR
from ..executors import get_executor


async def _is_port_used(executor, port: int) -> bool:
    r = await executor.run("bash", "-c",
                           f"ss -tlnp 'sport = :{port}' 2>/dev/null | grep -q :{port} && echo yes || echo no")
    return "yes" in (r.stdout or "")


async def _find_free_port(executor, start: int, step: int = 2) -> int:
    port = start
    while await _is_port_used(executor, port):
        port += step
    return port

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$")


class ApacheManager:
    def __init__(self, executor=None):
        self.executor = executor or get_executor()
        self.conf_dir = CONFIG_DIR / "apache"
        self.conf_dir.mkdir(parents=True, exist_ok=True)

    def _addon(self):
        from ..addons import AddonManager
        return AddonManager(self.executor).get("apache")

    async def status(self):
        from ..addons import AddonManager
        manager = AddonManager(self.executor)
        addon = manager.get("apache")
        return await manager.status(addon)

    async def install(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).install(self._addon())

    async def start(self):
        from ..addons import AddonManager
        manager = AddonManager(self.executor)
        addon = self._addon()
        st = await manager.status(addon)
        if not st.get("installed"):
            if self.executor.mode in ("local", "wsl"):
                await self._resolve_ports()
            await manager.install(addon)
        elif self.executor.mode in ("local", "wsl"):
            await self._resolve_ports()
        return await manager.action(addon, "start")

    async def _resolve_ports(self):
        free_http = await _find_free_port(self.executor, 80)
        free_https = await _find_free_port(self.executor, 443)
        ports_conf = "/etc/apache2/ports.conf"
        content = (
            f"Listen {free_http}\n"
            f"<IfModule ssl_module>\n"
            f"    Listen {free_https}\n"
            f"</IfModule>\n"
        )
        await self.executor.write_file(ports_conf, content)
        if free_http != 80:
            await self.executor.run("bash", "-c",
                f"echo 'Port {free_http} (80 occupied)'")
        if free_https != 443:
            await self.executor.run("bash", "-c",
                f"echo 'Port {free_https} (443 occupied)'")

    async def stop(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).action(self._addon(), "stop")

    async def restart(self):
        from ..addons import AddonManager
        return await AddonManager(self.executor).action(self._addon(), "restart")

    async def reload(self):
        return await self.executor.run("systemctl", "reload", "apache2")

    async def test(self):
        return await self.executor.run("bash", "-c", "sudo apache2ctl configtest")

    def _write(self, name: str, content: str) -> Path:
        if not _DOMAIN_RE.fullmatch(name):
            raise ValueError(f"nama config tidak valid: {name}")
        path = self.conf_dir / f"{name}.conf"
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------------- deploy
    async def _deploy(self, name: str):
        """Tulis config ke /etc/apache2 + symlink + test + reload."""
        if not _DOMAIN_RE.fullmatch(name):
            return
        if self.executor.mode not in ("local", "wsl"):
            return
        src = self.conf_dir / f"{name}.conf"
        if not src.exists():
            return
        ok = await self.executor.run("bash", "-c",
                                     "test -d /etc/apache2/sites-available && echo yes || echo no")
        if "yes" not in ok.stdout:
            return
        remote = f"/etc/apache2/sites-available/{name}.conf"
        await self.executor.write_file(remote, src.read_text(encoding="utf-8"))
        qname = shlex.quote(name)
        await self.executor.run("bash", "-c",
                                f"sudo a2ensite {qname}.conf 2>/dev/null")
        r = await self.executor.run("bash", "-c", "sudo apache2ctl configtest")
        if r.ok:
            await self.executor.run("systemctl", "reload", "apache2")
        else:
            await self.executor.run("bash", "-c",
                                    f"sudo a2dissite {qname}.conf 2>/dev/null")

    async def _remove(self, name: str):
        if not _DOMAIN_RE.fullmatch(name):
            return
        if self.executor.mode not in ("local", "wsl"):
            return
        qname = shlex.quote(name)
        await self.executor.run("bash", "-c",
            f"sudo a2dissite {qname}.conf 2>/dev/null; "
            f"sudo rm -f /etc/apache2/sites-available/{qname}.conf; "
            f"sudo systemctl reload apache2 2>/dev/null || true")

    def build_vhost(self, domain: str, root: str, proxy_target: str | None = None,
                    ssl: bool = False, server_alias: str = "",
                    server_tokens: str = "Prod", port: int = 0) -> str:
        listen_port = port if port else 80
        lines = [
            f"# Generated by Weborn - Apache VirtualHost for {domain}",
            "",
        ]

        if ssl:
            lines += [
                f"<VirtualHost *:{listen_port}>",
                f"    ServerName {domain}",
                f"    Redirect permanent / https://{domain}/",
                "</VirtualHost>",
                "",
                "<VirtualHost *:443>",
            ]
        else:
            lines += [
                f"<VirtualHost *:{listen_port}>",
            ]

        lines += [
            f"    ServerName {domain}",
        ]
        if server_alias:
            lines.append(f"    ServerAlias {server_alias}")
        lines += [
            f"    ServerTokens {server_tokens}",
            "",
            f"    DocumentRoot {root}",
            "",
            "    <Directory />",
            "        Options FollowSymLinks",
            "        AllowOverride All",
            "        Require all denied",
            "    </Directory>",
            f"    <Directory {root}>",
            "        Options -Indexes +FollowSymLinks +MultiViews",
            "        AllowOverride All",
            "        Require all granted",
            "    </Directory>",
        ]

        if ssl:
            lines += [
                "",
                "    SSLEngine on",
                f"    SSLCertificateFile    /etc/letsencrypt/live/{domain}/fullchain.pem",
                f"    SSLCertificateKeyFile /etc/letsencrypt/live/{domain}/privkey.pem",
            ]

        if proxy_target:
            proxy_target = proxy_target.rstrip("/")
            lines += [
                "",
                "    # Reverse proxy",
                "    ProxyPreserveHost On",
                f"    ProxyPass / {proxy_target}/",
                f"    ProxyPassReverse / {proxy_target}/",
                "",
                "    # WebSocket support",
                "    RewriteEngine On",
                "    RewriteCond %{HTTP:Upgrade} =websocket [NC]",
                "    RewriteRule /(.*) ws://127.0.0.1:{port}/$1 [P,L]",
            ]
            # Extract port from proxy_target
            m = re.search(r":(\d+)$", proxy_target)
            if m:
                lines[-1] = f"    RewriteRule /(.*) ws://127.0.0.1:{m.group(1)}/$1 [P,L]"
        else:
            lines += [
                "",
                "    # PHP-FPM",
                r"    <FilesMatch \.php$>",
                "        SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"",
                "    </FilesMatch>",
            ]

        lines += [
            "",
            "    ErrorLog ${APACHE_LOG_DIR}/" + domain + "_error.log",
            "    CustomLog ${APACHE_LOG_DIR}/" + domain + "_access.log combined",
            "",
            "</VirtualHost>",
        ]

        return "\n".join(lines)

    def apply_domain(self, domain: str, root: str, proxy_target: str | None = None,
                     ssl: bool = False, server_alias: str = "", port: int = 0):
        conf = self.build_vhost(domain, root, proxy_target, ssl, server_alias, port=port)
        return self._write(domain, conf)

    def list_configs(self):
        return sorted(p.name for p in self.conf_dir.glob("*.conf"))
