"""Email management: Postfix + Dovecot + Rspamd + OpenDKIM + Roundcube stack."""
import json
import secrets
import shlex
import socket
import string
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..config import CONF_TEMPLATES_DIR, CONFIG_DIR
from ..db import get_conn
from ..executors import get_executor
from ..ui import render

router = APIRouter()

MAIL_STACK = {
    "postfix": {"pkg": "postfix", "unit": "postfix", "bin": "postfix"},
    "dovecot": {"pkg": "dovecot-core dovecot-imapd dovecot-pop3d", "unit": "dovecot", "bin": "dovecot"},
    "rspamd": {"pkg": "rspamd", "unit": "rspamd", "bin": "rspamd"},
    "opendkim": {"pkg": "opendkim opendkim-tools", "unit": "opendkim", "bin": "opendkim"},
    "roundcube": {"pkg": "roundcube-core roundcube-mysql roundcube-plugins", "unit": "roundcube", "bin": "roundcube"},
    "spamc": {"pkg": "spamassassin spamc", "unit": "spamassassin", "bin": "spamassassin"},
}

MAIL_DOMAINS_CACHE: dict = {}


def _mail_domains():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name FROM domains WHERE kind='domain' ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def _get_server_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _random_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _render_template(name: str, context: dict) -> str:
    tpl = CONF_TEMPLATES_DIR / name
    if not tpl.exists():
        return ""
    content = tpl.read_text(encoding="utf-8")
    for key, val in context.items():
        content = content.replace("{{ " + key + " }}", str(val))
    return content


async def _check_mail_stack():
    ex = get_executor()
    status = {}
    for svc, info in MAIL_STACK.items():
        installed = False
        active = False
        if ex.mode in ("local", "wsl"):
            r = await ex.run("bash", "-c", f"command -v {info['bin']} && echo yes || echo no")
            installed = "yes" in r.stdout
            if installed and info["unit"]:
                r2 = await ex.run("bash", "-c", f"systemctl is-active {info['unit']} 2>/dev/null || echo inactive")
                active = r2.stdout.strip() == "active"
        status[svc] = {"installed": installed, "active": active}
    return status


def _get_mail_dns(domain: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM dns_records WHERE name = ? OR name LIKE ? ORDER BY type",
            (domain, f"%{domain}%")
        ).fetchall()
    return [dict(r) for r in rows]


# ────────────────────────────────── Main Page ─────────────────────────────────

@router.get("/email", response_class=HTMLResponse)
async def email_setup_page(request: Request, msg: str = "",
                           user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    stack_status = await _check_mail_stack()
    all_installed = all(s["installed"] for s in stack_status.values())
    all_active = all(s["active"] for s in stack_status.values())
    domains = _mail_domains()
    return render(request, "email.html", {
        "user": user, "msg": msg, "stack": stack_status,
        "all_installed": all_installed, "all_active": all_active,
        "domains": domains, "active": "email",
    })


# ────────────────────────────────── Setup Wizard ──────────────────────────────

@router.post("/email/setup")
async def email_setup_wizard(domain: str = Form(...),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    domain = domain.strip().lower()
    server_ip = _get_server_ip()

    if ex.mode in ("local", "wsl"):
        # ── Step 1: Install packages ──
        pkgs = " ".join(info["pkg"] for info in MAIL_STACK.values())
        await ex.run("bash", "-c", f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}")

        # ── Step 2: Set hostname ──
        qdomain = shlex.quote(f"mail.{domain}")
        await ex.run("bash", "-c", f"echo {qdomain} > /etc/hostname")
        await ex.run("bash", "-c", f"hostname {qdomain}")

        # ── Step 3: Create SSL cert (self-signed if no certbot) ──
        ssl_dir = f"/etc/ssl/mail.{domain}"
        qssl_dir = shlex.quote(ssl_dir)
        qdomain_cn = shlex.quote(f"mail.{domain}")
        await ex.run("bash", "-c",
                     f"sudo mkdir -p {qssl_dir} && "
                     f"sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
                     f"-keyout {qssl_dir}/privkey.pem "
                     f"-out {qssl_dir}/fullchain.pem "
                     f'-subj "/CN={qdomain_cn}" 2>/dev/null')

        # ── Step 4: Configure Postfix ──
        ctx = {"domain": domain, "generated_at": datetime.now().isoformat()}
        postfix_cf = _render_template("postfix-main.cf.j2", ctx)
        if postfix_cf:
            # Fix TLS path for self-signed
            postfix_cf = postfix_cf.replace(
                f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                f"{ssl_dir}/fullchain.pem"
            )
            postfix_cf = postfix_cf.replace(
                f"/etc/letsencrypt/live/{domain}/privkey.pem",
                f"{ssl_dir}/privkey.pem"
            )
            await ex.write_file("/etc/postfix/main.cf", postfix_cf)
        await ex.run("bash", "-c", f"sed -i 's/^smtp      inet  n       -       n       -       -       smtpd/smtp      inet  n       -       -       -       -       smtpd/' /etc/postfix/master.cf 2>/dev/null || true")

        # ── Step 5: Configure Dovecot ──
        dovecot_mail = _render_template("dovecot-10-mail.conf.j2", {})
        dovecot_auth = _render_template("dovecot-10-auth.conf.j2", ctx)
        dovecot_ssl = _render_template("dovecot-10-ssl.conf.j2", ctx)
        if dovecot_ssl:
            dovecot_ssl = dovecot_ssl.replace(
                f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                f"{ssl_dir}/fullchain.pem"
            ).replace(
                f"/etc/letsencrypt/live/{domain}/privkey.pem",
                f"{ssl_dir}/privkey.pem"
            )
        if dovecot_auth:
            dovecot_auth = dovecot_auth.replace(
                f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                f"{ssl_dir}/fullchain.pem"
            ).replace(
                f"/etc/letsencrypt/live/{domain}/privkey.pem",
                f"{ssl_dir}/privkey.pem"
            )
        if dovecot_mail:
            await ex.write_file("/etc/dovecot/conf.d/10-mail.conf", dovecot_mail)
        if dovecot_auth:
            await ex.write_file("/etc/dovecot/conf.d/10-auth.conf", dovecot_auth)
        if dovecot_ssl:
            await ex.write_file("/etc/dovecot/conf.d/10-ssl.conf", dovecot_ssl)

        # ── Step 6: Configure OpenDKIM ──
        await ex.run("bash", "-c", "sudo mkdir -p /etc/opendkim /var/lib/opendkim/keys /var/spool/postfix/opendkim")
        dkim_key_dir = f"/var/lib/opendkim/keys"
        await ex.run("bash", "-c",
                     f"sudo opendkim-genkey -D {dkim_key_dir} -d {domain} -s weborn -b 2048 2>/dev/null || true")
        await ex.run("bash", "-c", f"sudo chown -R opendkim:opendkim {dkim_key_dir} 2>/dev/null || true")

        dkim_trusted = _render_template("opendkim-TrustedHosts.j2", ctx)
        dkim_keytable = _render_template("opendkim-KeyTable.j2", ctx)
        dkim_sigtable = _render_template("opendkim-SigningTable.j2", ctx)
        dkim_conf = _render_template("opendkim.conf.j2", ctx)
        if dkim_trusted:
            await ex.write_file("/etc/opendkim/TrustedHosts", dkim_trusted)
        if dkim_keytable:
            await ex.write_file("/etc/opendkim/KeyTable", dkim_keytable)
        if dkim_sigtable:
            await ex.write_file("/etc/opendkim/SigningTable", dkim_sigtable)
        if dkim_conf:
            await ex.write_file("/etc/opendkim.conf", dkim_conf)

        # ── Step 7: Configure Rspamd ──
        await ex.run("bash", "-c", "sudo mkdir -p /etc/rspamd/local.d /var/lib/rspamd/dkim")
        rspamd_conf = _render_template("rspamd-local.conf.j2", ctx)
        if rspamd_conf:
            await ex.write_file("/etc/rspamd/local.d/local.conf", rspamd_conf)

        # ── Step 8: Create mail directory structure ──
        await ex.run("bash", "-c",
                     "mkdir -p /var/mail/vhosts /etc/postfix/opendkim 2>/dev/null || true")

        # ── Step 9: Enable & start all services ──
        for svc, info in MAIL_STACK.items():
            if info["unit"]:
                await ex.run("systemctl", "enable", info["unit"])
                await ex.run("systemctl", "restart", info["unit"])

    # ── Step 10: Generate DNS records ──
    now = datetime.now().isoformat()
    with get_conn() as conn:
        # Remove old mail DNS records
        conn.execute("DELETE FROM dns_records WHERE name = ? OR name LIKE ?",
                     (domain, f"mail.{domain}"))
        # MX record
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (domain, "MX", f"10 mail.{domain}", 300, now))
        # A record for mail subdomain
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (f"mail.{domain}", "A", server_ip, 300, now))
        # SPF
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (domain, "TXT", f"v=spf1 mx a ip4:{server_ip} ~all", 300, now))
        # DMARC
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (f"_dmarc.{domain}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:admin@{domain}", 300, now))
        conn.commit()

    return RedirectResponse("/email?msg=Mail%20server%20dikonfigurasi%20untuk%20" + domain,
                            status_code=303)


# ────────────────────────────────── Service Control ────────────────────────────

@router.post("/email/service/{service}/{action}")
async def email_service_action(service: str, action: str,
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from starlette.responses import JSONResponse
    if service not in MAIL_STACK or action not in ("start", "stop", "restart"):
        return JSONResponse({"ok": False, "error": "Invalid action"})
    unit = MAIL_STACK[service]["unit"]
    await get_executor().run("bash", "-c", f"sudo systemctl {action} {unit}")
    return JSONResponse({"ok": True, "output": f"{service} {action}d"})


# ────────────────────────────────── Mailbox ────────────────────────────────────

@router.get("/email/accounts", response_class=HTMLResponse)
async def email_accounts_page(request: Request, domain: str = "",
                              msg: str = "",
                              user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _mail_domains()
    if not domain and domains:
        domain = domains[0]["name"]
    ex = get_executor()
    mailboxes = []
    if ex.mode in ("local", "wsl") and domain:
        r = await ex.run("bash", "-c", "cut -d: -f1,6 /etc/passwd 2>/dev/null || true")
        skip_users = {
            "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
            "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
            "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
            "messagebus", "syslog", "_apt", "polkitd", "sshd", "statd",
            "avahi", "colord", "gdm", "lpadmin", "pulse", "rtkit",
            "usbmux", "dnsmasq", "kernoops", "tcpdump", "tss",
        }
        for line in r.stdout.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0] not in skip_users:
                mailboxes.append({"user": parts[0], "home": parts[1]})

    return render(request, "email_accounts.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "mailboxes": mailboxes,
        "active": "email-accounts",
    })


@router.post("/email/accounts/create")
async def email_account_create(username: str = Form(...),
                               domain: str = Form(...),
                               password: str = Form(...),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    import shlex
    ex = get_executor()
    full_email = f"{username}@{domain}"
    safe_user = shlex.quote(username)
    safe_pass = shlex.quote(f"{username}:{password}")
    if ex.mode in ("local", "wsl"):
        await ex.run("bash", "-c",
                     f"useradd -m -s /usr/sbin/nologin {safe_user} 2>/dev/null || true")
        await ex.run("bash", "-c",
                     f"echo {safe_pass} | chpasswd 2>/dev/null || true")
        home = f"/home/{username}"
        await ex.run("bash", "-c",
                     f"mkdir -p {home}/Maildir/{{cur,new,tmp}} 2>/dev/null || true")
        await ex.run("bash", "-c",
                     f"chown -R {safe_user}:{safe_user} {home}/Maildir 2>/dev/null || true")
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Akun%20{full_email}%20dibuat",
                            status_code=303)


@router.post("/email/accounts/delete")
async def email_account_delete(username: str = Form(...),
                               domain: str = Form(""),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("userdel", "-r", username)
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Akun%20dihapus",
                            status_code=303)


@router.post("/email/accounts/password")
async def email_account_password(username: str = Form(...),
                                 domain: str = Form(""),
                                 password: str = Form(...),
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    import shlex
    ex = get_executor()
    safe_pass = shlex.quote(f"{username}:{password}")
    if ex.mode in ("local", "wsl"):
        await ex.run("bash", "-c", f"echo {safe_pass} | chpasswd")
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Password%20diperbarui",
                            status_code=303)


# ────────────────────────────────── DNS Records ────────────────────────────────

@router.get("/email/dns", response_class=HTMLResponse)
async def email_dns_page(request: Request, domain: str = "",
                         msg: str = "",
                         user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _mail_domains()
    if not domain and domains:
        domain = domains[0]["name"]
    dns_records = _get_mail_dns(domain) if domain else []
    server_ip = _get_server_ip()
    return render(request, "email_dns.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "dns_records": dns_records,
        "server_ip": server_ip, "active": "email-dns",
    })


@router.post("/email/dns/record")
async def email_dns_add(domain: str = Form(...),
                        record_type: str = Form("MX"),
                        name: str = Form(""),
                        value: str = Form(""),
                        ttl: int = Form(300),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    record_name = name if name else domain
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
            (record_name, record_type, value, ttl, datetime.now().isoformat()))
        conn.commit()
    return RedirectResponse(f"/email/dns?domain={domain}&msg=DNS%20record%20ditambahkan",
                            status_code=303)


@router.post("/email/dns/record/delete")
async def email_dns_delete(record_id: int = Form(...),
                           domain: str = Form(""),
                           user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        conn.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
        conn.commit()
    return RedirectResponse(f"/email/dns?domain={domain}&msg=DNS%20record%20dihapus",
                            status_code=303)


# ────────────────────────────────── Webmail ────────────────────────────────────

@router.get("/email/webmail", response_class=HTMLResponse)
async def email_webmail_page(request: Request, msg: str = "",
                             user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed, running = False, False
    webmail_url = ""
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "ls /var/lib/roundcube 2>/dev/null && echo yes || echo no")
        installed = "yes" in r.stdout
        r = await ex.run("bash", "-c", "systemctl is-active roundcube 2>/dev/null || echo inactive")
        running = r.stdout.strip() == "active"
        r = await ex.run("bash", "-c", "hostname -I 2>/dev/null | awk '{print $1}'")
        ip = r.stdout.strip()
        if ip:
            webmail_url = f"https://{ip}/roundcube"
    return render(request, "email_webmail.html", {
        "user": user, "msg": msg,
        "installed": installed, "running": running,
        "webmail_url": webmail_url, "active": "email-webmail",
    })


@router.post("/email/webmail/install")
async def email_webmail_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from starlette.responses import JSONResponse
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("bash", "-c",
                     "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                     "roundcube-core roundcube-mysql roundcube-plugins")
        await ex.run("bash", "-c", "sudo systemctl enable roundcube 2>/dev/null || true")
        await ex.run("bash", "-c", "sudo systemctl restart roundcube 2>/dev/null || true")
    return JSONResponse({"ok": True, "output": "Roundcube dipasang"})


# ────────────────────────────────── Spam & Virus ───────────────────────────────

@router.get("/email/security", response_class=HTMLResponse)
async def email_security_page(request: Request, msg: str = "",
                              user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    rspamd_installed, rspamd_active = False, False
    clamav_installed, clamav_active = False, False
    spamassassin_installed, spamassassin_active = False, False
    opendkim_installed, opendkim_active = False, False
    if ex.mode in ("local", "wsl"):
        for svc, info in [("rspamd", "rspamd"), ("clamav", "clamav-daemon"),
                          ("spamassassin", "spamassassin"), ("opendkim", "opendkim")]:
            r = await ex.run("bash", "-c", f"command -v {info} && echo yes || echo no")
            is_installed = "yes" in r.stdout
            r2 = await ex.run("bash", "-c", f"systemctl is-active {info} 2>/dev/null || echo inactive")
            is_active = r2.stdout.strip() == "active"
            if svc == "rspamd":
                rspamd_installed, rspamd_active = is_installed, is_active
            elif svc == "clamav":
                clamav_installed, clamav_active = is_installed, is_active
            elif svc == "spamassassin":
                spamassassin_installed, spamassassin_active = is_installed, is_active
            elif svc == "opendkim":
                opendkim_installed, opendkim_active = is_installed, is_active
    return render(request, "email_security.html", {
        "user": user, "msg": msg,
        "rspamd_installed": rspamd_installed, "rspamd_active": rspamd_active,
        "clamav_installed": clamav_installed, "clamav_active": clamav_active,
        "spamassassin_installed": spamassassin_installed, "spamassassin_active": spamassassin_active,
        "opendkim_installed": opendkim_installed, "opendkim_active": opendkim_active,
        "active": "email-security",
    })


@router.post("/email/security/install")
async def email_security_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    from starlette.responses import JSONResponse
    if ex.mode in ("local", "wsl"):
        pkgs = "rspamd opendkim opendkim-tools spamassassin spamc clamav clamav-daemon"
        await ex.run("bash", "-c", f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}")
        for svc in ["rspamd", "opendkim", "spamassassin", "clamav-daemon"]:
            await ex.run("bash", "-c", f"sudo systemctl enable {svc} 2>/dev/null || true")
            await ex.run("bash", "-c", f"sudo systemctl restart {svc} 2>/dev/null || true")
    return JSONResponse({"ok": True, "output": "Spam & DKIM stack dipasang"})


@router.post("/email/security/service/{service}/{action}")
async def email_security_service(service: str, action: str,
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    from starlette.responses import JSONResponse
    service_map = {"rspamd": "rspamd", "clamav": "clamav-daemon",
                   "spamassassin": "spamassassin", "opendkim": "opendkim"}
    svc = service_map.get(service)
    if not svc or action not in ("start", "stop", "restart"):
        return JSONResponse({"ok": False, "error": "Invalid action"})
    await get_executor().run("bash", "-c", f"sudo systemctl {action} {svc}")
    return JSONResponse({"ok": True, "output": f"{service} {action}d"})
