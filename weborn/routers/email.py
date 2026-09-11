"""Email management: Postfix + Dovecot + Rspamd + OpenDKIM + Roundcube stack."""
import http.cookiejar
import json
import re
import secrets
import shlex
import socket
import string
import urllib.parse
import urllib.request
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

from ..auth import require_admin, require_user
from ..config import CONF_TEMPLATES_DIR, CONFIG_DIR
from ..db import get_conn, get_setting, set_setting
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Mail Server"])

# Nama mailbox (local-part): huruf kecil, angka, titik, strip, underscore (maks 32)
_MAILBOX_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
# Alamat email lengkap (created untuk alias/forwarder destination)
_EMAIL_ADDR_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9._-]{0,63}@[a-z0-9.-]+$")

# ─── Model virtual mailbox ────────────────────────────────────────────────────
# Semua mailbox adalah VIRTUAL USER milik satu owner OS yang sama. Maildir tiap
# email berada di /var/mail/vhosts/<email>/Maildir (bukan di home user).
MAIL_OWNER = "admin"
VMAILBOX_BASE = "/var/mail/vhosts"
VMAILBOX_PATH = "/etc/postfix/vmailbox"
VIRTUAL_PATH = "/etc/postfix/virtual"
DOVECOT_PASSWD = "/etc/dovecot/passwd"
DOVECOT_QUOTA_CONF = "/etc/dovecot/conf.d/90-quota.conf"


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

MAIL_STACK = {
    "postfix": {"pkg": "postfix", "unit": "postfix", "bin": "postfix"},
    "dovecot": {"pkg": "dovecot-core dovecot-imapd dovecot-pop3d dovecot-sieve", "unit": "dovecot", "bin": "dovecot"},
    "rspamd": {"pkg": "rspamd", "unit": "rspamd", "bin": "rspamd"},
    "opendkim": {"pkg": "opendkim opendkim-tools", "unit": "opendkim", "bin": "opendkim"},
    "roundcube": {"pkg": "roundcube-core roundcube-mysql roundcube-plugins", "unit": "apache2", "bin": "roundcube"},
}

MAIL_DOMAINS_CACHE: dict = {}


def _mail_domains():
    """Domain e-mail panel. Disimpan di setting mail_domains (JSON);
    fallback lama: tabel domains milik web hosting (backward-compat)."""
    raw = get_setting("mail_domains")
    if raw:
        try:
            names = json.loads(raw)
        except Exception:
            names = []
    else:
        with get_conn() as conn:
            names = [r["name"] for r in conn.execute(
                "SELECT name FROM domains WHERE kind='domain' ORDER BY name").fetchall()]
        if not names:
            names = ["localhost"]
    return [{"name": n} for n in sorted(set(names))]


def _mail_domain_names() -> list[str]:
    return [d["name"] for d in _mail_domains()]


async def _mail_domain_register(name: str):
    """Daftarkan domain sebagai virtual mail domain (postfix+dovecot)."""
    names = sorted(set(_mail_domain_names()) | {name})
    set_setting("mail_domains", json.dumps(names))
    await _apply_mail_domains(names)


async def _mail_domain_unregister(name: str):
    """Lepas domain dari virtual_mailbox_domains + bersihkan artefak mail domain tsb."""
    name = name.strip().lower()
    with get_conn() as conn:
        keys = [k for (k,) in conn.execute("SELECT key FROM settings").fetchall()
                if name in k and k != "mail_domains"]
        for k in keys:
            conn.execute("DELETE FROM settings WHERE key = ?", (k,))
        conn.commit()
    affected: list[str] = []
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        pw = await _read_dovecot_passwd()
        affected = [e for e in pw if e.rsplit("@", 1)[-1] == name]
        for e in affected:
            pw.pop(e, None)
        await _write_dovecot_passwd(pw)
        entries = [e for e in await _read_virtual_map() if not e["source"].endswith(f"@{name}")]
        await _write_virtual_map(entries)
        for e in affected:
            await ex.run("bash", "-c",
                         f"sudo rm -rf {shlex.quote(VMAILBOX_BASE)}/{shlex.quote(e)}")
    names = sorted(set(_mail_domain_names()) - {name}) or ["localhost"]
    set_setting("mail_domains", json.dumps(names))
    await _apply_mail_domains(names)


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


def _mailbox_key() -> bytes:
    """Kunci Fernet turunan dari secret_key panel (untuk enkripsi password mailbox)."""
    from ..db import get_secret_key
    digest = __import__("hashlib").sha256(get_secret_key().encode()).digest()
    return __import__("base64").urlsafe_b64encode(digest)


def _encrypt_mailbox_pass(password: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_mailbox_key()).encrypt(password.encode()).decode()


def _decrypt_mailbox_pass(stored: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_mailbox_key()).decrypt(stored.encode()).decode()


def _get_mailbox_pass(email: str) -> str | None:
    """Ambil password mailbox dari settings (terenkripsi)."""
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?",
                           (f"mail_pass:{email}",)).fetchone()
    if not row:
        return None
    try:
        return _decrypt_mailbox_pass(row["value"])
    except Exception:
        return None


def _set_mailbox_pass(email: str, password: str):
    from ..db import set_setting
    set_setting(f"mail_pass:{email}", _encrypt_mailbox_pass(password))


def _del_mailbox_pass(email: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key IN (?, ?, ?, ?, ?)",
                     (f"mail_pass:{email}", f"mail_vk:{email}", f"mail_members:{email}",
                      f"mail_quota:{email}", f"mail_vacation:{email}"))
        conn.commit()


def _mail_owner_uid_gid() -> tuple[int, int]:
    """UID/GID owner OS yang memiliki semua mailbox."""
    try:
        import pwd
        p = pwd.getpwnam(MAIL_OWNER)
        return p.pw_uid, p.pw_gid
    except Exception:
        return 1001, 1001


async def _read_text_file(path: str) -> str:
    r = await get_executor().run("bash", "-c",
                                 f"sudo cat {shlex.quote(path)} 2>/dev/null || true")
    return r.stdout


async def _write_text_file(path: str, content: str, chown: str | None = None,
                           mode: str | None = None):
    ex = get_executor()
    await ex.write_file(path, content)
    if chown:
        await ex.run("bash", "-c", f"sudo chown {chown} {shlex.quote(path)}")
    if mode:
        await ex.run("bash", "-c", f"sudo chmod {mode} {shlex.quote(path)}")


# ─── Postfix vmailbox map ─────────────────────────────────────────────────────

async def _read_vmailbox_emails() -> list[str]:
    """Alamat email yang terdaftar di /etc/postfix/vmailbox (text map)."""
    txt = await _read_text_file(VMAILBOX_PATH)
    emails, seen = [], set()
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "@" not in line:
            continue
        email = line.split(None, 1)[0].strip().lower()
        if email and email not in seen:
            seen.add(email)
            emails.append(email)
    return sorted(emails)


async def _write_vmailbox(emails: list[str]):
    content = "".join(f"{email}\t{email}/Maildir/\n" for email in sorted(emails))
    await _write_text_file(VMAILBOX_PATH, content, chown="root:root")
    await get_executor().run("bash", "-c", f"sudo postmap {VMAILBOX_PATH}")


# ─── Postfix virtual_alias_maps (alias & forwarder) ───────────────────────────

def _parse_virtual(txt: str) -> list[dict]:
    entries, cur = [], None
    for line in txt.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            if cur is not None:
                for part in line.split(","):
                    part = part.strip()
                    if part:
                        cur["dest"].append(part)
            continue
        parts = line.strip().split(None, 1)
        source = parts[0].strip().lower()
        dest = [d.strip() for d in parts[1].split(",") if d.strip()] if len(parts) == 2 else []
        cur = {"source": source, "dest": dest}
        entries.append(cur)
    return entries


async def _read_virtual_map() -> list[dict]:
    return _parse_virtual(await _read_text_file(VIRTUAL_PATH))


def _catchall_identity_entries(entries: list[dict]) -> list[dict]:
    """Entry alias identitas (source→source) untuk mailbox di domain yang punya
    catch-all. Kehadirannya wajib agar mail ke mailbox TIDAK tertangkap catch-all:
    Postfix memilih virtual_alias paling spesifik (alamat penuh menang atas @domain).
    Dipakai `_write_virtual_map` dan `_create_mailbox` (mailbox baru setelah
    catch-all aktif harus langsung mendapat alias identitas)."""
    catch_doms = {e["source"][1:] for e in entries if e["source"].startswith("@")}
    if not catch_doms:
        return []
    with get_conn() as conn:
        emails = [k.split(":", 1)[1] for k, in conn.execute(
            "SELECT key FROM settings WHERE key LIKE 'mail_pass:%'").fetchall()
            if ":" in k]
    cur_sources = {e["source"] for e in entries}
    out: list[dict] = []
    for em in sorted(set(emails)):
        if em.rsplit("@", 1)[-1] in catch_doms and em not in cur_sources:
            out.append({"source": em, "dest": [em]})
    return out


async def _write_virtual_map(entries: list[dict]):
    entries = list(entries)
    entries.extend(_catchall_identity_entries(entries))
    content = "".join(f"{e['source']}\t{', '.join(e['dest'])}\n" for e in entries)
    await _write_text_file(VIRTUAL_PATH, content, chown="root:root")
    await get_executor().run("bash", "-c", f"sudo postmap {VIRTUAL_PATH}")


def _entry_kind(entry: dict) -> str:
    """Tipe entry virtual map: 'alias', 'forwarder', 'list', 'catchall', atau
    'identity' (entry otomatis: root/postmaster & alias identitas mailbox)."""
    kind = get_setting(f"mail_vk:{entry['source']}")
    if kind in ("alias", "forwarder", "list", "catchall"):
        return kind
    local = entry["source"].split("@", 1)[0]
    if local in ("root", "postmaster"):
        return "identity"
    if len(entry["dest"]) == 1 and entry["dest"][0] == entry["source"]:
        return "identity"
    domains = {d["name"] for d in _mail_domains()} | {"localhost"}
    if any(dest.rsplit("@", 1)[-1] in domains for dest in entry["dest"]):
        return "alias"
    return "forwarder"


# ─── Dovecot passwd-file (password per-email) ─────────────────────────────────

async def _dovecot_hash(password: str) -> str:
    salt = secrets.token_hex(8)
    r = await get_executor().run("bash", "-c",
        f"openssl passwd -6 -salt {salt} {shlex.quote(password)} 2>/dev/null || true")
    h = r.stdout.strip()
    if not h:
        return "{SHA512-CRYPT}"
    return h if h.startswith("{SHA512-CRYPT}") else "{SHA512-CRYPT}" + h


async def _read_dovecot_passwd() -> dict[str, str]:
    out = {}
    for line in (await _read_text_file(DOVECOT_PASSWD)).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # format: email:hash:uid:gid::home:shell[:extra...] — cukup ambil hash
        # (kolom uid/gid/home di-_write ulang; mencegah duplikasi kolom).
        parts = line.split(":")
        if len(parts) >= 2 and parts[0]:
            out[parts[0].strip().lower()] = parts[1].strip()
    return out


def _get_mailbox_quota(email: str) -> str:
    """Batas kuota mailbox (string seperti '2G') atau '' bila tak dibatasi."""
    return (get_setting(f"mail_quota:{email}") or "").strip()


async def _maildir_size_kb(email: str) -> int:
    if get_executor().mode not in ("local", "wsl"):
        return 0
    r = await get_executor().run("bash", "-c",
        f"sudo du -sk {shlex.quote(VMAILBOX_BASE)}/{shlex.quote(email)}/Maildir 2>/dev/null || echo 0")
    try:
        return int(r.stdout.strip().split()[0])
    except Exception:
        return 0


async def _write_dovecot_passwd(passwords: dict[str, str]):
    """passwd-file lengkap (kolom uid/gid/home) + extra field kuota per email.

    Baris: email:{hash}:{uid}:{gid}::{home}:/usr/sbin/nologin[:userdb_quota_storage_size=<size>]
    Kolom lengkap diperlukan karena userdb = passwd-file (bukan static).
    Extra field kuota (Dovecot 2.4) dioverride per-user dari userdb lookups.
    """
    vuid, vgid = _mail_owner_uid_gid()
    lines = []
    for email, h in sorted(passwords.items()):
        home = f"{VMAILBOX_BASE}/{email}"
        quota = _get_mailbox_quota(email)
        extra = f":userdb_quota_storage_size={quota}" if quota else ""
        lines.append(f"{email}:{h}:{vuid}:{vgid}::{home}:/usr/sbin/nologin{extra}\n")
    await _write_text_file(DOVECOT_PASSWD, "".join(lines), chown="root:dovecot", mode="640")


# ─── Operasi mailbox (virtual) ────────────────────────────────────────────────

async def _ensure_mailbase():
    vuid, vgid = _mail_owner_uid_gid()
    await get_executor().run("bash", "-c",
                             f"sudo mkdir -p {VMAILBOX_BASE} && "
                             f"sudo chown -R {vuid}:{vgid} {VMAILBOX_BASE}")


async def _create_mailbox(email: str, password: str):
    if get_executor().mode not in ("local", "wsl"):
        return
    vuid, vgid = _mail_owner_uid_gid()
    mdir = f"{VMAILBOX_BASE}/{email}/Maildir"
    await get_executor().run("bash", "-c",
                             f"sudo mkdir -p {shlex.quote(mdir)}/{{cur,new,tmp}} && "
                             f"sudo chown -R {vuid}:{vgid} {shlex.quote(mdir)}")
    emails = await _read_vmailbox_emails()
    if email not in emails:
        emails.append(email)
        await _write_vmailbox(emails)
    pwmap = await _read_dovecot_passwd()
    pwmap[email] = await _dovecot_hash(password)
    await _write_dovecot_passwd(pwmap)
    _set_mailbox_pass(email, password)
    # Mailbox baru di domain ber-catch-all wajib dapat alias identitas seketika,
    # selain mail akan tertangkap catch-all sampai virtual map ditulis ulang.
    vm = await _read_virtual_map()
    if any(e["source"].startswith("@") for e in vm):
        await _write_virtual_map(vm)


async def _delete_mailbox(email: str):
    # Hapus settings dahulu agar `_write_virtual_map` (di bawah) tidak menambahkan
    # ulang alias identitas mailbox ini (helper membaca kunci mail_pass:*).
    _del_mailbox_pass(email)
    if get_executor().mode in ("local", "wsl"):
        emails = await _read_vmailbox_emails()
        if email in emails:
            emails.remove(email)
            await _write_vmailbox(emails)
        await get_executor().run("bash", "-c",
                                 f"sudo rm -rf {shlex.quote(VMAILBOX_BASE)}/{shlex.quote(email)}")
        pwmap = await _read_dovecot_passwd()
        pwmap.pop(email, None)
        await _write_dovecot_passwd(pwmap)
        keep = [e for e in await _read_virtual_map()
                if e["source"] != email and email not in e["dest"]]
        if len(keep) < len(await _read_virtual_map()):
            await _write_virtual_map(keep)


async def _set_mailbox_password(email: str, password: str):
    if get_executor().mode in ("local", "wsl"):
        pwmap = await _read_dovecot_passwd()
        pwmap[email] = await _dovecot_hash(password)
        await _write_dovecot_passwd(pwmap)
    _set_mailbox_pass(email, password)


def _quota_to_kb(quota: str) -> int:
    """Ubah string kuota ('2G', '500M', '100K') ke kilobyte; 0 bila tak terbatas."""
    if not quota:
        return 0
    m = re.match(r"^(\d+)\s*([KMGTP]?)B?$", quota.strip(), re.IGNORECASE)
    if not m:
        return 0
    mult = {"": 1, "K": 1, "M": 1024, "G": 1024 ** 2,
            "T": 1024 ** 3, "P": 1024 ** 4}[m.group(2).upper()]
    return int(m.group(1)) * mult


def _quota_pct(used_kb: int, quota_kb: int) -> int:
    if quota_kb <= 0:
        return 0
    return min(100, int(used_kb * 100 / quota_kb))


async def _seed_owner_mailbox(domain: str):
    """Pastikan mailbox owner + alias root/postmaster tersedia."""
    await _ensure_mailbase()
    email = f"{MAIL_OWNER}@{domain}"
    if email not in await _read_vmailbox_emails():
        await _create_mailbox(email, _random_password())
    entries = await _read_virtual_map()
    srcs = {e["source"] for e in entries}
    for alias in (f"root@{domain}", f"postmaster@{domain}"):
        if alias not in srcs:
            entries.append({"source": alias, "dest": [email]})
    await _write_virtual_map(entries)


# ─── Penerapan konfigurasi server (postfix + dovecot) ─────────────────────────

async def _apply_mail_domains(names: list[str]):
    """Tulis ulang /etc/postfix/main.cf dengan daftar virtual_mailbox_domains,
    pastikan master.cf punya pipe dovecot-lda, lalu reload postfix."""
    names = sorted(names or ["localhost"])
    # `localhost` selalu primary (myhostname + sertifikat TLS mail.localhost terpasang).
    names = ["localhost"] + [n for n in names if n != "localhost"]
    primary = names[0]
    vuid, vgid = _mail_owner_uid_gid()
    ctx = {"domain": primary, "generated_at": datetime.now().isoformat(),
           "vuid": vuid, "vgid": vgid, "mail_owner": MAIL_OWNER,
           "vdomains": " ".join(names)}
    postfix_cf = _render_template("postfix-main.cf.j2", ctx)
    if not postfix_cf:
        return
    ex = get_executor()
    ssl_dir = f"/etc/ssl/mail.{primary}"
    postfix_cf = postfix_cf.replace(
        f"/etc/letsencrypt/live/{primary}/fullchain.pem", f"{ssl_dir}/fullchain.pem"
    ).replace(
        f"/etc/letsencrypt/live/{primary}/privkey.pem", f"{ssl_dir}/privkey.pem"
    )
    await ex.write_file("/etc/postfix/main.cf", postfix_cf)
    await _ensure_postfix_master()
    await ex.run("bash", "-c", "sudo postfix reload 2>/dev/null || sudo postfix start 2>/dev/null || true")


async def _ensure_postfix_master():
    """Tambahkan/koreksi pipe dovecot-lda di master.cf (untuk sieve/LDA) dan
    layanan submission (587, STARTTLS) + submissions (465, TLS wrap) untuk
    klien email sungguhan (Thunderbird/Outlook).

    Argumen -d memakai `${user}@${domain}` karena username userdb adalah
    alamat lengkap (admin@localhost), bukan sekedar local-part.
    """
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return
    argv = "/usr/lib/dovecot/dovecot-lda -f ${sender} -d ${user}@${domain}"
    txt = await _read_text_file("/etc/postfix/master.cf")
    if f"argv={argv}" not in txt:
        block = (
            "\ndovecot   unix  -       n       n       -       -       pipe\n"
            f"  flags=DRhu user=admin argv={argv}\n"
        )
        # Ganti blok transport lama (argv tanpa @${domain}) agar tak dobel.
        pattern = re.compile(
            r"\ndovecot   unix  -       n       n       -       -       pipe\n"
            r"  flags=DRhu user=admin argv=[^\n]*"
        )
        txt = pattern.sub("", txt)
        await ex.write_file("/etc/postfix/master.cf", txt.rstrip() + block + "\n")
    if "\nsubmission inet" not in txt:
        client_services = (
            "\n"
            "submission inet n       -       y       -       -       smtpd\n"
            "  -o syslog_name=postfix/submission\n"
            "  -o smtpd_sasl_auth_enable=yes\n"
            "  -o smtpd_tls_security_level=encrypt\n"
            "  -o smtpd_forbid_unauth_pipelining=no\n"
            "  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject\n"
            "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
            "submissions inet n      -       y       -       -       smtpd\n"
            "  -o syslog_name=postfix/submissions\n"
            "  -o smtpd_sasl_auth_enable=yes\n"
            "  -o smtpd_tls_wrappermode=yes\n"
            "  -o smtpd_forbid_unauth_pipelining=no\n"
            "  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject\n"
            "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n"
        )
        await ex.write_file("/etc/postfix/master.cf", (await _read_text_file("/etc/postfix/master.cf")).rstrip() + client_services)


async def _apply_mail_quota_conf():
    """Tulis dovecot quota plugin config + pastikan 10-mail.conf memuatnya."""
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return
    quota_conf = _render_template("dovecot-90-quota.conf.j2", {})
    if quota_conf:
        await ex.write_file(DOVECOT_QUOTA_CONF, quota_conf)
    dovecot_mail = _render_template("dovecot-10-mail.conf.j2", {})
    if dovecot_mail:
        await ex.write_file("/etc/dovecot/conf.d/10-mail.conf", dovecot_mail)
    await ex.run("bash", "-c", "sudo dovecot reload 2>/dev/null || sudo systemctl restart dovecot 2>/dev/null || true")


async def _write_sieve_file(email: str, script: str):
    """Tulis script Sieve vacation ke Maildir user (home = /var/mail/vhosts/<email>)."""
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return
    path = f"{VMAILBOX_BASE}/{email}/.dovecot.sieve"
    await _write_text_file(path, script, chown=f"{MAIL_OWNER}:{MAIL_OWNER}")


def _vacation_script(subject: str, message: str) -> str:
    """Sieve vacation: handle berasaskan address (alamat tujuan seluruh email user)."""
    subject = (subject or "").replace("\n", " ").replace("\\", "\\\\").replace('"', '\\"')
    message = (message or "").strip().replace("\n", " ")
    message = message.replace("\\", "\\\\").replace('"', '\\"')
    return (
        'require ["vacation"];\n'
        f'vacation :days 7 :subject "{subject}" "{message}";\n'
    )


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
            if svc == "roundcube":
                r = await ex.run("bash", "-c", "ls /var/lib/roundcube 2>/dev/null && echo yes || echo no")
                installed = "yes" in r.stdout
            else:
                r = await ex.run("bash", "-c", f"command -v {info['bin']} 2>/dev/null && echo yes || echo no")
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
    domain = domain.strip().lower()
    server_ip = _get_server_ip()

    async def gen():
        ex = get_executor()
        try:
            # ── Step 1: Install packages ──
            yield _sse("step", {"step": "Install packages"})
            pkgs = " ".join(info["pkg"] for info in MAIL_STACK.values())
            await ex.run("bash", "-c", f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}")

            # ── Step 2: Set hostname ──
            yield _sse("step", {"step": "Set hostname"})
            qdomain = shlex.quote(f"mail.{domain}")
            await ex.run("bash", "-c", f"sudo bash -c 'echo {qdomain} > /etc/hostname'")
            await ex.run("bash", "-c", f"sudo hostname {qdomain}")

            # ── Step 3: Create SSL cert ──
            yield _sse("step", {"step": "Buat SSL certificate"})
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
            yield _sse("step", {"step": "Konfigurasi Postfix"})
            vuid, vgid = _mail_owner_uid_gid()
            ctx = {"domain": domain, "generated_at": datetime.now().isoformat(),
                   "vuid": vuid, "vgid": vgid, "mail_owner": MAIL_OWNER,
                   "vdomains": domain}
            postfix_cf = _render_template("postfix-main.cf.j2", ctx)
            if postfix_cf:
                postfix_cf = postfix_cf.replace(
                    f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                    f"{ssl_dir}/fullchain.pem"
                ).replace(
                    f"/etc/letsencrypt/live/{domain}/privkey.pem",
                    f"{ssl_dir}/privkey.pem"
                )
                await ex.write_file("/etc/postfix/main.cf", postfix_cf)
            await ex.run("bash", "-c", f"sudo sed -i 's/^smtp      inet  n       -       n       -       -       smtpd/smtp      inet  n       -       -       -       -       smtpd/' /etc/postfix/master.cf 2>/dev/null || true")

            # ── Step 5: Configure Dovecot ──
            yield _sse("step", {"step": "Konfigurasi Dovecot"})
            await ex.write_file("/etc/pam.d/dovecot",
                                "@include common-auth\n"
                                "@include common-account\n"
                                "@include common-session\n")
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
            await _ensure_postfix_master()
            await _apply_mail_quota_conf()

            # ── Step 6: Configure OpenDKIM ──
            yield _sse("step", {"step": "Konfigurasi OpenDKIM"})
            await ex.run("bash", "-c", "sudo mkdir -p /etc/opendkim /var/lib/opendkim/keys /var/spool/postfix/opendkim")
            dkim_key_dir = "/var/lib/opendkim/keys"
            await ex.run("bash", "-c",
                         f"sudo opendkim-genkey -D {dkim_key_dir} -d {shlex.quote(domain)} -s weborn -b 2048 2>/dev/null || true")
            # genkey menulis `weborn.private` (selector=weborn); rename agar konsisten
            # dengan KeyTable `{{ domain }}.weborn.private` (per-domain, aman multi-domain).
            await ex.run("bash", "-c",
                         f"sudo mv -f {dkim_key_dir}/weborn.private {dkim_key_dir}/{domain}.weborn.private 2>/dev/null || true")
            await ex.run("bash", "-c",
                         f"sudo mv -f {dkim_key_dir}/weborn.txt {dkim_key_dir}/{domain}.weborn.txt 2>/dev/null || true")
            # opendkim berjalan sebagai root (unit default Debian): kunci harus dimiliki
            # root agar termuat ("key data is not secure"), mode 0700.
            await ex.run("bash", "-c",
                         f"sudo chown -R root:root {dkim_key_dir} && sudo chmod 700 {dkim_key_dir}")
            # Soket milter dibaca postfix (user postfix): dir memakai setgid agar opendkim
            # membuat socket bergroup `postfix`.
            await ex.run("bash", "-c",
                         "sudo chown opendkim:postfix /var/spool/postfix/opendkim && sudo chmod 2775 /var/spool/postfix/opendkim")

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
            yield _sse("step", {"step": "Konfigurasi Rspamd"})
            await ex.run("bash", "-c", "sudo mkdir -p /etc/rspamd/local.d /var/lib/rspamd/dkim")
            rspamd_conf = _render_template("rspamd-local.conf.j2", ctx)
            if rspamd_conf:
                await ex.write_file("/etc/rspamd/local.d/local.conf", rspamd_conf)

            # ── Step 8: Create mail directory structure ──
            yield _sse("step", {"step": "Buat direktori mailbox"})
            await _ensure_mailbase()
            await ex.run("bash", "-c",
                         f"sudo mkdir -p /var/mail/vhosts /etc/postfix 2>/dev/null || true")
            # Seed: mailbox owner + alias root/postmaster (Semua mailbox virtual).
            # Hash password owner dibuat otomatis & disimpan terenkripsi di settings.
            await _seed_owner_mailbox(domain)

            # ── Step 9: Enable & start all services ──
            yield _sse("step", {"step": "Aktifkan semua service"})
            for svc, info in MAIL_STACK.items():
                if info["unit"]:
                    yield _sse("step", {"step": f"Start {svc}", "output": f"sudo systemctl enable + restart {info['unit']}"})
                    await ex.run("bash", "-c", f"sudo systemctl enable {info['unit']} 2>/dev/null || true")
                    await ex.run("bash", "-c", f"sudo systemctl restart {info['unit']} 2>/dev/null || true")

            # ── Step 10: Generate DNS records ──
            yield _sse("step", {"step": "Generate DNS records"})
            now = datetime.now().isoformat()
            with get_conn() as conn:
                conn.execute("DELETE FROM dns_records WHERE name = ? OR name LIKE ?",
                             (domain, f"mail.{domain}"))
                conn.execute(
                    "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                    (domain, "MX", f"10 mail.{domain}", 300, now))
                conn.execute(
                    "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                    (f"mail.{domain}", "A", server_ip, 300, now))
                conn.execute(
                    "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                    (domain, "TXT", f"v=spf1 mx a ip4:{server_ip} ~all", 300, now))
                conn.execute(
                    "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                    (f"_dmarc.{domain}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:admin@{domain}", 300, now))
                conn.commit()

            # DKIM public key → rekam DNS TXT (publikasi agar penerima bisa verifikasi).
            dkim_pub = await _read_text_file(f"{dkim_key_dir}/{domain}.weborn.txt")
            dkim_val = "".join(re.findall(r'"([^"]*)"', dkim_pub or "")).strip() or (dkim_pub or "").strip()
            if dkim_val:
                with get_conn() as conn:
                    conn.execute(
                        "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                        (f"weborn._domainkey.{domain}", "TXT", dkim_val, 300, datetime.now().isoformat()))
                    conn.commit()

            yield _sse("done", {"ok": True})
        except Exception as e:
            yield _sse("error", {"error": str(e)})

    return StreamingResponse(gen(), media_type="text/event-stream")


# ────────────────────────────────── Service Control ────────────────────────────

@router.post("/email/service/{service}/{action}")
async def email_service_action(service: str, action: str,
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
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
    mailboxes = []
    if get_executor().mode in ("local", "wsl") and domain:
        for email in await _read_vmailbox_emails():
            if email.endswith(f"@{domain}"):
                quota = _get_mailbox_quota(email)
                used_kb = await _maildir_size_kb(email)
                vacation = get_setting(f"mail_vacation:{email}") or ""
                q_kb = _quota_to_kb(quota)
                mailboxes.append({
                    "user": email.rsplit("@", 1)[0],
                    "email": email,
                    "home": f"{VMAILBOX_BASE}/{email}/Maildir",
                    "quota": quota,
                    "quota_kb": q_kb,
                    "quota_pct": _quota_pct(used_kb, q_kb),
                    "quota_label": f"{used_kb / 1024:.2f}M" if used_kb >= 1024 else f"{used_kb}K",
                    "used_kb": used_kb,
                    "vacation": bool(vacation),
                })
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
    if not _MAILBOX_RE.match(username):
        return RedirectResponse("/email/accounts?msg=Username%20tidak%20valid", status_code=303)
    full_email = f"{username}@{domain}"
    await _create_mailbox(full_email, password)
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Akun%20{full_email}%20dibuat",
                            status_code=303)


@router.post("/email/accounts/delete")
async def email_account_delete(username: str = Form(...),
                               domain: str = Form(""),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if not _MAILBOX_RE.match(username):
        return RedirectResponse("/email/accounts?msg=Username%20tidak%20valid", status_code=303)
    await _delete_mailbox(f"{username}@{domain}")
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Akun%20dihapus",
                            status_code=303)


@router.post("/email/accounts/password")
async def email_account_password(username: str = Form(...),
                                 domain: str = Form(""),
                                 password: str = Form(...),
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if not _MAILBOX_RE.match(username):
        return RedirectResponse("/email/accounts?msg=Username%20tidak%20valid", status_code=303)
    await _set_mailbox_password(f"{username}@{domain}", password)
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Password%20diperbarui",
                            status_code=303)


@router.post("/email/accounts/quota")
async def email_account_quota(username: str = Form(...),
                              domain: str = Form(""),
                              quota: str = Form(""),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{username}@{domain}".lower()
    quota = quota.strip().upper()
    if quota and _quota_to_kb(quota) <= 0:
        return RedirectResponse(f"/email/accounts?domain={domain}&msg=Format%20kuota%20tidak%20valid",
                                status_code=303)
    if quota:
        set_setting(f"mail_quota:{email}", quota)
    else:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (f"mail_quota:{email}",))
            conn.commit()
    # Tulis ulang passwd-file supaya kolom kuota ikut berlaku (userdb passwd-file)
    if get_executor().mode in ("local", "wsl"):
        pwmap = await _read_dovecot_passwd()
        if email in pwmap:
            await _write_dovecot_passwd(pwmap)
    await _apply_mail_quota_conf()
    return RedirectResponse(f"/email/accounts?domain={domain}&msg=Kuota%20{email}%20=%20{quota or 'tak terbatas'}",
                            status_code=303)


# ────────────────────────────────── Domain (Multi) ─────────────────────────────

@router.post("/email/domains/add")
async def email_domain_add(name: str = Form(...),
                           user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    name = name.strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", name) or ".." in name:
        return RedirectResponse("/email/accounts?msg=Domain%20tidak%20valid", status_code=303)
    names = sorted({d["name"] for d in _mail_domains()} | {name})
    set_setting("mail_domains", json.dumps(names))
    await _seed_owner_mailbox(name)
    await _apply_mail_domains(names)
    _add_mail_dns(name)
    return RedirectResponse(f"/email/accounts?domain={name}&msg=Domain%20{name}%20ditambahkan",
                            status_code=303)


@router.post("/email/domains/delete")
async def email_domain_delete(name: str = Form(...),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    name = name.strip().lower()
    domains = _mail_domains()
    if name == "localhost" or len(domains) <= 1:
        return RedirectResponse("/email/accounts?msg=Domain%20terakhir%20tidak%20bisa%20dihapus",
                                status_code=303)
    if any(e.endswith(f"@{name}") for e in await _read_vmailbox_emails()):
        return RedirectResponse("/email/accounts?msg=Hanya%20domain%20tanpa%20mailbox%20yang%20bisa%20dihapus",
                                status_code=303)
    names = [d["name"] for d in domains if d["name"] != name]
    set_setting("mail_domains", json.dumps(names))
    # Hapus entry vmailbox tersisa + virtual map + setting milik domain
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key LIKE ?", (f"%{name}%",))
        conn.commit()
    if get_executor().mode in ("local", "wsl"):
        entries = [e for e in await _read_virtual_map() if not e["source"].endswith(f"@{name}")]
        await _write_virtual_map(entries)
    await _apply_mail_domains(names)
    return RedirectResponse(f"/email/accounts?domain={names[-1]}&msg=Domain%20{name}%20dihapus",
                            status_code=303)


def _add_mail_dns(domain: str):
    server_ip = _get_server_ip()
    now = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM dns_records WHERE name = ? OR name LIKE ?",
                     (domain, f"mail.{domain}"))
        conn.execute("INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                     (domain, "MX", f"10 mail.{domain}", 300, now))
        conn.execute("INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                     (f"mail.{domain}", "A", server_ip, 300, now))
        conn.execute("INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                     (domain, "TXT", f"v=spf1 mx a ip4:{server_ip} ~all", 300, now))
        conn.execute("INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                     (f"_dmarc.{domain}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:admin@{domain}", 300, now))
        conn.commit()


# ────────────────────────────────── Catch-all Alias ────────────────────────────

@router.post("/email/aliases/catchall")
async def email_alias_catchall(domain: str = Form(...),
                               dest: str = Form(""),
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    source = f"@{domain}"
    targets = await _alias_targets(dest)
    existing = await _read_vmailbox_emails()
    if not targets or len(targets) != 1 or targets[0] not in existing:
        return RedirectResponse(f"/email/aliases?domain={domain}&msg=Tujuan%20harus%20satu%20mailbox%20yang%20ada",
                                status_code=303)
    entries = [e for e in await _read_virtual_map() if e["source"] != source]
    entries.append({"source": source, "dest": targets})
    await _write_virtual_map(entries)
    set_setting(f"mail_vk:{source}", "catchall")
    return RedirectResponse(f"/email/aliases?domain={domain}&msg=Catch-all%20{domain}%20→%20{targets[0]}",
                            status_code=303)


@router.post("/email/aliases/catchall/clear")
async def email_alias_catchall_clear(domain: str = Form(""),
                                     user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    source = f"@{domain}"
    # Buang entry @domain + alias identitas sisa mailbox domain tsb (rapi).
    entries = [e for e in await _read_virtual_map()
               if e["source"] != source and not (
                   e["source"].endswith(f"@{domain}")
                   and len(e["dest"]) == 1 and e["dest"][0] == e["source"])]
    await _write_virtual_map(entries)
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (f"mail_vk:{source}",))
        conn.commit()
    return RedirectResponse(f"/email/aliases?domain={domain}&msg=Catch-all%20dinonaktifkan",
                            status_code=303)


# ────────────────────────────────── Vacation / Autoresponder ──────────────────

@router.post("/email/accounts/vacation")
async def email_account_vacation(username: str = Form(...),
                                 domain: str = Form(""),
                                 subject: str = Form(""),
                                 message: str = Form(""),
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{username}@{domain}".lower()
    if subject.strip() and message.strip():
        set_setting(f"mail_vacation:{email}",
                    json.dumps({"subject": subject.strip(), "message": message.strip()}))
        await _write_sieve_file(email, _vacation_script(subject, message))
        msg = "Autoresponder%20diaktifkan"
    else:
        with get_conn() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (f"mail_vacation:{email}",))
            conn.commit()
        await _write_sieve_file(email, "# disabled\n")
        msg = "Autoresponder%20dinonaktifkan"
    return RedirectResponse(f"/email/accounts?domain={domain}&msg={msg}", status_code=303)


# ────────────────────────────────── Mail Alias & Forwarder ─────────────────────

@router.get("/email/aliases", response_class=HTMLResponse)
async def email_aliases_page(request: Request, domain: str = "",
                             msg: str = "",
                             user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _mail_domains()
    if not domain and domains:
        domain = domains[0]["name"]
    entries = [e for e in await _read_virtual_map() if _entry_kind(e) == "alias"]
    mailboxes = await _read_vmailbox_emails() if get_executor().mode in ("local", "wsl") else []
    catchall = next((e["dest"] for e in await _read_virtual_map()
                     if e["source"] == f"@{domain}"), [])
    return render(request, "email_aliases.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "entries": entries,
        "mailboxes": mailboxes, "catchall": catchall,
        "active": "email-aliases",
    })


async def _alias_targets(dest: str) -> list[str]:
    targets = [d.strip().lower() for d in dest.split(",") if d.strip()]
    if not targets:
        return []
    for t in targets:
        if not _EMAIL_ADDR_RE.match(t):
            return []
    return targets


async def _resolve_alias_dest(raw: str, existing: list[str]) -> list[str] | None:
    """Validasi destination alias: harus mailbox yang sudah ada."""
    targets = await _alias_targets(raw)
    if targets and all(t in existing for t in targets):
        return targets
    return None


@router.post("/email/aliases/add")
async def email_alias_add(source: str = Form(...),
                          domain: str = Form(...),
                          dest: str = Form(...),
                          user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    if not _EMAIL_ADDR_RE.match(email):
        return RedirectResponse("/email/aliases?msg=Alias%20tidak%20valid", status_code=303)
    existing = await _read_vmailbox_emails()
    targets = await _resolve_alias_dest(dest, existing)
    if not targets:
        return RedirectResponse("/email/aliases?msg=Target%20harus%20mailbox%20yang%20ada", status_code=303)
    entries = [e for e in await _read_virtual_map() if e["source"] != email]
    entries.append({"source": email, "dest": targets})
    await _write_virtual_map(entries)
    set_setting(f"mail_vk:{email}", "alias")
    return RedirectResponse(f"/email/aliases?domain={domain}&msg=Alias%20{email}%20dibuat",
                            status_code=303)


@router.post("/email/aliases/delete")
async def email_alias_delete(source: str = Form(...),
                             domain: str = Form(""),
                             user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    keep = [e for e in await _read_virtual_map() if e["source"] != email]
    await _write_virtual_map(keep)
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (f"mail_vk:{email}",))
        conn.commit()
    return RedirectResponse(f"/email/aliases?domain={domain}&msg=Alias%20dihapus",
                            status_code=303)


@router.get("/email/forwarders", response_class=HTMLResponse)
async def email_forwarders_page(request: Request, domain: str = "",
                                msg: str = "",
                                user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _mail_domains()
    if not domain and domains:
        domain = domains[0]["name"]
    entries = [e for e in await _read_virtual_map() if _entry_kind(e) == "forwarder"]
    return render(request, "email_forwarders.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "entries": entries,
        "active": "email-forwarders",
    })


@router.post("/email/forwarders/add")
async def email_forwarder_add(source: str = Form(...),
                              domain: str = Form(...),
                              dest: str = Form(...),
                              user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    if not _EMAIL_ADDR_RE.match(email):
        return RedirectResponse("/email/forwarders?msg=Alamat%20tidak%20valid", status_code=303)
    targets = await _alias_targets(dest)
    if not targets:
        return RedirectResponse("/email/forwarders?msg=Tujuan%20tidak%20valid", status_code=303)
    entries = [e for e in await _read_virtual_map() if e["source"] != email]
    entries.append({"source": email, "dest": targets})
    await _write_virtual_map(entries)
    set_setting(f"mail_vk:{email}", "forwarder")
    return RedirectResponse(f"/email/forwarders?domain={domain}&msg=Forwarder%20{email}%20dibuat",
                            status_code=303)


@router.post("/email/forwarders/delete")
async def email_forwarder_delete(source: str = Form(...),
                                 domain: str = Form(""),
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    keep = [e for e in await _read_virtual_map() if e["source"] != email]
    await _write_virtual_map(keep)
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (f"mail_vk:{email}",))
        conn.commit()
    return RedirectResponse(f"/email/forwarders?domain={domain}&msg=Forwarder%20dihapus",
                            status_code=303)


# ────────────────────────────────── Mailing List ───────────────────────────────

@router.get("/email/lists", response_class=HTMLResponse)
async def email_lists_page(request: Request, domain: str = "",
                           msg: str = "",
                           user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    domains = _mail_domains()
    if not domain and domains:
        domain = domains[0]["name"]
    entries = [e for e in await _read_virtual_map() if _entry_kind(e) == "list"]
    mailboxes = await _read_vmailbox_emails() if get_executor().mode in ("local", "wsl") else []
    return render(request, "email_lists.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "entries": entries,
        "mailboxes": mailboxes, "active": "email-lists",
    })


@router.post("/email/lists/add")
async def email_list_add(source: str = Form(...),
                         domain: str = Form(...),
                         dest: str = Form(...),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    if not _EMAIL_ADDR_RE.match(email):
        return RedirectResponse("/email/lists?msg=Nama%20list%20tidak%20valid", status_code=303)
    existing = await _read_vmailbox_emails()
    members = await _resolve_alias_dest(dest, existing)
    if not members:
        return RedirectResponse("/email/lists?msg=Anggota%20harus%20mailbox%20yang%20ada", status_code=303)
    entries = [e for e in await _read_virtual_map() if e["source"] != email]
    entries.append({"source": email, "dest": members})
    await _write_virtual_map(entries)
    set_setting(f"mail_vk:{email}", "list")
    # Catat daftar anggota sebagai setting terpisah agar mudah diekspos ke panel lain
    set_setting(f"mail_members:{email}", ",".join(members))
    return RedirectResponse(f"/email/lists?domain={domain}&msg=List%20{email}%20disimpan",
                            status_code=303)


@router.post("/email/lists/delete")
async def email_list_delete(source: str = Form(...),
                            domain: str = Form(""),
                            user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    email = f"{source}@{domain}".lower()
    keep = [e for e in await _read_virtual_map() if e["source"] != email]
    await _write_virtual_map(keep)
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key IN (?, ?)",
                     (f"mail_vk:{email}", f"mail_members:{email}"))
        conn.commit()
    return RedirectResponse(f"/email/lists?domain={domain}&msg=List%20dihapus",
                            status_code=303)


def _roundcube_autologin(email: str, password: str,
                         base: str = "http://127.0.0.1/roundcube") -> dict[str, str]:
    """Login ke Roundcube server-side dan kembalikan SEMUA cookie sesi.

    Roundcube 1.6+ menerbitkan dua cookie penanda sesi:
    `roundcube_sessid` (PHP session) dan `roundcube_sessauth`
    (anti session-hijacking). Keduanya wajib dipasang di browser agar
    sesi dianggap sah; mengembalikan dict nama->nilai, atau {} bila gagal.
    `base` bisa diganti untuk test/instalasi non-standar.
    """
    base = base.rstrip("/")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        # 1) Ambil halaman login: dapatkan CSRF token + sesi awal.
        with opener.open(base + "/?_task=login", timeout=15) as resp:
            html = resp.read().decode("utf-8", "replace")
        m = re.search(r'name="_token"\s+value="([^"]+)"', html)
        if not m:
            return {}
        token = m.group(1).replace("&amp;", "&")

        # 2) POST kredensial.
        data = urllib.parse.urlencode({
            "_token": token,
            "_task": "login",
            "_action": "login",
            "_timezone": "_default_",
            "_url": "_task=login",
            "_host": "localhost:143",
            "_user": email,
            "_pass": password,
        }).encode()
        req = urllib.request.Request(base + "/?_task=login", data=data)
        with opener.open(req, timeout=25) as resp:
            resp.read()

        # 3) Kumpulkan semua cookie penanda sesi dari cookie jar.
        cookies: dict[str, str] = {}
        for c in jar:
            if c.name.startswith("roundcube_sess"):
                cookies[c.name] = c.value
        return cookies
    except Exception:
        return {}


@router.get("/email/accounts/webmail/{username}")
async def email_account_webmail(username: str, request: Request,
                                domain: str = "",
                                user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    email = f"{username}@{domain}" if domain else f"{username}@localhost"
    password = _get_mailbox_pass(email)
    if not password:
        return HTMLResponse("<div style='font-family:system-ui;padding:2rem'>"
                            "Password mailbox tidak tersimpan — set password dahulu.</div>",
                            status_code=400)
    cookies = _roundcube_autologin(email, password)
    if not cookies or "roundcube_sessid" not in cookies:
        return HTMLResponse("<div style='font-family:system-ui;padding:2rem'>"
                            "Auto-login ke Roundcube gagal. Cek layanan mail server.</div>",
                            status_code=502)
    # Pasang cookie sesi Roundcube via Set-Cookie (HttpOnly + SameSite=Lax)
    # sehingga browser memakainya saat dialihkan ke webmail di host yang sama
    # (cookie berbasis host, port bebas). Skema & host diambil dari request panel.
    secure = request.url.scheme == "https"
    scheme = request.url.scheme
    host = request.url.hostname
    resp = HTMLResponse(
        f"<!DOCTYPE html><html><body><script>\n"
        f"window.location.replace(\"{scheme}://{host}/roundcube/\");\n"
        f"</script></body></html>")
    for name, value in cookies.items():
        resp.set_cookie(name, value, path="/", secure=secure,
                        httponly=True, samesite="lax")
    return resp


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
    dkim_name = f"weborn._domainkey.{domain}" if domain else ""
    dkim_val = next((r["value"] for r in dns_records
                     if r["name"] == dkim_name and r["type"] == "TXT"), "")
    dkim_val = "".join(dkim_val.split())  # buang semua whitespace
    return render(request, "email_dns.html", {
        "user": user, "msg": msg, "domains": domains,
        "selected_domain": domain, "dns_records": dns_records,
        "dkim_name": dkim_name, "server_ip": server_ip,
        "dkim_value": dkim_val,
        "domain_has_dkim": f"weborn._domainkey.{domain}" in {r["name"] for r in dns_records},
        "active": "email-dns",
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


@router.post("/email/dns/record/edit")
async def email_dns_edit(record_id: int = Form(...),
                         domain: str = Form(""),
                         record_type: str = Form("MX"),
                         name: str = Form(""),
                         value: str = Form(""),
                         ttl: int = Form(300),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    with get_conn() as conn:
        conn.execute(
            "UPDATE dns_records SET type=?, name=?, value=?, ttl=? WHERE id=?",
            (record_type, name, value, ttl, record_id))
        conn.commit()
    return RedirectResponse(f"/email/dns?domain={domain}&msg=DNS%20record%20diperbarui",
                            status_code=303)


@router.post("/email/dns/dkim/generate")
async def email_dns_dkim_generate(domain: str = Form(""),
                                  user: dict = Depends(require_admin)):
    """Regenerasi pasangan kunci DKIM untuk domain mail tertentu.

    Mengulang langkah setup: opendkim-genkey → rename key `{domain}.weborn.*`
    → kepemilikan root:root 0700 → publikasi ulang TXT `weborn._domainkey.{domain}`
    di dns_records (upsert) → restart opendkim agar kunci baru dimuat.
    """
    if hasattr(user, "headers"):
        return user
    if domain not in _mail_domain_names():
        return RedirectResponse("/email/dns?msg=Domain%20bukan%20mail%20domain",
                                status_code=303)
    ex = get_executor()
    dkim_key_dir = "/var/lib/opendkim/keys"
    await ex.run("bash", "-c",
                 "sudo mkdir -p /etc/opendkim /var/lib/opendkim/keys /var/spool/postfix/opendkim")
    await ex.run("bash", "-c",
                 f"sudo opendkim-genkey -D {dkim_key_dir} -d {shlex.quote(domain)} -s weborn -b 2048 2>/dev/null || true")
    await ex.run("bash", "-c",
                 f"sudo mv -f {dkim_key_dir}/weborn.private {dkim_key_dir}/{domain}.weborn.private 2>/dev/null || true")
    await ex.run("bash", "-c",
                 f"sudo mv -f {dkim_key_dir}/weborn.txt {dkim_key_dir}/{domain}.weborn.txt 2>/dev/null || true")
    # opendkim berjalan sebagai root → kunci root:root 0700 agar termuat.
    await ex.run("bash", "-c",
                 f"sudo chown -R root:root {dkim_key_dir} && sudo chmod 700 {dkim_key_dir}")
    await ex.run("bash", "-c",
                 "sudo chown opendkim:postfix /var/spool/postfix/opendkim && sudo chmod 2775 /var/spool/postfix/opendkim")
    dkim_pub = await _read_text_file(f"{dkim_key_dir}/{domain}.weborn.txt")
    dkim_val = "".join(re.findall(r'"([^"]*)"', dkim_pub or "")).strip() or (dkim_pub or "").strip()
    if dkim_val:
        with get_conn() as conn:
            conn.execute("DELETE FROM dns_records WHERE name = ? AND type = 'TXT'",
                         (f"weborn._domainkey.{domain}",))
            conn.execute(
                "INSERT INTO dns_records(name, type, value, ttl, created_at) VALUES (?,?,?,?,?)",
                (f"weborn._domainkey.{domain}", "TXT", dkim_val, 300, datetime.now().isoformat()))
            conn.commit()
    if ex.mode in ("local", "wsl"):
        await ex.run("bash", "-c", "sudo systemctl restart opendkim 2>/dev/null || true")
    return RedirectResponse(f"/email/dns?domain={domain}&msg=DKIM%20key%20di-generate%20ulang",
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
        r = await ex.run("bash", "-c", "systemctl is-active apache2 2>/dev/null || echo inactive")
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
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("bash", "-c",
                     "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                     "roundcube-core roundcube-mysql roundcube-plugins")
        await ex.run("bash", "-c", "sudo systemctl enable apache2 2>/dev/null || true")
        await ex.run("bash", "-c", "sudo systemctl restart apache2 2>/dev/null || true")
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
    opendkim_installed, opendkim_active = False, False
    if ex.mode in ("local", "wsl"):
        for svc, unit, bin_name in [
            ("rspamd", "rspamd", "rspamd"),
            ("clamav", "clamav-daemon", "clamd"),
            ("opendkim", "opendkim", "opendkim"),
        ]:
            r = await ex.run("bash", "-c", f"command -v {bin_name} 2>/dev/null && echo yes || echo no")
            is_installed = "yes" in r.stdout
            r2 = await ex.run("bash", "-c", f"systemctl is-active {unit} 2>/dev/null || echo inactive")
            is_active = r2.stdout.strip() == "active"
            if svc == "rspamd":
                rspamd_installed, rspamd_active = is_installed, is_active
            elif svc == "clamav":
                clamav_installed, clamav_active = is_installed, is_active
            elif svc == "opendkim":
                opendkim_installed, opendkim_active = is_installed, is_active
    return render(request, "email_security.html", {
        "user": user, "msg": msg,
        "rspamd_installed": rspamd_installed, "rspamd_active": rspamd_active,
        "clamav_installed": clamav_installed, "clamav_active": clamav_active,
        "opendkim_installed": opendkim_installed, "opendkim_active": opendkim_active,
        "active": "email-security",
    })


@router.post("/email/security/install")
async def email_security_install(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        pkgs = "rspamd opendkim opendkim-tools clamav clamav-daemon"
        await ex.run("bash", "-c", f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}")
        for svc in ["rspamd", "opendkim", "clamav-daemon"]:
            await ex.run("bash", "-c", f"sudo systemctl enable {svc} 2>/dev/null || true")
            await ex.run("bash", "-c", f"sudo systemctl restart {svc} 2>/dev/null || true")
    return JSONResponse({"ok": True, "output": "Spam & DKIM stack dipasang"})


@router.post("/email/security/service/{service}/{action}")
async def email_security_service(service: str, action: str,
                                 user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    service_map = {"rspamd": "rspamd", "clamav": "clamav-daemon",
                   "opendkim": "opendkim"}
    svc = service_map.get(service)
    if not svc or action not in ("start", "stop", "restart"):
        return JSONResponse({"ok": False, "error": "Invalid action"})
    await get_executor().run("bash", "-c", f"sudo systemctl {action} {svc}")
    return JSONResponse({"ok": True, "output": f"{service} {action}d"})
