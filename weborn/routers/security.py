"""Security management: ClamAV, Fail2Ban, UFW."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..ui import render

router = APIRouter()


# ────────────────────────────────── ClamAV ────────────────────────────────────

@router.get("/security/clamav", response_class=HTMLResponse)
async def clamav_page(request: Request, msg: str = "",
                      user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed, version, db_date = True, "", ""
    scan_result = []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v clamscan && echo yes || echo no")
        installed = "yes" in r.stdout
        if installed:
            r = await ex.run("clamscan", "--version")
            version = r.stdout.strip().splitlines()[0] if r.stdout else ""
            r = await ex.run("bash", "-c", "stat -c %Y /var/lib/clamav/daily.cvd 2>/dev/null || echo 0")
            ts = r.stdout.strip()
            if ts.isdigit() and ts != "0":
                from datetime import datetime
                db_date = datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    return render(request, "security_clamav.html", {
        "user": user, "installed": installed, "version": version,
        "db_date": db_date, "scan_result": scan_result,
        "msg": msg, "active": "clamav",
    })


@router.post("/security/clamav/update")
async def clamav_update(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        await ex.run("freshclam", "--quiet")
    return RedirectResponse("/security/clamav?msg=Database%20ClamAV%20diperbarui", status_code=303)


@router.post("/security/clamav/scan")
async def clamav_scan(request: Request, path: str = Form("/home"),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("clamscan", "-r", "--infected", "--no-summary", path)
        return render(request, "security_clamav.html", {
            "user": user, "installed": True, "version": "", "db_date": "",
            "scan_result": r.stdout.splitlines()[:100],
            "scan_path": path, "scan_ok": r.ok, "active": "clamav",
        })
    return RedirectResponse("/security/clamav?msg=Dry-run%3A%20scan%20disimulasi", status_code=303)


@router.post("/security/clamav/scan/stop")
async def clamav_scan_stop(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("pkill", "-f", "clamscan")
    return RedirectResponse("/security/clamav?msg=Scan%20dihentikan", status_code=303)


# ────────────────────────────────── Fail2Ban ──────────────────────────────────

@router.get("/security/fail2ban", response_class=HTMLResponse)
async def fail2ban_page(request: Request, msg: str = "",
                        user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    installed, service_active = True, False
    jails, banned = [], []
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", "command -v fail2ban-client && echo yes || echo no")
        installed = "yes" in r.stdout
        if installed:
            r = await ex.run("fail2ban-client", "status")
            service_active = r.ok and "running" in r.stdout.lower()
            if service_active:
                for line in r.stdout.splitlines():
                    if "Jail list" in line:
                        jails = [j.strip() for j in line.split(":")[-1].split(",") if j.strip()]
                for jail in jails:
                    r3 = await ex.run("fail2ban-client", "status", jail)
                    for line in r3.stdout.splitlines():
                        if "Banned IP" in line:
                            ips = line.split(":")[-1].strip()
                            if ips and ips != "[]":
                                for ip in ips.strip("[]").split():
                                    banned.append({"ip": ip, "jail": jail})
    return render(request, "security_fail2ban.html", {
        "user": user, "installed": installed, "service_active": service_active,
        "jails": jails, "banned": banned,
        "msg": msg, "active": "fail2ban",
    })


@router.post("/security/fail2ban/start")
async def fail2ban_start(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("fail2ban-client", "start")
    return RedirectResponse("/security/fail2ban?msg=Fail2Ban%20dimulai", status_code=303)


@router.post("/security/fail2ban/stop")
async def fail2ban_stop(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("fail2ban-client", "stop")
    return RedirectResponse("/security/fail2ban?msg=Fail2Ban%20dihentikan", status_code=303)


@router.post("/security/fail2ban/unban")
async def fail2ban_unban(ip: str = Form(...), jail: str = Form("sshd"),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("fail2ban-client", "set", jail, "unbanip", ip)
    return RedirectResponse(f"/security/fail2ban?msg={ip}%20diunban", status_code=303)


@router.post("/security/fail2ban/ban")
async def fail2ban_ban(ip: str = Form(...), jail: str = Form("sshd"),
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("fail2ban-client", "set", jail, "banip", ip)
    return RedirectResponse(f"/security/fail2ban?msg={ip}%20dibanned", status_code=303)


# ────────────────────────────────── UFW Firewall ──────────────────────────────

@router.get("/security/firewall", response_class=HTMLResponse)
async def firewall_page(request: Request, msg: str = "",
                        user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    rules = []
    service_active = False
    if ex.mode in ("local", "wsl"):
        r = await ex.run("ufw", "status", "numbered")
        service_active = r.ok and "active" in r.stdout.lower()
        for line in r.stdout.splitlines():
            if line.strip().startswith("["):
                rules.append(line.strip())
    return render(request, "security_firewall.html", {
        "user": user, "rules": rules, "service_active": service_active,
        "msg": msg, "active": "security",
    })


@router.post("/security/firewall/allow")
async def firewall_allow(port: str = Form(...), proto: str = Form("tcp"),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("ufw", "allow", f"{port}/{proto}")
    return RedirectResponse("/security/firewall?msg=Port%20diizinkan", status_code=303)


@router.post("/security/firewall/deny")
async def firewall_deny(port: str = Form(...), proto: str = Form("tcp"),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("ufw", "deny", f"{port}/{proto}")
    return RedirectResponse("/security/firewall?msg=Port%20ditolak", status_code=303)


@router.post("/security/firewall/toggle")
async def firewall_toggle(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    r = await ex.run("ufw", "status")
    if "active" in r.stdout.lower():
        await ex.run("ufw", "disable")
        return RedirectResponse("/security/firewall?msg=Firewall%20dimatikan", status_code=303)
    else:
        await ex.run("bash", "-c", "echo 'y' | ufw enable")
        return RedirectResponse("/security/firewall?msg=Firewall%20diaktifkan", status_code=303)
