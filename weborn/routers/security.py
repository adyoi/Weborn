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
            r = await ex.run("bash", "-c", "clamscan --version")
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
        await ex.run("bash", "-c", "sudo freshclam --quiet 2>/dev/null || true")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": "Database diperbarui"})


@router.post("/security/clamav/scan")
async def clamav_scan(request: Request, path: str = Form("/home"),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo clamscan -r --infected --no-summary {path} 2>/dev/null")
        from starlette.responses import JSONResponse
        return JSONResponse({
            "ok": r.ok,
            "output": r.stdout[:2000] if r.stdout else r.stderr[:1000],
            "infected": not r.ok,
        })
    return JSONResponse({"ok": True, "output": "[dry-run] scan disimulasi"})


@router.post("/security/clamav/scan/stop")
async def clamav_scan_stop(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("bash", "-c", "sudo pkill -f clamscan 2>/dev/null || true")
    return RedirectResponse("/security/clamav?msg=Scan+dihentikan", status_code=303)


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
            r = await ex.run("bash", "-c", "sudo fail2ban-client status 2>/dev/null || echo ''")
            service_active = r.ok and "running" in r.stdout.lower()
            if service_active:
                for line in r.stdout.splitlines():
                    if "Jail list" in line:
                        jails = [j.strip() for j in line.split(":")[-1].split(",") if j.strip()]
                for jail in jails:
                    r3 = await ex.run("bash", "-c", f"sudo fail2ban-client status {jail} 2>/dev/null || echo ''")
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
    await get_executor().run("bash", "-c", "sudo fail2ban-client start")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": "Fail2Ban dimulai"})


@router.post("/security/fail2ban/stop")
async def fail2ban_stop(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("bash", "-c", "sudo fail2ban-client stop")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": "Fail2Ban dihentikan"})


@router.post("/security/fail2ban/unban")
async def fail2ban_unban(ip: str = Form(...), jail: str = Form("sshd"),
                         user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("bash", "-c", f"sudo fail2ban-client set {jail} unbanip {ip}")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": f"{ip} diunban"})


@router.post("/security/fail2ban/ban")
async def fail2ban_ban(ip: str = Form(...), jail: str = Form("sshd"),
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("bash", "-c", f"sudo fail2ban-client set {jail} banip {ip}")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": f"{ip} dibanned"})


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
        r = await ex.run("bash", "-c", "sudo ufw status numbered 2>/dev/null || echo ''")
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
    await get_executor().run("bash", "-c", f"echo 'y' | sudo ufw allow {port}/{proto}")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": f"Port {port}/{proto} diizinkan"})


@router.post("/security/firewall/deny")
async def firewall_deny(port: str = Form(...), proto: str = Form("tcp"),
                        user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    await get_executor().run("bash", "-c", f"echo 'y' | sudo ufw deny {port}/{proto}")
    from starlette.responses import JSONResponse
    return JSONResponse({"ok": True, "output": f"Port {port}/{proto} ditolak"})


@router.post("/security/firewall/toggle")
async def firewall_toggle(user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    from starlette.responses import JSONResponse
    r = await ex.run("bash", "-c", "sudo ufw status 2>/dev/null || echo ''")
    if "active" in r.stdout.lower():
        await ex.run("bash", "-c", "echo 'y' | sudo ufw disable")
        return JSONResponse({"ok": True, "output": "Firewall dimatikan"})
    else:
        await ex.run("bash", "-c", "echo 'y' | sudo ufw enable")
        return JSONResponse({"ok": True, "output": "Firewall diaktifkan"})
