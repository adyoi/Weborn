"""Router App Monitor: Gunicorn process monitoring, self-monitoring & orphan detection."""
import asyncio
import json
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from starlette.responses import JSONResponse

from ..auth import require_admin
from ..config import APP_TYPES, GUNICORN_SOCK_DIR, PANEL_HTTP_PORT
from ..db import get_app, list_apps
from ..executors import get_executor
from ..managers.apps import AppManager, _app_type_for, _detect_pm, _slug
from ..ui import render

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Self-monitoring: detect panel's own Gunicorn/Uvicorn processes
# ─────────────────────────────────────────────────────────────────────────────
async def _detect_panel_process(ex) -> dict:
    """Detect the Weborn panel's own running process(es).

    Returns dict with keys: mode, master_pid, workers, port, pids
    mode: 'gunicorn' | 'uvicorn' | 'python' | 'unknown'
    """
    info = {"mode": "unknown", "master_pid": "", "workers": [], "port": PANEL_HTTP_PORT, "pids": []}

    if ex.mode not in ("local", "wsl"):
        info["mode"] = "dry-run"
        return info

    # Find processes listening on panel port
    r = await ex.run("bash", "-c",
                     f"ss -tlnp sport = :{PANEL_HTTP_PORT} 2>/dev/null | grep -v State")
    pids_found = set()
    for line in r.stdout.splitlines():
        m = re.search(r'pid=(\d+)', line)
        if m:
            pids_found.add(m.group(1))

    if not pids_found:
        # Fallback: find by command pattern
        r2 = await ex.run("bash", "-c",
                          "ps -eo pid,cmd --no-headers | grep -E 'uvicorn.*weborn\\.main|gunicorn.*weborn\\.main|python.*run\\.py' | grep -v grep")
        for line in r2.stdout.splitlines():
            parts = line.split(None, 1)
            if parts:
                pids_found.add(parts[0])

    if not pids_found:
        return info

    info["pids"] = list(pids_found)
    # Take the first (main) PID
    main_pid = list(pids_found)[0]

    # Determine mode from command
    r3 = await ex.run("bash", "-c", f"ps -p {main_pid} -o cmd= 2>/dev/null")
    cmd = r3.stdout.strip()
    info["master_pid"] = main_pid

    if "gunicorn" in cmd:
        info["mode"] = "gunicorn"
        # Find master PID (gunicorn master has -w flag)
        r4 = await ex.run("bash", "-c",
                          f"ps -eo pid,ppid,cmd --no-headers | grep 'gunicorn.*weborn\\.main\\|gunicorn.*main:app' | grep -v grep")
        gunicorn_pids = {}
        for line in r4.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 3:
                pid, ppid, gcmd = parts
                gunicorn_pids[pid] = (ppid, gcmd)

        # Find the master (the one with -w flag)
        master = main_pid
        for pid, (ppid, gcmd) in gunicorn_pids.items():
            if "-w" in gcmd:
                master = pid
                break
        info["master_pid"] = master

        # Find workers (children of master)
        r5 = await ex.run("bash", "-c",
                          f"ps --ppid {master} -o pid,pcpu,pmem,etime,cmd --no-headers 2>/dev/null")
        for line in r5.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 5:
                info["workers"].append({
                    "pid": parts[0], "cpu": parts[1], "mem": parts[2],
                    "uptime": parts[3], "cmd": parts[4],
                })

    elif "uvicorn" in cmd:
        info["mode"] = "uvicorn"
        # Check for --workers flag
        if "--workers" in cmd:
            # Find child processes
            r4 = await ex.run("bash", "-c",
                              f"ps --ppid {main_pid} -o pid,pcpu,pmem,etime,cmd --no-headers 2>/dev/null")
            for line in r4.stdout.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    info["workers"].append({
                        "pid": parts[0], "cpu": parts[1], "mem": parts[2],
                        "uptime": parts[3], "cmd": parts[4],
                    })

    elif "python" in cmd and "run.py" in cmd:
        info["mode"] = "python"
        info["master_pid"] = main_pid
        # Get resource info for single-process panel
        r5 = await ex.run("bash", "-c",
                          f"ps -p {main_pid} -o pcpu,pmem,etime --no-headers 2>/dev/null")
        parts = r5.stdout.strip().split()
        if len(parts) >= 3:
            info["workers"] = [{
                "pid": main_pid, "cpu": parts[0], "mem": parts[1],
                "uptime": parts[2], "cmd": cmd,
            }]

    return info


# ─────────────────────────────────────────────────────────────────────────────
# Orphan detection: python/gunicorn/uvicorn processes NOT managed by systemd
# ─────────────────────────────────────────────────────────────────────────────
async def _collect_descendants(ex, pid: str) -> set:
    """Recursively collect all descendant PIDs of a given PID."""
    pids = set()
    r = await ex.run("bash", "-c",
                     f"ps --ppid {pid} -o pid= 2>/dev/null")
    for line in r.stdout.splitlines():
        child = line.strip()
        if child.isdigit():
            pids.add(child)
            pids |= await _collect_descendants(ex, child)
    return pids


async def _detect_orphan_processes(ex) -> list:
    """Find python/gunicorn/uvicorn processes NOT managed by systemd weborn-* services.

    Returns list of dicts: {pid, ppid, user, cpu, mem, uptime, cmd}
    """
    if ex.mode not in ("local", "wsl"):
        return []

    # 1) Collect ALL PIDs managed by weborn-* systemd services (recursive)
    managed_pids = set()
    r = await ex.run("bash", "-c",
                     "systemctl list-units --type=service --all --no-legend 2>/dev/null "
                     "| awk '/weborn-/{print $1}'")
    for svc in r.stdout.splitlines():
        svc = svc.strip()
        if not svc:
            continue
        r2 = await ex.run("bash", "-c",
                          f"systemctl show {svc} --property=MainPID --value 2>/dev/null")
        mp = r2.stdout.strip()
        if mp and mp.isdigit() and int(mp) > 0:
            managed_pids.add(mp)
            children = await _collect_descendants(ex, mp)
            managed_pids |= children

    # 2) Collect panel PID + ALL descendants (journalctl streams, etc)
    r4 = await ex.run("bash", "-c",
                      f"ss -tlnp sport = :{PANEL_HTTP_PORT} 2>/dev/null "
                      "| grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+'")
    panel_pids = set()
    for line in r4.stdout.splitlines():
        pid = line.strip()
        if pid.isdigit():
            panel_pids.add(pid)
            children = await _collect_descendants(ex, pid)
            panel_pids |= children
    managed_pids |= panel_pids

    # 3) Find all python/gunicorn/uvicorn processes
    r5 = await ex.run("bash", "-c",
                      "ps -eo pid,ppid,user,pcpu,pmem,etime,cmd --no-headers 2>/dev/null "
                      "| grep -E 'gunicorn|uvicorn' "
                      "| grep -v grep")
    orphans = []
    for line in r5.stdout.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, ppid, user, cpu, mem, uptime, cmd = parts
        if pid in managed_pids:
            continue
        orphans.append({
            "pid": pid, "ppid": ppid, "user": user,
            "cpu": cpu, "mem": mem, "uptime": uptime, "cmd": cmd,
        })

    return orphans


@router.get("/apps/monitor", response_class=HTMLResponse)
async def apps_monitor_page(request: Request, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    apps = list_apps()
    ex = get_executor()
    manager = AppManager(ex)

    # Enrich app data with Gunicorn status
    for a in apps:
        stored = a.get("app_type", "")
        a["app_type"] = stored if stored else _app_type_for(a["language"], a.get("framework", ""))
        if a.get("command"):
            a["process_manager"] = _detect_pm(a["command"])
        else:
            a["process_manager"] = APP_TYPES.get(a["app_type"], {}).get("process_manager", "direct")
        a["slug"] = _slug(a["name"])

        if a["process_manager"] in ("gunicorn", "uvicorn") and ex.mode in ("local", "wsl"):
            status = await manager.get_process_status(a["name"])
            a["gunicorn_status"] = status.get("status", "unknown")
            a["master_pid"] = status.get("master_pid", "")
            a["workers"] = status.get("workers", [])
        else:
            a["gunicorn_status"] = a.get("status", "unknown")
            a["master_pid"] = ""
            a["workers"] = []

    # Self-monitoring: Weborn panel's own process
    panel_info = await _detect_panel_process(ex)

    # Orphan detection: python processes outside systemd
    orphans = await _detect_orphan_processes(ex)

    return render(request, "app_monitor.html", {
        "user": user,
        "apps": apps,
        "panel_info": panel_info,
        "orphans": orphans,
        "active": "app-monitor",
    })


@router.get("/apps/{app_id}/monitor", response_class=HTMLResponse)
async def apps_monitor_detail(request: Request, app_id: int,
                               user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return HTMLResponse("App tidak ditemukan", status_code=404)

    ex = get_executor()
    manager = AppManager(ex)

    stored = app.get("app_type", "")
    app["app_type"] = stored if stored else _app_type_for(app["language"], app.get("framework", ""))
    if app.get("command"):
        app["process_manager"] = _detect_pm(app["command"])
    else:
        app["process_manager"] = APP_TYPES.get(app["app_type"], {}).get("process_manager", "direct")
    app["slug"] = _slug(app["name"])

    # Process status
    gstatus = {"status": "unknown", "master_pid": "", "workers": []}
    if app["process_manager"] in ("gunicorn", "uvicorn") and ex.mode in ("local", "wsl"):
        gstatus = await manager.get_process_status(app["name"])
    elif ex.mode in ("local", "wsl"):
        # For non-gunicorn, check systemd status
        r = await ex.run("bash", "-c",
                         f"systemctl is-active {app['unit']} 2>/dev/null || echo stopped")
        gstatus["status"] = r.stdout.strip()

    # Get resource usage from /proc if running
    resource_info = {}
    if gstatus.get("master_pid") and gstatus["master_pid"].isdigit():
        pid = gstatus["master_pid"]
        r = await ex.run("bash", "-c",
                         f"cat /proc/{pid}/status 2>/dev/null | grep -E '^(VmRSS|VmSize|Threads|Name)' || echo none")
        if r.ok and "none" not in r.stdout:
            for line in r.stdout.strip().splitlines():
                k, _, v = line.partition(":")
                resource_info[k.strip()] = v.strip()

    # Memory/CPU summary from all workers
    total_cpu = 0.0
    total_mem = 0.0
    for w in gstatus.get("workers", []):
        try:
            total_cpu += float(w.get("cpu", "0"))
        except ValueError:
            pass
        try:
            total_mem += float(w.get("mem", "0"))
        except ValueError:
            pass

    return render(request, "app_monitor_detail.html", {
        "user": user,
        "app": app,
        "gstatus": gstatus,
        "resource_info": resource_info,
        "total_cpu": total_cpu,
        "total_mem": total_mem,
        "active": "app-monitor",
    })


@router.get("/apps/{app_id}/status")
async def app_status(app_id: int, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    app = get_app(app_id)
    if not app:
        return JSONResponse({"ok": False, "error": "app tidak ditemukan"}, status_code=404)

    ex = get_executor()
    manager = AppManager(ex)
    status = await manager.get_process_status(app["name"])
    status["app"] = app["name"]
    status["ok"] = True
    return JSONResponse(status)


@router.post("/api/monitor/kill-orphan")
async def kill_orphan_process(request: Request, user: dict = Depends(require_admin)):
    """Kill an orphan process by PID."""
    if hasattr(user, "headers"):
        return user
    body = await request.json()
    pid = body.get("pid", "")
    if not pid or not str(pid).isdigit():
        return JSONResponse({"ok": False, "error": "PID tidak valid"}, status_code=400)

    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return JSONResponse({"ok": False, "error": "dry-run mode"}, status_code=400)

    await ex.run("bash", "-c", f"kill -15 {pid} 2>/dev/null")
    import asyncio
    await asyncio.sleep(0.5)
    await ex.run("bash", "-c", f"kill -9 {pid} 2>/dev/null")

    return JSONResponse({"ok": True, "message": f"Process {pid} terminated"})


@router.post("/api/monitor/kill-all-orphans")
async def kill_all_orphans(request: Request, user: dict = Depends(require_admin)):
    """Kill all orphan processes."""
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        return JSONResponse({"ok": False, "error": "dry-run mode"}, status_code=400)

    orphans = await _detect_orphan_processes(ex)
    killed = 0
    import asyncio
    for o in orphans:
        pid = o["pid"]
        await ex.run("bash", "-c", f"kill -9 {pid} 2>/dev/null")
        killed += 1

    return JSONResponse({"ok": True, "message": f"Killed {killed} orphan processes"})
