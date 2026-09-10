"""Health check untuk semua aplikasi inti Weborn.

Dipakai halaman Info → Status. Mengumpulkan per-layanan:
installed / active / reachable / latency / version, lalu merangkum
kondisi keseluruhan (ok | warn | down | not-installed).
"""
import asyncio
from datetime import datetime

from .addons import AddonManager
from .config import PANEL_HTTP_PORT, VERSION
from .db import list_apps
from .executors import get_executor
from .managers.apps import _slug

CATEGORY_ICON = {
    "panel": "bolt",
    "web-server": "globe-alt",
    "database": "server-stack",
    "cache": "square-3-stack-3d",
    "mail": "envelope",
    "security": "shield-check",
    "monitoring": "eye",
    "runtime": "code-bracket",
    "remote-access": "key",
    "watchdog": "clock",
    "log": "document-text",
    "other": "cube",
    "app": "rocket-launch",
}

CATEGORY_LABEL = {
    "panel": "Panel",
    "web-server": "Web Server",
    "database": "Database",
    "cache": "Cache",
    "mail": "Mail Server",
    "security": "Keamanan",
    "monitoring": "Monitoring",
    "runtime": "Runtime",
    "remote-access": "Akses Jauh",
    "watchdog": "Watchdog",
    "log": "Log Rotation",
    "other": "Lainnya",
    "app": "Weborn Apps",
}


async def tcp_probe(port, host="127.0.0.1", timeout=1.5):
    """Probe TCP ke host:port. Return (ok: bool|None, latency_ms: float|None)."""
    if not port:
        return None, None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None, None
    try:
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        latency = round((loop.time() - t0) * 1000, 1)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True, latency
    except Exception:
        return False, None


def _compute_state(item, simulated: bool) -> str:
    """Kesimpulan status: ok | warn | down | not-installed."""
    if simulated:
        return "ok"
    if not item["installed"]:
        return "not-installed"
    if not item.get("needs_active", True):
        return "ok"  # runtime / plugin image cukup 'terpasang'
    if not item["active"]:
        return "down"
    if item["reachable"] is False:
        return "warn"  # unit aktif tapi port tidak merespon
    return "ok"


async def collect_health(ex=None) -> dict:
    """Kumpulkan health check semua aplikasi inti.

    Return dict: {checks: [...], summary: {...}, mode, checked_at}.
    """
    ex = ex or get_executor()
    simulated = ex.mode == "dry-run"
    do_probe = ex.mode in ("local", "wsl")
    manager = AddonManager(ex)
    checks = []

    def add(check: dict):
        check["state"] = _compute_state(check, simulated)
        checks.append(check)

    # ── Panel itu sendiri ──
    ok, lat = await tcp_probe(PANEL_HTTP_PORT) if do_probe else (None, None)
    add({
        "id": "weborn", "kind": "core", "category": "panel",
        "name": "Weborn Panel", "icon": "bolt", "unit": "weborn",
        "version": VERSION, "port": PANEL_HTTP_PORT,
        "installed": True, "active": True, "core": True,
        "reachable": ok if do_probe else None, "latency": lat,
        "needs_active": True, "detail": "Panel control aktif",
    })

    # ── Aplikasi Weborn (deployed apps) ──
    for a in list_apps():
        unit = a.get("unit") or f"weborn-{_slug(a['name'])}.service"
        port = a.get("port")
        active_r = await ex.systemctl("is-active", unit) if ex.mode in ("local", "wsl") else None
        active = bool(active_r and active_r.ok) if active_r else (a.get("status") == "running")
        ok, lat = await tcp_probe(port) if do_probe else (None, None)
        add({
            "id": f"app-{a['id']}", "kind": "app", "category": "app",
            "name": a["name"], "icon": "rocket-launch", "unit": unit,
            "version": a.get("framework") or a.get("language", "—"),
            "port": port, "installed": True, "active": active, "core": False,
            "reachable": ok if do_probe else None, "latency": lat,
            "needs_active": True,
            "detail": f"{a.get('language', '?')} · port {port or '—'}",
        })

    # ── Addon store (semua addon: aplikasi inti & pilihan) ──
    for addon in manager.list_addons():
        if addon.type == "builtin":
            continue
        try:
            st = await manager.status(addon)
        except Exception:
            st = {"installed": False, "active": False, "state": "unknown", "version": "—"}
        port = addon.ports[0] if addon.ports else None
        ok, lat = await tcp_probe(port) if do_probe else (None, None)
        needs_active = addon.type in ("system", "app")
        add({
            "id": addon.id, "kind": "addon", "category": addon.category,
            "name": addon.name, "icon": CATEGORY_ICON.get(addon.category, "cube"),
            "unit": addon.unit, "version": st.get("version", "—"),
            "port": port, "installed": st.get("installed", False),
            "active": st.get("active", False), "state_raw": st.get("state", "unknown"),
            "reachable": ok if do_probe else None, "latency": lat,
            "needs_active": needs_active, "core": bool(addon.core),
            "detail": (f"{addon.category} · {addon.source}"),
        })

    # ── Ringkasan (umum + aplikasi inti Weborn) ──
    order = ["ok", "warn", "down", "not-installed"]
    summary = {s: sum(1 for c in checks if c["state"] == s) for s in order}
    summary["total"] = len(checks)
    installed = [c for c in checks if c["state"] != "not-installed"]
    if summary["down"]:
        summary["overall"] = "down"
    elif summary["warn"]:
        summary["overall"] = "warn"
    elif len(installed) == summary["total"]:
        summary["overall"] = "ok"
    else:
        summary["overall"] = "partial"

    cores = [c for c in checks if c.get("core")]
    summary["core_total"] = len(cores)
    summary["core_ok"] = sum(1 for c in cores if c["state"] == "ok")
    summary["core_fault"] = sum(1 for c in cores if c["state"] in ("down", "warn"))
    if any(c["state"] in ("down", "warn") for c in cores):
        summary["core_overall"] = "fault"
    else:
        summary["core_overall"] = "ok"

    return {
        "checks": checks,
        "summary": summary,
        "mode": ex.mode,
        "simulated": simulated,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }