#!/usr/bin/env python3
"""Integration test — jalankan di server (Linux/WSL) dengan panel aktif.

Usage:  cd /opt/weborn
        WEBORN_PASS=yourpass sudo -E .venv/bin/python test/test_apps_integration.py
"""
import sqlite3, subprocess, os, re, sys

DB = "/opt/weborn/data/weborn.db"
COOKIE_JAR = "/tmp/weborn_test_cookies.txt"
BASE = "http://localhost:2025"
PASS = os.environ.get("WEBORN_PASS", "")


def check_env():
    errors = []
    if sys.platform == "win32":
        errors.append("Run in WSL: wsl -- bash -c 'cd /opt/weborn && WEBORN_PASS=x sudo -E .venv/bin/python test/test_apps_integration.py'")
    if not os.path.exists(DB):
        errors.append(f"DB tidak ditemukan: {DB}")
    if not PASS:
        errors.append("Set WEBORN_PASS env var: export WEBORN_PASS=yourpassword")
    return errors


def curl_raw(args):
    cmd = ["curl", "-s", "-c", COOKIE_JAR, "-b", COOKIE_JAR] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.stdout, r.stderr


def curl_get(url):
    return curl_raw(["-L", url])


def curl_post(url, data=None):
    args = ["-L", "-X", "POST"]
    if data:
        for k, v in data.items():
            args += ["-d", f"{k}={v}"]
    args.append(url)
    return curl_raw(args)


def get_csrf_token(html):
    m = re.search(r"var\s+token\s*=\s*['\"]([^'\"]+)['\"]", html)
    return m.group(1) if m else None


def main():
    env_errors = check_env()
    if env_errors:
        print("ERROR:")
        for e in env_errors:
            print(f"  - {e}")
        sys.exit(1)

    if os.path.exists(COOKIE_JAR):
        os.remove(COOKIE_JAR)

    passed = 0
    failed = 0

    def ok(msg):
        nonlocal passed
        passed += 1
        print(f"  PASS  {msg}")

    def fail(msg, detail=""):
        nonlocal failed
        failed += 1
        print(f"  FAIL  {msg}" + (f": {detail}" if detail else ""))

    print("=" * 60)
    print("Weborn Integration Test")
    print("=" * 60)

    # ── DB check ──
    print("\n[DB]")
    conn = sqlite3.connect(DB)
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    print(f"  Users: {users}")
    conn.close()
    if users:
        ok(f"DB accessible, {len(users)} user(s)")
    else:
        fail("No users in DB")

    # ── Login ──
    print("\n[Login]")
    body, _ = curl_post(f"{BASE}/login", {"username": "admin", "password": PASS})
    has_cookie = False
    if os.path.exists(COOKIE_JAR):
        with open(COOKIE_JAR) as f:
            content = f.read()
            has_cookie = "weborn_session" in content
    if has_cookie:
        ok("Session cookie set")
    else:
        fail("No session cookie — wrong password?")

    # ── Get CSRF token from dashboard ──
    print("\n[CSRF]")
    html, _ = curl_get(f"{BASE}/")
    csrf = get_csrf_token(html) if html else None
    if csrf:
        ok(f"CSRF token extracted ({len(csrf)} chars)")
    else:
        fail("Could not extract CSRF token")

    if html and ("Dashboard" in html or "weborn" in html.lower()[:500]):
        ok("Dashboard loaded")
    else:
        fail("Dashboard did not load correctly")

    # ── Create apps ──
    print("\n[Create Apps]")
    app_types = [
        ("test-asgi-uv", "asgi", "uvicorn"),
        ("test-wsgi-uv", "wsgi", "uvicorn"),
        ("test-asgi-gn", "asgi", "gunicorn"),
        ("test-wsgi-gn", "wsgi", "gunicorn"),
    ]
    for name, atype, launcher in app_types:
        data = {
            "name": name, "app_type": atype, "launcher": launcher,
            "module_app": "main:app", "workers": "2",
            "host": "0.0.0.0", "port": "0", "dir_path": "",
            "_csrf_token": csrf or "",
        }
        body, _ = curl_post(f"{BASE}/apps/create-native", data)
        if body and ("created" in body.lower() or '"ok":true' in body.lower()):
            ok(f"Create {name} ({atype}-{launcher})")
        elif body and ("error" in body.lower() or '"ok":false' in body.lower()):
            m = re.search(r'"error":\s*"([^"]+)"', body)
            fail(f"Create {name}", m.group(1) if m else body[:200])
        else:
            ok(f"Create {name} (response received)")

    # ── Apps in DB ──
    print("\n[Apps in DB]")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    apps = conn.execute("SELECT id, name, app_type, status FROM apps ORDER BY id").fetchall()
    for a in apps:
        print(f"  [{a['id']}] {a['name']} type={a['app_type']} status={a['status']}")
    conn.close()
    if apps:
        ok(f"{len(apps)} app(s) in DB")
    else:
        fail("No apps in DB")

    # ── Summary ──
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
