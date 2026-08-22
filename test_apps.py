import sqlite3, subprocess, os, re

DB = "/var/lib/weborn/panel.db"
COOKIE_JAR = "/tmp/weborn_test_cookies.txt"
BASE = "http://localhost:2025"

def curl(method, url, data=None):
    cmd = ["curl", "-s", "-c", COOKIE_JAR, "-b", COOKIE_JAR, "-L"]
    if method == "POST":
        cmd += ["-X", "POST", url]
        if data:
            for k, v in data.items():
                cmd += ["-d", f"{k}={v}"]
    else:
        cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.stdout

conn = sqlite3.connect(DB)
users = conn.execute("SELECT id, username, role FROM users").fetchall()
print(f"Users: {users}")
conn.close()

print("\n=== Login ===")
resp = curl("POST", f"{BASE}/login", {"username": "admin", "password": "admin"})
if os.path.exists(COOKIE_JAR):
    with open(COOKIE_JAR) as f:
        cookies = f.read()
    has_session = "weborn_session" in cookies
    print(f"Has session cookie: {has_session}")
else:
    print("No cookies file")

app_types = [
    ("test-asgi-uv", "asgi", "uvicorn"),
    ("test-wsgi-uv", "wsgi", "uvicorn"),
    ("test-asgi-gn", "asgi", "gunicorn"),
    ("test-wsgi-gn", "wsgi", "gunicorn"),
]

for name, atype, launcher in app_types:
    print(f"\n=== Creating {name} ({atype}-{launcher}) ===")
    data = {
        "name": name,
        "app_type": atype,
        "launcher": launcher,
        "module_app": "main:app",
        "workers": "2",
        "host": "0.0.0.0",
        "port": "0",
        "dir_path": "",
    }
    resp = curl("POST", f"{BASE}/apps/create-native", data)
    if "created=1" in resp:
        print(f"  CREATED OK")
    elif "error" in resp.lower() or "gagal" in resp.lower():
        m = re.search(r'"error":\s*"([^"]+)"', resp)
        if m:
            print(f"  ERROR: {m.group(1)}")
        else:
            print(f"  Response: {resp[:500]}")
    else:
        print(f"  Response: {resp[:500]}")

print("\n=== Apps in DB ===")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
apps = conn.execute("SELECT id, name, app_type, command, status, unit FROM apps ORDER BY id").fetchall()
for a in apps:
    print(f"  [{a['id']}] {a['name']} type={a['app_type']} status={a['status']}")
    print(f"       cmd={a['command']}")
    print(f"       unit={a['unit']}")
conn.close()
