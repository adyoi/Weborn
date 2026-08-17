"""Weborn Control Panel - WSGI entry point.

Untuk production dengan gunicorn + uvicorn workers:
    gunicorn weborn.wsgi:application -k uvicorn.workers.UvicornWorker \\
             -b 0.0.0.0:2025 -w 4 --timeout 120

Atau langsung (dev):
    python -m weborn.wsgi --port 2025
"""
import argparse
import os

from weborn.main import app as application  # noqa: F401


def main():
    parser = argparse.ArgumentParser(description="Weborn Panel (gunicorn launcher)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2025)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    os.environ.setdefault("WEBORN_EXECUTOR_MODE", "local")

    import subprocess, sys
    cmd = [
        sys.executable, "-m", "gunicorn",
        "weborn.wsgi:application",
        "-k", "uvicorn.workers.UvicornWorker",
        "-b", f"{args.host}:{args.port}",
        "-w", str(args.workers),
        "--timeout", "120",
    ]
    print(f"Weborn Panel (gunicorn+uvicorn) -> http://{args.host}:{args.port}")
    subprocess.execvp(sys.executable, cmd)


if __name__ == "__main__":
    main()
