"""Weborn Engine CLI.

Contoh:
  python -m engine --mode asgi --port 8080 --root /var/www      # async (uvicorn)
  python -m engine --mode wsgi --port 8080 --root /var/www      # wsgi (gunicorn)
  python -m engine --mode sync  --port 8080 --root /var/www     # sync (http.server)
  uvicorn engine.asgi:app --port 8080
  gunicorn engine.wsgi:application -b 0.0.0.0:8080 -w 4
"""
import argparse


def main():
    ap = argparse.ArgumentParser(description="Weborn Engine webserver")
    ap.add_argument("--mode", choices=["asgi", "wsgi", "sync"], default="asgi")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--root", default="/var/www")
    ap.add_argument("--config", default="", help="path engine.json (default {root}/.weborn/engine.json)")
    ap.add_argument("--no-panel", action="store_true", help="jangan mount GUI panel di /panel")
    ap.add_argument("--workers", type=int, default=4, help="jumlah worker (wsgi only, default 4)")
    args = ap.parse_args()

    if args.mode == "sync":
        from .server import run_server
        run_server(port=args.port, directory=args.root)
        return

    if args.mode == "wsgi":
        import subprocess
        import sys
        cmd = [
            sys.executable, "-m", "gunicorn",
            "engine.wsgi:application",
            "-b", f"0.0.0.0:{args.port}",
            "-w", str(args.workers),
            "--timeout", "120",
        ]
        print(f"Weborn Engine (wsgi/gunicorn) -> http://0.0.0.0:{args.port}  root={args.root}")
        subprocess.execvp(sys.executable, cmd)
        return

    import uvicorn
    from .asgi import create_engine
    app = create_engine(static_root=args.root, config=args.config or None,
                        panel=not args.no_panel)
    print(f"Weborn Engine (asgi) -> http://0.0.0.0:{args.port}  root={args.root}")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
