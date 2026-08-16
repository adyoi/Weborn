"""Weborn Engine CLI.

Contoh:
  python -m engine --mode asgi --port 8080 --root /var/www      # async (uvicorn)
  python -m engine --mode sync  --port 8080 --root /var/www     # sync (http.server)
  uvicorn engine.asgi:app --port 8080
  gunicorn -k uvicorn.workers.UvicornWorker engine.asgi:app -b 0.0.0.0:8080
"""
import argparse


def main():
    ap = argparse.ArgumentParser(description="Weborn Engine webserver")
    ap.add_argument("--mode", choices=["asgi", "sync"], default="asgi")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--root", default="/var/www")
    ap.add_argument("--config", default="", help="path engine.json (default {root}/.weborn/engine.json)")
    ap.add_argument("--no-panel", action="store_true", help="jangan mount GUI panel di /panel")
    args = ap.parse_args()

    if args.mode == "sync":
        from .server import run_server
        run_server(port=args.port, directory=args.root)
        return

    import uvicorn
    from .asgi import create_engine
    app = create_engine(static_root=args.root, config=args.config or None,
                        panel=not args.no_panel)
    print(f"Weborn Engine (asgi) -> http://0.0.0.0:{args.port}  root={args.root}")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
