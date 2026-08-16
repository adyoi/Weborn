"""Entry point Weborn Control Panel.

Jalankan:  python run.py          (dev, dry-run)
           python run.py --local  (linux: eksekusi sistem nyata)
"""
import argparse
import sys

import uvicorn

from weborn.config import PANEL_HTTP_PORT


def main():
    parser = argparse.ArgumentParser(description="Weborn Control Panel")
    parser.add_argument("--local", action="store_true",
                        help="aktifkan EXECUTOR_MODE=local (eksekusi sistem nyata, butuh root)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=PANEL_HTTP_PORT)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--ssl-cert", default=None, help="path sertifikat TLS panel")
    parser.add_argument("--ssl-key", default=None, help="path kunci privat TLS panel")
    args = parser.parse_args()

    if args.local:
        import os
        os.environ["WEBORN_EXECUTOR_MODE"] = "local"

    ssl_kwargs = {}
    if args.ssl_cert and args.ssl_key:
        ssl_kwargs = {"ssl_certfile": args.ssl_cert, "ssl_keyfile": args.ssl_key}

    uvicorn.run("weborn.main:app", host=args.host, port=args.port,
                reload=args.reload, **ssl_kwargs)


if __name__ == "__main__":
    sys.exit(main())
