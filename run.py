"""Entry point Weborn Control Panel.

Jalankan:  python run.py          (dev, dry-run)
           python run.py --local  (linux: eksekusi sistem nyata)
"""
import argparse
import os
import signal
import socket
import subprocess
import sys

import uvicorn

from weborn.config import PANEL_HTTP_PORT


def _kill_port(port: int):
    """Hentikan proses yang menduduki port tertentu (Linux/WSL only)."""
    if sys.platform == "win32":
        return
    try:
        r = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            if f":{port}" in line:
                # ss output: LISTEN  0  128  0.0.0.0:2025  ... users:(("python3",pid=1234,fd=7))
                import re
                m = re.search(r'pid=(\d+)', line)
                if m:
                    pid = int(m.group(1))
                    if pid != os.getpid():
                        os.kill(pid, signal.SIGTERM)
                        import time
                        time.sleep(0.5)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except OSError:
                            pass
    except Exception:
        pass


def main():
    ascii_art = """
    $$\\      $$\\           $$$$$$$\\                                
    $$ | $\\  $$ |          $$  __$$\\                               
    $$ |$$$\\ $$ | $$$$$$\\  $$ |  $$ | $$$$$$\\   $$$$$$\\  $$$$$$$\\  
    $$ $$ $$\\$$ |$$  __$$\\ $$$$$$$\\ |$$  __$$\\ $$  __$$\\ $$  __$$\\ 
    $$$$  _$$$$ |$$$$$$$$ |$$  __$$\\ $$ /  $$ |$$ |  \\__|$$ |  $$ |
    $$$  / \\$$$ |$$   ____|$$ |  $$ |$$ |  $$ |$$ |      $$ |  $$ |
    $$  /   \\$$ |\\$$$$$$$\\ $$$$$$$  |\\$$$$$$  |$$ |      $$ |  $$ |
    \\__/     \\__| \\_______|\\_______/  \\______/ \\__|      \\__|  \\__|                                                     
    """
    print("%s" % ascii_art)

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
        os.environ["WEBORN_EXECUTOR_MODE"] = "local"

    # Auto-kill proses lama yang menduduki port yang sama
    _kill_port(args.port)

    ssl_kwargs = {}
    if args.ssl_cert and args.ssl_key:
        ssl_kwargs = {"ssl_certfile": args.ssl_cert, "ssl_keyfile": args.ssl_key}

    uvicorn.run("weborn.main:app", host=args.host, port=args.port,
                reload=args.reload, **ssl_kwargs)


if __name__ == "__main__":
    sys.exit(main())
