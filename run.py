"""Entry point Weborn Control Panel.

Jalankan:  python run.py          (dev, dry-run)
           python run.py --local  (linux: eksekusi sistem nyata)
"""

import os
import re
import sys
import time
import signal
import socket
import uvicorn
import argparse
import subprocess

from weborn.config import PANEL_HTTP_PORT


def _kill_port(port: int):
    """
    Hentikan SEMUA proses yang menduduki port tertentu (cross-platform).
    Mengembalikan True jika berhasil, False jika gagal atau tidak ada proses.
    """
    if sys.platform == "win32":
        # Windows: netstat -> taskkill
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            
            if result.returncode != 0:
                return False
            
            pids = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1]:
                    try:
                        pid = int(parts[-1])
                        if pid != os.getpid() and pid not in pids:
                            pids.append(pid)
                    except ValueError:
                        continue
            
            if not pids:
                return False
            
            # Kill semua PID (taskkill /F selalu force di Windows)
            success_count = 0
            for pid in pids:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True,
                        timeout=10,
                        check=True
                    )
                    success_count += 1
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    continue
            
            # Tunggu sebentar
            time.sleep(0.3)
            
            # Verifikasi
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False
            )
            
            for line in result.stdout.splitlines():
                if f":{port}" in line:
                    return False
            
            return success_count > 0
            
        except Exception:
            return False
    
    else:
        # Linux/WSL: ss -> multiple PIDs -> signals
        try:
            result = subprocess.run(
                ["ss", "-tlnp", "--numeric"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            
            if result.returncode != 0:
                return False
            
            # Regex untuk menangkap SEMUA pid=XXX
            pattern = r'pid=(\d+)'
            pids = []
            
            for line in result.stdout.splitlines():
                if f":{port}" in line:
                    matches = re.findall(pattern, line)
                    for match in matches:
                        try:
                            pid = int(match)
                            if pid != os.getpid() and pid not in pids:
                                pids.append(pid)
                        except ValueError:
                            continue
            
            # Validasi PID masih aktif
            valid_pids = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    valid_pids.append(pid)
                except OSError:
                    continue
            
            if not valid_pids:
                return False
            
            # Kill semua PIDs (SIGTERM dulu, lalu SIGKILL)
            killed_count = 0
            for pid in valid_pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    
                    # Cek apakah masih hidup
                    try:
                        os.kill(pid, 0)
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass  # Sudah mati graceful
                    
                    killed_count += 1
                    
                except (OSError, ProcessLookupError):
                    continue
            
            # Tunggu sistem membersihkan resource
            time.sleep(0.3)
            
            # Verifikasi port benar-benar bebas
            result = subprocess.run(
                ["ss", "-tlnp", "--numeric"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False
            )
            
            for line in result.stdout.splitlines():
                if f":{port}" in line:
                    if re.search(pattern, line):
                        return False
            
            return killed_count > 0
            
        except Exception:
            return False


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
        os.environ["WEBORN_SSL_CERT"] = args.ssl_cert

    uvicorn.run("weborn.main:app", host=args.host, port=args.port,
                reload=args.reload, workers=1, **ssl_kwargs)


if __name__ == "__main__":
    sys.exit(main())
