"""Terminal WebSocket: PTY-based shell access."""
import asyncio
import os
import re
import signal

_pty = _fcntl = _struct = _termios = None
if os.name == "posix":
    try:
        import pty as _pty
        import fcntl as _fcntl
        import struct as _struct
        import termios as _termios
    except ImportError:
        pass

from fastapi import APIRouter, Depends, Form, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse

from ..auth import require_admin, require_user
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Terminal"])


@router.get("/terminal", response_class=HTMLResponse)
async def terminal_page(request: Request, user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    return render(request, "terminal.html", {"user": user, "active": "terminal"})


@router.post("/terminal/run")
async def terminal_run(cmd: str = Form(...), request: Request = None,
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    if request:
        from ..ratelimit import limiter
        ip = request.client.host if request.client else "unknown"
        if limiter.is_limited(f"term:{ip}:{user.get('id')}", max_tokens=20, window_sec=60):
            return JSONResponse({"ok": False, "error": "terlalu banyak perintah, coba lagi nanti"}, status_code=429)
    if len(cmd) > 4000:
        return JSONResponse({"ok": False, "error": "perintah terlalu panjang"}, status_code=400)
    r = await get_executor().run("bash", "-c", cmd)
    return {"ok": r.ok, "returncode": r.returncode, "output": r.output}


@router.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    from ..auth import ws_require_admin
    user = await ws_require_admin(websocket)
    if not user:
        return
    ex = get_executor()
    if ex.mode not in ("local", "wsl"):
        await websocket.send_text("[error] Terminal WebSocket hanya tersedia di mode local/WSL\r\n")
        await websocket.close()
        return
    master_fd = None
    slave_fd = None
    child_pid = None
    try:
        if not _pty or not _fcntl or not _struct or not _termios:
            await websocket.send_text("[error] Terminal tidak tersedia di platform ini\r\n")
            await websocket.close()
            return
        master_fd, slave_fd = _pty.openpty()
        flags = _fcntl.fcntl(master_fd, _fcntl.F_GETFL)
        _fcntl.fcntl(master_fd, _fcntl.F_SETFL, flags | os.O_NONBLOCK)
        child_pid = os.fork()
        if child_pid == 0:
            os.close(master_fd)
            os.setsid()
            _fcntl.ioctl(slave_fd, _termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            username = user.get("username", "root")
            import subprocess
            try:
                result = subprocess.run(["id", username], capture_output=True, timeout=3)
                if result.returncode == 0:
                    os.execvp("sudo", ["sudo", "-u", username, "-i"])
                else:
                    os.execvp("/bin/bash", ["/bin/bash", "--login"])
            except Exception:
                pass
            # Semua execvp gagal: hentikan child dan JANGAN pernah melanjutkan
            # ke kode asyncio parent (akibat loop event rusak di dalam fork).
            try:
                os.execvp("/bin/bash", ["/bin/bash", "--login"])
            except Exception:
                os._exit(127)
        os.close(slave_fd)
        slave_fd = None
        await websocket.send_text("\033[1;32m[Terminal Weborn]\033[0m Siap.\r\n")
        async def read_pty():
            while True:
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break  # child shell keluar → EOF
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except (OSError, RuntimeError):
                    break  # socket tertutup / fd invalid
        async def read_ws():
            while True:
                try:
                    data = await websocket.receive_text()
                except Exception:
                    break  # client disconnect → stop task
                if data.startswith("\x1b["):
                    m = re.match(r"\x1b\[(\d+);(\d+)R", data)
                    if m:
                        rows, cols = int(m.group(1)), int(m.group(2))
                        winsize = _struct.pack("HHHH", rows, cols, 0, 0)
                        # TIOCSWINSZ harus di master_fd (slave_fd sudah ditutup di parent)
                        _fcntl.ioctl(master_fd, _termios.TIOCSWINSZ, winsize)
                        continue
                try:
                    os.write(master_fd, data.encode("utf-8"))
                except (BlockingIOError, OSError):
                    await asyncio.sleep(0.01)
        tasks = [asyncio.create_task(read_pty()), asyncio.create_task(read_ws())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        try:
            await websocket.send_text(f"\r\n[error] {e}\r\n")
        except Exception:
            pass
    finally:
        # Bersihkan proses child (juga grup prosesnya agar tidak jadi orphan)
        if child_pid and child_pid > 0:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child_pid, sig)
                except Exception:
                    try:
                        os.kill(child_pid, sig)
                    except Exception:
                        pass
            try:
                os.waitpid(child_pid, os.WNOHANG)
            except Exception:
                pass
        if master_fd is not None:
            try:
                os.close(master_fd)
            except Exception:
                pass
        if slave_fd is not None:
            try:
                os.close(slave_fd)
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
