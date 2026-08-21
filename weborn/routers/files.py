"""File explorer: browse, edit, chown, chmod, create, delete."""
import os
import re
import stat
from datetime import datetime
from pathlib import Path

if os.name == "posix":
    import grp
    import pwd
else:
    grp = pwd = None

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from ..auth import require_admin, require_user
from ..config import BASE_DIR, WEB_ROOT
from ..executors import get_executor
from ..ui import render

router = APIRouter(tags=["Files"])

ALLOWED_FS_ROOTS = ("/var/www", "/etc", "/opt", "/home", "/srv", "/usr/share", "/srv/www", str(BASE_DIR))

OWNER_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}(:[a-zA-Z0-9_.-]{1,32})?$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")


def _resolve_fs_path(raw: str) -> Path | None:
    p = Path(raw).resolve()
    if p.is_absolute():
        for root in ALLOWED_FS_ROOTS:
            if str(p) == root or str(p).startswith(root + os.sep):
                return p
    return None


def _owner_of(st: os.stat_result) -> tuple:
    if pwd is None:
        return "?", "?"
    try:
        oname = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        oname = str(st.st_uid)
    try:
        gname = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        gname = str(st.st_gid)
    return oname, gname


async def _os_users(ex) -> list:
    users = ["root", "www-data"]
    if ex.mode in ("local", "wsl"):
        r = await ex.run("getent", "passwd")
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                if uid == 0 or uid >= 1000:
                    users.append(parts[0])
    seen, out = set(), []
    for u in users:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def _os_groups(ex) -> list:
    groups = ["root", "www-data", "sudo"]
    if ex.mode in ("local", "wsl"):
        r = await ex.run("getent", "group")
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                groups.append(parts[0])
    seen, out = set(), []
    for g in groups:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


@router.get("/files", response_class=HTMLResponse)
async def files_page(request: Request, path: str = "", user: dict = Depends(require_user)):
    if hasattr(user, "headers"):
        return user
    ex = get_executor()
    default_root = WEB_ROOT if ex.mode in ("local", "wsl") else str(BASE_DIR)
    if not path:
        path = default_root
    resolved = _resolve_fs_path(path)
    error, entries = None, []
    if resolved is None:
        error = f"Path di luar izin (akar: {', '.join(ALLOWED_FS_ROOTS)})"
        resolved = Path(default_root)

    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c",
                         f"sudo ls -la '{resolved}' 2>&1")
        lines = r.stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            mode_str, owner, group = parts[0], parts[2], parts[3]
            name = parts[8]
            if name in (".", ".."):
                continue
            is_dir = mode_str.startswith("d")
            try:
                size = int(parts[4])
            except ValueError:
                size = 0
            mtime_raw = f"{parts[5]} {parts[6]} {parts[7]}"
            child = resolved / name
            try:
                st = child.stat()
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                mode_num = "%03o" % stat.S_IMODE(st.st_mode)
            except OSError:
                mtime = mtime_raw
                try:
                    mode_num = oct(int(mode_str[1:].replace("-", "0").replace("r", "4").replace("w", "2").replace("x", "1"), 8))[-3:]
                except Exception:
                    mode_num = "???"
            entries.append({
                "name": name,
                "dir": is_dir,
                "size": size,
                "mtime": mtime,
                "mode": mode_str,
                "mode_num": mode_num,
                "owner": owner,
                "group": group,
            })
    else:
        try:
            for child in sorted(resolved.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                try:
                    st = child.stat()
                    oname, gname = _owner_of(st)
                    entries.append({
                        "name": child.name,
                        "dir": child.is_dir(),
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "mode": stat.filemode(st.st_mode),
                        "mode_num": "%03o" % stat.S_IMODE(st.st_mode),
                        "owner": oname,
                        "group": gname,
                    })
                except OSError:
                    continue
        except OSError as e:
            error = str(e)

    users = await _os_users(ex)
    groups = await _os_groups(ex)
    return render(request, "files.html", {"user": user, "path": str(resolved), "entries": entries,
                                          "error": error, "active": "files",
                                          "users": users, "groups": groups})


@router.post("/files/rename")
async def files_rename(path: str = Form(...), new_name: str = Form(...),
                       user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    new_name = new_name.strip()
    if not new_name or "/" in new_name or new_name in (".", ".."):
        return JSONResponse({"ok": False, "error": "nama tidak valid"}, status_code=400)
    target = resolved.parent / new_name
    if target.exists():
        return JSONResponse({"ok": False, "error": f"'{new_name}' sudah ada"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo mv '{resolved}' '{target}'")
        ok = r.ok
    else:
        resolved.rename(target)
        ok = True
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&renamed={ok}&name={new_name}&ts={ts}", status_code=303)


@router.get("/files/compress")
async def files_compress(path: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"error": "path tidak valid"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        tar_name = resolved.name + ".tar.gz"
        tar_path = f"/tmp/weborn-{tar_name}"
        r = await ex.run("bash", "-c",
                         f"sudo tar -czf '{tar_path}' -C '{resolved.parent}' '{resolved.name}' 2>/dev/null")
        if r.ok:
            return FileResponse(tar_path, filename=tar_name, media_type="application/gzip")
    return JSONResponse({"error": "gagal compress"}, status_code=500)


@router.get("/files/download")
async def files_download(path: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None or not resolved.is_file():
        return JSONResponse({"error": "file tidak valid"}, status_code=400)
    try:
        resolved.stat()
        return FileResponse(resolved, filename=resolved.name)
    except PermissionError:
        pass
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo cat '{resolved}' 2>/dev/null")
        if r.ok:
            from fastapi.responses import Response
            return Response(content=r.stdout, media_type="application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{resolved.name}"'})
    return JSONResponse({"error": "file tidak dapat diakses"}, status_code=400)


@router.post("/files/save")
async def files_save(path: str = Form(...), content: str = Form(""),
                     user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    r = await get_executor().write_file(str(resolved), content)
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&saved={r.ok}&name={resolved.name}&ts={ts}", status_code=303)


@router.post("/files/delete")
async def files_delete(path: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo rm -rf '{resolved}'")
        ok = r.ok
    else:
        if resolved.is_file():
            resolved.unlink()
            ok = True
        elif resolved.is_dir():
            try:
                resolved.rmdir()
                ok = True
            except OSError:
                ok = False
        else:
            ok = False
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&deleted={ok}&name={resolved.name}&ts={ts}", status_code=303)


@router.post("/files/chown")
async def files_chown(path: str = Form(...), owner: str = Form(...),
                      group: str = Form(""), recursive: str = Form(""),
                      user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    owner = owner.strip()
    group = group.strip()
    if not owner or not OWNER_RE.match(owner) or (group and not OWNER_RE.match(group)):
        return JSONResponse({"ok": False, "error": "user/group tidak valid"}, status_code=400)
    spec = f"{owner}:{group}" if group else owner
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        args = ["chown"]
        if recursive == "1":
            args.append("-R")
        args += [spec, str(resolved)]
        r = await ex.run(*args)
        ok = r.ok
    else:
        ok = True
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&chown={ok}&name={resolved.name}&ts={ts}", status_code=303)


@router.post("/files/chmod")
async def files_chmod(path: str = Form(...), mode: str = Form(...),
                      recursive: str = Form(""), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    mode = mode.strip()
    if not mode or not MODE_RE.match(mode):
        return JSONResponse({"ok": False, "error": "mode tidak valid (contoh: 644, 755)"},
                            status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        args = ["chmod"]
        if recursive == "1":
            args.append("-R")
        args += [mode, str(resolved)]
        r = await ex.run(*args)
        ok = r.ok
    else:
        ok = True
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&chmod={ok}&name={resolved.name}&ts={ts}", status_code=303)


@router.post("/files/create")
async def files_create(path: str = Form(...), name: str = Form(...),
                       kind: str = Form("file"), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    name = name.strip()
    if not name or "/" in name or name in (".", ".."):
        return JSONResponse({"ok": False, "error": "nama tidak valid"}, status_code=400)
    target = resolved / name
    if target.exists():
        return JSONResponse({"ok": False, "error": f"'{name}' sudah ada"}, status_code=400)
    ex = get_executor()
    if kind == "dir":
        if ex.mode in ("local", "wsl"):
            r = await ex.run("bash", "-c", f"sudo mkdir -p '{target}'")
            ok = r.ok
        else:
            target.mkdir(parents=True, exist_ok=True)
            ok = True
    else:
        if ex.mode in ("local", "wsl"):
            r = await ex.run("bash", "-c", f"sudo touch '{target}' && sudo chown $(id -u):$(id -g) '{target}'")
            ok = r.ok
        else:
            target.touch()
            ok = True
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved}&created={ok}&name={name}&kind={kind}&ts={ts}", status_code=303)


@router.get("/files/edit")
async def files_edit_get(path: str, user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None or not resolved.is_file():
        return JSONResponse({"ok": False, "error": "file tidak valid"}, status_code=400)
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
        return JSONResponse({"ok": True, "content": content, "path": str(resolved)})
    except PermissionError:
        pass
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo cat '{resolved}' 2>/dev/null")
        if r.ok:
            return JSONResponse({"ok": True, "content": r.stdout, "path": str(resolved)})
    return JSONResponse({"ok": False, "error": "permission denied"}, status_code=403)


@router.post("/files/mkdir")
async def files_mkdir(path: str = Form(...), user: dict = Depends(require_admin)):
    if hasattr(user, "headers"):
        return user
    resolved = _resolve_fs_path(path)
    if resolved is None:
        return JSONResponse({"ok": False, "error": "path tidak valid"}, status_code=400)
    if resolved.exists():
        return JSONResponse({"ok": False, "error": "sudah ada"}, status_code=400)
    ex = get_executor()
    if ex.mode in ("local", "wsl"):
        r = await ex.run("bash", "-c", f"sudo mkdir -p '{resolved}'")
        ok = r.ok
    else:
        resolved.mkdir(parents=True, exist_ok=True)
        ok = True
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return RedirectResponse(f"/files?path={resolved.parent}&created={ok}&name={resolved.name}&kind=dir&ts={ts}", status_code=303)
