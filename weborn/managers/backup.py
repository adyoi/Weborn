"""Backup/restore: arsipkan /var/www + database panel ke data/backups.

Menggunakan tarfile Python agar berjalan baik di mode dry-run (Windows)
maupun local/wsl — /var/www hanya diikutkan bila benar-benar ada.
"""
import tarfile
from datetime import datetime
from pathlib import Path

from ..config import BACKUP_DIR, CONFIG_DIR, DB_PATH, WEB_ROOT


class BackupManager:
    def __init__(self, backup_dir: str | Path | None = None):
        self.backup_dir = Path(backup_dir) if backup_dir else BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- listing
    def list_backups(self) -> list[dict]:
        out = []
        for p in sorted(self.backup_dir.glob("weborn_*.tar.gz"), reverse=True):
            out.append({
                "name": p.name,
                "size": p.stat().st_size,
                "created": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        return out

    def safe_name(self, name: str) -> Path:
        """Pastikan nama = file .tar.gz di backup_dir (cegah traversal)."""
        p = (self.backup_dir / Path(name).name).resolve()
        if (p.parent != self.backup_dir.resolve() or not str(p).endswith(".tar.gz")
                or not p.exists()):
            raise FileNotFoundError(name)
        return p

    # ---------------------------------------------------------------- create
    def create(self, include_www: bool = True, include_db: bool = True) -> dict:
        archive = self.backup_dir / f"weborn_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
        www = Path(WEB_ROOT)
        added = {"www": False, "db": False, "configs": False}
        with tarfile.open(archive, "w:gz") as tar:
            if include_www and www.exists():
                tar.add(www, arcname="www")
                added["www"] = True
            if include_db and DB_PATH.exists():
                tar.add(DB_PATH, arcname="data/weborn.db")
                added["db"] = True
                for suf in ("-wal", "-shm"):
                    p = Path(str(DB_PATH) + suf)
                    if p.exists():
                        tar.add(p, arcname=f"data/weborn.db{suf}")
            if CONFIG_DIR.exists():
                tar.add(CONFIG_DIR, arcname="configs")
                added["configs"] = True
        return {"name": archive.name, "size": archive.stat().st_size, **added}

    # ---------------------------------------------------------------- restore
    def restore(self, name: str, restore_www: bool = True,
                restore_db: bool = False) -> dict:
        """Ekstrak arsip ke staging, lalu salin ke lokasi asli (aman)."""
        archive = self.safe_name(name)
        staging = self.backup_dir / ".staging"
        if staging.exists():
            import shutil
            shutil.rmtree(staging)
        with tarfile.open(archive) as tar:
            for m in tar.getmembers():
                if m.name.startswith("/") or ".." in Path(m.name).parts:
                    raise ValueError(f"Arsip tidak aman: {m.name}")
            tar.extractall(staging)

        import shutil
        result = {"www": False, "db": False}
        www_src = staging / "www"
        if restore_www and www_src.exists():
            www = Path(WEB_ROOT)
            www.mkdir(parents=True, exist_ok=True)
            for item in www_src.iterdir():
                dst = www / item.name
                if dst.exists():
                    shutil.rmtree(dst) if dst.is_dir() else dst.unlink()
                shutil.move(str(item), str(dst))
            result["www"] = True
        db_src = staging / "data" / "weborn.db"
        if restore_db and db_src.exists():
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(db_src, DB_PATH)
            result["db"] = True
        shutil.rmtree(staging, ignore_errors=True)
        return result
