#!/bin/bash
# ============================================================
# Weborn - Quick Update (sync kode dev → /opt/weborn)
#
#   sudo bash update.sh           # sync + restart
#   sudo bash update.sh --no-restart  # sync only
#
# Jalankan dari direktori repo /mnt/d/Documents/GitHub/Weborn
# ============================================================
set -euo pipefail

APP_DIR="${WEBORN_APP_DIR:-/opt/weborn}"
RESTART=1

if [ "${1:-}" = "--no-restart" ]; then
    RESTART=0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: jalankan sebagai root: sudo bash $0"
    exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$SRC_DIR/weborn" ]; then
    echo "ERROR: $SRC_DIR/weborn/ tidak ditemukan. Jalankan dari root repo."
    exit 1
fi

echo "==> Sync $SRC_DIR → $APP_DIR"

# sync kode (exclude data, git, venv, pycache)
(cd "$SRC_DIR" && tar --exclude=.git --exclude=data --exclude=.venv \
    --exclude=.venv-wsl --exclude=__pycache__ --exclude='*.pyc' \
    --exclude=node_modules --exclude='*.sqlite3' -cf - .) \
    | (cd "$APP_DIR" && tar -xf -)

# sync requirements → pip install
"$APP_DIR/.venv/bin/pip" install -q -r "$SRC_DIR/requirements.txt" 2>/dev/null || true

# bersihkan pycache
find "$APP_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

if [ "$RESTART" -eq 1 ]; then
    echo "==> Restart weborn.service..."
    systemctl restart weborn
    sleep 2
    if systemctl is-active --quiet weborn; then
        echo "OK  weborn active on $(ss -tlnp | grep ':2025' | awk '{print $4}' | head -1)"
    else
        echo "ERROR weborn gagal start. Cek: journalctl -u weborn -e"
        exit 1
    fi
else
    echo "OK  Selesai (tanpa restart)"
fi
