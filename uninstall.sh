#!/bin/bash
# ============================================================
# Weborn Control Panel - Uninstaller
#   sudo bash uninstall.sh [--app-dir=/opt/weborn] [--purge]
#   --purge  hapus juga data/ (database, konfigurasi, log)
# ============================================================
set -euo pipefail

APP_DIR="${WEBORN_APP_DIR:-/opt/weborn}"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --app-dir=*) APP_DIR="${arg#*=}" ;;
        --purge) PURGE=1 ;;
        --help)
            echo "Penggunaan: sudo bash uninstall.sh [--purge] [--app-dir=P]"
            exit 0 ;;
        *) echo "Argumen tidak dikenal: $arg"; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: jalankan sebagai root"
    exit 1
fi

echo "==> Hentikan & nonaktifkan service..."
systemctl disable --now weborn 2>/dev/null || true
rm -f /etc/systemd/system/weborn.service
systemctl daemon-reload

if [ "$PURGE" -eq 1 ]; then
    echo "==> Hapus $APP_DIR beserta data (--purge)..."
    rm -rf "$APP_DIR"
else
    echo "==> Hapus kode, data dipertahankan di $APP_DIR/data"
    rm -rf "$APP_DIR/.venv" "$APP_DIR/weborn" "$APP_DIR/run.py" \
           "$APP_DIR/requirements.txt"
fi

echo "✅ Weborn dihapus."
