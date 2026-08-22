#!/bin/bash
# ============================================================
# Weborn Control Panel - Installer (Debian/Ubuntu)
#
#   sudo bash install.sh                # install fresh
#   sudo bash install.sh --update       # upgrade kode (data aman)
#   sudo bash install.sh --port=8080    # ganti port panel
#   sudo bash install.sh --app-dir=/srv/weborn
#
# Panel dijalankan sebagai root (systemd) karena harus mengelola
# sistem (apt/systemctl/akun OS/iptables) — setara Webuzo/cPanel.
# ============================================================
set -euo pipefail

PORT="${WEBORN_PANEL_PORT:-2025}"
APP_DIR="${WEBORN_APP_DIR:-/opt/weborn}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
UPDATE=0

usage() {
    echo "Penggunaan: bash $0 [--update] [--port=N] [--app-dir=PATH] [--help]"
    echo "  --update      upgrade kode tanpa menyentuh data/ di APP_DIR"
    echo "  --port=N      port panel (default 2025)"
    echo "  --app-dir=P   direktori instalasi (default /opt/weborn)"
    echo "  --help        tampilkan bantuan"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --update) UPDATE=1 ;;
        --port=*) PORT="${1#*=}" ;;
        --app-dir=*) APP_DIR="${1#*=}" ;;
        --help) usage; exit 0 ;;
        *) echo "Argumen tidak dikenal: $1"; usage; exit 1 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: jalankan sebagai root: sudo bash $0"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: installer ini untuk distro Debian/Ubuntu (apt)."
    exit 1
fi

APP_DIR="$(realpath "$APP_DIR")"
echo "==> Weborn: install ke $APP_DIR, port $PORT"

# ---------- 1. dependensi sistem ----------
echo "==> [1/5] Install dependensi sistem (python3, venv, build tools)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev build-essential curl

# ---------- 2. venv + requirements ----------
echo "==> [2/5] Siapkan venv & install requirements..."
mkdir -p "$APP_DIR"
if [ ! -d "$APP_DIR/.venv" ]; then
    python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --upgrade pip -q
"$APP_DIR/.venv/bin/pip" install -r "$SRC_DIR/requirements.txt" -q

# ---------- 3. salin kode (tanpa data/git) ----------
echo "==> [3/5] Salin kode aplikasi..."
if [ "$UPDATE" -eq 1 ]; then
    mkdir -p "$APP_DIR"
fi
(cd "$SRC_DIR" && tar --exclude=.git --exclude=data --exclude=.venv \
    --exclude='__pycache__' --exclude='*.pyc' -cf - .) \
    | (cd "$APP_DIR" && tar -xf -)

# ---------- 4. struktur data ----------
echo "==> [4/5] Siapkan direktori data..."
mkdir -p "$APP_DIR/data/configs" "$APP_DIR/data/logs" "$APP_DIR/data/addons"

# ---------- 5. unit systemd ----------
echo "==> [5/5] Pasang unit systemd weborn.service..."
cat > /etc/systemd/system/weborn.service <<EOF
[Unit]
Description=Weborn Control Panel
After=network.target

[Service]
Type=simple
Environment=WEBORN_EXECUTOR_MODE=local
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/weborn.py --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable weborn >/dev/null 2>&1 || true
systemctl restart weborn

# ---------- verifikasi ----------
sleep 3
if curl -sf -o /dev/null "http://127.0.0.1:$PORT/login"; then
    echo ""
    echo "✅ Weborn terpasang & berjalan: http://<IP-server>:$PORT"
    echo "   Login default: admin / weborn  (SEGERA GANTI password!)"
    echo "   Log: journalctl -u weborn -f"
    echo "   Data: $APP_DIR/data | Kode: $APP_DIR | Unit: /etc/systemd/system/weborn.service"
else
    echo ""
    echo "⚠️  Service mungkin belum siap. Cek log: journalctl -u weborn -e"
    exit 1
fi
