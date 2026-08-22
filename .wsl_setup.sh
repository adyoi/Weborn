#!/bin/bash
# Setup + jalankan Weborn di dalam WSL Debian (root). Prioritas apt (anti-konflik pip).
cd /mnt/d/Documents/GitHub/Weborn

echo "== 1. Install dependensi via apt"
apt-get install -y -qq python3-fastapi python3-uvicorn python3-jinja2 \
    python3-psutil python3-multipart 2>&1 | tail -3 || true

echo "== 1b. Fallback pip untuk package yang belum ada via apt"
python3 -m pip install --quiet --break-system-packages \
    PyJWT websockets gunicorn 2>&1 | tail -2 || true

echo "== 2. Verifikasi import"
python3 -c "import fastapi, uvicorn, jinja2, psutil, jwt, websockets; print('DEPS OK')" || exit 1

echo "== 3. Jalankan panel (background, bind 0.0.0.0:2025)"
mkdir -p data/logs
export WEBORN_EXECUTOR_MODE=local
nohup python3 weborn.py --host 0.0.0.0 --port 2025 > data/logs/panel.log 2>&1 &
echo "PID: $!"

echo "== 4. Tunggu & cek log"
sleep 7
tail -15 data/logs/panel.log || true
