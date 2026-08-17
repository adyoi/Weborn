"""Weborn Engine - webserver Python asli.

Tiga mode:
    python -m engine --mode asgi  --port 8080 --root /var/www   # async (uvicorn)
    python -m engine --mode sync  --port 8080 --root /var/www   # sync (http.server)
    python -m engine --mode wsgi  --port 8080 --root /var/www   # wsgi (gunicorn)
"""
