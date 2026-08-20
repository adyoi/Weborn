"""CSRF protection middleware for Weborn panel."""
import hashlib
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .config import SESSION_COOKIE


def _get_csrf_secret() -> bytes:
    from .db import get_secret_key
    return hashlib.sha256(get_secret_key().encode() + b"csrf").digest()


def generate_csrf_token(session_id: str) -> str:
    secret = _get_csrf_secret()
    msg = session_id.encode()
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]
    return f"{session_id}:{sig}"


def validate_csrf_token(token: str, session_id: str) -> bool:
    if not token or not session_id:
        return False
    expected = generate_csrf_token(session_id)
    return hmac.compare_digest(token, expected)


def _get_jwt_from_request(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE, "")


class CSRFMiddleware(BaseHTTPMiddleware):
    EXEMPT_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PATHS = {"/login", "/setup", "/logout", "/ws/terminal"}

    async def dispatch(self, request: Request, call_next):
        if request.method in self.EXEMPT_METHODS:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return await call_next(request)

        if path.startswith("/ws/") or path.startswith("/api/"):
            return await call_next(request)

        raw_token = _get_jwt_from_request(request)
        if not raw_token:
            return await call_next(request)

        session_id = raw_token

        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            csrf_token = form.get("_csrf_token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)
        elif "application/json" in content_type or request.headers.get("accept") == "text/event-stream":
            csrf_token = request.headers.get("x-csrf-token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)
        else:
            csrf_token = request.headers.get("x-csrf-token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)

        return await call_next(request)
