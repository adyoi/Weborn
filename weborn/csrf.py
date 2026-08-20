"""CSRF protection middleware for Weborn panel."""
import hashlib
import hmac
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..config import SESSION_COOKIE


def _get_csrf_secret() -> bytes:
    """Get or create CSRF secret (derived from session secret)."""
    from ..db import get_secret_key
    return hashlib.sha256(get_secret_key().encode() + b"csrf").digest()


def generate_csrf_token(session_id: str) -> str:
    """Generate a CSRF token tied to the session."""
    secret = _get_csrf_secret()
    msg = session_id.encode()
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]
    return f"{session_id}:{sig}"


def validate_csrf_token(token: str, session_id: str) -> bool:
    """Validate a CSRF token against the session."""
    if not token or not session_id:
        return False
    expected = generate_csrf_token(session_id)
    return hmac.compare_digest(token, expected)


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF middleware: validates tokens on state-changing requests."""

    EXEMPT_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PATHS = {"/login", "/setup", "/logout", "/ws/terminal"}

    async def dispatch(self, request: Request, call_next):
        # Skip safe methods and exempt paths
        if request.method in self.EXEMPT_METHODS:
            response = await call_next(request)
            return response

        path = request.url.path
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            response = await call_next(request)
            return response

        # Skip WebSocket and API endpoints (JSON POSTs)
        if path.startswith("/ws/") or path.startswith("/api/"):
            response = await call_next(request)
            return response

        # Get session ID from cookie
        session_id = request.session.get(SESSION_COOKIE, "")
        if not session_id:
            response = await call_next(request)
            return response

        # For form submissions, check CSRF token
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            csrf_token = form.get("_csrf_token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)
        # For AJAX POST, check X-CSRF-Token header
        elif "application/json" in content_type or request.headers.get("accept") == "text/event-stream":
            csrf_token = request.headers.get("x-csrf-token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)
        # For other POST requests without content-type, check header too
        else:
            csrf_token = request.headers.get("x-csrf-token", "")
            if not validate_csrf_token(str(csrf_token), str(session_id)):
                return Response("CSRF token invalid", status_code=403)

        response = await call_next(request)
        return response
