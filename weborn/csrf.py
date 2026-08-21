"""CSRF protection middleware for Weborn panel."""
import hashlib
import hmac

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

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


def _get_jwt_from_request(scope: dict, headers: dict) -> str:
    cookie_header = headers.get(b"cookie", b"").decode("latin-1")
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            if k.strip() == SESSION_COOKIE:
                return v.strip()
    return ""


class CSRFMiddleware:
    EXEMPT_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PATHS = {"/login", "/setup", "/logout", "/ws/terminal"}

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope["method"]
        if method in self.EXEMPT_METHODS:
            return await self.app(scope, receive, send)

        path = scope["path"]
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return await self.app(scope, receive, send)

        if path.startswith("/ws/") or path.startswith("/api/"):
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        raw_token = _get_jwt_from_request(scope, headers)
        if not raw_token:
            return await self.app(scope, receive, send)

        session_id = raw_token

        content_type = headers.get(b"content-type", b"").decode("latin-1")

        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break

            from urllib.parse import parse_qs
            csrf_token = ""
            if "application/x-www-form-urlencoded" in content_type:
                form_data = parse_qs(body.decode("latin-1"))
                vals = form_data.get("_csrf_token", [])
                csrf_token = vals[0] if vals else ""
            elif "multipart/form-data" in content_type:
                import re
                boundary_match = re.search(r"boundary=(.+?)(?:;|$)", content_type)
                if boundary_match:
                    boundary = boundary_match.group(1).strip().encode()
                    parts = body.split(b"--" + boundary)
                    for part in parts:
                        if b"_csrf_token" in part:
                            idx = part.find(b"\r\n\r\n")
                            if idx >= 0:
                                csrf_token = part[idx+4:].strip().decode("latin-1", errors="replace").rstrip("\r\n")
                            break

            if not validate_csrf_token(csrf_token, session_id):
                return Response("CSRF token invalid", status_code=403)

            async def receive_body():
                return {"type": "http.request", "body": body}

            scope["_csrf_cached_body"] = body
            return await self.app(scope, receive_body, send)

        elif "application/json" in content_type:
            csrf_token = headers.get(b"x-csrf-token", b"").decode("latin-1")
            if not validate_csrf_token(csrf_token, session_id):
                return Response("CSRF token invalid", status_code=403)
        else:
            csrf_token = headers.get(b"x-csrf-token", b"").decode("latin-1")
            if not validate_csrf_token(csrf_token, session_id):
                return Response("CSRF token invalid", status_code=403)

        return await self.app(scope, receive, send)
