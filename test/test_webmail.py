"""Unit test untuk _roundcube_autologin (stdlib only, pakai HTTP server lokal)."""
import http.server
import threading
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TOKEN = "tok123"
GOOD_SESSID = "session-one"
GOOD_SESSAUTH = "auth-one"

STATE = {"cookies": {}, "posts": 0}


class FakeRoundcube(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _set_sess_cookies(self):
        self.send_header("Set-Cookie",
                         f"roundcube_sessid={GOOD_SESSID}; HttpOnly; Path=/")
        self.send_header("Set-Cookie",
                         f"roundcube_sessauth={GOOD_SESSAUTH}; HttpOnly; Path=/")

    def do_GET(self):
        if "/broken" in self.path:
            self.send_response(500)
            self.end_headers()
            return
        body = b'<html><form><input type="hidden" name="_token" value="' + TOKEN.encode() + b'"></form></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        STATE["posts"] += 1
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if "_token=" + TOKEN not in raw:
            self.send_response(400)
            self.end_headers()
            return
        self.send_response(200)
        self._set_sess_cookies()
        self.send_header("Content-Length", "0")
        self.end_headers()


class TestRoundcubeAutoLogin:
    @classmethod
    def setup_class_static(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeRoundcube)
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def teardown_class_static(cls):
        cls.srv.shutdown()
        cls.th.join(timeout=5)

    def test_returns_sessid_and_sessauth(self):
        from weborn.routers.email import _roundcube_autologin
        cookies = _roundcube_autologin("admin@localhost", "pw",
                                       base=f"http://127.0.0.1:{self.port}/roundcube")
        assert cookies.get("roundcube_sessid") == GOOD_SESSID
        assert cookies.get("roundcube_sessauth") == GOOD_SESSAUTH

    def test_returns_empty_on_connection_error(self):
        from weborn.routers.email import _roundcube_autologin
        # port 9 (discard) biasanya tertutup -> koneksi ditolak
        cookies = _roundcube_autologin("a@localhost", "pw",
                                       base="http://127.0.0.1:9/roundcube")
        assert cookies == {}

    def test_returns_empty_on_http_error(self):
        from weborn.routers.email import _roundcube_autologin
        PORT = type(self).port
        cookies = _roundcube_autologin("bad@localhost", "pw",
                                       base=f"http://127.0.0.1:{PORT}/broken")
        assert cookies == {}


TestRoundcubeAutoLogin.setup_class_static()