import sys, os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

MOCK_SECRET = "test-jwt-secret-key-for-unit-tests"


class TestJWT:
    def test_encode_decode_roundtrip(self):
        with patch("weborn.auth._get_jwt_secret", return_value=MOCK_SECRET):
            from weborn.auth import encode_jwt, decode_jwt
            token = encode_jwt(1, "admin", "admin")
            payload = decode_jwt(token)
            assert payload is not None
            assert payload["user_id"] == 1
            assert payload["username"] == "admin"
            assert payload["role"] == "admin"

    def test_decode_invalid_token(self):
        with patch("weborn.auth._get_jwt_secret", return_value=MOCK_SECRET):
            from weborn.auth import decode_jwt
            assert decode_jwt("invalid.token.here") is None

    def test_decode_empty(self):
        with patch("weborn.auth._get_jwt_secret", return_value=MOCK_SECRET):
            from weborn.auth import decode_jwt
            assert decode_jwt("") is None

    def test_decode_tampered(self):
        with patch("weborn.auth._get_jwt_secret", return_value=MOCK_SECRET):
            from weborn.auth import encode_jwt, decode_jwt
            token = encode_jwt(1, "admin", "admin")
            tampered = token[:-5] + "XXXXX"
            assert decode_jwt(tampered) is None

    def test_different_users_different_tokens(self):
        with patch("weborn.auth._get_jwt_secret", return_value=MOCK_SECRET):
            from weborn.auth import encode_jwt, decode_jwt
            t1 = encode_jwt(1, "alice", "admin")
            t2 = encode_jwt(2, "bob", "user")
            p1 = decode_jwt(t1)
            p2 = decode_jwt(t2)
            assert p1["user_id"] != p2["user_id"]
            assert p1["username"] != p2["username"]


class TestIdleLock:
    def test_not_idle_when_no_activity(self):
        from weborn.auth import is_idle_locked
        assert is_idle_locked(99999, 300) is False

    def test_not_idle_within_timeout(self):
        from weborn.auth import touch_activity, is_idle_locked
        touch_activity(1)
        assert is_idle_locked(1, 300) is False

    def test_zero_timeout_never_locks(self):
        from weborn.auth import touch_activity, is_idle_locked
        touch_activity(1)
        assert is_idle_locked(1, 0) is False

    def test_negative_timeout_never_locks(self):
        from weborn.auth import touch_activity, is_idle_locked
        touch_activity(1)
        assert is_idle_locked(1, -1) is False
