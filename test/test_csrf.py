import sys, os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

MOCK_SECRET = "test-secret-key-for-unit-tests"

def _mock_get_secret():
    return MOCK_SECRET

class TestCSRF:
    def test_generate_returns_string(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token
            token = generate_csrf_token("session123")
            assert isinstance(token, str)
            assert ":" in token

    def test_validate_correct_token(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token, validate_csrf_token
            session_id = "my-session-id"
            token = generate_csrf_token(session_id)
            assert validate_csrf_token(token, session_id) is True

    def test_validate_wrong_token(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import validate_csrf_token
            assert validate_csrf_token("wrong:token", "session123") is False

    def test_validate_empty_token(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import validate_csrf_token
            assert validate_csrf_token("", "session123") is False

    def test_validate_empty_session(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token, validate_csrf_token
            token = generate_csrf_token("session123")
            assert validate_csrf_token(token, "") is False

    def test_validate_both_empty(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import validate_csrf_token
            assert validate_csrf_token("", "") is False

    def test_different_sessions_different_tokens(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token
            t1 = generate_csrf_token("session-a")
            t2 = generate_csrf_token("session-b")
            assert t1 != t2

    def test_token_tied_to_session(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token, validate_csrf_token
            t1 = generate_csrf_token("session-a")
            assert validate_csrf_token(t1, "session-b") is False

    def test_deterministic(self):
        with patch("weborn.csrf._get_csrf_secret", return_value=b"mock"):
            from weborn.csrf import generate_csrf_token
            t1 = generate_csrf_token("same-session")
            t2 = generate_csrf_token("same-session")
            assert t1 == t2
