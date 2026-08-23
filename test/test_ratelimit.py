import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from weborn.ratelimit import RateLimiter


class TestRateLimiter:
    def test_first_request_allowed(self):
        rl = RateLimiter()
        assert rl.is_limited("key1", max_tokens=3, window_sec=60) is False

    def test_exceeds_limit(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.is_limited("key2", max_tokens=3, window_sec=60)
        assert rl.is_limited("key2", max_tokens=3, window_sec=60) is True

    def test_different_keys_independent(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.is_limited("a", max_tokens=3, window_sec=60)
        assert rl.is_limited("a", max_tokens=3, window_sec=60) is True
        assert rl.is_limited("b", max_tokens=3, window_sec=60) is False

    def test_pair_key(self):
        rl = RateLimiter()
        for _ in range(2):
            rl.is_limited_pair("1.2.3.4", "/login", max_tokens=2, window_sec=60)
        assert rl.is_limited_pair("1.2.3.4", "/login", max_tokens=2, window_sec=60) is True
        assert rl.is_limited_pair("1.2.3.4", "/other", max_tokens=2, window_sec=60) is False
