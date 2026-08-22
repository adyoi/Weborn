"""Simple in-memory rate limiter for mutating endpoints."""
import time
from collections import defaultdict


class RateLimiter:
    """Token bucket per key.  max_tokens refill per window_sec."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str, max_tokens: int = 5, window_sec: int = 60) -> bool:
        now = time.monotonic()
        cutoff = now - window_sec
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
        if len(self._buckets[key]) >= max_tokens:
            return True
        self._buckets[key].append(now)
        return False

    def is_limited_pair(self, ip: str, path: str, max_tokens: int = 5, window_sec: int = 60) -> bool:
        return self.is_limited(f"{ip}:{path}", max_tokens, window_sec)


limiter = RateLimiter()
