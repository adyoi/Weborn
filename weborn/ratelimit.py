"""Simple in-memory rate limiter for mutating endpoints."""
import time
from collections import defaultdict


class RateLimiter:
    """Sliding-window counter per key: kwota max_tokens dalam window_sec terakhir."""

    MAX_KEYS = 10_000

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def _purge(self, now: float, window_sec: int):
        if len(self._buckets) <= self.MAX_KEYS:
            return
        cutoff = now - 3600
        stale = [k for k, v in self._buckets.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._buckets[k]

    def is_limited(self, key: str, max_tokens: int = 5, window_sec: int = 60) -> bool:
        now = time.monotonic()
        cutoff = now - window_sec
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
        self._purge(now, window_sec)
        if len(self._buckets[key]) >= max_tokens:
            return True
        self._buckets[key].append(now)
        return False

    def is_limited_pair(self, ip: str, path: str, max_tokens: int = 5, window_sec: int = 60) -> bool:
        return self.is_limited(f"{ip}:{path}", max_tokens, window_sec)


limiter = RateLimiter()
