import threading
import time
from collections import deque
from dataclasses import dataclass, field


def client_ip(
    host: str | None,
    forwarded_for: str | None,
    trusted_proxy_count: int,
) -> str:
    """Client identity for per-IP limits — trusted hops only (contract §7).

    With `trusted_proxy_count = N`, the client is the Nth hop from the
    right of `X-Forwarded-For`; a client-supplied header is believed
    only as far as the proxy chain is explicitly trusted.
    """
    client = host or "unknown"
    if trusted_proxy_count <= 0 or not forwarded_for:
        return client
    hops = [hop.strip() for hop in forwarded_for.split(",") if hop.strip()]
    if not hops:
        return client
    index = len(hops) - trusted_proxy_count
    if index < 0:
        return hops[0]
    return hops[index]


@dataclass
class RateLimiter:
    """In-process sliding-window limiter (career's pattern, family §7).

    Buckets are keyed freely (`ip:<addr>`, `email:<addr>`). Limits are
    per-minute; entries are pruned lazily and capped so a hostile source
    cannot grow memory without bound. Multi-worker deployments must
    divide the ceilings by worker count or move the limiter to Redis —
    documented, not silently wrong.
    """

    per_minute: int = 10
    _hits: dict[str, deque[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _max_keys: int = 4096

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        current = now if now is not None else time.monotonic()
        window_start = current - 60.0
        with self._lock:
            if len(self._hits) >= self._max_keys and key not in self._hits:
                self._prune(window_start)
                if len(self._hits) >= self._max_keys:
                    return False, 60
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= window_start:
                hits.popleft()
            if len(hits) >= self.per_minute:
                retry_after = max(1, int(hits[0] + 60.0 - current) + 1)
                return False, retry_after
            hits.append(current)
            return True, 0

    def _prune(self, window_start: float) -> None:
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1] <= window_start]:
            self._hits.pop(key, None)
