"""Rate limiting — the family HTTP security surface (plan 21).

Two layers share this module:

- the **auth limiters** (`RateLimiter`, sync, in-process sliding window)
  that guard the kit's own auth flows (§7; the password-confirming
  actions ride them — S17). Unchanged in v0.4.0.
- the **general-purpose limiter** (plan 21 D1/D2): a counter-pluggable
  limiter over the frozen five-bucket family set, mounted explicitly by
  products (never wired into `install()`):
  - `Counter` protocol + `InMemoryCounter` (default — single-process
    self-host/desktop) + `RedisCounter` (optional `redis` extra —
    multi-process; degrades **open** on backend failure: a rate limiter
    must never be the outage);
  - `RateLimitMiddleware` (per-IP, product-routed buckets) and the
    `rate_limit(bucket, key=…)` FastAPI dependency, both driven by a
    `RateLimitPolicy` the product backs with its `Settings`
    (`<P>_RATELIMIT_*` §16 knobs — ceilings are resolved per request,
    never frozen at mount time).
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

#: The frozen family bucket set (plan 21 D1) — the only legal bucket
#: names for the general limiter; the constants live here and nowhere
#: else (product drift gates enforce kit-only copies).
BUCKETS: tuple[str, ...] = ("AUTH", "AUTH_EMAIL", "AI", "MCP", "DEFAULT")

_BUCKET_INDEX = {name.lower(): name for name in BUCKETS}


def normalize_bucket(name: str) -> str:
    """Canonical bucket name from any casing; unknown names are a
    `ValueError` (the set is frozen vocabulary, not a free-form key)."""
    canonical = _BUCKET_INDEX.get(str(name).strip().lower())
    if canonical is None:
        raise ValueError(f"unknown rate-limit bucket {name!r} (family set: {BUCKETS})")
    return canonical


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


# ---------------------------------------------------------------------------
# General-purpose limiter (plan 21 D1/D2)
# ---------------------------------------------------------------------------


@runtime_checkable
class Counter(Protocol):
    """One counting backend behind the family limiter.

    `incr` records one event for `key` inside a `window`-seconds window
    and returns the event count for the key within that window. Backends
    choose the window mechanics (sliding deques in-process; INCR+EXPIRE
    in Redis) — callers only compare the count to a ceiling.
    """

    async def incr(self, key: str, window: int) -> int: ...


class InMemoryCounter:
    """Sliding-window deques per key (the default, single-process backend).

    True sliding semantics (events age out individually), thread-safe,
    lazily pruned and key-capped so hostile traffic cannot grow memory
    without bound — the same discipline as the sync `RateLimiter`.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._max_keys = 4096

    def clear(self) -> None:
        """Drop all counters (product test suites isolate their spend)."""
        with self._lock:
            self._events.clear()

    async def incr(self, key: str, window: int) -> int:
        now = self._clock()
        with self._lock:
            if len(self._events) >= self._max_keys and key not in self._events:
                self._prune(now)
                if len(self._events) >= self._max_keys:
                    # Key budget exhausted: refuse to grow, count as "at
                    # limit" (the ceiling decides) — never crash the request.
                    return 2**31
            events = self._events.setdefault(key, deque())
            cutoff = now - window
            while events and events[0] <= cutoff:
                events.popleft()
            events.append(now)
            return len(events)

    def _prune(self, now: float) -> None:
        stale_before = now - 3600.0
        for key in [k for k, q in self._events.items() if not q or q[-1] < stale_before]:
            self._events.pop(key, None)


class _RedisLike(Protocol):
    """The structural slice of an async Redis client the counter needs."""

    async def incr(self, key: str) -> int: ...

    async def expire(self, key: str, ttl: int) -> Any: ...


class RedisCounter:
    """Fixed-window INCR+EXPIRE counter (multi-process backend).

    The counter holds across every process sharing the Redis database
    (uvicorn workers + Celery). **Degrades open**: a Redis outage logs a
    warning and counts the event as `0` so the request proceeds —
    rate limiting is defence-in-depth, never an availability gate
    (health's rationale, family rule since plan 21 D2). Keys are used
    verbatim so existing counter state (health's `rl:*` shape) survives
    adoption unchanged.
    """

    def __init__(self, client: _RedisLike) -> None:
        self._client = client

    async def incr(self, key: str, window: int) -> int:
        try:
            count = await self._client.incr(key)
            if count == 1:
                await self._client.expire(key, window)
            return count
        except Exception as exc:  # degrade open: any backend error, never the request
            logger.warning("Rate-limit backend unavailable, allowing request: %s", exc)
            return 0


@dataclass
class RateLimitPolicy:
    """Mount-time configuration driving middleware + dependency.

    `ceiling` resolves a bucket (canonical name) to its per-minute
    ceiling — `None` means "no policy ceiling" (the caller's route
    default applies, health's pre-§16 semantics); ``0`` disables the
    bucket. Both are read per request so products can back them with
    live `Settings` (§16 knobs route `.env` and OS env identically).
    """

    ceiling: Callable[[str], int | None]
    counter: Counter = field(default_factory=InMemoryCounter)
    enabled: Callable[[], bool] | None = None
    trusted_proxy_count: int = 0
    window: int = 60

    def identity(self, scope: Mapping[str, Any]) -> str:
        """Per-IP client identity from the ASGI scope (D3)."""
        client = scope.get("client") or (None, 0)
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        return client_ip(client[0], headers.get("x-forwarded-for"), self.trusted_proxy_count)

    async def hit(self, key: str, *, limit: int, window: int = 60) -> int | None:
        """Raw keyed check outside the bucket vocabulary.

        For product-specific throttles that still share the counter and
        the degrade-open rule: health's `rl:*` keyed limiters (exact key
        shape + window preserved) and per-tool windows. Same contract as
        `check` — `None` ⇒ allowed, positive ⇒ retry-after seconds.
        """
        if limit <= 0:
            return None
        try:
            count = await self.counter.incr(key, window)
        except Exception as exc:  # degrade open: the limiter is never the outage
            logger.warning("Rate-limit backend unavailable, allowing request: %s", exc)
            return None
        if count > limit:
            return max(1, window)
        return None

    async def check(
        self, bucket: str, key: str, *, fallback: int | None = None
    ) -> int | None:
        """Record one event; return retry-after seconds when over budget.

        `None` ⇒ allowed (or the bucket disabled); a positive int ⇒ the
        caller should refuse with 429 + `Retry-After`.
        """
        if self.enabled is not None and not self.enabled():
            return None
        canonical = normalize_bucket(bucket)
        ceiling = self.ceiling(canonical)
        limit = ceiling if ceiling is not None else fallback
        if limit is None or limit <= 0:
            return None
        # Bucket-namespaced key: windows are independent per bucket (R6).
        try:
            count = await self.counter.incr(f"{canonical.lower()}:{key}", self.window)
        except Exception as exc:  # degrade open: the limiter is never the outage
            logger.warning("Rate-limit backend unavailable, allowing request: %s", exc)
            return None
        if count > limit:
            return max(1, self.window)
        return None


class RateLimitMiddleware:
    """Per-IP limits over the frozen family buckets (ASGI).

    `bucket_for(scope)` maps a request to a bucket (or `None` to skip —
    non-API paths); ceilings/identity come from the `RateLimitPolicy`.
    Refusals answer 429 JSON with `Retry-After`.
    """

    def __init__(
        self,
        app: Any,
        *,
        policy: RateLimitPolicy,
        bucket_for: Callable[[Mapping[str, Any]], str | None],
    ) -> None:
        self.app = app
        self.policy = policy
        self.bucket_for = bucket_for

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        bucket = self.bucket_for(scope)
        if bucket is None:
            await self.app(scope, receive, send)
            return
        retry_after = await self.policy.check(bucket, self.policy.identity(scope))
        if retry_after is not None:
            from fastapi.responses import JSONResponse

            response = JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def rate_limit(
    bucket: str,
    *,
    prefix: str = "",
    default: int | None = None,
    key: Callable[[Request], str] | None = None,
) -> Callable[[Request], Any]:
    """FastAPI dependency over the frozen family buckets.

    Requires `mount_rate_limit` (the policy on `app.state.nx_rate_limit`).
    `default` is the route's own ceiling when the policy carries none
    for the bucket; `key` selects the identity (per-IP by default —
    pass a callable for the keyed limiters: per-user, per-integration).
    Raises 429 + `Retry-After` over budget; `0`/disabled buckets pass.
    """
    canonical = normalize_bucket(bucket)

    async def _dependency(request: Request) -> None:
        policy: RateLimitPolicy | None = getattr(request.app.state, "nx_rate_limit", None)
        if policy is None:
            return
        identity = key(request) if key is not None else policy.identity(request.scope)
        scoped = f"{prefix}:{identity}" if prefix else identity
        retry_after = await policy.check(canonical, scoped, fallback=default)
        if retry_after is not None:
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(retry_after)},
            )

    return _dependency


def mount_rate_limit(
    app: Any,
    *,
    policy: RateLimitPolicy,
    bucket_for: Callable[[dict[str, Any]], str | None],
) -> None:
    """Mount the family limiter: middleware + the dependency's policy.

    Products call this explicitly (D1 — the limiter is never wired into
    `install()`); `bucket_for` is the product's route→bucket table.
    """
    app.state.nx_rate_limit = policy
    app.add_middleware(RateLimitMiddleware, policy=policy, bucket_for=bucket_for)
