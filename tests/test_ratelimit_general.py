"""General-purpose family limiter (plan 21) — contract case 19 + 22.

Pins the R-matrix properties at the kit level: burst ⇒ 429 with
`Retry-After` and a window that resets (R1), spoofed `X-Forwarded-For`
ignored at `TRUSTED_PROXY_COUNT=0` and the rightmost hop trusted behind
one proxy (R2/R3), Redis unreachable ⇒ requests proceed + a log record
(R4), ceiling `0` disables a bucket (R5), bucket windows independent
(R6), ceilings resolved per request rather than frozen at mount time
(case 22 — the mechanism products back with their Settings knobs).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from nx_auth.ratelimit import (
    BUCKETS,
    InMemoryCounter,
    RateLimiter,
    RateLimitMiddleware,
    RateLimitPolicy,
    RedisCounter,
    mount_rate_limit,
    normalize_bucket,
    rate_limit,
)

pytestmark = pytest.mark.contract  # identity-auth §18 cases 19 + 22 (plan 21)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeRedis:
    """Deterministic stand-in for the async Redis client (health's tests
    use the same shape); `fail` simulates the backend going down."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.expired: dict[str, int] = {}
        self.fail = False

    async def incr(self, key: str) -> int:
        if self.fail:
            raise RuntimeError("redis down")
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, ttl: int) -> None:
        self.expired[key] = ttl


def _policy(
    ceilings: dict[str, int],
    *,
    enabled: bool = True,
    trusted_proxy_count: int = 0,
    counter: Any | None = None,
) -> RateLimitPolicy:
    return RateLimitPolicy(
        ceiling=lambda bucket: ceilings.get(bucket),
        enabled=lambda: enabled,
        counter=counter if counter is not None else InMemoryCounter(clock=FakeClock()),
        trusted_proxy_count=trusted_proxy_count,
    )


def _scope(
    path: str = "/api/v1/x",
    headers: list[tuple[str, str]] | None = None,
    client: tuple[str, int] | None = ("1.2.3.4", 5),
    query: bytes = b"",
) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "query_string": query,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or [])],
        "client": client,
        "server": ("test", 80),
    }


def _drive(app: Any, scope: dict[str, Any]) -> tuple[int, dict[bytes, bytes]]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    return start["status"], dict(start["headers"])


async def _ok_app(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _middleware(policy: RateLimitPolicy, bucket: str = "DEFAULT") -> Any:
    return RateLimitMiddleware(_ok_app, policy=policy, bucket_for=lambda scope: bucket)


# --------------------------------------------------------------------- basics


def test_bucket_set_is_frozen_vocabulary() -> None:
    assert BUCKETS == ("AUTH", "AUTH_EMAIL", "AI", "MCP", "DEFAULT")
    assert normalize_bucket("ai") == "AI"
    assert normalize_bucket(" AUTH_EMAIL ") == "AUTH_EMAIL"
    with pytest.raises(ValueError, match="unknown rate-limit bucket"):
        normalize_bucket("nope")


# ----------------------------------------------------------------- R1 / R5 / R6


def test_burst_over_ceiling_returns_429_then_window_resets() -> None:
    app = _middleware(_policy({"AUTH": 3}), bucket="AUTH")
    for _ in range(3):
        status, _ = _drive(app, _scope())
        assert status == 200
    status, headers = _drive(app, _scope())
    assert status == 429
    assert b"retry-after" in headers
    assert int(headers[b"retry-after"]) >= 1
    # The window is the policy's: with the frozen fake clock nothing
    # resets until `window` seconds pass.
    assert _drive(app, _scope())[0] == 429


def test_in_memory_window_resets_after_window_elapses() -> None:
    clock = FakeClock()
    policy = _policy({"AI": 2})
    policy.counter = InMemoryCounter(clock=clock)
    app = _middleware(policy, bucket="AI")
    assert _drive(app, _scope())[0] == 200
    assert _drive(app, _scope())[0] == 200
    assert _drive(app, _scope())[0] == 429
    clock.now += 61  # every recorded event ages out
    assert _drive(app, _scope())[0] == 200


def test_in_memory_counter_clear_drops_all_state() -> None:
    counter = InMemoryCounter(clock=FakeClock())
    policy = RateLimitPolicy(ceiling=lambda bucket: 1, counter=counter)
    assert asyncio.run(policy.check("AI", "k")) is None
    assert asyncio.run(policy.check("AI", "k")) is not None
    counter.clear()
    assert asyncio.run(policy.check("AI", "k")) is None, "product suites isolate their spend"


def test_zero_ceiling_disables_bucket() -> None:
    app = _middleware(_policy({"DEFAULT": 0}))
    for _ in range(25):
        assert _drive(app, _scope())[0] == 200


def test_buckets_have_independent_windows() -> None:
    ceilings = {"AUTH": 1, "DEFAULT": 1}
    auth = _middleware(_policy(ceilings), bucket="AUTH")
    default = _middleware(_policy(ceilings), bucket="DEFAULT")
    assert _drive(auth, _scope())[0] == 200
    assert _drive(auth, _scope())[0] == 429
    # DEFAULT never saw the AUTH hit — no cross-bucket exhaustion (R6).
    assert _drive(default, _scope())[0] == 200
    assert _drive(default, _scope())[0] == 429


def test_disabled_policy_lets_everything_through() -> None:
    app = _middleware(_policy({"DEFAULT": 1}, enabled=False))
    for _ in range(25):
        assert _drive(app, _scope())[0] == 200


# -------------------------------------------------------------------- R2 / R3


def test_spoofed_forwarded_for_ignored_without_trusted_proxies() -> None:
    """R2: with TRUSTED_PROXY_COUNT=0 a rotating spoofed X-Forwarded-For
    cannot mint fresh buckets — the socket IP keys the window."""
    app = _middleware(_policy({"DEFAULT": 3}, trusted_proxy_count=0))
    for spoof in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        assert _drive(app, _scope(headers=[("X-Forwarded-For", spoof)]))[0] == 200
    status, _ = _drive(app, _scope(headers=[("X-Forwarded-For", "9.9.9.9")]))
    assert status == 429, "all four requests keyed on the socket IP"


def test_rightmost_trusted_hop_keys_the_window() -> None:
    """R3: one trusted proxy — the hop nginx appended is the identity;
    attacker-prependend hops to its left fall away."""
    app = _middleware(_policy({"DEFAULT": 1}, trusted_proxy_count=1))
    ok, _ = _drive(
        app, _scope(headers=[("X-Forwarded-For", "6.6.6.6, 203.0.113.9")], client=("10.0.0.1", 5))
    )
    assert ok == 200
    # Same spoof-prefix, same real client hop ⇒ same bucket (blocked).
    status, _ = _drive(
        app,
        _scope(headers=[("X-Forwarded-For", "7.7.7.7, 203.0.113.9")], client=("10.0.0.1", 5)),
    )
    assert status == 429
    # A different real client hop gets its own bucket.
    other = _drive(
        app, _scope(headers=[("X-Forwarded-For", "198.51.100.7")], client=("10.0.0.1", 5))
    )
    assert other[0] == 200


# ------------------------------------------------------------------------- R4


def test_redis_counter_counts_and_expires_verbatim_keys() -> None:
    redis = FakeRedis()
    counter = RedisCounter(redis)

    async def run() -> None:
        assert await counter.incr("rl:login:1.2.3.4:100", 60) == 1
        assert await counter.incr("rl:login:1.2.3.4:100", 60) == 2

    asyncio.run(run())
    # Keys are used verbatim (health's `rl:*` counter state survives
    # adoption) and the first hit arms the expiry.
    assert redis.store == {"rl:login:1.2.3.4:100": 2}
    assert redis.expired == {"rl:login:1.2.3.4:100": 60}


def test_redis_down_degrades_open_and_logs() -> None:
    redis = FakeRedis()
    redis.fail = True
    counter = RedisCounter(redis)

    async def run() -> int:
        return await counter.incr("rl:login:1.2.3.4:100", 60)

    logger = logging.getLogger("nx_auth.ratelimit")
    with pytest.MonkeyPatch.context() as _mp:
        records: list[logging.LogRecord] = []
        handler = logging.Handler()

        def _capture(record: logging.LogRecord) -> None:
            records.append(record)

        handler.emit = _capture  # type: ignore[method-assign]
        logger.addHandler(handler)
        try:
            for _ in range(50):
                assert asyncio.run(run()) == 0, "degrade open: count 0 ⇒ allowed"
        finally:
            logger.removeHandler(handler)
    assert any("unavailable" in r.getMessage() for r in records), "the outage is logged (R4)"


def test_failing_counter_backend_lets_requests_proceed() -> None:
    """R4 end-to-end: an unreachable backend never becomes an outage —
    the middleware proceeds for every request."""

    class ExplodingCounter:
        async def incr(self, key: str, window: int) -> int:
            raise RuntimeError("backend gone")

    policy = _policy({"DEFAULT": 1})
    policy.counter = ExplodingCounter()
    app = _middleware(policy)
    for _ in range(10):
        assert _drive(app, _scope())[0] == 200


# ------------------------------------------------- dependency + mount (D1/D5)


def _mounted_app(ceilings: dict[str, int]) -> FastAPI:
    state: dict[str, dict[str, int]] = {"ceilings": ceilings}

    app = FastAPI()
    mount_rate_limit(
        app,
        policy=RateLimitPolicy(
            ceiling=lambda bucket: state["ceilings"].get(bucket),
            counter=InMemoryCounter(clock=FakeClock()),
        ),
        bucket_for=lambda scope: "DEFAULT" if scope.get("path", "").startswith("/api/") else None,
    )

    @app.get("/api/v1/probe")
    def probe() -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/static-untouched")
    def untouched() -> dict[str, str]:
        return {"ok": "1"}

    app.state._ceilings = state
    return app


def test_middleware_skips_paths_without_a_bucket() -> None:
    client = TestClient(_mounted_app({"DEFAULT": 1}))
    for _ in range(5):
        assert client.get("/static-untouched").status_code == 200
    assert client.get("/api/v1/probe").status_code == 200
    assert client.get("/api/v1/probe").status_code == 429


def test_rate_limit_dependency_enforces_bucket() -> None:
    app = FastAPI()
    mount_rate_limit(
        app,
        policy=RateLimitPolicy(
            ceiling=lambda bucket: {"AI": 2}.get(bucket),
            counter=InMemoryCounter(clock=FakeClock()),
        ),
        bucket_for=lambda scope: None,
    )

    @app.get("/ai")
    def ai(_rl: None = Depends(rate_limit("AI", prefix="ai"))) -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/untouched")
    def untouched() -> dict[str, str]:
        return {"ok": "1"}

    client = TestClient(app)
    for _ in range(2):
        assert client.get("/ai").status_code == 200
    blocked = client.get("/ai")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    # A route without the dependency is untouched.
    assert client.get("/untouched").status_code == 200


def test_rate_limit_dependency_keyed_identity() -> None:
    """The keyed limiters (R8): `key=` selects per-user identity instead
    of the per-IP default — one user's budget is not another's."""
    app = FastAPI()
    seen: list[str] = []

    def _user_key(request: Any) -> str:
        user = str(request.query_params.get("user", "anon"))
        seen.append(user)
        return user

    mount_rate_limit(
        app,
        policy=RateLimitPolicy(
            ceiling=lambda bucket: {"AI": 1}.get(bucket),
            counter=InMemoryCounter(clock=FakeClock()),
        ),
        bucket_for=lambda scope: None,
    )

    @app.get("/ai")
    def ai(_rl: None = Depends(rate_limit("AI", key=_user_key))) -> dict[str, str]:
        return {"ok": "1"}

    client = TestClient(app)
    assert client.get("/ai?user=alice").status_code == 200
    assert client.get("/ai?user=alice").status_code == 429
    assert client.get("/ai?user=bob").status_code == 200, "per-user windows are independent"
    assert seen == ["alice", "alice", "bob"], "the key callable resolved identities"


def test_dependency_default_ceiling_when_policy_has_none() -> None:
    """Health's pre-§16 semantics: a bucket without a policy ceiling
    falls back to the route's own default (R8 shape)."""
    app = FastAPI()
    mount_rate_limit(
        app,
        policy=RateLimitPolicy(
            ceiling=lambda bucket: None,
            counter=InMemoryCounter(clock=FakeClock()),
        ),
        bucket_for=lambda scope: None,
    )

    @app.get("/login")
    def login(_rl: None = Depends(rate_limit("AUTH", prefix="login", default=2))) -> dict[str, str]:
        return {"ok": "1"}

    client = TestClient(app)
    assert client.get("/login").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/login").status_code == 429


def test_ceilings_resolve_per_request_not_at_mount_time() -> None:
    """Case 22 (kit half): the ceiling callable is consulted on every
    check — a product's live Settings change applies without remount."""
    app = _mounted_app({"DEFAULT": 5})
    client = TestClient(app)
    for _ in range(5):
        assert client.get("/api/v1/probe").status_code == 200
    assert client.get("/api/v1/probe").status_code == 429
    state = app.state._ceilings
    state["ceilings"]["DEFAULT"] = 10
    assert client.get("/api/v1/probe").status_code == 200


def test_hit_raw_keyed_check_preserves_key_and_window() -> None:
    """`hit` is the escape hatch for product keyed limiters (R8): the
    key arrives verbatim at the counter and the window is the caller's
    (health's 300s AI windows), independent of the policy window."""
    counter = InMemoryCounter(clock=FakeClock())
    policy = RateLimitPolicy(
        ceiling=lambda bucket: {"AI": 1}.get(bucket), counter=counter, window=60
    )

    async def run() -> int | None:
        return await policy.hit("rl:ai_assist:u:alice:100", limit=2, window=300)

    assert asyncio.run(run()) is None
    assert asyncio.run(run()) is None
    assert asyncio.run(run()) == 300
    # The raw key reached the counter untouched.
    assert "rl:ai_assist:u:alice:100" in counter._events


def test_hit_zero_limit_disables() -> None:
    policy = RateLimitPolicy(ceiling=lambda bucket: None)
    assert asyncio.run(policy.hit("k", limit=0, window=60)) is None


def test_auth_limiters_unchanged_r7a() -> None:
    """The sync auth limiters (§7 / S17) are untouched by the new
    backends: sliding window + per-minute ceilings still apply."""
    limiter = RateLimiter(per_minute=2)
    assert limiter.allow("ip:1.2.3.4", now=100.0) == (True, 0)
    assert limiter.allow("ip:1.2.3.4", now=100.0)[0] is True
    assert limiter.allow("ip:1.2.3.4", now=100.0)[0] is False
