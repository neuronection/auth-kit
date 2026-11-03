"""Provider-delegation OAuth tests — the plan 52 §13 matrix.

Pins, at the kit level, every law ``nx_auth.oauth`` enforces for the
family hosts: PKCE S256 (the RFC 7636 §4.2 vector), bind-state
single-use/expiry/principal-binding (Rev 3 E12 — the anti-bind-CSRF
law), code exchange over an injected transport (no network), the
closed typed-error mapping (``invalid_grant`` → ``needs-auth`` stop),
single-flight refresh under concurrency, bounded full-jitter transient
backoff, rotation-crash safety (new grant persisted before the old is
discarded), sealed custody over ``nx_auth.atrest`` — and the custody
law itself: **no token value in any repr, str, error or returned dict**.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta

import pytest

from nx_auth.atrest import SECRET_MARKER, SecretCipher
from nx_auth.oauth import (
    ERROR_CODES,
    STATE_TTL_SECONDS,
    AuthorizationOffer,
    InMemorySealedStore,
    InMemoryStateStore,
    OAuthClient,
    OAuthError,
    TokenClient,
    TokenResponse,
    TokenSet,
    TokenTransport,
    TokenVault,
    authorize,
    build_authorize_url,
    code_challenge,
    exchange_code,
    grant_failure,
    new_state,
    new_verifier,
    refresh_tokens,
)
from nx_auth.testing import FakeTokenTransport, assert_no_token_leak, token_response

FIXED_NOW = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)

# Fixed test-only key material (tests/test_atrest.py pattern — never a real key).
TEST_DATA_KEY = "ERERERERERERERERERERERERERERERERERERERERERE="

ACCESS = "live-access-token-0123456789abcdef"
REFRESH = "live-refresh-token-0123456789abcdef"


class _Clock:
    """Deterministic wall clock for expiry-driven decisions."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


class _Monotonic:
    """Deterministic monotonic clock for the flight-window decisions."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class SleepyScriptTransport:
    """A scripted transport that holds each call briefly — forces lock
    contention so the single-flight tests would fail loudly without it."""

    def __init__(self, *script: TokenResponse, delay: float = 0.05) -> None:
        self._script = list(script)
        self._delay = delay
        self.calls: list[tuple[str, dict[str, str]]] = []

    def post_form(
        self, url: str, data: Mapping[str, str], *, headers: Mapping[str, str] | None = None
    ) -> TokenResponse:
        self.calls.append((url, dict(data)))
        time.sleep(self._delay)
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


class CrashStore:
    """A SealedStore whose ``set`` fails a configurable number of times —
    the rotation-crash producer (ADR-0042 clause 6's broken chain)."""

    def __init__(self) -> None:
        self._inner = InMemorySealedStore()
        self.fail_next = False
        self.set_attempts = 0

    def get(self, binding_id: str) -> dict[str, str] | None:
        return self._inner.get(binding_id)

    def set(self, binding_id: str, sealed: dict[str, str]) -> None:
        self.set_attempts += 1
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("disk full")
        self._inner.set(binding_id, sealed)

    def delete(self, binding_id: str) -> None:
        self._inner.delete(binding_id)


def _client(**overrides: object) -> OAuthClient:
    base: dict[str, object] = {
        "client_id": "test-client-id",
        "token_url": "https://provider.example/token",
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "authorize_url": "https://provider.example/authorize",
        "scopes": ("calendar.read", "calendar.write"),
    }
    base.update(overrides)
    return OAuthClient(**base)  # type: ignore[arg-type]


def _cipher() -> SecretCipher:
    return SecretCipher(TEST_DATA_KEY)


def _vault(store: InMemorySealedStore | None = None) -> TokenVault:
    return TokenVault(store or InMemorySealedStore(), cipher=_cipher())


def _tokens(**overrides: object) -> TokenSet:
    base: dict[str, object] = {
        "access_token": ACCESS,
        "refresh_token": REFRESH,
        "expires_at": FIXED_NOW + timedelta(seconds=3600),
        "scope": "calendar.read calendar.write",
    }
    base.update(overrides)
    return TokenSet(**base)  # type: ignore[arg-type]


def _expired_tokens() -> TokenSet:
    return _tokens(expires_at=FIXED_NOW - timedelta(seconds=90))


def _client_for(vault: TokenVault, transport: object, **kwargs: object) -> TokenClient:
    base: dict[str, object] = {
        "vault": vault,
        "transport": transport,
        "clock": lambda: FIXED_NOW,  # deterministic expiry decisions
    }
    base.update(kwargs)
    return TokenClient(_client(), **base)  # type: ignore[arg-type]


def _run_concurrently(fn: Callable[[], object], n: int = 8) -> tuple[list[object], list[Exception]]:
    """Run ``fn`` in ``n`` threads released together by a barrier — the
    contention producer for the single-flight assertions."""
    barrier = threading.Barrier(n)
    results: list[object] = []
    errors: list[Exception] = []

    def worker() -> None:
        barrier.wait(timeout=5)
        try:
            results.append(fn())
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads), "a worker hung"
    return results, errors


# ---------------------------------------------------------------------------
# 1. PKCE — RFC 7636 §4.2 vector + generator discipline
# ---------------------------------------------------------------------------

def test_pkce_s256_rfc7636_appendix_b_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_new_verifier_is_rfc7636_compliant_and_unique() -> None:
    for _ in range(50):
        verifier = new_verifier()
        assert 43 <= len(verifier) <= 128
        assert code_challenge(verifier)  # passes the §4.1 charset check
    assert len({new_verifier() for _ in range(50)}) == 50


def test_code_challenge_rejects_out_of_spec_verifiers() -> None:
    for bad in ("short", "a" * 42, "a" * 129, "has spaces and more than forty three chars!!"):
        with pytest.raises(ValueError, match="RFC 7636"):
            code_challenge(bad)


def test_new_state_is_opaque_and_unique() -> None:
    states = {new_state() for _ in range(50)}
    assert len(states) == 50
    assert min(len(s) for s in states) >= 32


# ---------------------------------------------------------------------------
# 2. Bind state — single-use, expiry, principal binding (Rev 3 E12)
# ---------------------------------------------------------------------------

def _offer(store: InMemoryStateStore, principal: str = "user-1") -> AuthorizationOffer:
    return authorize(_client(), store=store, principal_id=principal, now=FIXED_NOW)


def _fixed_store() -> InMemoryStateStore:
    """A state store on the fixed clock (issue-time and consume-time agree)."""
    return InMemoryStateStore(clock=lambda: FIXED_NOW)


def test_state_roundtrip_returns_the_issued_record() -> None:
    store = _fixed_store()
    offer = _offer(store)
    record = store.consume(offer.state, principal_id="user-1")
    assert record.code_verifier == offer.record.code_verifier
    assert record.principal_id == "user-1"
    assert record.redirect_uri == _client().redirect_uri
    assert record.expires_at == FIXED_NOW + timedelta(seconds=STATE_TTL_SECONDS)


def test_state_is_single_use() -> None:
    store = _fixed_store()
    offer = _offer(store)
    store.consume(offer.state, principal_id="user-1")
    with pytest.raises(OAuthError) as excinfo:
        store.consume(offer.state, principal_id="user-1")
    assert excinfo.value.code == "invalid"


def test_state_expiry_fails_closed_typed() -> None:
    clock = _Clock(FIXED_NOW)
    store = InMemoryStateStore(clock=clock)
    offer = authorize(_client(), store=store, principal_id="user-1", now=FIXED_NOW)
    clock.advance(STATE_TTL_SECONDS + 1)
    with pytest.raises(OAuthError) as excinfo:
        store.consume(offer.state, principal_id="user-1")
    assert excinfo.value.code == "not-ready"


def test_state_principal_mismatch_is_refused_and_killed() -> None:
    """The bind-CSRF case: another principal's callback cannot complete
    the flow — and the record is destroyed either way (single-use holds
    even for the failed consume)."""
    store = _fixed_store()
    offer = _offer(store, principal="user-1")
    with pytest.raises(OAuthError) as excinfo:
        store.consume(offer.state, principal_id="user-2")
    assert excinfo.value.code == "invalid"
    with pytest.raises(OAuthError) as second:
        store.consume(offer.state, principal_id="user-1")
    assert second.value.code == "invalid"


def test_state_discard_maps_to_canceled() -> None:
    store = _fixed_store()
    offer = _offer(store)
    store.discard(offer.state)
    with pytest.raises(OAuthError) as excinfo:
        store.consume(offer.state, principal_id="user-1")
    assert excinfo.value.code == "canceled"


def test_unknown_state_is_invalid() -> None:
    store = InMemoryStateStore()
    with pytest.raises(OAuthError) as excinfo:
        store.consume("never-issued", principal_id="user-1")
    assert excinfo.value.code == "invalid"


def test_state_record_repr_masks_the_nonce_and_verifier() -> None:
    offer = _offer(_fixed_store())
    text = f"{offer.record!s}\n{offer.record!r}"
    assert offer.state not in text
    assert offer.record.code_verifier not in text
    assert "principal_id='user-1'" in repr(offer.record)


# ---------------------------------------------------------------------------
# 3. Authorize URL — scopes verbatim, PKCE, provider-quirk data
# ---------------------------------------------------------------------------

def test_authorize_url_carries_pkce_scopes_and_state() -> None:
    url = build_authorize_url(
        _client(),
        state="s-1",
        code_challenge="c-1",
        redirect_uri="http://127.0.0.1:9999/cb",
    )
    assert url.startswith("https://provider.example/authorize?")
    for piece in (
        "response_type=code",
        "client_id=test-client-id",
        "redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb",
        "scope=calendar.read+calendar.write",
        "state=s-1",
        "code_challenge=c-1",
        "code_challenge_method=S256",
    ):
        assert piece in url


def test_authorize_url_appends_to_an_endpoint_with_a_query() -> None:
    url = build_authorize_url(
        _client(authorize_url="https://provider.example/authorize?tenant=acme"),
        state="s-1",
        code_challenge="c-1",
    )
    assert url.startswith("https://provider.example/authorize?tenant=acme&")


def test_prompt_and_access_type_and_extra_param_precedence() -> None:
    consent = build_authorize_url(
        _client(), state="s-1", code_challenge="c-1", prompt="consent", access_type="offline"
    )
    assert "prompt=consent" in consent
    assert "access_type=offline" in consent
    # Provider-quirk DATA wins over the conveniences (the catalog row rules).
    overridden = build_authorize_url(
        _client(),
        state="s-1",
        code_challenge="c-1",
        prompt="consent",
        extra_params={"prompt": "login", "hd": "example.com"},
    )
    assert "prompt=login" in overridden
    assert "prompt=consent" not in overridden
    assert "hd=example.com" in overridden


def test_authorize_url_requires_client_and_authorize_config() -> None:
    with pytest.raises(OAuthError) as no_id:
        build_authorize_url(_client(client_id=""), state="s", code_challenge="c")
    assert no_id.value.code == "needs-config"
    with pytest.raises(OAuthError) as no_url:
        build_authorize_url(_client(authorize_url=""), state="s", code_challenge="c")
    assert no_url.value.code == "needs-config"


def test_authorize_issues_a_principal_bound_record_with_host_extra() -> None:
    store = _fixed_store()
    offer = authorize(
        _client(),
        store=store,
        principal_id="user-1",
        extra={"binding_id": "binding-9"},
        now=FIXED_NOW,
    )
    assert offer.state == offer.record.state
    assert "code_challenge_method=S256" in offer.authorize_url
    record = store.consume(offer.state, principal_id="user-1")
    assert record.extra == {"binding_id": "binding-9"}


# ---------------------------------------------------------------------------
# 4. Code exchange — happy path, client kinds, typed error mapping
# ---------------------------------------------------------------------------

def test_exchange_happy_path_public_client() -> None:
    transport = FakeTokenTransport(token_response(scope="calendar.read"))
    tokens = exchange_code(
        _client(),
        code="auth-code-1",
        code_verifier=new_verifier(),
        transport=transport,
        redirect_uri="http://127.0.0.1:8765/callback",
        now=FIXED_NOW,
    )
    assert tokens.access_token == "test-access-token"
    assert tokens.refresh_token == "test-refresh-token"
    assert tokens.expires_at == FIXED_NOW + timedelta(seconds=3600)
    assert tokens.scope == "calendar.read"
    assert tokens.token_type == "Bearer"
    url, form = transport.calls[0]
    assert url == "https://provider.example/token"
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code-1"
    assert form["client_id"] == "test-client-id"
    assert "client_secret" not in form  # public client: PKCE is the proof


def test_exchange_confidential_client_sends_its_secret() -> None:
    transport = FakeTokenTransport(token_response())
    exchange_code(
        _client(client_secret="confidential-secret"),
        code="auth-code-1",
        code_verifier=new_verifier(),
        transport=transport,
        now=FIXED_NOW,
    )
    assert transport.calls[0][1]["client_secret"] == "confidential-secret"


def test_exchange_maps_invalid_grant_to_needs_auth_stop() -> None:
    transport = FakeTokenTransport(
        token_response(
            status_code=400,
            access_token="",
            refresh_token=None,
            expires_in=None,
            scope="",
            error="invalid_grant",
            error_description="Token has been expired or revoked.",
        )
    )
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(
            _client(), code="used-code", code_verifier=new_verifier(), transport=transport
        )
    assert excinfo.value.code == "needs-auth"
    assert excinfo.value.retryable is False
    assert excinfo.value.grant_error == "invalid_grant"


def test_exchange_error_mapping_table() -> None:
    def exchange_with(error: str) -> OAuthError:
        transport = FakeTokenTransport(
            token_response(status_code=400, access_token="", refresh_token=None, error=error)
        )
        with pytest.raises(OAuthError) as excinfo:
            exchange_code(
                _client(), code="c", code_verifier=new_verifier(), transport=transport
            )
        return excinfo.value

    assert exchange_with("invalid_client").code == "needs-secret"
    assert exchange_with("insufficient_scope").code == "needs-secret"
    assert exchange_with("unsupported_grant_type").code == "provider"
    assert exchange_with("totally_novel_error").code == "provider"


def test_exchange_maps_http_conditions() -> None:
    throttled = FakeTokenTransport(token_response(status_code=429, retry_after=12.0))
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(_client(), code="c", code_verifier=new_verifier(), transport=throttled)
    assert excinfo.value.code == "rate-limited"
    assert excinfo.value.retryable is True
    assert excinfo.value.retry_after == 12.0

    down = FakeTokenTransport(token_response(status_code=503, access_token=""))
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(_client(), code="c", code_verifier=new_verifier(), transport=down)
    assert excinfo.value.code == "unreachable"
    assert excinfo.value.retryable is True

    non_json = FakeTokenTransport(TokenResponse(status_code=200, data=None))
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(_client(), code="c", code_verifier=new_verifier(), transport=non_json)
    assert excinfo.value.code == "provider"

    no_token = FakeTokenTransport(token_response(access_token="", refresh_token=None))
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(_client(), code="c", code_verifier=new_verifier(), transport=no_token)
    assert excinfo.value.code == "provider"


def test_exchange_transport_exception_maps_unreachable_and_scrubs_urls() -> None:
    code = "auth-code-xyz"
    transport = FakeTokenTransport(
        OSError(f"POST https://provider.example/token?code={code} dropped")
    )
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(_client(), code=code, code_verifier=new_verifier(), transport=transport)
    assert excinfo.value.code == "unreachable"
    assert f"code={code}" not in str(excinfo.value)


def test_exchange_requires_config() -> None:
    transport = FakeTokenTransport()
    with pytest.raises(OAuthError) as excinfo:
        exchange_code(
            _client(client_id=""), code="c", code_verifier="v", transport=transport
        )
    assert excinfo.value.code == "needs-config"
    assert transport.calls == []  # no network without config


def test_grant_failure_helper_serves_callback_errors() -> None:
    assert grant_failure("access_denied", "the user declined").code == "canceled"
    assert grant_failure("slow_down").code == "rate-limited"
    assert grant_failure("slow_down").retryable is True
    assert grant_failure("something_new").code == "provider"


def test_unknown_error_code_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="closed family set"):
        OAuthError("explode", "not in the vocabulary")


def test_error_vocabulary_is_closed_and_typed() -> None:
    assert ERROR_CODES == (
        "needs-auth",
        "needs-secret",
        "needs-config",
        "invalid",
        "rate-limited",
        "unreachable",
        "provider",
        "not-ready",
        "canceled",
    )
    for code in ERROR_CODES:
        error = OAuthError(code, "probe")
        assert error.code == code
        assert str(error).startswith(f"{code}:")  # typed, not raw exception text


def test_retryable_defaults_follow_the_family_posture() -> None:
    assert OAuthError("needs-auth", "x").retryable is False
    assert OAuthError("unreachable", "x").retryable is True
    assert OAuthError("provider", "x", retryable=True).retryable is True  # explicit wins


# ---------------------------------------------------------------------------
# 5. Refresh — single flight, bounded backoff, rotation-crash safety
# ---------------------------------------------------------------------------

def test_refresh_tokens_direct_grant_form_and_carry_forward() -> None:
    """The raw grant (no policy layer): form shape + the carry-forward rule."""
    transport = FakeTokenTransport(token_response(refresh_token=None, access_token="new-access"))
    fresh = refresh_tokens(_client(), refresh_token=REFRESH, transport=transport, now=FIXED_NOW)
    url, form = transport.calls[0]
    assert url == "https://provider.example/token"
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == REFRESH
    assert form["client_id"] == "test-client-id"
    assert "client_secret" not in form
    assert fresh.refresh_token == REFRESH  # omitted ≠ revoked
    assert fresh.expires_at == FIXED_NOW + timedelta(seconds=3600)


def test_refresh_is_single_flight_under_concurrency() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = SleepyScriptTransport(
        token_response(access_token="fresh-access", refresh_token="rot-2")
    )
    client = _client_for(vault, transport)
    results, errors = _run_concurrently(lambda: client.access("binding-1"))
    assert errors == []
    assert results == ["fresh-access"] * 8
    assert len(transport.calls) == 1  # one attempt; everyone awaited it


def test_invalid_grant_stops_and_the_failure_is_adopted_by_followers() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = SleepyScriptTransport(
        token_response(
            status_code=400,
            access_token="",
            refresh_token=None,
            error="invalid_grant",
            error_description="revoked",
        )
    )
    client = _client_for(vault, transport)
    _, errors = _run_concurrently(lambda: client.refresh("binding-1"))
    assert len(errors) == 8
    assert {getattr(exc, "code", None) for exc in errors} == {"needs-auth"}
    assert len(transport.calls) == 1  # "stop" — one burned round-trip, not eight


def test_transient_backoff_is_bounded_and_jittered_then_succeeds() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = FakeTokenTransport(
        token_response(status_code=503, access_token=""),
        token_response(status_code=503, access_token=""),
        token_response(access_token="fresh-access", refresh_token="rot-2"),
    )
    sleeps: list[float] = []
    client = _client_for(
        vault,
        transport,
        sleep=sleeps.append,
        jitter=lambda bound: bound / 2,
        max_attempts=3,
        base_delay=1.0,
        max_delay=4.0,
    )
    tokens = client.refresh("binding-1")
    assert tokens.access_token == "fresh-access"
    assert len(transport.calls) == 3
    assert sleeps == [0.5, 1.0]  # full-jitter half of bounds 1, 2
    assert all(delay <= 4.0 for delay in sleeps)


def test_retry_honors_a_capped_retry_after() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = FakeTokenTransport(
        token_response(status_code=429, retry_after=30.0),
        token_response(access_token="fresh-access"),
    )
    sleeps: list[float] = []
    client = _client_for(vault, transport, sleep=sleeps.append, max_delay=4.0)
    tokens = client.refresh("binding-1")
    assert tokens.access_token == "fresh-access"
    assert sleeps == [4.0]  # Retry-After capped at max_delay


def test_retry_exhaustion_raises_the_transient_error() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = FakeTokenTransport(*[token_response(status_code=503) for _ in range(3)])
    sleeps: list[float] = []
    client = _client_for(
        vault,
        transport,
        sleep=sleeps.append,
        jitter=lambda bound: bound / 2,
        max_attempts=3,
        base_delay=1.0,
    )
    with pytest.raises(OAuthError) as excinfo:
        client.refresh("binding-1")
    assert excinfo.value.code == "unreachable"
    assert len(transport.calls) == 3
    assert len(sleeps) == 2  # retry between attempts, never after the last
    assert all(delay <= 4.0 for delay in sleeps)


def test_refresh_carries_the_old_refresh_token_forward_when_not_rotated() -> None:
    vault = _vault()
    vault.seal("binding-1", _expired_tokens())
    transport = FakeTokenTransport(token_response(refresh_token=None, access_token="new-access"))
    client = _client_for(vault, transport)
    fresh = client.refresh("binding-1")
    assert fresh.refresh_token == REFRESH  # omitted ≠ revoked
    stored = vault.unseal("binding-1")
    assert stored.access_token == "new-access"
    assert stored.refresh_token == REFRESH


def test_rotation_crash_persists_new_grant_only_after_one_atomic_write() -> None:
    """ADR-0042 clause 6: the new token is persisted **before** the old is
    discarded. A failing store write leaves the old grant sealed and
    readable — never a half-written record — and raises typed."""
    store = CrashStore()
    vault = TokenVault(store, cipher=_cipher())
    vault.seal("binding-1", _expired_tokens())
    transport = FakeTokenTransport(
        token_response(access_token="new-access", refresh_token="rot-2"),
        token_response(access_token="new-access", refresh_token="rot-2"),
    )
    mono = _Monotonic()
    client = _client_for(vault, transport, monotonic=mono)

    store.fail_next = True
    with pytest.raises(OAuthError) as excinfo:
        client.refresh("binding-1")
    assert excinfo.value.code == "not-ready"
    assert excinfo.value.retryable is True

    # The old grant survived untouched — the crash window lost nothing.
    survivor = vault.unseal("binding-1")
    assert survivor.access_token == ACCESS
    assert survivor.refresh_token == REFRESH

    # A follower inside the flight window adopts the failure — no second
    # doomed provider round-trip with the already-rotated token.
    with pytest.raises(OAuthError) as adopted:
        client.refresh("binding-1")
    assert adopted.value.code == "not-ready"
    assert len(transport.calls) == 1

    # After the flight window, the host's own retry path succeeds.
    mono.advance(60.0)
    fresh = client.refresh("binding-1")
    assert fresh.refresh_token == "rot-2"
    assert vault.unseal("binding-1").refresh_token == "rot-2"
    assert vault.unseal("binding-1").access_token == "new-access"


def test_access_never_serves_a_token_inside_its_skew_window() -> None:
    vault = _vault()
    soon = _tokens(expires_at=FIXED_NOW + timedelta(seconds=30))  # inside the 60 s skew
    vault.seal("binding-1", soon)
    transport = FakeTokenTransport(token_response(access_token="fresh-access"))
    client = _client_for(vault, transport, clock=lambda: FIXED_NOW)
    assert client.access("binding-1") == "fresh-access"
    assert len(transport.calls) == 1


def test_access_serves_a_still_fresh_token_without_a_refresh() -> None:
    vault = _vault()
    vault.seal("binding-1", _tokens(expires_at=FIXED_NOW + timedelta(minutes=30)))
    transport = FakeTokenTransport()
    client = _client_for(vault, transport, clock=lambda: FIXED_NOW)
    assert client.access("binding-1") == ACCESS
    assert transport.calls == []


def test_access_without_a_stored_grant_is_needs_auth() -> None:
    client = _client_for(_vault(), FakeTokenTransport())
    with pytest.raises(OAuthError) as excinfo:
        client.access("binding-1")
    assert excinfo.value.code == "needs-auth"


# ---------------------------------------------------------------------------
# 6. Custody — sealed at rest, context-bound, leak-proof
# ---------------------------------------------------------------------------

def test_custody_roundtrip_preserves_every_field() -> None:
    vault = _vault()
    tokens = _tokens(provider_extra={"patient": "abc123"})
    vault.seal("binding-1", tokens)
    assert vault.find("binding-1") == tokens
    assert vault.has("binding-1") is True
    assert vault.unseal("binding-1").provider_extra == {"patient": "abc123"}


def test_sealed_form_is_ciphertext_only() -> None:
    store = InMemorySealedStore()
    vault = TokenVault(store, cipher=_cipher())
    vault.seal("binding-1", _tokens())
    sealed = store.get("binding-1")
    assert sealed is not None
    assert SECRET_MARKER in sealed  # the at-rest wrapper shape
    assert ACCESS not in str(sealed)
    assert REFRESH not in str(sealed)


def test_context_binding_refuses_a_copied_envelope() -> None:
    """The at-rest cut-and-paste defense: a ciphertext moved to another
    binding fails custody — typed, fail closed."""
    store = InMemorySealedStore()
    vault = TokenVault(store, cipher=_cipher())
    vault.seal("binding-1", _tokens())
    copied = store.get("binding-1")
    assert copied is not None
    store.set("binding-2", copied)
    with pytest.raises(OAuthError) as excinfo:
        vault.find("binding-2")
    assert excinfo.value.code == "needs-secret"


def test_vault_without_a_cipher_fails_closed() -> None:
    vault = TokenVault(InMemorySealedStore(), cipher=None)
    with pytest.raises(OAuthError) as seal_exc:
        vault.seal("binding-1", _tokens())
    assert seal_exc.value.code == "needs-secret"
    with pytest.raises(OAuthError) as read_exc:
        vault.find("binding-1")
    assert read_exc.value.code == "needs-secret"


def test_vault_absent_binding_is_needs_auth() -> None:
    vault = _vault()
    assert vault.find("never-bound") is None
    with pytest.raises(OAuthError) as excinfo:
        vault.unseal("never-bound")
    assert excinfo.value.code == "needs-auth"


def test_clear_removes_the_sealed_record() -> None:
    store = InMemorySealedStore()
    vault = _vault(store)
    vault.seal("binding-1", _tokens())
    vault.clear("binding-1")
    assert store.get("binding-1") is None
    assert vault.find("binding-1") is None


def test_no_token_value_leaks_from_any_returned_surface() -> None:
    """The custody law, asserted over everything the module hands back:
    token values, reprs, sealed envelopes, typed errors, flow records."""
    store = InMemorySealedStore()
    vault = TokenVault(store, cipher=_cipher())
    tokens = _tokens()
    vault.seal("binding-1", tokens)

    flow_store = InMemoryStateStore(clock=lambda: FIXED_NOW)
    offer = authorize(_client(), store=flow_store, principal_id="user-1", now=FIXED_NOW)

    code = "auth-code-echoed-back"
    verifier = offer.record.code_verifier
    echoing = FakeTokenTransport(
        TokenResponse(
            status_code=400,
            data={
                "error": "invalid_request",
                "error_description": f"rejecting code={code} verifier={verifier}",
            },
        )
    )
    with pytest.raises(OAuthError) as echoed:
        exchange_code(
            _client(),
            code=code,
            code_verifier=verifier,
            transport=echoing,
            redirect_uri=offer.record.redirect_uri,
        )
    assert "<redacted>" in echoed.value.detail  # scrubbing engaged

    sealed = store.get("binding-1")
    assert sealed is not None
    assert_no_token_leak(
        tokens,
        tokens.redacted(),
        repr(tokens),
        sealed,
        vault.find("binding-1"),
        offer,
        offer.record,
        echoed.value,
        secrets=(ACCESS, REFRESH, code, verifier),
    )
    # The authorize URL carries the state nonce and challenge by design,
    # but never the verifier or any token value.
    assert verifier not in offer.authorize_url
    assert ACCESS not in offer.authorize_url


def test_token_client_and_transport_protocol_shapes() -> None:
    assert isinstance(FakeTokenTransport(), TokenTransport)  # runtime_checkable

    client = TokenClient(
        _client(),
        vault=_vault(),
        transport=FakeTokenTransport(),
        clock=lambda: FIXED_NOW,
    )
    text = repr(client)
    assert ACCESS not in text  # nothing secret is cached into the repr
