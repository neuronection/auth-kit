from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from nx_auth.config import AuthConfig
from nx_auth.lockout import LockoutState, is_locked, register_failure, register_success
from nx_auth.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
    verify_password,
    verify_password_or_dummy,
)
from nx_auth.principal import Principal
from nx_auth.ratelimit import RateLimiter, client_ip
from nx_auth.tenants import RoleChecker, RoleResolver, require_tenant
from nx_auth.tokens import AuthMode

NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


def _state(failed: int = 0, locked: datetime | None = None) -> LockoutState:
    return LockoutState(
        failed_login_attempts=failed,
        locked_until=locked,
        threshold=3,
        lockout_minutes=15,
    )


def test_password_policy_and_roundtrip() -> None:
    check_policy("long-enough-password", 10)
    with pytest.raises(PasswordPolicyError):
        check_policy("short", 10)
    hashed = hash_password("correct-horse-battery")
    assert verify_password("correct-horse-battery", hashed)
    assert not verify_password("wrong-password", hashed)
    with pytest.raises(ValueError):
        hash_password("x", rounds=8)


def test_password_policy_byte_cap_measured_in_utf8_bytes() -> None:
    """The bcrypt cap is 72 *bytes* (identity-auth §7): exactly 72 passes,
    73 fails, and multibyte characters count every encoded byte."""
    check_policy("a" * 72)
    with pytest.raises(PasswordPolicyError, match="at most 72 bytes"):
        check_policy("a" * 73)
    check_policy("ξ" * 36)
    with pytest.raises(PasswordPolicyError, match="at most 72 bytes"):
        check_policy("ξ" * 37)
    with pytest.raises(PasswordPolicyError, match="at most 72 bytes"):
        hash_password("x" * 100)


def test_dummy_verify_never_matches_and_never_omits_work() -> None:
    assert not verify_password_or_dummy("anything-at-all", None)


def test_lockout_counts_threshold_and_window() -> None:
    first = register_failure(_state(), now=NOW)
    assert first.failed_login_attempts == 1
    second = register_failure(first, now=NOW)
    locked = register_failure(second, now=NOW)
    assert locked.failed_login_attempts == 3
    assert locked.locked_until == NOW + timedelta(minutes=15)
    assert is_locked(locked, now=NOW)
    assert not is_locked(locked, now=NOW + timedelta(minutes=16))
    fresh = register_success(locked)
    assert fresh.failed_login_attempts == 0 and fresh.locked_until is None


def test_rate_limiter_sliding_window() -> None:
    limiter = RateLimiter(per_minute=2)
    t0 = 1000.0
    assert limiter.allow("k", now=t0) == (True, 0)
    assert limiter.allow("k", now=t0)[0] is True
    blocked, retry = limiter.allow("k", now=t0)
    assert blocked is False and retry >= 1
    # After the window slides past the first two hits, requests pass again.
    assert limiter.allow("k", now=t0 + 61)[0] is True
    # Independent keys don't interfere.
    assert limiter.allow("other", now=t0)[0] is True


def test_client_ip_trusted_proxy_hops_only() -> None:
    assert client_ip("10.0.0.1", None, 0) == "10.0.0.1"
    # Zero trust: the header is never believed.
    assert client_ip("10.0.0.1", "1.2.3.4", 0) == "10.0.0.1"
    # ProxyFix semantics: N trusted proxies ⇒ take the Nth hop from the
    # right; attacker-prepended garbage on the left falls away.
    assert client_ip("proxy", "client, proxy2", 1) == "proxy2"
    assert client_ip("edge", "a, b, real-client", 2) == "b"
    # Over-trusted count: fall back to the leftmost entry.
    assert client_ip("edge", "only", 3) == "only"


def test_hidden_404_for_tenant_mismatch() -> None:
    principal = Principal(
        user_id="u1",
        email="a@b.c",
        full_name="",
        is_admin=False,
        is_active=True,
        ver=1,
        auth_mode=AuthMode.PASSWORD,
        tenant_id="tenant-a",
    )
    require_tenant(principal, "tenant-a")
    with pytest.raises(HTTPException) as mismatch:
        require_tenant(principal, "tenant-b")
    assert mismatch.value.status_code == 404
    with pytest.raises(HTTPException) as missing_tenant:
        require_tenant(principal, None)
    assert missing_tenant.value.status_code == 404


def test_role_checker_hide_vs_403() -> None:
    principal = Principal(
        user_id="u1",
        email="a@b.c",
        full_name="",
        is_admin=False,
        is_active=True,
        ver=1,
        auth_mode=AuthMode.PASSWORD,
    )

    class _Resolver(RoleResolver):
        def role_of(self, p: Principal) -> str | None:
            del p
            return None

    hiding = RoleChecker(_Resolver(), frozenset({"admin"}), hide=True)
    with pytest.raises(HTTPException) as hidden:
        hiding(principal)
    assert hidden.value.status_code == 404

    strict = RoleChecker(_Resolver(), frozenset({"admin"}), hide=False)
    with pytest.raises(HTTPException) as denied:
        strict(principal)
    assert denied.value.status_code == 403


def test_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("T_AUTH_ACCESS_TTL_MINUTES", "30")
    monkeypatch.setenv("T_AUTH_LOCKOUT_THRESHOLD", "7")
    monkeypatch.setenv("T_REGISTRATION_ENABLED", "false")
    monkeypatch.setenv("T_IDENTITY_MODE", "desktop")
    config = AuthConfig.from_env("T", iss="testkit")
    assert config.access_ttl_minutes == 30
    assert config.lockout_threshold == 7
    assert config.registration_enabled is False
    assert config.identity_mode == "desktop"
    # Garbage falls back to defaults, never to something insecure.
    monkeypatch.setenv("T_AUTH_ACCESS_TTL_MINUTES", "not-a-number")
    assert AuthConfig.from_env("T", iss="testkit").access_ttl_minutes == 60
