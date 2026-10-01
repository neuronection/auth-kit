"""The family security test kit (contract §17).

Reusable helpers so every implementing product asserts the *same*
security properties: contract cases (the checklist), token forging for
negative tests, cookie-flag assertions, and a batteries-included test
app over an in-memory database.
"""

from __future__ import annotations

from typing import Any

import jwt
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from nx_auth.config import AuthConfig
from nx_auth.install import install
from nx_auth.instance import InstanceMode
from nx_auth.keys import KeyRing
from nx_auth.sqlalchemy_stores import (
    SqlAuditSink,
    SqlInstanceStore,
    SqlProfileStore,
    SqlSessionStore,
    SqlUserStore,
    create_all,
)
from nx_auth.tokens import ALGORITHM

CONTRACT_CASES: tuple[str, ...] = (
    "1 forged/wrong-secret/kind-mismatch tokens rejected",
    "2 expired access => 401; refresh path recovers",
    "3 refresh rotation; replay of rotated token => family revoked + ver bump",
    "4 lockout: N failures => 423, unlocks after window",
    "5 cookie flags exact; CSRF enforced on cookie-authenticated POSTs; WS Origin checked",
    "6 instance mode: authenticated DB + desktop => login required; env flip cannot "
    "disable auth; unknown auth_mode fails closed; exchange absent unless open "
    "desktop; local-boot rejected when authenticated",
    "7 admin guard: non-admin => 403; last-admin rails hold",
    "8 profile binding: cross-user X-Profile-Id => 403; absent => 400 (server); "
    "profile-independent endpoints exempt; Default profile auto-provisioned",
    "9 is_active=false => 401 everywhere; deletion cascades fully",
    "10 login error generic; no user enumeration (dummy-hash timing)",
    "11 demo principal on non-demo instance => 401; demo seeder refuses non-demo targets",
    "12 key separation: refresh token verifies under SESSION_KEY => rejected; "
    "DATA_KEY decrypts no JWTs",
    "13 boot guards: production refuses partial/weak/duplicate key pins and "
    "non-Fernet DATA_KEY material; DEBUG/DEMO_MODE refuse production boot; "
    "unpinned keys fatal on server, generated 0600 auth_keys.json on desktop",
    "14 knob map: every §16 tunable reachable from .env and OS env (OS env "
    "wins); unprefixed names inert; .env walk-up disabled in production",
    "15 password-confirming actions (admin/instance, me password change, "
    "account delete) share login's lockout counter and the auth rate limit",
)


def make_test_keyring() -> KeyRing:
    """Fixed, distinct, ≥256-bit test keys — never the real ones."""
    return KeyRing(
        session_key="test-session-key-0123456789abcdefghijklmnopqrstuv",
        refresh_key="test-refresh-key-0123456789abcdefghijklmnopqrstuv",
        data_key="test-data-key-0123456789abcdefghijklmnopqrstuv",
    )


def forge_token(key: str, claims: dict[str, Any], *, algorithm: str = ALGORITHM) -> str:
    """Mint a token *outside* the kit — the negative-test producer."""
    return jwt.encode(claims, key, algorithm=algorithm)


def assert_cookie_flags(
    set_cookie_lines: list[str],
    name: str,
    *,
    http_only: bool,
    secure: bool,
    same_site: str = "Lax",
    path: str | None = None,
) -> None:
    matching = [line for line in set_cookie_lines if line.startswith(f"{name}=")]
    if not matching:
        raise AssertionError(f"cookie {name!r} not set (got {set_cookie_lines})")
    line = matching[0]
    checks = [
        ("HttpOnly" in line, http_only, "HttpOnly"),
        ("Secure" in line, secure, "Secure"),
        (f"samesite={same_site.lower()}" in line.lower(), True, f"SameSite={same_site}"),
    ]
    if path is not None:
        checks.append((f"Path={path}" in line, True, f"Path={path}"))
    for present, expected, label in checks:
        if present != expected:
            raise AssertionError(
                f"cookie {name!r}: expected {label}={'yes' if expected else 'no'} in {line!r}"
            )


def csrf_headers(client: Any) -> dict[str, str]:
    value = client.cookies.get("nx_csrf")
    if not value:
        raise AssertionError("no nx_csrf cookie on the client — log in first")
    return {"X-CSRF-Token": value}


def make_test_app(
    *,
    auth_mode: str | None = "authenticated",
    identity_mode: str = "server",
    demo: bool = False,
    registration: bool = True,
    cookie_secure: bool = False,
    shell_secret: str | None = None,
    require_shell_secret: bool = False,
    shell_exempt_prefixes: tuple[str, ...] = (),
    lockout_threshold: int = 5,
    rate_per_minute: int = 1000,
) -> FastAPI:
    """Batteries-included app: in-memory SQLite, reference stores, audit
    sink, and `install()` applied. `auth_mode=None` simulates a fresh
    DB with no `instance_settings` row (fail-closed ⇒ authenticated)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    factory = sessionmaker(engine)
    instance = SqlInstanceStore(factory)
    if auth_mode is not None:
        instance.set("auth_mode", auth_mode)
    if demo:
        instance.set("demo_mode", "true")
    app = FastAPI()
    app.state.test_engine = engine
    app.state.test_factory = factory
    install(
        app,
        config=AuthConfig(
            iss="testkit",
            identity_mode=identity_mode,  # type: ignore[arg-type]
            registration_enabled=registration,
            cookie_secure=cookie_secure,
            require_shell_secret=require_shell_secret,
            lockout_threshold=lockout_threshold,
            auth_rate_per_minute=rate_per_minute,
            auth_email_rate_per_minute=rate_per_minute,
        ),
        ring=make_test_keyring(),
        users=SqlUserStore(factory),
        sessions=SqlSessionStore(factory),
        profiles=SqlProfileStore(factory),
        instance=instance,
        audit=SqlAuditSink(factory),
        shell_secret=shell_secret,
        shell_exempt_prefixes=shell_exempt_prefixes,
    )
    return app


__all__ = [
    "CONTRACT_CASES",
    "InstanceMode",
    "assert_cookie_flags",
    "csrf_headers",
    "forge_token",
    "make_test_app",
    "make_test_keyring",
]
