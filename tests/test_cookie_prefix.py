"""Per-app cookie prefixes and legacy clearing (co-location isolation).

Co-location fact (verified 2026-11-20): cookies are scoped by hostname —
ports are ignored — so three apps sharing `nx_access`/`nx_refresh`/
`nx_csrf` on one host shadow each other's sessions. The prefix knob
gives every product distinct names; the legacy middleware retires the
old `nx_*` names on sight instead of letting them linger for the
refresh absolute TTL.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nx_auth.config import AuthConfig
from nx_auth.cookies import (
    LEGACY_COOKIE_NAMES,
    CsrfMiddleware,
    LegacyCookieClearingMiddleware,
    cookie_names,
    session_cookie_names,
)


def _cfg(prefix: str, secure: bool = False) -> AuthConfig:
    return AuthConfig(iss="t", cookie_prefix=prefix, cookie_secure=secure)


class TestPrefixNames:
    def test_default_prefix_reproduces_historical_names(self) -> None:
        names = cookie_names(AuthConfig(iss="t"))
        assert (names.access, names.refresh, names.csrf) == (
            "nx_access",
            "nx_refresh",
            "nx_csrf",
        )

    @pytest.mark.parametrize("prefix", ["ha_", "sa_", "career_", "nx_"])
    def test_prefixed_names(self, prefix: str) -> None:
        names = cookie_names(_cfg(prefix))
        assert names.access == f"{prefix}access"
        assert names.refresh == f"{prefix}refresh"
        assert names.csrf == f"{prefix}csrf"

    def test_secure_takes_host_prefix(self) -> None:
        names = cookie_names(_cfg("ha_", secure=True))
        assert names.access == "__Host-ha_access"
        # refresh keeps the narrower Path, so never the __Host- prefix
        assert names.refresh == "ha_refresh"

    def test_session_cookie_names_covers_both_variants(self) -> None:
        assert session_cookie_names(_cfg("ha_", secure=True)) == (
            "__Host-ha_access",
            "ha_access",
            "ha_refresh",
        )

    @pytest.mark.parametrize(
        "bad", ["", "_", "Ha_", "ha", "hA_", "1a_", "ha__", "ha-b_", "nx"]
    )
    def test_invalid_prefix_fails_closed(self, bad: str) -> None:
        with pytest.raises(ValueError, match="cookie_prefix"):
            _cfg(bad)


class _App:
    def __init__(self, *, csrf_name: str, session_names: tuple[str, ...]) -> None:
        app = FastAPI()

        @app.post("/echo")
        async def echo() -> dict[str, bool]:
            return {"ok": True}

        app.add_middleware(
            CsrfMiddleware,
            cookie_name=csrf_name,
            exempt_prefixes=(),
            session_cookie_names=session_names,
        )
        self.client = TestClient(app)


class TestCsrfMiddlewarePrefixed:
    def test_prefixed_csrf_echo_accepted(self) -> None:
        app = _App(csrf_name="sa_csrf", session_names=session_cookie_names(_cfg("sa_")))
        r = app.client.post(
            "/echo",
            cookies={"sa_csrf": "tok"},
            headers={"x-csrf-token": "tok"},
        )
        assert r.status_code == 200

    def test_legacy_name_alone_is_not_a_session(self) -> None:
        # A stale pre-prefix nx_access must not arm the CSRF gate: with no
        # *current* session names present, the request is cookie-less as
        # far as CSRF is concerned (the legacy clearing middleware retires
        # the stale jar entry on this very response).
        app = _App(csrf_name="sa_csrf", session_names=session_cookie_names(_cfg("sa_")))
        r = app.client.post("/echo", cookies={"nx_access": "stale"})
        assert r.status_code == 200

    def test_prefixed_session_without_echo_forbidden(self) -> None:
        app = _App(csrf_name="sa_csrf", session_names=session_cookie_names(_cfg("sa_")))
        r = app.client.post("/echo", cookies={"sa_access": "live"})
        assert r.status_code == 403


class TestLegacyClearingMiddleware:
    def _app(self) -> TestClient:
        app = FastAPI()

        @app.get("/x")
        async def x() -> dict[str, bool]:
            return {"ok": True}

        app.add_middleware(LegacyCookieClearingMiddleware)
        return TestClient(app)

    @staticmethod
    def _set_cookies(response: Any) -> set[str]:
        expired: set[str] = set()
        for raw in response.headers.get_list("set-cookie"):
            value = raw if isinstance(raw, str) else str(getattr(raw, "value", raw))
            name = value.split("=", 1)[0]
            if "max-age=0" in value.lower():
                expired.add(name)
        return expired

    def test_legacy_names_expired_on_sight(self) -> None:
        client = self._app()
        r = client.get("/x", cookies={"nx_access": "a", "nx_csrf": "c"})
        expired = self._set_cookies(r)
        assert {"nx_access", "nx_csrf"} <= expired

    def test_refresh_expired_at_both_paths(self) -> None:
        client = self._app()
        r = client.get("/x", cookies={"nx_refresh": "r"})
        raw = [str(v) for v in r.headers.get_list("set-cookie") if str(v).startswith("nx_refresh=")]
        paths = {seg.split("=", 1)[1] for v in raw for seg in v.split("; ") if seg.startswith("Path=")}
        assert paths == {"/", "/api/v1/auth"}

    def test_host_prefixed_access_expired(self) -> None:
        client = self._app()
        r = client.get("/x", cookies={"__Host-nx_access": "a"})
        assert "__Host-nx_access" in self._set_cookies(r)

    def test_clean_jar_gets_no_clearing_headers(self) -> None:
        client = self._app()
        r = client.get("/x", cookies={"sa_access": "current"})
        assert not self._set_cookies(r)

    def test_no_cookies_no_headers(self) -> None:
        client = self._app()
        r = client.get("/x")
        assert not self._set_cookies(r)


def test_legacy_names_match_pre_0_7_constants() -> None:
    # The names browsers actually hold from pre-prefix deployments.
    assert LEGACY_COOKIE_NAMES == ("nx_access", "nx_refresh", "nx_csrf")
