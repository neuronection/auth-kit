"""Security headers middleware (plan 21) — contract cases 20 + 21.

Pins the H-matrix at the kit level: the family baseline on every
response incl. static mounts (H1/H3), the web/desktop CSP split with
`?shell=` marker gating (H2 — career's rule as family law), the
no-CSP policy shape (health), conditional HSTS behind a TLS proxy, and
per-route `X-Frame-Options` overrides.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.staticfiles import StaticFiles

from nx_auth.headers import (
    CSP_TEMPLATE,
    HeaderPolicy,
    SecurityHeadersMiddleware,
    desktop_csp,
    web_csp,
)

pytestmark = pytest.mark.contract  # identity-auth §18 cases 20 + 21 (plan 21)

WEB = web_csp()
DESKTOP = desktop_csp()


def test_family_csp_template_bytes() -> None:
    """The family CSP body — career's template, byte-for-byte."""
    assert CSP_TEMPLATE == (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
        " script-src {script}; connect-src 'self'; font-src 'self' data:; object-src 'none';"
        " frame-ancestors 'none'; base-uri 'self'"
    )
    assert "script-src 'self';" in WEB
    assert "unsafe-eval" not in WEB
    assert "script-src 'self' 'unsafe-eval';" in DESKTOP


def _scope(
    path: str = "/",
    headers: list[tuple[str, str]] | None = None,
    query: bytes = b"",
    scheme: str = "http",
) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": path,
        "query_string": query,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or [])],
        "client": ("1.2.3.4", 5),
        "server": ("test", 80),
    }


def _drive(app: Any, scope: dict[str, Any]) -> dict[bytes, bytes]:
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    return dict(start["headers"])


async def _ok_app(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _wrapped(
    policy: HeaderPolicy, marker: Any = None, inner: Any = _ok_app
) -> SecurityHeadersMiddleware:
    kwargs: dict[str, Any] = {"policy": policy}
    if marker is not None:
        kwargs["desktop_marker"] = marker
    return SecurityHeadersMiddleware(inner, **kwargs)


# ------------------------------------------------------------------ H1 (web)


def test_every_response_carries_the_family_baseline() -> None:
    app = _wrapped(HeaderPolicy())
    headers = _drive(app, _scope())
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"x-frame-options"] == b"DENY"
    assert headers[b"referrer-policy"] == b"strict-origin-when-cross-origin"
    assert headers[b"content-security-policy"].decode() == WEB
    assert b"strict-transport-security" not in headers


def test_web_csp_is_strict_even_with_shell_shaped_query() -> None:
    """H2 web half: nothing a browser can send unlocks eval — a marker
    without the per-boot secret stays on the web CSP."""
    app = _wrapped(HeaderPolicy(desktop_csp=DESKTOP), marker=lambda value: value == "real")
    for query in (b"", b"shell=", b"shell=not-the-token"):
        headers = _drive(app, _scope(query=query))
        assert "unsafe-eval" not in headers[b"content-security-policy"].decode()


def test_valid_shell_marker_unlocks_the_desktop_csp() -> None:
    """H2 desktop half: the desktop shell document (valid per-boot
    marker) — and only it — serves the eval-capable variant."""
    app = _wrapped(HeaderPolicy(desktop_csp=DESKTOP), marker=lambda value: value == "real")
    headers = _drive(app, _scope(query=b"shell=real"))
    assert headers[b"content-security-policy"].decode() == DESKTOP
    assert "unsafe-eval" in headers[b"content-security-policy"].decode()
    # Every other response on the same boot keeps the web CSP.
    assert _drive(app, _scope(query=b""))[b"content-security-policy"].decode() == WEB


def test_stale_marker_after_rotation_keeps_web_csp() -> None:
    """The token is per-boot: after rotation the old marker is inert."""
    token = {"value": "boot-1"}

    def _marker(candidate: str | None) -> bool:
        return bool(candidate) and candidate == token["value"]

    app = _wrapped(HeaderPolicy(desktop_csp=DESKTOP), marker=_marker)
    assert "unsafe-eval" in _drive(app, _scope(query=b"shell=boot-1"))[
        b"content-security-policy"
    ].decode()
    token["value"] = "boot-2"
    assert "unsafe-eval" not in _drive(app, _scope(query=b"shell=boot-1"))[
        b"content-security-policy"
    ].decode()
    assert "unsafe-eval" in _drive(app, _scope(query=b"shell=boot-2"))[
        b"content-security-policy"
    ].decode()


def test_no_desktop_variant_never_serves_eval() -> None:
    """A web-only product passes no desktop CSP — no marker can change
    the response (health shape, and web deployments generally)."""
    app = _wrapped(HeaderPolicy())
    assert _drive(app, _scope(query=b"shell=anything"))[b"content-security-policy"] == (
        WEB.encode()
    )


# ------------------------------------------------------------- health shapes


def test_policy_without_csp_emits_no_csp_header() -> None:
    app = _wrapped(HeaderPolicy(web_csp=None))
    headers = _drive(app, _scope())
    assert b"content-security-policy" not in headers
    assert headers[b"x-content-type-options"] == b"nosniff"


def test_hsts_only_when_client_connection_was_https() -> None:
    app = _wrapped(HeaderPolicy(web_csp=None, hsts_behind_proxy=True))
    # Plain http: never.
    assert b"strict-transport-security" not in _drive(app, _scope())
    # Behind the TLS-terminating proxy: the client-side hop decides.
    via_proxy = _drive(
        app, _scope(headers=[("X-Forwarded-Proto", "https")])
    )
    assert b"max-age=31536000" in via_proxy[b"strict-transport-security"]
    assert b"strict-transport-security" not in _drive(
        app, _scope(headers=[("X-Forwarded-Proto", "http")])
    )
    assert b"strict-transport-security" not in _drive(
        app, _scope(headers=[("X-Forwarded-Proto", "http, https")])
    ), "the FIRST (client-side) hop only — an http client behind a TLS origin leg"
    # Direct TLS (no proxy header) also counts.
    assert b"strict-transport-security" in _drive(app, _scope(scheme="https"))


def test_hsts_off_by_default() -> None:
    assert b"strict-transport-security" not in _drive(
        _wrapped(HeaderPolicy()), _scope(headers=[("X-Forwarded-Proto", "https")])
    )


def test_per_route_frame_options_override_wins() -> None:
    """`frame_overridable`: a route's explicit X-Frame-Options survives
    (health's inline document download relaxes to SAMEORIGIN)."""

    async def _route(scope: Any, receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"x-frame-options", b"SAMEORIGIN")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    headers = _drive(_wrapped(HeaderPolicy(), inner=_route), _scope())
    assert headers[b"x-frame-options"] == b"SAMEORIGIN"
    assert headers[b"x-content-type-options"] == b"nosniff", "baseline still applies"
    # The strict policy shape replaces instead.
    strict = _drive(
        _wrapped(HeaderPolicy(frame_overridable=False), inner=_route), _scope()
    )
    assert strict[b"x-frame-options"] == b"DENY"


def test_extra_policy_headers_appended() -> None:
    policy = HeaderPolicy(web_csp=None, extra=(("x-family", "neuronection"),))
    headers = _drive(_wrapped(policy), _scope())
    assert headers[b"x-family"] == b"neuronection"


def test_non_http_scopes_pass_through() -> None:
    """WS/lifespan scopes are untouched (the CSP marker is an HTTP
    concern; the WS Origin gate is a separate mechanism)."""
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    async def ws_app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "websocket.accept"})

    app = _wrapped(HeaderPolicy(), inner=ws_app)
    asyncio.run(
        app({"type": "websocket", "path": "/ws", "query_string": b"", "headers": []}, receive, send)
    )
    assert messages == [{"type": "websocket.accept"}]


# ------------------------------------------------------------------- H3 (SPA)


def test_headers_present_on_static_mounts_too(tmp_path: Any) -> None:
    """H3: the SPA shell and its assets get the same hardening — the
    middleware wraps the mounted StaticFiles, not just API routes."""
    (tmp_path / "index.html").write_text("<html><body>spa</body></html>")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log('spa')")

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, policy=HeaderPolicy())

    @app.get("/api/v1/ping")
    def ping() -> dict[str, str]:
        return {"ok": "1"}

    app.mount("/", StaticFiles(directory=str(tmp_path), html=True), name="spa")
    client = TestClient(app)

    for path in ("/api/v1/ping", "/", "/assets/app.js"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.headers["x-content-type-options"] == "nosniff", path
        assert response.headers["x-frame-options"] == "DENY", path
        assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin", path
        assert response.headers["content-security-policy"] == WEB, path
