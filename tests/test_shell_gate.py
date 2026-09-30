"""Shell-secret gate (§11): the per-boot token on `/api/*`, with the
ADR-0024 navigation-served content exemption.

Navigation requests (PDF iframes, `<img>` subresources) cannot carry
`X-Shell-Token`; a product may list those content routes as exempt. The
exemption skips the shell token ONLY — session enforcement and route
ownership still apply (401 without a session; foreign ids 404 at the
route).
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nx_auth.testing import make_test_app


def _app(**kwargs: object) -> FastAPI:
    return make_test_app(
        # shared-device shape: `open` instances mount no self-signup
        # (§11.3), but these gate tests need a registerable user.
        auth_mode="authenticated",
        identity_mode="desktop",
        shell_secret="boot-secret",
        require_shell_secret=True,
        **kwargs,  # type: ignore[arg-type]
    )


def test_shell_gate_blocks_api_without_the_token() -> None:
    with TestClient(_app()) as client:
        assert client.get("/api/v1/auth/me").status_code == 403


def test_shell_gate_accepts_the_per_boot_token() -> None:
    with TestClient(_app(), headers={"X-Shell-Token": "boot-secret"}) as client:
        # gate passed — the session check is what answers now
        assert client.get("/api/v1/auth/me").status_code == 401


def test_exempt_content_route_skips_token_but_not_session() -> None:
    app = _app(shell_exempt_prefixes=("/api/v1/blobs",))
    with TestClient(app) as client:
        # navigation-shaped: no shell token AND no session → the session
        # check answers (401), not the shell gate (403)
        assert client.get("/api/v1/blobs/abc").status_code == 401
        # non-exempt routes still die at the shell gate
        assert client.get("/api/v1/auth/me").status_code == 403


def test_exempt_content_route_reaches_the_router_with_a_session() -> None:
    app = _app(shell_exempt_prefixes=("/api/v1/blobs",))
    with TestClient(app, headers={"X-Shell-Token": "boot-secret"}) as boot:
        created = boot.post(
            "/api/v1/auth/register",
            json={"email": "nav@example.com", "password": "correct-horse-battery"},
        )
        assert created.status_code in (200, 201), created.text
        cookie_header = "; ".join(f"{k}={v}" for k, v in boot.cookies.items())

    # navigation-shaped client: cookies only — no X-Shell-Token anywhere
    with TestClient(app, headers={"Cookie": cookie_header}) as nav:
        # reaches the router (this kit app has no /api/v1/blobs route)
        assert nav.get("/api/v1/blobs/abc").status_code == 404
        # the shell gate still arms every non-exempt route
        assert nav.get("/api/v1/auth/me").status_code == 403
