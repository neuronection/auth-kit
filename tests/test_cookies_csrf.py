from fastapi import FastAPI
from fastapi.testclient import TestClient

from nx_auth.testing import assert_cookie_flags, csrf_headers, make_test_app

EMAIL = "cookie@example.com"
PASSWORD = "correct-horse-battery"


def _register(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
    )
    assert response.status_code == 201


def test_cookie_flags_match_contract() -> None:
    with TestClient(make_test_app()) as client:
        response = client.post(
            "/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
        )
        lines = response.headers.get_list("set-cookie")
        assert_cookie_flags(lines, "nx_access", http_only=True, secure=False, path="/")
        assert_cookie_flags(
            lines, "nx_refresh", http_only=True, secure=False, path="/api/v1/auth"
        )
        assert_cookie_flags(lines, "nx_csrf", http_only=False, secure=False, path="/")


def test_secure_mode_uses_host_prefix_on_access_only() -> None:
    with TestClient(make_test_app(cookie_secure=True)) as client:
        response = client.post(
            "/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
        )
        lines = response.headers.get_list("set-cookie")
        assert_cookie_flags(
            lines, "__Host-nx_access", http_only=True, secure=True, path="/"
        )
        assert_cookie_flags(
            lines, "nx_refresh", http_only=True, secure=True, path="/api/v1/auth"
        )
        assert_cookie_flags(lines, "nx_csrf", http_only=False, secure=True, path="/")
        assert not any(line.startswith("nx_access=") for line in lines)


def test_csrf_enforced_on_cookie_authenticated_posts(app: FastAPI | None = None) -> None:
    with TestClient(make_test_app()) as client:
        _register(client)
        without_header = client.post("/api/v1/auth/logout")
        assert without_header.status_code == 403
        wrong_header = client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": "not-the-cookie"}
        )
        assert wrong_header.status_code == 403
        ok = client.post("/api/v1/auth/logout", headers=csrf_headers(client))
        assert ok.status_code == 200


def test_login_with_stale_cookie_jar_needs_no_csrf() -> None:
    """A stale jar from a previous session (identity-auth §10/§12) must not
    403 the bootstrap: login carries old cookies, sends no echo, and still
    passes CSRF (the middleware is path-aware for bootstrap paths)."""
    with TestClient(make_test_app()) as client:
        _register(client)
        # Simulate a dead session: old cookies remain in the jar while the
        # server-side family is gone (DB recreate / key rotation).
        client.cookies.set("nx_access", "stale-access-token")
        client.cookies.set("nx_refresh", "stale-refresh-token")
        client.cookies.set("nx_csrf", "stale-csrf")
        login = client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
        )
        assert login.status_code == 200, login.text
        assert login.json()["email"] == EMAIL


def test_login_before_any_session_needs_no_csrf() -> None:
    with TestClient(make_test_app()) as client:
        _register(client)
        client.cookies.clear()
        login = client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
        )
        assert login.status_code == 200


def test_demo_bootstrap_needs_no_csrf() -> None:
    """`POST /api/v1/auth/demo` is a bootstrap path (identity-auth
    §10/§12): the exemption prefix must match the real route, so a
    client holding a stale cookie jar reaches the demo entrypoint
    without the double-submit echo."""
    with TestClient(make_test_app(demo=True)) as client:
        _register(client)
        demo = client.post("/api/v1/auth/demo")
        assert demo.status_code == 200, demo.text


def test_bearer_clients_skip_csrf_entirely() -> None:
    with TestClient(make_test_app()) as client:
        _register(client)
        refresh_token = client.cookies.get("nx_refresh")
        assert refresh_token
        client.cookies.clear()
        rotated = client.post(
            "/api/v1/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
        )
        assert rotated.status_code == 200


def test_get_requests_never_need_csrf() -> None:
    with TestClient(make_test_app()) as client:
        _register(client)
        assert client.get("/api/v1/auth/me").status_code == 200
