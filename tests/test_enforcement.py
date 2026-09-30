from fastapi import Depends
from fastapi.testclient import TestClient

from nx_auth.deps import get_current_user
from nx_auth.principal import Principal
from nx_auth.testing import make_test_app

EMAIL = "enforced@example.com"
PASSWORD = "correct-horse-battery"


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
    )
    assert response.status_code == 201


def test_api_requires_session_and_stashes_principal() -> None:
    app = make_test_app()

    @app.get("/api/v1/probe")
    def probe(principal: Principal = Depends(get_current_user)) -> dict[str, str]:
        return {"as": principal.email}

    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/probe").status_code == 401
        _login(anonymous)
        allowed = anonymous.get("/api/v1/probe")
        assert allowed.status_code == 200
        assert allowed.json() == {"as": EMAIL}


def test_exempt_prefixes_stay_reachable() -> None:
    app = make_test_app()

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    with TestClient(app) as anonymous:
        # auth flows + health probe work without a session
        assert anonymous.get("/api/v1/health").status_code == 200
        login = anonymous.post(
            "/api/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
        )
        assert login.status_code == 401  # reachable: generic credential error


def test_middleware_applies_instance_rules_to_cookies() -> None:
    # A local-boot cookie on an authenticated server instance is refused
    # by the *middleware* (401) before any endpoint runs.
    from nx_auth.testing import make_test_keyring
    from nx_auth.tokens import AuthMode, TokenKind, mint_token

    app = make_test_app(auth_mode="authenticated", identity_mode="desktop")
    token = mint_token(
        make_test_keyring(),
        app.state.auth.config,
        kind=TokenKind.SESSION,
        sub="x",
        ver=1,
        auth_mode=AuthMode.LOCAL_BOOT,
    )
    with TestClient(app) as client:
        refused = client.get(
            "/api/v1/auth/me", headers={"Cookie": f"nx_access={token}"}
        )
        assert refused.status_code == 401


def test_non_api_paths_unaffected() -> None:
    app = make_test_app()

    @app.get("/spa-thing")
    def spa() -> dict[str, str]:
        return {"ok": "yes"}

    with TestClient(app) as client:
        assert client.get("/spa-thing").status_code == 200


def test_access_cookie_resolved_by_configured_name() -> None:
    # Cookies ignore ports: a __Host-nx_access jar entry can only come
    # from a TLS-mode deployment of a family app on this host. It must
    # never shadow the nx_access session this server minted (§10).
    app = make_test_app()

    @app.get("/api/v1/probe")
    def probe(principal: Principal = Depends(get_current_user)) -> dict[str, str]:
        return {"as": principal.email}

    with TestClient(app) as client:
        _login(client)
        access = client.cookies["nx_access"]
    with TestClient(app) as anonymous:
        shadowed = anonymous.get(
            "/api/v1/probe",
            headers={
                "Cookie": f"__Host-nx_access=stale-foreign-cookie; nx_access={access}"
            },
        )
        assert shadowed.status_code == 200
        assert shadowed.json() == {"as": EMAIL}


def test_tls_mode_resolves_host_prefixed_cookie() -> None:
    app = make_test_app(cookie_secure=True)

    @app.get("/api/v1/probe")
    def probe(principal: Principal = Depends(get_current_user)) -> dict[str, str]:
        return {"as": principal.email}

    with TestClient(app) as client:
        _login(client)
        host_access = client.cookies["__Host-nx_access"]
    with TestClient(app) as anonymous:
        shadowed = anonymous.get(
            "/api/v1/probe",
            headers={
                "Cookie": f"nx_access=stale-foreign-cookie; __Host-nx_access={host_access}"
            },
        )
        assert shadowed.status_code == 200
        assert shadowed.json() == {"as": EMAIL}


def test_bearer_session_works_on_enforced_routes() -> None:
    """§9 "User client" class: a cookie-less CLI presents the session
    token as `Authorization: Bearer` and reaches enforced routes."""
    from nx_auth.testing import make_test_keyring
    from nx_auth.tokens import AuthMode, TokenKind, mint_token

    app = make_test_app()
    register = TestClient(app).post(
        "/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
    )
    assert register.status_code == 201
    user_id = str(register.json()["id"])

    @app.get("/api/v1/probe")
    def probe(principal: Principal = Depends(get_current_user)) -> dict[str, str]:
        return {"as": principal.user_id}

    token = mint_token(
        make_test_keyring(),
        app.state.auth.config,
        kind=TokenKind.SESSION,
        sub=user_id,
        ver=1,
        auth_mode=AuthMode.PASSWORD,
    )
    with TestClient(app) as client:
        allowed = client.get(
            "/api/v1/probe", headers={"Authorization": f"Bearer {token}"}
        )
        assert allowed.status_code == 200
        assert allowed.json() == {"as": user_id}
        # forged bearer is refused like any bad session
        forged = client.get(
            "/api/v1/probe", headers={"Authorization": "Bearer not-a-token"}
        )
        assert forged.status_code == 401
