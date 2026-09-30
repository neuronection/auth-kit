from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from nx_auth.deps import require_admin
from nx_auth.install import audit_rows
from nx_auth.principal import Principal
from nx_auth.sqlalchemy_stores import SqlProfileStore, UserRow
from nx_auth.testing import csrf_headers, make_test_app

EMAIL = "user@example.com"
PASSWORD = "correct-horse-battery"


@pytest.fixture
def app() -> FastAPI:
    return make_test_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def register(
    client: TestClient, email: str = EMAIL, password: str = PASSWORD
) -> Any:
    return client.post(
        "/api/v1/auth/register", json={"email": email, "password": password}
    )


def test_first_user_admin_lowercased_and_cookies_set(client: TestClient) -> None:
    response = register(client, email="User@Example.COM")
    assert response.status_code == 201
    body = response.json()
    assert body["is_admin"] is True
    assert body["email"] == "user@example.com"
    assert set(body) == {"id", "email", "full_name", "is_admin", "is_active"}
    set_cookies = response.headers.get_list("set-cookie")
    assert any(line.startswith("nx_access=") for line in set_cookies)
    assert any(line.startswith("nx_refresh=") for line in set_cookies)
    assert any(line.startswith("nx_csrf=") for line in set_cookies)
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["id"] == body["id"]


def test_second_user_not_admin_and_default_profile_auto_provisioned(
    app: FastAPI, client: TestClient
) -> None:
    first = register(client).json()
    with TestClient(app) as other:
        second = register(other, email="second@example.com")
        assert second.status_code == 201
        assert second.json()["is_admin"] is False
    factory = app.state.test_factory
    profiles = SqlProfileStore(factory)
    assert profiles.count_for(first["id"]) == 1
    assert profiles.count_for(second.json()["id"]) == 1


def test_me_requires_session(client: TestClient) -> None:
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_generic_error_no_enumeration(client: TestClient) -> None:
    register(client)
    client.cookies.clear()
    missing = client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
    )
    wrong = client.post(
        "/api/v1/auth/login", json={"email": EMAIL, "password": "wrong-password-123"}
    )
    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["detail"] == wrong.json()["detail"] == "Invalid email or password"


def test_lockout_threshold_423_and_unlock(app: FastAPI, client: TestClient) -> None:
    app = make_test_app(lockout_threshold=3)
    with TestClient(app) as locked_client:
        body = register(locked_client).json()
        locked_client.cookies.clear()
        for attempt in range(2):
            failed = locked_client.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": f"wrong-{attempt}"},
            )
            assert failed.status_code == 401
        third = locked_client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": "wrong-final"}
        )
        assert third.status_code == 423
        # Even the correct password is refused while locked.
        correct = locked_client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
        )
        assert correct.status_code == 423
        # Unlock (simulated window expiry) → correct password works.
        factory = app.state.test_factory
        from nx_auth.sqlalchemy_stores import SqlUserStore

        SqlUserStore(factory).reset_login_failures(body["id"])
        unlocked = locked_client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
        )
        assert unlocked.status_code == 200


def test_refresh_rotation_and_reuse_detection(app: FastAPI, client: TestClient) -> None:
    register(client)
    old_refresh = client.cookies.get("nx_refresh")
    old_access = client.cookies.get("nx_access")
    assert old_refresh and old_access
    rotated = client.post("/api/v1/auth/refresh", headers=csrf_headers(client))
    assert rotated.status_code == 200
    new_refresh = rotated.headers.get_list("set-cookie")
    assert not any(line.startswith(f"nx_refresh={old_refresh};") for line in new_refresh)
    # Replay the rotated (old) refresh token with an explicit cookie set.
    replay = TestClient(app)
    stale = replay.post(
        "/api/v1/auth/refresh",
        headers={
            "Cookie": f"nx_refresh={old_refresh}; nx_csrf=proof",
            "X-CSRF-Token": "proof",
        },
    )
    assert stale.status_code == 423
    # Reuse revoked the family AND bumped token_version → old access is dead too.
    dead = TestClient(app).get(
        "/api/v1/auth/me", headers={"Cookie": f"nx_access={old_access}"}
    )
    assert dead.status_code == 401


def test_refresh_lost_rotation_race_revokes_family(
    app: FastAPI, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The compare-and-swap branch: when a concurrent refresh wins the
    rotation, the loser gets the reuse-detection answer (423 + family
    revoked + ver bump) — never a second 200 whose token would later
    trip reuse detection."""
    register(client)
    refresh_token = client.cookies.get("nx_refresh")
    access_token = client.cookies.get("nx_access")
    store = app.state.auth.sessions
    monkeypatch.setattr(store, "rotate_if_current", lambda *args, **kwargs: False)
    raced = TestClient(app).post(
        "/api/v1/auth/refresh",
        headers={"Cookie": f"nx_refresh={refresh_token}; nx_csrf=p", "X-CSRF-Token": "p"},
    )
    assert raced.status_code == 423
    assert raced.json()["detail"] == "Session revoked"
    monkeypatch.undo()
    dead = TestClient(app).get("/api/v1/auth/me", headers={"Cookie": f"nx_access={access_token}"})
    assert dead.status_code == 401
    outcomes = {(row["action"], row["outcome"]) for row in audit_rows(app.state.test_engine)}
    assert ("auth.refresh", "reuse-denied") in outcomes


def test_logout_revokes_refresh_family(app: FastAPI, client: TestClient) -> None:
    register(client)
    refresh_token = client.cookies.get("nx_refresh")
    access_token = client.cookies.get("nx_access")
    out = client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    assert out.status_code == 200
    replay = TestClient(app).post(
        "/api/v1/auth/refresh",
        headers={"Cookie": f"nx_refresh={refresh_token}; nx_csrf=p", "X-CSRF-Token": "p"},
    )
    assert replay.status_code == 401
    # Access survives logout (short-TTL by design); logout-all kills it.
    still = TestClient(app).get("/api/v1/auth/me", headers={"Cookie": f"nx_access={access_token}"})
    assert still.status_code == 200


def test_logout_all_bumps_token_version(app: FastAPI, client: TestClient) -> None:
    register(client)
    access_token = client.cookies.get("nx_access")
    out = client.post("/api/v1/auth/logout-all", headers=csrf_headers(client))
    assert out.status_code == 200
    assert out.json()["revoked"] >= 1
    dead = TestClient(app).get("/api/v1/auth/me", headers={"Cookie": f"nx_access={access_token}"})
    assert dead.status_code == 401


def test_inactive_user_rejected_everywhere(app: FastAPI, client: TestClient) -> None:
    body = register(client).json()
    factory = app.state.test_factory
    with factory() as session:
        row = session.get(UserRow, body["id"])
        assert row is not None
        row.is_active = False
        session.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_registration_disabled_403() -> None:
    with TestClient(make_test_app(registration=False)) as client:
        response = register(client)
        assert response.status_code == 403


def test_password_policy_and_duplicate_email(client: TestClient) -> None:
    short = register(client, password="short")
    assert short.status_code == 422
    assert register(client).status_code == 201
    client.cookies.clear()
    duplicate = register(client)
    assert duplicate.status_code == 409


def test_register_rejects_passwords_over_bcrypt_byte_cap(client: TestClient) -> None:
    """bcrypt refuses >72-byte input (identity-auth §7): ASCII and
    multibyte oversizes alike are policy 422s, never unhandled 500s."""
    ascii_oversize = register(client, email="ascii@example.com", password="x" * 100)
    assert ascii_oversize.status_code == 422
    assert "at most 72 bytes" in ascii_oversize.json()["detail"]
    multibyte_oversize = register(client, email="greek@example.com", password="ξ" * 40)
    assert multibyte_oversize.status_code == 422
    within_cap = register(client, email="greek-ok@example.com", password="ξ" * 30)
    assert within_cap.status_code == 201


def test_login_with_over_cap_password_is_generic_401(client: TestClient) -> None:
    register(client)
    client.cookies.clear()
    oversize = client.post(
        "/api/v1/auth/login", json={"email": EMAIL, "password": "x" * 100}
    )
    assert oversize.status_code == 401
    assert oversize.json()["detail"] == "Invalid email or password"


def test_rate_limit_429_with_retry_after() -> None:
    with TestClient(make_test_app(rate_per_minute=3)) as client:
        for _ in range(3):
            client.post(
                "/api/v1/auth/login", json={"email": EMAIL, "password": "whatever-123"}
            )
        limited = client.post(
            "/api/v1/auth/login", json={"email": EMAIL, "password": "whatever-123"}
        )
        assert limited.status_code == 429
        assert int(limited.headers["Retry-After"]) >= 1


def test_admin_guard_403_for_non_admin(client: TestClient) -> None:
    app = client.app
    assert isinstance(app, FastAPI)
    guard = APIRouter()

    @guard.get("/admin-only")
    def admin_only(principal: Principal = Depends(require_admin)) -> dict[str, str]:
        return {"as": principal.email}

    app.include_router(guard, prefix="/api/v1")
    register(client)  # first user = admin
    assert client.get("/api/v1/admin-only").status_code == 200
    with TestClient(app) as other:
        register(other, email="plain@example.com")
        assert other.get("/api/v1/admin-only").status_code == 403


def test_audit_trail_records_auth_actions(app: FastAPI, client: TestClient) -> None:
    register(client)
    client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    actions = {row["action"] for row in audit_rows(app.state.test_engine)}
    assert {"auth.register", "auth.logout"} <= actions


def test_optional_principal_never_raises(client: TestClient) -> None:
    app = client.app
    assert isinstance(app, FastAPI)
    from nx_auth.deps import get_optional_principal

    probe = APIRouter()

    # Optional-principal semantics live on exempt auth paths; enforced
    # API routes never see an anonymous request (middleware 401s first).
    @probe.get("/api/v1/auth/whoami")
    def maybe(principal: Principal | None = Depends(get_optional_principal)) -> dict[str, object]:
        return {"anon": principal is None}

    app.include_router(probe)
    assert client.get("/api/v1/auth/whoami").json() == {"anon": True}
    register(client)
    assert client.get("/api/v1/auth/whoami").json() == {"anon": False}
