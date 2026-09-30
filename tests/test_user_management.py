"""User management surface (identity-auth §12): `/api/v1/me` account
self-service and `/api/v1/admin` user + instance endpoints.

Covers the §12 rows added past the auth flows: sessions list/revoke,
password change, cascade account delete, the admin user table with
activity counts, promote/demote with guard rails, reset-password,
force-logout, and §4.5 instance transitions — plus the §7 error
semantics (404 hides existence, 403 generic, 422 policy) and `ver`
bumps killing tokens.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nx_auth.install import audit_rows
from nx_auth.passwords import hash_password
from nx_auth.session_flow import device_hint
from nx_auth.sqlalchemy_stores import (
    SqlInstanceStore,
    SqlProfileStore,
    SqlSessionStore,
    SqlUserStore,
)
from nx_auth.testing import csrf_headers, make_test_app

EMAIL = "admin@example.com"
PLAIN_EMAIL = "plain@example.com"
SECOND_ADMIN_EMAIL = "second-admin@example.com"
DELEGATE_EMAIL = "delegate@example.com"
PASSWORD = "correct-horse-battery"
NEW_PASSWORD = "another-strong-pass"
ADMIN_KEYS = {"id", "email", "full_name", "is_admin", "is_active", "created_at", "activity_count"}
PUBLIC_KEYS = {"id", "email", "full_name", "is_admin", "is_active"}


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
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})


def sessions_of(client: TestClient) -> list[dict[str, Any]]:
    response = client.get("/api/v1/me/sessions")
    assert response.status_code == 200
    entries: list[dict[str, Any]] = response.json()
    return entries


def access_probe(app: FastAPI, token: str) -> Any:
    return TestClient(app).get("/api/v1/auth/me", headers={"Cookie": f"nx_access={token}"})


def refresh_probe(app: FastAPI, token: str) -> Any:
    return TestClient(app).post(
        "/api/v1/auth/refresh",
        headers={"Cookie": f"nx_refresh={token}; nx_csrf=p", "X-CSRF-Token": "p"},
    )


def admin_actions(app: FastAPI) -> set[str]:
    return {row["action"] for row in audit_rows(app.state.test_engine)}


# ---------------------------------------------------------------------------
# /api/v1/me/sessions
# ---------------------------------------------------------------------------


def test_me_sessions_list_shape_and_current(app: FastAPI) -> None:
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"User-Agent": "StudyDesk/2.1"},
        )
        assert created.status_code == 201
        entries = sessions_of(client)
        assert len(entries) == 1
        entry = entries[0]
        assert set(entry) == {
            "id",
            "client_label",
            "created_at",
            "expires_at",
            "revoked_at",
            "current",
        }
        assert entry["current"] is True
        assert entry["client_label"] == "StudyDesk/2.1"
        assert entry["created_at"] is not None
        assert entry["expires_at"] is not None
        assert entry["revoked_at"] is None


def test_me_sessions_lists_every_family_with_one_current(app: FastAPI) -> None:
    with TestClient(app) as first:
        register(first)
        with TestClient(app) as second:
            login = second.post(
                "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
            )
            assert login.status_code == 200
            entries = sessions_of(second)
            assert len(entries) == 2
            assert sum(1 for entry in entries if entry["current"]) == 1
            assert all(entry["revoked_at"] is None for entry in entries)


def test_me_sessions_revoke_foreign_and_unknown_404(app: FastAPI) -> None:
    with TestClient(app) as first:
        register(first)
        with TestClient(app) as second:
            register(second, email=PLAIN_EMAIL)
            foreign = sessions_of(second)[0]["id"]
            hidden = first.request(
                "DELETE",
                f"/api/v1/me/sessions/{foreign}",
                headers=csrf_headers(first),
            )
            assert hidden.status_code == 404
            unknown = first.request(
                "DELETE",
                f"/api/v1/me/sessions/{uuid.uuid4()}",
                headers=csrf_headers(first),
            )
            assert unknown.status_code == 404
            # the foreign family survives untouched
            assert sessions_of(second)[0]["revoked_at"] is None
            assert second.get("/api/v1/auth/me").status_code == 200


def test_me_sessions_revoke_other_family_kills_only_that_family(app: FastAPI) -> None:
    with TestClient(app) as kept:
        register(kept)
        kept_access = kept.cookies.get("nx_access")
        with TestClient(app) as doomed:
            login = doomed.post(
                "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
            )
            assert login.status_code == 200
            doomed_access = doomed.cookies.get("nx_access")
            doomed_refresh = doomed.cookies.get("nx_refresh")
            doomed_family = sessions_of(doomed)[0]["id"]
            revoked = kept.request(
                "DELETE", f"/api/v1/me/sessions/{doomed_family}", headers=csrf_headers(kept)
            )
            assert revoked.status_code == 204
            # revoking someone else's family leaves the caller's cookies alone
            assert kept.cookies.get("nx_access") == kept_access
        # the revoked family cannot refresh (logout = revoke row, §5) …
        assert refresh_probe(app, doomed_refresh).status_code == 401
        # … while the other family still works end to end
        assert refresh_probe(app, kept.cookies.get("nx_refresh")).status_code == 200
        assert access_probe(app, doomed_access).status_code == 200


def test_me_sessions_revoke_current_clears_cookies(app: FastAPI) -> None:
    with TestClient(app) as client:
        register(client)
        refresh_token = client.cookies.get("nx_refresh")
        current = sessions_of(client)[0]["id"]
        revoked = client.request(
            "DELETE", f"/api/v1/me/sessions/{current}", headers=csrf_headers(client)
        )
        assert revoked.status_code == 204
        assert client.cookies.get("nx_access") is None
        assert client.cookies.get("nx_refresh") is None
        assert refresh_probe(app, refresh_token).status_code == 401
        row = SqlSessionStore(app.state.test_factory).get(current)
        assert row is not None
        assert row.revoked_at is not None


# ---------------------------------------------------------------------------
# /api/v1/me/password
# ---------------------------------------------------------------------------


def test_me_password_wrong_current_403_generic(app: FastAPI, client: TestClient) -> None:
    register(client)
    wrong = client.patch(
        "/api/v1/me/password",
        json={"current_password": "wrong-password-123", "new_password": NEW_PASSWORD},
        headers=csrf_headers(client),
    )
    assert wrong.status_code == 403
    assert wrong.json()["detail"] == "Invalid password"
    # nothing changed: the old password still signs in
    client.cookies.clear()
    assert (
        client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}).status_code
        == 200
    )


def test_me_password_policy_422(app: FastAPI, client: TestClient) -> None:
    register(client)
    short = client.patch(
        "/api/v1/me/password",
        json={"current_password": PASSWORD, "new_password": "short"},
        headers=csrf_headers(client),
    )
    assert short.status_code == 422
    assert "at least 10" in short.json()["detail"]


def test_me_password_over_bcrypt_byte_cap_422(app: FastAPI, client: TestClient) -> None:
    """A >72-byte new password (UTF-8 bytes, identity-auth §7) is a
    policy 422 — bcrypt would otherwise crash the handler with a 500."""
    register(client)
    oversize = client.patch(
        "/api/v1/me/password",
        json={"current_password": PASSWORD, "new_password": "x" * 100},
        headers=csrf_headers(client),
    )
    assert oversize.status_code == 422
    assert "at most 72 bytes" in oversize.json()["detail"]
    multibyte = client.patch(
        "/api/v1/me/password",
        json={"current_password": PASSWORD, "new_password": "ξ" * 40},
        headers=csrf_headers(client),
    )
    assert multibyte.status_code == 422
    unchanged = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert unchanged.status_code == 200


def test_admin_reset_password_over_bcrypt_byte_cap_422(
    app: FastAPI, client: TestClient
) -> None:
    register(client)
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        oversize = client.post(
            f"/api/v1/admin/users/{plain['id']}/reset-password",
            json={"new_password": "x" * 100},
            headers=csrf_headers(client),
        )
        assert oversize.status_code == 422
        assert "at most 72 bytes" in oversize.json()["detail"]
        assert (
            other.post(
                "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": PASSWORD}
            ).status_code
            == 200
        )


def test_me_password_change_bumps_ver_and_keeps_caller_signed_in(app: FastAPI) -> None:
    with TestClient(app) as client:
        created = register(client).json()
        old_access = client.cookies.get("nx_access")
        with TestClient(app) as other_device:
            login = other_device.post(
                "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
            )
            assert login.status_code == 200
            other_access = other_device.cookies.get("nx_access")
            changed = client.patch(
                "/api/v1/me/password",
                json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
                headers=csrf_headers(client),
            )
            assert changed.status_code == 200
            assert set(changed.json()) == PUBLIC_KEYS
            assert changed.json()["id"] == created["id"]
            # fresh cookies for the caller — same issuance path as login
            assert client.cookies.get("nx_access") != old_access
            assert client.cookies.get("nx_refresh") is not None
            # every other session died with the ver bump (§8) …
            assert access_probe(app, old_access).status_code == 401
            assert access_probe(app, other_access).status_code == 401
        # … but the caller is still signed in
        assert client.get("/api/v1/auth/me").status_code == 200
        # old password refused, new password works
        with TestClient(app) as fresh:
            assert (
                fresh.post(
                    "/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
                ).status_code
                == 401
            )
            assert (
                fresh.post(
                    "/api/v1/auth/login", json={"email": EMAIL, "password": NEW_PASSWORD}
                ).status_code
                == 200
            )
    assert "auth.password_change" in admin_actions(app)


# ---------------------------------------------------------------------------
# DELETE /api/v1/me
# ---------------------------------------------------------------------------


def test_delete_me_wrong_password_403(app: FastAPI, client: TestClient) -> None:
    register(client)
    denied = client.request(
        "DELETE",
        "/api/v1/me",
        json={"password": "wrong-password-123"},
        headers=csrf_headers(client),
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Invalid password"
    assert client.get("/api/v1/auth/me").status_code == 200


def test_delete_me_cascades_and_clears_cookies(app: FastAPI) -> None:
    with TestClient(app) as client:
        created = register(client).json()
        with TestClient(app) as other:
            register(other, email=PLAIN_EMAIL)
            deleted = client.request(
                "DELETE", "/api/v1/me", json={"password": PASSWORD}, headers=csrf_headers(client)
            )
            assert deleted.status_code == 204
            assert client.cookies.get("nx_access") is None
            factory = app.state.test_factory
            assert SqlUserStore(factory).get(created["id"]) is None
            assert SqlSessionStore(factory).list_for_user(created["id"]) == []
            assert SqlProfileStore(factory).count_for(created["id"]) == 0
            # the other account is untouched
            assert other.get("/api/v1/auth/me").status_code == 200
    assert "auth.account_delete" in admin_actions(app)


# ---------------------------------------------------------------------------
# /api/v1/admin/users
# ---------------------------------------------------------------------------


def test_admin_users_list_shape_and_activity_counts(
    app: FastAPI, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = register(client).json()
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        # activity is product-defined; the reference store returns {}
        monkeypatch.setattr(
            app.state.auth.users, "activity_counts", lambda: {admin["id"]: 7}
        )
        listed = client.get("/api/v1/admin/users")
        assert listed.status_code == 200
        rows = {row["id"]: row for row in listed.json()}
        assert set(rows) == {admin["id"], plain["id"]}
        for row in rows.values():
            assert set(row) == ADMIN_KEYS
            assert row["created_at"] is not None
        assert rows[admin["id"]]["activity_count"] == 7
        assert rows[admin["id"]]["is_admin"] is True
        assert rows[plain["id"]]["activity_count"] == 0
        assert rows[plain["id"]]["is_admin"] is False
        # non-admins are refused (require_admin)
        assert other.get("/api/v1/admin/users").status_code == 403


def test_admin_update_unknown_user_404(app: FastAPI, client: TestClient) -> None:
    register(client)
    response = client.patch(
        f"/api/v1/admin/users/{uuid.uuid4()}",
        json={"is_active": False},
        headers=csrf_headers(client),
    )
    assert response.status_code == 404


def test_admin_update_self_rails_403(app: FastAPI, client: TestClient) -> None:
    admin = register(client).json()
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        promote = client.patch(
            f"/api/v1/admin/users/{plain['id']}",
            json={"is_admin": True},
            headers=csrf_headers(client),
        )
        assert promote.status_code == 200
    # a second admin exists — the self rail alone must hold (§12)
    for payload in (
        {"is_admin": False},
        {"is_active": False},
        {"is_admin": False, "is_active": False},
    ):
        denied = client.patch(
            f"/api/v1/admin/users/{admin['id']}", json=payload, headers=csrf_headers(client)
        )
        assert denied.status_code == 403
    row = {r["id"]: r for r in client.get("/api/v1/admin/users").json()}[admin["id"]]
    assert row["is_admin"] is True and row["is_active"] is True
    # no ver bump: the caller's own session still works
    assert client.get("/api/v1/auth/me").status_code == 200


def test_admin_update_promote_demote_bumps_target_ver(app: FastAPI) -> None:
    with TestClient(app) as client:
        register(client)
        with TestClient(app) as other:
            plain = register(other, email=PLAIN_EMAIL).json()
            promoted = client.patch(
                f"/api/v1/admin/users/{plain['id']}",
                json={"is_admin": True},
                headers=csrf_headers(client),
            )
            assert promoted.status_code == 200
            assert set(promoted.json()) == ADMIN_KEYS
            assert promoted.json()["is_admin"] is True
            # effective change ⇒ the target's tokens died (§12 `ver`)
            assert other.get("/api/v1/auth/me").status_code == 401
            other.cookies.clear()
            assert (
                other.post(
                    "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": PASSWORD}
                ).status_code
                == 200
            )
            assert other.get("/api/v1/auth/me").json()["is_admin"] is True
            assert other.get("/api/v1/admin/users").status_code == 200
            demoted = client.patch(
                f"/api/v1/admin/users/{plain['id']}",
                json={"is_admin": False},
                headers=csrf_headers(client),
            )
            assert demoted.status_code == 200
            assert demoted.json()["is_admin"] is False
            assert other.get("/api/v1/auth/me").status_code == 401
            other.cookies.clear()
            assert (
                other.post(
                    "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": PASSWORD}
                ).status_code
                == 200
            )
            assert other.get("/api/v1/admin/users").status_code == 403
    assert "admin.user_update" in admin_actions(app)


def test_admin_update_no_op_does_not_bump_ver(app: FastAPI, client: TestClient) -> None:
    register(client)
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        unchanged = client.patch(
            f"/api/v1/admin/users/{plain['id']}",
            json={"is_active": True},
            headers=csrf_headers(client),
        )
        assert unchanged.status_code == 200
        assert unchanged.json()["is_active"] is True
        # no effective change ⇒ no ver bump ⇒ the target keeps its session
        assert other.get("/api/v1/auth/me").status_code == 200


def test_admin_deactivate_kills_requests_everywhere(app: FastAPI, client: TestClient) -> None:
    register(client)
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        deactivated = client.patch(
            f"/api/v1/admin/users/{plain['id']}",
            json={"is_active": False},
            headers=csrf_headers(client),
        )
        assert deactivated.status_code == 200
        assert deactivated.json()["is_active"] is False
        assert other.get("/api/v1/auth/me").status_code == 401
        # login itself is refused (§18.9): a deactivated account never
        # obtains a fresh — but unusable — session
        other.cookies.clear()
        login = other.post(
            "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": PASSWORD}
        )
        assert login.status_code == 401
        assert login.json()["detail"] == "Account deactivated"
        assert other.get("/api/v1/auth/me").status_code == 401
        assert login.headers.get_list("set-cookie") == []
    denied = [
        row
        for row in audit_rows(app.state.test_engine)
        if row["action"] == "auth.login" and row["outcome"] == "denied"
    ]
    assert any(row["resource"] == plain["id"] for row in denied)


def test_demo_login_refuses_deactivated_demo_user() -> None:
    app = make_test_app(demo=True)
    with TestClient(app) as client:
        first = client.post("/api/v1/auth/demo")
        assert first.status_code == 200
        demo_user = app.state.auth.users.get(app.state.auth.config.demo_user_id)
        assert demo_user is not None
        app.state.auth.users.set_active(demo_user.id, False)
        client.cookies.clear()
        refused = client.post("/api/v1/auth/demo")
        assert refused.status_code == 401
        assert refused.json()["detail"] == "Account deactivated"


def test_admin_last_admin_guard_rails(app: FastAPI, client: TestClient) -> None:
    admin = register(client).json()
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        promote = client.patch(
            f"/api/v1/admin/users/{plain['id']}",
            json={"is_admin": True},
            headers=csrf_headers(client),
        )
        assert promote.status_code == 200
        # demoting the *other* admin is fine — the last-admin rail only
        # guards the final one
        ok = client.patch(
            f"/api/v1/admin/users/{plain['id']}",
            json={"is_admin": False},
            headers=csrf_headers(client),
        )
        assert ok.status_code == 200
    # the caller is now the last admin: no request may remove them
    for payload in (
        {"is_admin": False},
        {"is_active": False},
        {"is_admin": False, "is_active": False},
    ):
        denied = client.patch(
            f"/api/v1/admin/users/{admin['id']}", json=payload, headers=csrf_headers(client)
        )
        assert denied.status_code == 403
    row = {r["id"]: r for r in client.get("/api/v1/admin/users").json()}[admin["id"]]
    assert row["is_admin"] is True and row["is_active"] is True


# ---------------------------------------------------------------------------
# /api/v1/admin/users/{id}/reset-password + force-logout
# ---------------------------------------------------------------------------


def test_admin_reset_password_flow(app: FastAPI, client: TestClient) -> None:
    register(client)
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        plain_access = other.cookies.get("nx_access")
        users = SqlUserStore(app.state.test_factory)
        users.set_login_failures(
            plain["id"], 4, datetime.now(UTC) + timedelta(minutes=5)
        )
        short = client.post(
            f"/api/v1/admin/users/{plain['id']}/reset-password",
            json={"new_password": "short"},
            headers=csrf_headers(client),
        )
        assert short.status_code == 422
        done = client.post(
            f"/api/v1/admin/users/{plain['id']}/reset-password",
            json={"new_password": NEW_PASSWORD},
            headers=csrf_headers(client),
        )
        assert done.status_code == 204
        row = users.get(plain["id"])
        assert row is not None
        assert row.failed_login_attempts == 0
        assert row.locked_until is None
        # ver bump ⇒ old tokens die
        assert access_probe(app, plain_access).status_code == 401
        other.cookies.clear()
        assert (
            other.post(
                "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": PASSWORD}
            ).status_code
            == 401
        )
        assert (
            other.post(
                "/api/v1/auth/login", json={"email": PLAIN_EMAIL, "password": NEW_PASSWORD}
            ).status_code
            == 200
        )
    assert "admin.password_reset" in admin_actions(app)


def test_admin_reset_password_unknown_404(app: FastAPI, client: TestClient) -> None:
    register(client)
    response = client.post(
        f"/api/v1/admin/users/{uuid.uuid4()}/reset-password",
        json={"new_password": NEW_PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 404


def test_admin_force_logout(app: FastAPI, client: TestClient) -> None:
    register(client)
    with TestClient(app) as other:
        plain = register(other, email=PLAIN_EMAIL).json()
        plain_access = other.cookies.get("nx_access")
        plain_refresh = other.cookies.get("nx_refresh")
        unknown = client.post(
            f"/api/v1/admin/users/{uuid.uuid4()}/force-logout",
            headers=csrf_headers(client),
        )
        assert unknown.status_code == 404
        done = client.post(
            f"/api/v1/admin/users/{plain['id']}/force-logout",
            headers=csrf_headers(client),
        )
        assert done.status_code == 204
        # ver bump ⇒ access and refresh both die
        assert access_probe(app, plain_access).status_code == 401
        assert refresh_probe(app, plain_refresh).status_code == 401
    assert "admin.force_logout" in admin_actions(app)


# ---------------------------------------------------------------------------
# /api/v1/admin/instance — §4.5 transitions
# ---------------------------------------------------------------------------


def test_instance_requires_admin_and_current_password(app: FastAPI) -> None:
    with TestClient(app) as client:
        register(client)
        with TestClient(app) as other:
            register(other, email=PLAIN_EMAIL)
            assert (
                other.patch(
                    "/api/v1/admin/instance",
                    json={"auth_mode": "open", "password": PASSWORD},
                    headers=csrf_headers(other),
                ).status_code
                == 403
            )
        wrong = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "authenticated", "password": "wrong-password-123"},
            headers=csrf_headers(client),
        )
        assert wrong.status_code == 403
        assert wrong.json()["detail"] == "Invalid password"
        invalid = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "bogus", "password": PASSWORD},
            headers=csrf_headers(client),
        )
        assert invalid.status_code == 422


def test_instance_server_never_runs_open(app: FastAPI, client: TestClient) -> None:
    register(client)
    refused = client.patch(
        "/api/v1/admin/instance",
        json={"auth_mode": "open", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert refused.status_code == 403
    assert SqlInstanceStore(app.state.test_factory).get("auth_mode") == "authenticated"


def test_instance_no_op_returns_state_and_demo_flag() -> None:
    app = make_test_app(demo=True)
    with TestClient(app) as client:
        register(client)
        state = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "authenticated", "password": PASSWORD},
            headers=csrf_headers(client),
        )
        assert state.status_code == 200
        assert state.json() == {"auth_mode": "authenticated", "demo_mode": True}
        # no-op ⇒ no side effects
        assert client.get("/api/v1/auth/me").status_code == 200


def test_instance_authenticated_to_open_refused_with_other_users() -> None:
    app = make_test_app(auth_mode="authenticated", identity_mode="desktop")
    with TestClient(app) as client:
        register(client)
        with TestClient(app) as other:
            register(other, email=PLAIN_EMAIL)
            refused = client.patch(
                "/api/v1/admin/instance",
                json={"auth_mode": "open", "password": PASSWORD},
                headers=csrf_headers(client),
            )
            assert refused.status_code == 403
            assert "other user accounts exist" in refused.json()["detail"]
        assert SqlInstanceStore(app.state.test_factory).get("auth_mode") == "authenticated"


def test_instance_authenticated_to_open_revokes_every_session() -> None:
    app = make_test_app(auth_mode="authenticated", identity_mode="desktop")
    with TestClient(app) as client:
        register(client)
        access = client.cookies.get("nx_access")
        opened = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "open", "password": PASSWORD},
            headers=csrf_headers(client),
        )
        assert opened.status_code == 200
        assert opened.json() == {"auth_mode": "open", "demo_mode": False}
        assert SqlInstanceStore(app.state.test_factory).get("auth_mode") == "open"
        # §4.5: every session revoked (rows + ver bump) and cookies cleared
        assert access_probe(app, access).status_code == 401
        assert client.cookies.get("nx_access") is None
    assert "admin.instance_transition" in admin_actions(app)


def test_instance_open_to_authenticated_sets_owner_credentials() -> None:
    app = make_test_app(auth_mode="open", identity_mode="desktop", shell_secret="boot-secret")
    with TestClient(app) as client:
        exchanged = client.post(
            "/api/v1/auth/desktop/exchange", headers={"X-Shell-Token": "boot-secret"}
        )
        assert exchanged.status_code == 200
        owner_id = exchanged.json()["id"]
        # §4.5: open → authenticated *sets* credentials for the implicit
        # owner — re-verification cannot apply to a password-less row
        flipped = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "authenticated", "password": NEW_PASSWORD},
            headers=csrf_headers(client),
        )
        assert flipped.status_code == 200
        assert flipped.json() == {"auth_mode": "authenticated", "demo_mode": False}
        users = SqlUserStore(app.state.test_factory)
        owner = users.get(owner_id)
        assert owner is not None
        assert owner.password_hash is not None
        assert owner.is_admin is True
        # local-boot tokens die with the mode (§4.3)
        assert client.get("/api/v1/auth/me").status_code == 401
        # … and the owner signs in with the new credentials
        client.cookies.clear()
        login = client.post(
            "/api/v1/auth/login", json={"email": "owner@local", "password": NEW_PASSWORD}
        )
        assert login.status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 200
    assert "admin.instance_transition" in admin_actions(app)


def test_instance_open_to_authenticated_needs_owner_credentials() -> None:
    app = make_test_app(auth_mode="open", identity_mode="desktop", shell_secret="boot-secret")
    with TestClient(app) as client:
        exchanged = client.post(
            "/api/v1/auth/desktop/exchange", headers={"X-Shell-Token": "boot-secret"}
        )
        assert exchanged.status_code == 200
        # §11.3: an `open` instance mounts no self-registration — a
        # password-holding delegate can only exist as defensive depth
        # (a row predating the open state), so construct it directly
        # through the store instead of the (absent) register route.
        delegate_row = SqlUserStore(app.state.test_factory).create(
            email=DELEGATE_EMAIL, password_hash=hash_password(PASSWORD)
        )
        with TestClient(app) as other:
            promote = client.patch(
                f"/api/v1/admin/users/{delegate_row.id}",
                json={"is_admin": True},
                headers=csrf_headers(client),
            )
            assert promote.status_code == 200
            other.cookies.clear()
            assert (
                other.post(
                    "/api/v1/auth/login", json={"email": DELEGATE_EMAIL, "password": PASSWORD}
                ).status_code
                == 200
            )
            # a password-holding admin that is not the implicit owner:
            # the owner's credentials must be set first
            refused = other.patch(
                "/api/v1/admin/instance",
                json={"auth_mode": "authenticated", "password": PASSWORD},
                headers=csrf_headers(other),
            )
            assert refused.status_code == 403
            assert "set owner credentials" in refused.json()["detail"]
        assert SqlInstanceStore(app.state.test_factory).get("auth_mode") == "open"


# ---------------------------------------------------------------------------
# device hints (client_label pass-through)
# ---------------------------------------------------------------------------


def test_device_hint_sanitizes_and_caps() -> None:
    assert device_hint(None) is None
    assert device_hint("") is None
    assert device_hint(" \x01\x02 ") is None
    assert device_hint("a\t b") == "a b"
    assert device_hint("A" * 250) == "A" * 200


def test_device_label_from_user_agent(app: FastAPI) -> None:
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"User-Agent": "StudyDesk/2.1 (Linux; x86_64)"},
        )
        assert created.status_code == 201
        assert sessions_of(client)[0]["client_label"] == "StudyDesk/2.1 (Linux; x86_64)"


def test_device_label_sanitized_and_capped(app: FastAPI) -> None:
    raw = "Dev\tTool " + "x" * 300
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"User-Agent": raw},
        )
        assert created.status_code == 201
        label = sessions_of(client)[0]["client_label"]
        assert len(label) == 200
        assert label.startswith("DevTool ")
        assert "\t" not in label


def test_device_label_falls_back_to_flow_label(app: FastAPI) -> None:
    with TestClient(app) as client:
        client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"User-Agent": "   "},
        )
        assert sessions_of(client)[0]["client_label"] == "register"
        client.cookies.clear()
        login = client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
            headers={"User-Agent": "   "},
        )
        assert login.status_code == 200
        assert {entry["client_label"] for entry in sessions_of(client)} == {
            "register",
            "login",
        }


def test_demo_flow_label_unchanged() -> None:
    app = make_test_app(demo=True)
    with TestClient(app) as client:
        assert client.post("/api/v1/auth/demo").status_code == 200
        assert sessions_of(client)[0]["client_label"] == "demo"


# ---------------------------------------------------------------------------
# session enforcement on the new surface
# ---------------------------------------------------------------------------


def test_me_and_admin_require_session(app: FastAPI) -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/me/sessions").status_code == 401
        assert (
            client.request(
                "DELETE", f"/api/v1/me/sessions/{uuid.uuid4()}", json={}
            ).status_code
            == 401
        )
        assert (
            client.patch(
                "/api/v1/me/password", json={"current_password": "x", "new_password": "y"}
            ).status_code
            == 401
        )
        assert client.request("DELETE", "/api/v1/me", json={"password": "x"}).status_code == 401
        assert client.get("/api/v1/admin/users").status_code == 401
        assert (
            client.patch("/api/v1/admin/instance", json={"password": "x"}).status_code == 401
        )


def test_new_endpoints_enforce_csrf(app: FastAPI, client: TestClient) -> None:
    register(client)
    # cookie-authenticated non-GET without the double-submit echo ⇒ 403 (§10)
    assert (
        client.patch(
            "/api/v1/me/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code
        == 403
    )
    assert (
        client.request("DELETE", "/api/v1/me", json={"password": PASSWORD}).status_code == 403
    )
