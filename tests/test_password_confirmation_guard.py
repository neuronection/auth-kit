"""Password-confirming actions share login's defenses (S17, §7/§10).

A hijacked session must not get unlimited guesses at `PATCH
/api/v1/admin/instance`, `PATCH /api/v1/me/password` or `DELETE
/api/v1/me`: every wrong answer counts toward the same lockout counter as
login (423 once tripped) and every call rides the auth rate limit
(429 + Retry-After).
"""

from fastapi.testclient import TestClient

from nx_auth.testing import csrf_headers, make_test_app

PASSWORD = "supersecret1"


def _signed_up_admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/register", json={"email": "owner@example.com", "password": PASSWORD}
    )
    assert response.status_code == 201, response.text
    return csrf_headers(client)


def test_instance_transition_locks_after_repeated_wrong_passwords() -> None:
    app = make_test_app(
        auth_mode="authenticated", identity_mode="desktop", lockout_threshold=3
    )
    with TestClient(app) as client:
        headers = _signed_up_admin(client)
        for _ in range(2):
            denied = client.patch(
                "/api/v1/admin/instance",
                json={"auth_mode": "open", "password": "wrong"},
                headers=headers,
            )
            assert denied.status_code == 403
        locked = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "open", "password": "wrong"},
            headers=headers,
        )
        assert locked.status_code == 423
        still = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "open", "password": PASSWORD},
            headers=headers,
        )
        assert still.status_code == 423, "the right password is refused while locked"


def test_confirmation_success_clears_the_failure_counter() -> None:
    app = make_test_app(lockout_threshold=3)
    with TestClient(app) as client:
        headers = _signed_up_admin(client)
        for _ in range(2):
            assert (
                client.patch(
                    "/api/v1/me/password",
                    json={"current_password": "wrong", "new_password": "even-newer-1234"},
                    headers=headers,
                ).status_code
                == 403
            )
        changed = client.patch(
            "/api/v1/me/password",
            json={"current_password": PASSWORD, "new_password": "even-newer-1234"},
            headers=headers,
        )
        assert changed.status_code == 200, changed.text
        headers = csrf_headers(client)
        for _ in range(2):
            assert (
                client.patch(
                    "/api/v1/me/password",
                    json={"current_password": "wrong", "new_password": "third-one-1234"},
                    headers=headers,
                ).status_code
                == 403
            ), "a success resets the counter — no lockout two attempts in"


def test_me_password_change_locks_after_repeated_wrong_passwords() -> None:
    app = make_test_app(lockout_threshold=3)
    with TestClient(app) as client:
        headers = _signed_up_admin(client)
        for _ in range(3):
            denied = client.patch(
                "/api/v1/me/password",
                json={"current_password": "wrong", "new_password": "even-newer-1234"},
                headers=headers,
            )
        assert denied.status_code == 423


def test_account_delete_locks_after_repeated_wrong_passwords() -> None:
    app = make_test_app(lockout_threshold=3)
    with TestClient(app) as client:
        headers = _signed_up_admin(client)
        for _ in range(3):
            denied = client.request(
                "DELETE",
                "/api/v1/me",
                json={"password": "wrong"},
                headers=headers,
            )
        assert denied.status_code == 423


def test_password_confirming_endpoints_ride_the_auth_rate_limit() -> None:
    app = make_test_app(
        auth_mode="authenticated", identity_mode="desktop", rate_per_minute=3
    )
    with TestClient(app) as client:
        headers = _signed_up_admin(client)
        assert (
            client.patch(
                "/api/v1/admin/instance",
                json={"auth_mode": "open", "password": "wrong"},
                headers=headers,
            ).status_code
            == 403
        )
        assert (
            client.patch(
                "/api/v1/admin/instance",
                json={"auth_mode": "open", "password": "wrong"},
                headers=headers,
            ).status_code
            == 403
        )
        throttled = client.patch(
            "/api/v1/admin/instance",
            json={"auth_mode": "open", "password": "wrong"},
            headers=headers,
        )
        assert throttled.status_code == 429
        assert throttled.headers.get("Retry-After") is not None
