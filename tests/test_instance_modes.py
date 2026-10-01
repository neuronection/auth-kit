import logging

import pytest
from fastapi.testclient import TestClient

from nx_auth.config import AuthConfig
from nx_auth.instance import (
    IdentityMode,
    InstanceMode,
    InstanceState,
    effective_auth_mode,
    initialize_instance,
    parse_identity_mode,
    read_state,
    request_transition,
)
from nx_auth.sqlalchemy_stores import SqlInstanceStore, SqlProfileStore, SqlUserStore
from nx_auth.testing import make_test_app, make_test_keyring
from nx_auth.tokens import AuthMode, TokenKind, mint_token

pytestmark = pytest.mark.contract  # identity-auth §18 contract cases

CONFIG = AuthConfig(iss="testkit")


def _local_boot_token() -> str:
    return mint_token(
        make_test_keyring(),
        CONFIG,
        kind=TokenKind.SESSION,
        sub="someone",
        ver=1,
        auth_mode=AuthMode.LOCAL_BOOT,
    )


def test_exchange_route_absent_on_server_entrypoint() -> None:
    with TestClient(make_test_app(identity_mode="server")) as client:
        response = client.post("/api/v1/auth/desktop/exchange")
        assert response.status_code == 404


def test_local_boot_rejected_on_authenticated_instance() -> None:
    token = _local_boot_token()
    with TestClient(make_test_app(auth_mode="authenticated")) as client:
        me = client.get("/api/v1/auth/me", headers={"Cookie": f"nx_access={token}"})
        assert me.status_code == 401


def test_local_boot_rejected_on_server_identity_even_when_open() -> None:
    token = _local_boot_token()
    with TestClient(make_test_app(auth_mode="open", identity_mode="server")) as client:
        me = client.get("/api/v1/auth/me", headers={"Cookie": f"nx_access={token}"})
        assert me.status_code == 401


def test_exchange_requires_matching_shell_secret() -> None:
    app = make_test_app(auth_mode="open", identity_mode="desktop", shell_secret="boot-secret")
    with TestClient(app) as client:
        assert client.post("/api/v1/auth/desktop/exchange").status_code == 403
        wrong = client.post(
            "/api/v1/auth/desktop/exchange", headers={"X-Shell-Token": "nope"}
        )
        assert wrong.status_code == 403
        right = client.post(
            "/api/v1/auth/desktop/exchange", headers={"X-Shell-Token": "boot-secret"}
        )
        assert right.status_code == 200
        body = right.json()
        assert body["is_admin"] is True
        # Owner got the auto Default profile.
        factory = app.state.test_factory
        assert SqlProfileStore(factory).count_for(body["id"]) == 1
        # Zero-setup: password is NULL (password login refused for the row).
        user = SqlUserStore(factory).get(body["id"])
        assert user is not None and user.password_hash is None
        # local-boot session works until the instance mode changes.
        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        instance = SqlInstanceStore(factory)
        instance.set("auth_mode", "authenticated")
        assert client.get("/api/v1/auth/me").status_code == 401
        # A fresh boot attempt (no cookies ⇒ no CSRF short-circuit) sees
        # the endpoint as absent.
        client.cookies.clear()
        assert (
            client.post(
                "/api/v1/auth/desktop/exchange", headers={"X-Shell-Token": "boot-secret"}
            ).status_code
            == 404
        )


def test_exchange_without_shell_secret_is_dev_open() -> None:
    """Gate disarmed (shell-less desktop dev, family ADR-0023): no secret
    is configured, so the exchange mints the implicit owner to loopback
    callers of the dev server — browser dev needs no accounts. The Host
    header must name the loopback listener (the SPA's own origin)."""
    app = make_test_app(auth_mode="open", identity_mode="desktop")
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        response = client.post(
            "/api/v1/auth/desktop/exchange", headers={"Host": "127.0.0.1:8100"}
        )
        assert response.status_code == 200
        assert response.json()["is_admin"] is True
        assert client.get("/api/v1/auth/me").status_code == 200


def test_exchange_without_shell_secret_rejects_non_loopback_callers() -> None:
    """The disarmed-gate shape is loopback-only by contract: a remote
    caller must never receive the implicit owner, even when the server
    was (mis)bound to a routable interface."""
    app = make_test_app(auth_mode="open", identity_mode="desktop")
    with TestClient(app, client=("203.0.113.9", 50000)) as client:
        response = client.post(
            "/api/v1/auth/desktop/exchange", headers={"Host": "127.0.0.1:8100"}
        )
        assert response.status_code == 403
        assert client.get("/api/v1/auth/me").status_code == 401


def test_exchange_without_shell_secret_rejects_dns_rebinding() -> None:
    """DNS-rebinding defense: a public page rebound to 127.0.0.1 keeps a
    loopback TCP peer but sends the attacker's domain in Host/Origin.
    The loopback-peer rule alone would mint the attacker an owner
    session; the Host rule refuses it (same 403 as a bad shell token —
    no signal about which layer refused)."""
    app = make_test_app(auth_mode="open", identity_mode="desktop")
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        for host in ("evil.example", "evil.example:8100", "rebind.attacker.test"):
            response = client.post("/api/v1/auth/desktop/exchange", headers={"Host": host})
            assert response.status_code == 403, host
        assert client.get("/api/v1/auth/me").status_code == 401


def test_exchange_without_shell_secret_accepts_loopback_host_variants() -> None:
    app = make_test_app(auth_mode="open", identity_mode="desktop")
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        for host in ("localhost:8100", "127.0.0.1", "[::1]:8100", "::1"):
            response = client.post("/api/v1/auth/desktop/exchange", headers={"Host": host})
            assert response.status_code == 200, host


def test_open_instance_mounts_no_self_registration() -> None:
    """§11.3: `open` desktop instances are personal devices — anonymous
    self-registration answers 404 (no probe target, no cross-site
    pre-provisioning, no login-CSRF shape); additional users come from
    the admin surface. /login stays mounted by design: password holders
    must authenticate for the open→authenticated transition (§4)."""
    with TestClient(make_test_app(auth_mode="open", identity_mode="desktop")) as client:
        assert (
            client.post(
                "/api/v1/auth/register",
                json={"email": "x@example.test", "password": "correct-horse-battery"},
            ).status_code
            == 404
        )
        # login is mounted (shared-device transition flow) — unknown
        # credentials get the generic 401, not a route-absent 404
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": "x@example.test", "password": "correct-horse-battery"},
            ).status_code
            == 401
        )
    with TestClient(make_test_app(auth_mode="authenticated", identity_mode="desktop")) as client:
        response = client.post(
            "/api/v1/auth/register",
            json={"email": "x@example.test", "password": "correct-horse-battery"},
        )
        assert response.status_code in (200, 201)


def test_unknown_auth_mode_fails_closed() -> None:
    app = make_test_app(auth_mode=None)
    SqlInstanceStore(app.state.test_factory).set("auth_mode", "bogus-value")
    token = _local_boot_token()
    with TestClient(app) as client:
        me = client.get("/api/v1/auth/me", headers={"Cookie": f"nx_access={token}"})
        assert me.status_code == 401


def test_demo_principal_only_on_demo_instance() -> None:
    with TestClient(make_test_app(demo=False)) as client:
        assert client.post("/api/v1/auth/demo").status_code == 404
        demo_token = mint_token(
            make_test_keyring(),
            CONFIG,
            kind=TokenKind.SESSION,
            sub="demo",
            ver=1,
            auth_mode=AuthMode.DEMO,
        )
        me = client.get("/api/v1/auth/me", headers={"Cookie": f"nx_access={demo_token}"})
        assert me.status_code == 401

    app = make_test_app(demo=True)
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/demo")
        assert login.status_code == 200
        assert login.json()["id"] == CONFIG.demo_user_id
        # §13: the demo principal must never bootstrap admin — demo-login
        # on a fresh instance creates user #1, and the first-user-admin
        # rule must not fire for it.
        assert login.json()["is_admin"] is False
        assert client.get("/api/v1/auth/me").status_code == 200
        # The anonymous demo identity cannot reach the admin surface.
        assert client.get("/api/v1/admin/users").status_code == 403
        SqlInstanceStore(app.state.test_factory).set("demo_mode", "false")
        assert client.get("/api/v1/auth/me").status_code == 401


def test_demo_principal_never_bootstraps_admin() -> None:
    """§13 demo guard: demo-login as the very first user stays non-admin.

    Regression for the hole where `users.create(is_admin=False)` was still
    OR-ed with the first-user-admin rule, making the fixed anonymous demo
    identity user #1 ⇒ admin ⇒ account takeover via admin password reset.
    Documented tradeoff: on a demo instance whose demo principal was created
    first, a later registration is NOT user #1 and does not bootstrap admin
    either — public demos run with registration disabled anyway.
    """
    app = make_test_app(demo=True)
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/demo")
        assert login.status_code == 200
        assert login.json()["is_admin"] is False
        assert client.get("/api/v1/admin/users").status_code == 403

        register = client.post(
            "/api/v1/auth/register",
            json={"email": "real.user@example.test", "password": "correct-horse-battery"},
        )
        assert register.status_code in (200, 201)
        assert register.json()["is_admin"] is False

    # The first-user-admin bootstrap (§12) still applies on instances where
    # the first user is a real registration, not the demo principal.
    with TestClient(make_test_app(demo=False)) as client:
        register = client.post(
            "/api/v1/auth/register",
            json={"email": "founder@example.test", "password": "correct-horse-battery"},
        )
        assert register.status_code in (200, 201)
        assert register.json()["is_admin"] is True


def test_read_state_fail_closed_and_effective() -> None:
    empty = read_state(_EmptyStore(), "desktop")
    assert empty.auth_mode is None
    assert effective_auth_mode(empty) is InstanceMode.AUTHENTICATED


def test_transition_guard_rails() -> None:
    open_state = InstanceState(
        auth_mode=InstanceMode.OPEN, demo_mode=False, identity_mode="desktop"
    )
    auth_state = InstanceState(
        auth_mode=InstanceMode.AUTHENTICATED, demo_mode=False, identity_mode="server"
    )
    assert request_transition(open_state, InstanceMode.AUTHENTICATED).error is not None
    ok = request_transition(
        open_state, InstanceMode.AUTHENTICATED, owner_has_password=True
    )
    assert ok.mode is InstanceMode.AUTHENTICATED
    assert request_transition(auth_state, InstanceMode.OPEN).error is not None
    with_others = request_transition(
        auth_state, InstanceMode.OPEN, password_confirmed=True, other_user_count=2
    )
    assert with_others.error is not None
    clean = request_transition(
        auth_state, InstanceMode.OPEN, password_confirmed=True, other_user_count=0
    )
    assert clean.mode is InstanceMode.OPEN


class _EmptyStore:
    def get(self, key: str) -> str | None:
        return None

    def set(self, key: str, value: str) -> None:  # pragma: no cover - unused
        del key, value


class _MemoryStore:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value


# --- initialize_instance (§4 init-only rules; ADR-0028) ----------------


def test_parse_identity_mode_fails_closed_to_server() -> None:
    assert parse_identity_mode("desktop") is IdentityMode.DESKTOP
    assert parse_identity_mode("DESKTOP") is IdentityMode.DESKTOP
    assert parse_identity_mode(" desktop ") is IdentityMode.DESKTOP
    for raw in (None, "", "server", "SERVER", "laptop", "desktop-ish", "Desktops"):
        assert parse_identity_mode(raw) is IdentityMode.SERVER


def test_initialize_desktop_defaults_open() -> None:
    store = _MemoryStore()
    mode = initialize_instance(
        store,
        identity_mode=IdentityMode.DESKTOP,
        auth_mode_env="",
        demo_mode_env=False,
    )
    assert mode == InstanceMode.OPEN.value
    assert store.get("auth_mode") == "open"
    assert store.get("demo_mode") == "false"


def test_initialize_desktop_honors_authenticated_env() -> None:
    """S13: desktop + AUTH_MODE=authenticated ⇒ login at boot."""
    store = _MemoryStore()
    mode = initialize_instance(
        store,
        identity_mode="desktop",
        auth_mode_env="authenticated",
        demo_mode_env=False,
    )
    assert mode == InstanceMode.AUTHENTICATED.value


def test_initialize_server_defaults_authenticated() -> None:
    store = _MemoryStore()
    mode = initialize_instance(
        store, identity_mode="server", auth_mode_env="", demo_mode_env=False
    )
    assert mode == InstanceMode.AUTHENTICATED.value


def test_initialize_server_open_coerced_authenticated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """S1: `open` on a server entrypoint is never legal (§4.4)."""
    store = _MemoryStore()
    with caplog.at_level(logging.WARNING):
        mode = initialize_instance(
            store,
            identity_mode=IdentityMode.SERVER,
            auth_mode_env="open",
            demo_mode_env=False,
        )
    assert mode == InstanceMode.AUTHENTICATED.value
    assert store.get("auth_mode") == "authenticated"
    assert any("§4.4" in record.message for record in caplog.records)


def test_initialize_unknown_env_fails_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """S2: junk AUTH_MODE ⇒ warn + authenticated on both entrypoints."""
    for identity in (IdentityMode.DESKTOP, IdentityMode.SERVER):
        store = _MemoryStore()
        with caplog.at_level(logging.WARNING):
            mode = initialize_instance(
                store,
                identity_mode=identity,
                auth_mode_env="WideOpen",
                demo_mode_env=False,
            )
        assert mode == InstanceMode.AUTHENTICATED.value
    assert any("not a valid mode" in record.message for record in caplog.records)


def test_initialize_demo_mode_written_explicitly() -> None:
    """S4: demo_mode is stored either way at init, never left unset."""
    store = _MemoryStore()
    initialize_instance(
        store, identity_mode="server", auth_mode_env="", demo_mode_env=True
    )
    assert store.get("demo_mode") == "true"
    fresh = _MemoryStore()
    initialize_instance(
        fresh, identity_mode="server", auth_mode_env="", demo_mode_env=False
    )
    assert fresh.get("demo_mode") == "false"


def test_initialize_post_init_flips_ignored_loudly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """S3/S4: stored values win; env/CLI flips warn and change nothing."""
    store = _MemoryStore()
    initialize_instance(
        store, identity_mode="server", auth_mode_env="", demo_mode_env=False
    )
    with caplog.at_level(logging.WARNING):
        mode = initialize_instance(
            store,
            identity_mode="server",
            auth_mode_env="open",
            demo_mode_env=True,
        )
    assert mode == InstanceMode.AUTHENTICATED.value
    assert store.get("auth_mode") == "authenticated"
    assert store.get("demo_mode") == "false"
    assert any("authoritative" in record.message for record in caplog.records)
    assert any("DEMO_MODE" in record.message for record in caplog.records)
