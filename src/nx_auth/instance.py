from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from nx_auth.audit import AuditEvent, AuditSink, NullAuditSink

if TYPE_CHECKING:
    from nx_auth.protocols import InstanceStore

logger = logging.getLogger(__name__)

#: Audit action written whenever §4.4 coerces `open` → `authenticated`
#: on a server entrypoint (seeding *and* stored-row paths).
COERCE_AUDIT_ACTION = "instance.auth_mode_coerced"


class InstanceMode(StrEnum):
    OPEN = "open"
    AUTHENTICATED = "authenticated"


VALID_AUTH_MODES: tuple[str, ...] = tuple(mode.value for mode in InstanceMode)


class IdentityMode(StrEnum):
    """Entrypoint half of the instance-mode matrix (contract §4).

    `SERVER` is the web/docker entrypoint; `DESKTOP` is the product
    shell (`<P> app`, ADR-0010). Parsing fails **closed to `SERVER`** —
    anything unknown gets the stricter half (ADR-0028).
    """

    SERVER = "server"
    DESKTOP = "desktop"


def parse_identity_mode(raw: str | None) -> IdentityMode:
    """Parse the entrypoint mode; unknown/missing ⇒ `SERVER` (fail-closed)."""
    if raw is not None and raw.strip().lower() == IdentityMode.DESKTOP.value:
        return IdentityMode.DESKTOP
    return IdentityMode.SERVER


@dataclass(frozen=True)
class InstanceState:
    """What the database says this instance is (contract §4).

    `auth_mode=None` means *unknown/missing* — and unknown always
    evaluates as `authenticated` (fail-closed). The state is read fresh
    on every request; it is never a boot-time snapshot.
    """

    auth_mode: InstanceMode | None
    demo_mode: bool
    identity_mode: Literal["server", "desktop"]


def effective_auth_mode(state: InstanceState) -> InstanceMode:
    if state.auth_mode is InstanceMode.OPEN:
        return InstanceMode.OPEN
    return InstanceMode.AUTHENTICATED


def can_accept_local_boot(state: InstanceState) -> bool:
    """`local-boot` tokens are legal only on `open` desktop instances."""
    return (
        effective_auth_mode(state) is InstanceMode.OPEN
        and state.identity_mode == "desktop"
    )


def can_accept_demo(state: InstanceState) -> bool:
    return state.demo_mode


def can_accept_registration(state: InstanceState) -> bool:
    """Self-signup (`/register`) exists only on `authenticated` instances.

    `open` desktop instances are personal devices: the owner boots via
    the DIM exchange and additional users are created through the admin
    surface (§12), never by anonymous self-registration — so /register
    answers 404 there: a route that doesn't exist can't be probed,
    pre-provisioned, or CSRF'd. `/login` stays mounted on `open`
    instances by design: password-holding users (created via admin) must
    authenticate for the open→authenticated transition flow (§4).
    """
    return effective_auth_mode(state) is InstanceMode.AUTHENTICATED


def read_state(
    store: InstanceStore, identity_mode: Literal["server", "desktop"]
) -> InstanceState:
    """Fresh, per-request read of the instance's identity (contract §4).

    Unknown/missing `auth_mode` parses to `None` → evaluates as
    `authenticated` (fail-closed); anything unparsable behaves the same.
    """
    return InstanceState(
        auth_mode=parse_auth_mode(store.get("auth_mode")),
        demo_mode=store.get("demo_mode") == "true",
        identity_mode=identity_mode,
    )


def parse_auth_mode(raw: str | None) -> InstanceMode | None:
    if raw == "open":
        return InstanceMode.OPEN
    if raw == "authenticated":
        return InstanceMode.AUTHENTICATED
    return None


def _coerce_open_on_server(*, product: str, audit: AuditSink | None) -> str:
    """§4.4: `open` is never legal on a server entrypoint.

    Shared by the seeding and stored-row paths: loud operator warning +
    one audit event (`COERCE_AUDIT_ACTION`), returning the coerced
    `authenticated` mode. The audit sink is injected — `initialize_instance`
    keeps no global state; products pass their `AuditSink` so the coercion
    is persisted, and without one the coercion still happens and warns but
    no event is written.
    """
    logger.warning(
        "%s_AUTH_MODE=open is not legal on a server entrypoint "
        "(contract §4.4) — coercing to authenticated",
        product,
    )
    sink: AuditSink = audit if audit is not None else NullAuditSink()
    sink.record(
        AuditEvent(
            actor="system",
            action=COERCE_AUDIT_ACTION,
            resource="instance_settings.auth_mode",
            outcome="coerced",
        )
    )
    return InstanceMode.AUTHENTICATED.value


def initialize_instance(
    store: InstanceStore,
    *,
    identity_mode: IdentityMode | str,
    auth_mode_env: str,
    demo_mode_env: bool,
    product: str = "AUTH",
    audit: AuditSink | None = None,
) -> str:
    """Seed `instance_settings` on an empty DB; return the effective mode (§4).

    The single family implementation of the init-only rules (ADR-0028):

    - empty DB ⇒ write `auth_mode` (env value if legal; else the §4
      default: `open` on desktop, `authenticated` on server) and
      `demo_mode` explicitly, either way (§13);
    - `open` on a server entrypoint is never legal (§4.4) — the write
      becomes `authenticated` with a loud warning;
    - an unknown env value fails closed to `authenticated` with a loud
      warning;
    - existing DB ⇒ the stored value wins; env/CLI flips are ignored with
      a loud warning (mode changes are authenticated admin actions
      through `request_transition`, never launch-time) — **except** that
      a *stored* `open` on a server entrypoint is coerced to
      `authenticated` at boot just like a seeded one (§4.4 again: the
      "server never runs open" invariant holds on every boot, loudly and
      with an audit event). Desktop keeps a stored `open` untouched.

    `product` is the env prefix (`SA`, `CAREER`, …) used in warnings.
    `audit` (optional) is the product's `AuditSink`; it receives one
    `COERCE_AUDIT_ACTION` event whenever the §4.4 coercion fires.
    """
    identity = parse_identity_mode(str(identity_mode))
    env_mode = auth_mode_env.strip().lower()
    if env_mode and env_mode not in VALID_AUTH_MODES:
        logger.warning(
            "%s_AUTH_MODE=%r is not a valid mode (%s) — failing closed to authenticated",
            product,
            auth_mode_env,
            "/".join(VALID_AUTH_MODES),
        )
        env_mode = InstanceMode.AUTHENTICATED.value

    stored = store.get("auth_mode")
    if stored is None:
        mode = env_mode or (
            InstanceMode.OPEN.value
            if identity is IdentityMode.DESKTOP
            else InstanceMode.AUTHENTICATED.value
        )
        if identity is not IdentityMode.DESKTOP and mode == InstanceMode.OPEN.value:
            mode = _coerce_open_on_server(product=product, audit=audit)
        store.set("auth_mode", mode)
        store.set("demo_mode", "true" if demo_mode_env else "false")
        logger.info(
            "instance_settings initialized: auth_mode=%s (identity_mode=%s)",
            mode,
            identity.value,
        )
        return mode

    if stored == InstanceMode.OPEN.value and identity is not IdentityMode.DESKTOP:
        # §4.4 covers the stored row too: a DB left `open` (e.g. seeded by
        # an older buggy boot) must not run a server entrypoint open.
        stored = _coerce_open_on_server(product=product, audit=audit)
        store.set("auth_mode", stored)

    if env_mode and env_mode != stored:
        logger.warning(
            "%s_AUTH_MODE=%s ignored — instance_settings.auth_mode=%s is "
            "authoritative (contract §4: mode changes are authenticated "
            "admin actions, never launch-time)",
            product,
            env_mode,
            stored,
        )
    if demo_mode_env and store.get("demo_mode") != "true":
        logger.warning(
            "%s_DEMO_MODE=true ignored — instance_settings.demo_mode is "
            "authoritative after initialization (contract §13)",
            product,
        )
    return stored


@dataclass(frozen=True)
class TransitionResult:
    mode: InstanceMode | None
    error: str | None = None


def request_transition(
    state: InstanceState,
    target: InstanceMode,
    *,
    other_user_count: int = 0,
    owner_has_password: bool = False,
    password_confirmed: bool = False,
) -> TransitionResult:
    """Pure version of the §4.5 mode-change guard rails.

    Never a launch-time action: products expose this behind an
    authenticated admin endpoint that first verifies the current
    password, then applies the result and writes an audit event.

    - `open → authenticated`: owner credentials must already be set
      (the caller provisions them before flipping the mode).
    - `authenticated → open`: current password confirmed, and no other
      user rows may exist (multi-user instances cannot go open).
    - Same-mode requests are no-ops (success without side effects).
    """
    if target is state.auth_mode:
        return TransitionResult(mode=effective_auth_mode(state))
    if target is InstanceMode.AUTHENTICATED:
        if not owner_has_password:
            return TransitionResult(mode=None, error="set owner credentials before enabling auth")
        return TransitionResult(mode=InstanceMode.AUTHENTICATED)
    if not password_confirmed:
        return TransitionResult(mode=None, error="current password required to disable auth")
    if other_user_count > 0:
        return TransitionResult(mode=None, error="other user accounts exist; remove them first")
    return TransitionResult(mode=InstanceMode.OPEN)


def utcnow() -> datetime:
    return datetime.now(UTC)
