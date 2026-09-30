from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from nx_auth.protocols import InstanceStore


class InstanceMode(StrEnum):
    OPEN = "open"
    AUTHENTICATED = "authenticated"


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
