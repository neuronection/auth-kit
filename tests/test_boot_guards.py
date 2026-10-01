"""Boot guards (ADR-0028): fail-soft in dev, abort in production (§8/§13)."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Sequence

import pytest

from nx_auth.boot import (
    DEFAULT_WEAK_SECRETS,
    BootConfigError,
    validate_boot_config,
)
from nx_auth.instance import IdentityMode

SESSION_KEY = "session-key-0123456789abcdefghijklmnopqrstuv"
REFRESH_KEY = "refresh-key-0123456789abcdefghijklmnopqrstuv"
DATA_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()  # valid Fernet
OTHER_DATA_KEY = base64.urlsafe_b64encode(bytes(range(32, 64))).decode()


def _check(
    *,
    session_key: str | None = SESSION_KEY,
    refresh_key: str | None = REFRESH_KEY,
    data_key: str | None = DATA_KEY,
    data_key_previous: Sequence[str] = (),
    weak_secrets: Iterable[str] = (),
    debug: bool = False,
    demo_mode: bool = False,
    identity_mode: IdentityMode | str = IdentityMode.SERVER,
) -> list[str]:
    return validate_boot_config(
        production=True,
        identity_mode=identity_mode,
        session_key=session_key,
        refresh_key=refresh_key,
        data_key=data_key,
        data_key_previous=data_key_previous,
        weak_secrets=weak_secrets,
        debug=debug,
        demo_mode=demo_mode,
    )


def test_dev_boot_never_enforces() -> None:
    assert (
        validate_boot_config(
            production=False,
            identity_mode=IdentityMode.SERVER,
            debug=True,
            demo_mode=True,
        )
        == []
    )


def test_valid_pins_pass() -> None:
    assert _check() == []
    desktop = _check(identity_mode=IdentityMode.DESKTOP)
    assert desktop == []


def test_partial_pin_fails_closed() -> None:
    """S6: two of three pins is a config-shape error, not a boot."""
    with pytest.raises(BootConfigError, match="partial key pin"):
        _check(data_key=None)


def test_weak_and_short_pins_refused() -> None:
    """S7: known dev/test values and short keys never reach production."""
    blocked = next(iter(DEFAULT_WEAK_SECRETS))
    with pytest.raises(BootConfigError, match="known dev/test value"):
        _check(session_key=blocked)
    with pytest.raises(BootConfigError, match="known dev/test value"):
        _check(session_key="x" * 31)


def test_product_weak_secrets_hook() -> None:
    fixture_key = "fixture-key-0123456789abcdefghijklmnopqrst"
    with pytest.raises(BootConfigError, match="known dev/test value"):
        _check(session_key=fixture_key, weak_secrets=[fixture_key])


def test_debug_and_demo_refused_in_production() -> None:
    """S8: production entrypoints abort on DEBUG / DEMO_MODE (§13)."""
    with pytest.raises(BootConfigError, match="DEMO_MODE"):
        _check(demo_mode=True)
    with pytest.raises(BootConfigError, match="DEBUG"):
        _check(debug=True)


def test_data_key_must_be_fernet_material() -> None:
    with pytest.raises(BootConfigError, match="DATA_KEY must be usable Fernet"):
        _check(data_key="not-fernet-material-0123456789abcdefghijklmno")
    with pytest.raises(BootConfigError, match="DATA_KEY_PREVIOUS entry 1"):
        _check(data_key_previous=["also-not-fernet-0123456789abcdefghijklmn"])
    # rotation entries must pass the same check
    assert _check(data_key_previous=[OTHER_DATA_KEY]) == []


def test_duplicate_pins_refused() -> None:
    with pytest.raises(BootConfigError, match="distinct"):
        _check(refresh_key=SESSION_KEY)


def test_no_pins_server_fatal_desktop_warns() -> None:
    with pytest.raises(BootConfigError, match="missing"):
        validate_boot_config(
            production=True, identity_mode=IdentityMode.SERVER
        )
    warnings = validate_boot_config(
        production=True, identity_mode=IdentityMode.DESKTOP
    )
    assert any("auth_keys.json" in warning for warning in warnings)
