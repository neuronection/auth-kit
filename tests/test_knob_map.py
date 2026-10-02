"""§16 knob map (ADR-0028 §3): one table, two routing paths, no drift."""

from __future__ import annotations

import dataclasses
import logging
from typing import Literal, cast

import pytest

from nx_auth.config import (
    AUTH_KNOB_ENV_NAMES,
    NON_KNOB_FIELDS,
    AuthConfig,
    knob_overrides,
)


def _sample_value(name: str) -> object:
    """A value every knob parser accepts — the drift probe feeds this
    one getter over the whole map."""
    return "desktop" if name.endswith("_IDENTITY_MODE") else "1"


def test_knob_map_covers_every_auth_config_tunable() -> None:
    """S12: adding a tunable without a knob name fails this case.

    The only carve-out is `NON_KNOB_FIELDS` — the kit-side list whose
    entries each carry a written reason (see the next case)."""
    parsed = knob_overrides("SA", _sample_value)
    fields = {field.name for field in dataclasses.fields(AuthConfig)}
    assert set(parsed) == fields - set(NON_KNOB_FIELDS)


def test_non_knob_fields_carry_stated_reasons() -> None:
    """The kit-side exclusion list is not a silent set: every entry must
    be a real `AuthConfig` field and say why it cannot be env-routed."""
    fields = {field.name for field in dataclasses.fields(AuthConfig)}
    assert set(NON_KNOB_FIELDS) <= fields
    assert all(reason.strip() for reason in NON_KNOB_FIELDS.values())


def test_knob_map_names_are_prefixed_shapes() -> None:
    assert "AUTH_ACCESS_TTL_MINUTES" in AUTH_KNOB_ENV_NAMES
    assert "RATELIMIT_AUTH" in AUTH_KNOB_ENV_NAMES
    assert "COOKIE_SECURE" in AUTH_KNOB_ENV_NAMES
    assert "IDENTITY_MODE" in AUTH_KNOB_ENV_NAMES
    assert "REQUIRE_SHELL_SECRET" in AUTH_KNOB_ENV_NAMES
    assert all(name == name.upper() for name in AUTH_KNOB_ENV_NAMES)


def test_knob_overrides_parses_typed_and_string_values() -> None:
    values: dict[str, object] = {
        "SA_AUTH_ACCESS_TTL_MINUTES": 15,
        "SA_AUTH_LOCKOUT_THRESHOLD": "7",
        "SA_COOKIE_SECURE": True,
        "SA_REGISTRATION_ENABLED": "off",
        "SA_TRUSTED_PROXY_COUNT": None,
        "SA_RATELIMIT_AUTH": "",
        "SA_RATELIMIT_AUTH_EMAIL": "many",
    }
    overrides = knob_overrides("SA", values.get)
    assert overrides == {
        "access_ttl_minutes": 15,
        "lockout_threshold": 7,
        "cookie_secure": True,
        "registration_enabled": False,
    }


def test_knob_map_routes_identity_mode_and_shell_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7: the two previously-missing tunables are first-class knobs on
    both routing paths (Settings-backed and OS env)."""
    values: dict[str, object] = {
        "SA_IDENTITY_MODE": "desktop",
        "SA_REQUIRE_SHELL_SECRET": "true",
    }
    assert knob_overrides("SA", values.get) == {
        "identity_mode": "desktop",
        "require_shell_secret": True,
    }
    monkeypatch.setenv("TST_IDENTITY_MODE", "desktop")
    monkeypatch.setenv("TST_REQUIRE_SHELL_SECRET", "yes")
    config = AuthConfig.from_env("TST", iss="test")
    assert config.identity_mode == "desktop"
    assert config.require_shell_secret is True


def test_auth_config_normalizes_identity_mode() -> None:
    """F17: one parser on every construction path — a direct
    `AuthConfig(...)` normalizes exactly like `<P>_IDENTITY_MODE`."""
    desktop = cast(Literal["server", "desktop"], " DESKTOP ")
    assert AuthConfig(iss="test", identity_mode=desktop).identity_mode == "desktop"
    junk = cast(Literal["server", "desktop"], "laptop")
    assert AuthConfig(iss="test", identity_mode=junk).identity_mode == "server"


def test_knob_overrides_reads_all_five_knobs_from_settings_style_getter() -> None:
    """S5 shape: `.env`-backed Settings values reach the kit config."""
    values = {
        "CAREER_COOKIE_SECURE": "true",
        "CAREER_AUTH_ACCESS_TTL_MINUTES": "45",
        "CAREER_AUTH_REFRESH_TTL_DAYS": "14",
        "CAREER_AUTH_LOCKOUT_THRESHOLD": "3",
        "CAREER_TRUSTED_PROXY_COUNT": "1",
    }
    overrides = knob_overrides("CAREER", values.get)
    config = AuthConfig.from_env("OTHER_PREFIX_NEVER_SET", iss="career", **overrides)
    assert config.cookie_secure is True
    assert config.access_ttl_minutes == 45
    assert config.refresh_ttl_days == 14
    assert config.lockout_threshold == 3
    assert config.trusted_proxy_count == 1


def test_from_env_reads_rate_limit_and_password_knobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TST_RATELIMIT_AUTH", "25")
    monkeypatch.setenv("TST_RATELIMIT_AUTH_EMAIL", "40")
    monkeypatch.setenv("TST_AUTH_PASSWORD_MIN_LENGTH", "16")
    config = AuthConfig.from_env("TST", iss="test")
    assert config.auth_rate_per_minute == 25
    assert config.auth_email_rate_per_minute == 40
    assert config.password_min_length == 16


def test_overrides_beat_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TST_COOKIE_SECURE", "false")
    config = AuthConfig.from_env(
        "TST", iss="test", **knob_overrides("TST", lambda _: "true")
    )
    assert config.cookie_secure is True


# --- F8: knob values never fail open on typos or destructive bounds ---


def test_unparsable_knobs_warn_and_fall_back_to_defaults(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A typo is never silently mis-parsed: each dropped value warns
    naming the env name and value, and the documented family default
    (here: the fail-closed one) applies."""
    monkeypatch.setenv("TST_COOKIE_SECURE", "maybe")
    monkeypatch.setenv("TST_AUTH_LOCKOUT_THRESHOLD", "oops")
    monkeypatch.setenv("TST_RATELIMIT_AUTH_EMAIL", "many")
    monkeypatch.setenv("TST_IDENTITY_MODE", "laptop")
    with caplog.at_level(logging.WARNING):
        config = AuthConfig.from_env("TST", iss="test")
    assert config.cookie_secure is False
    assert config.lockout_threshold == 5
    assert config.auth_email_rate_per_minute == 30
    assert config.identity_mode == "server"
    for name, value in (
        ("TST_COOKIE_SECURE", "maybe"),
        ("TST_AUTH_LOCKOUT_THRESHOLD", "oops"),
        ("TST_RATELIMIT_AUTH_EMAIL", "many"),
        ("TST_IDENTITY_MODE", "laptop"),
    ):
        assert any(
            name in record.message and value in record.message
            for record in caplog.records
        ), f"no warning naming {name}={value}"


def test_unparsable_settings_backed_knobs_warn_and_drop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The Settings-backed routing path reports the same way (one map,
    two paths)."""
    values: dict[str, object] = {"SA_RATELIMIT_AUTH": "many"}
    with caplog.at_level(logging.WARNING):
        overrides = knob_overrides("SA", values.get)
    assert "auth_rate_per_minute" not in overrides
    assert any(
        "SA_RATELIMIT_AUTH" in record.message and "many" in record.message
        for record in caplog.records
    )


def test_destructive_bounds_are_refused() -> None:
    """F8: a knob may tune a guard, never disable it — zero lockout
    window, gutted password floor and dead rate limits raise instead of
    booting."""
    with pytest.raises(ValueError, match="lockout_minutes"):
        AuthConfig(iss="test", lockout_minutes=0)
    with pytest.raises(ValueError, match="lockout_threshold"):
        AuthConfig(iss="test", lockout_threshold=0)
    with pytest.raises(ValueError, match="password_min_length"):
        AuthConfig(iss="test", password_min_length=0)
    with pytest.raises(ValueError, match="password_min_length"):
        AuthConfig(iss="test", password_min_length=9)
    with pytest.raises(ValueError, match="rate limits"):
        AuthConfig(iss="test", auth_rate_per_minute=0)
    with pytest.raises(ValueError, match="rate limits"):
        AuthConfig(iss="test", auth_email_rate_per_minute=0)


def test_destructive_bounds_refused_on_the_env_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TST_AUTH_LOCKOUT_MINUTES", "0")
    with pytest.raises(ValueError, match="lockout_minutes"):
        AuthConfig.from_env("TST", iss="test")


def test_minimum_bounds_are_accepted() -> None:
    """Positive counterparts: the lowest legal values construct fine."""
    config = AuthConfig(
        iss="test",
        lockout_threshold=1,
        lockout_minutes=1,
        password_min_length=10,
        auth_rate_per_minute=1,
        auth_email_rate_per_minute=1,
        trusted_proxy_count=0,
    )
    assert config.lockout_minutes == 1
    assert config.password_min_length == 10
