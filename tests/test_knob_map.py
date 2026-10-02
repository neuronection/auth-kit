"""§16 knob map (ADR-0028 §3): one table, two routing paths, no drift."""

from __future__ import annotations

import dataclasses

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
