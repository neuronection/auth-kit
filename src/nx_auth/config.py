from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

DEFAULT_ACCESS_TTL_MINUTES = 60
MAX_ACCESS_TTL_MINUTES = 24 * 60
DEFAULT_REFRESH_TTL_DAYS = 7
DEFAULT_REFRESH_ABSOLUTE_DAYS = 30
DEFAULT_LOCKOUT_THRESHOLD = 5
DEFAULT_LOCKOUT_MINUTES = 15
DEFAULT_PASSWORD_MIN_LENGTH = 10

# §16 knob map (ADR-0028 §3): every tunable of `AuthConfig` with its
# canonical `<PREFIX>_<SUFFIX>` env name and parser. `from_env` and
# `knob_overrides` both read through this table, so the OS-environment
# and Settings-backed paths can never drift apart (contract case §18.14).
_KNOB_SPECS: tuple[tuple[str, str, type], ...] = (
    ("AUTH_ACCESS_TTL_MINUTES", "access_ttl_minutes", int),
    ("AUTH_REFRESH_TTL_DAYS", "refresh_ttl_days", int),
    ("AUTH_REFRESH_ABSOLUTE_DAYS", "refresh_absolute_days", int),
    ("AUTH_LOCKOUT_THRESHOLD", "lockout_threshold", int),
    ("AUTH_LOCKOUT_MINUTES", "lockout_minutes", int),
    ("AUTH_PASSWORD_MIN_LENGTH", "password_min_length", int),
    ("REGISTRATION_ENABLED", "registration_enabled", bool),
    ("COOKIE_SECURE", "cookie_secure", bool),
    ("TRUSTED_PROXY_COUNT", "trusted_proxy_count", int),
    ("RATELIMIT_AUTH", "auth_rate_per_minute", int),
    ("RATELIMIT_AUTH_EMAIL", "auth_email_rate_per_minute", int),
)

#: Canonical `<PREFIX>_<SUFFIX>` env names of every tunable knob.
AUTH_KNOB_ENV_NAMES: tuple[str, ...] = tuple(suffix for suffix, _, _ in _KNOB_SPECS)

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _parse_bool(raw: object) -> bool | None:
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return None


def _parse_int(raw: object) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def knob_overrides(
    prefix: str, getter: Callable[[str], object | None]
) -> dict[str, object]:
    """Build `AuthConfig` kwargs from Settings-backed values (ADR-0028 §3).

    `getter` receives the canonical env name (`<PREFIX>_<SUFFIX>`) and
    returns the value — or `None` when unset. Products back it with their
    pydantic `Settings` (which already merged `.env` + OS env, OS env
    winning per key) so `.env`-file values reach the kit config exactly
    like process-environment ones; the kit's own `os.environ` read stays
    the fallback layer. Missing/blank/unparseable values fall back to the
    family defaults — never to an insecure value (the 24h access cap is
    enforced by `__post_init__` regardless of source).
    """
    kwargs: dict[str, object] = {}
    for suffix, field_name, parser in _KNOB_SPECS:
        raw = getter(f"{prefix}_{suffix}")
        if raw is None or raw == "":
            continue
        parsed = _parse_bool(raw) if parser is bool else _parse_int(raw)
        if parsed is not None:
            kwargs[field_name] = parsed
    return kwargs


@dataclass(frozen=True)
class AuthConfig:
    iss: str
    identity_mode: Literal["server", "desktop"] = "server"
    access_ttl_minutes: int = DEFAULT_ACCESS_TTL_MINUTES
    refresh_ttl_days: int = DEFAULT_REFRESH_TTL_DAYS
    refresh_absolute_days: int = DEFAULT_REFRESH_ABSOLUTE_DAYS
    lockout_threshold: int = DEFAULT_LOCKOUT_THRESHOLD
    lockout_minutes: int = DEFAULT_LOCKOUT_MINUTES
    password_min_length: int = DEFAULT_PASSWORD_MIN_LENGTH
    registration_enabled: bool = True
    cookie_secure: bool = False
    trusted_proxy_count: int = 0
    require_shell_secret: bool = False
    demo_user_id: str = "00000000-0000-4000-8000-00000000d0e0"
    auth_rate_per_minute: int = 10
    auth_email_rate_per_minute: int = 30
    auth_exempt_prefixes: tuple[str, ...] = (
        "/api/v1/auth/",
        "/api/v1/health",
        "/api/docs",
        "/api/v1/shell/rendered",
    )
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.iss:
            raise ValueError("iss (product slug) is required")
        if not 1 <= self.access_ttl_minutes <= MAX_ACCESS_TTL_MINUTES:
            raise ValueError(
                f"access_ttl_minutes must be 1..{MAX_ACCESS_TTL_MINUTES} (24h hard cap)"
            )
        if self.refresh_ttl_days < 1 or self.refresh_absolute_days < self.refresh_ttl_days:
            raise ValueError("refresh TTLs must satisfy 1 <= rolling <= absolute")

    @property
    def access_ttl_seconds(self) -> int:
        return self.access_ttl_minutes * 60

    @property
    def refresh_ttl_seconds(self) -> int:
        return self.refresh_ttl_days * 24 * 60 * 60

    @property
    def refresh_absolute_seconds(self) -> int:
        return self.refresh_absolute_days * 24 * 60 * 60

    @classmethod
    def from_env(cls, prefix: str, iss: str, **overrides: object) -> AuthConfig:
        """Read `<PREFIX>_<SUFFIX>` env vars (init-time configuration).

        `iss` (the product slug) is a code constant, not env. Knobs are
        read through `AUTH_KNOB_ENV_NAMES` (same table as
        `knob_overrides`, so both configuration paths cover identical
        names); missing/unparseable values fall back to the family
        defaults — never to an insecure value (the 24h access cap is
        enforced by `__post_init__` regardless of source).
        """

        identity_raw = os.environ.get(f"{prefix}_IDENTITY_MODE", "server")
        identity: Literal["server", "desktop"] = (
            "desktop" if identity_raw == "desktop" else "server"
        )
        kwargs: dict[str, object] = {
            "iss": iss,
            "identity_mode": identity,
            **knob_overrides(prefix, os.environ.get),
        }
        kwargs.update(overrides)
        return cls(**kwargs)  # type: ignore[arg-type]
