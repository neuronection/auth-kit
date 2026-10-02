from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from nx_auth.instance import IdentityMode, parse_identity_mode

logger = logging.getLogger(__name__)

DEFAULT_ACCESS_TTL_MINUTES = 60
MAX_ACCESS_TTL_MINUTES = 24 * 60
DEFAULT_REFRESH_TTL_DAYS = 7
DEFAULT_REFRESH_ABSOLUTE_DAYS = 30
DEFAULT_LOCKOUT_THRESHOLD = 5
DEFAULT_LOCKOUT_MINUTES = 15
DEFAULT_PASSWORD_MIN_LENGTH = 10

# Lower bounds: knobs may tune, but never disable a guard. The password
# floor is the §7 family policy (10 chars) — the knob can only tighten
# it. Rate limits must stay positive (0/negative refuses every request).
MIN_LOCKOUT_THRESHOLD = 1
MIN_LOCKOUT_MINUTES = 1
MIN_PASSWORD_MIN_LENGTH = 10
MIN_RATE_PER_MINUTE = 1

_KnobParser = Callable[[object], object | None]

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


def _parse_identity(raw: object) -> str | None:
    """`<P>_IDENTITY_MODE` — `parse_identity_mode` is the one family
    parser (strips + lowercases, fails closed to `SERVER`). Values that
    name no mode are junk: dropped like any other unparsable knob (falling
    back to `server` — also the fail-closed half)."""
    text = str(raw).strip().lower()
    if text not in (IdentityMode.SERVER.value, IdentityMode.DESKTOP.value):
        return None
    return parse_identity_mode(text).value


# §16 knob map (ADR-0028 §3): every env-tunable of `AuthConfig` with its
# canonical `<PREFIX>_<SUFFIX>` env name and parser. `from_env` and
# `knob_overrides` both read through this table, so the OS-environment
# and Settings-backed paths can never drift apart (contract case §18.14).
# Fields that cannot be env-routed live in `NON_KNOB_FIELDS` with a
# stated reason each — every `AuthConfig` field must appear in exactly
# one of the two lists, enforced by `tests/test_knob_map.py`.
_KNOB_SPECS: tuple[tuple[str, str, str, _KnobParser], ...] = (
    ("IDENTITY_MODE", "identity_mode", "identity", _parse_identity),
    ("AUTH_ACCESS_TTL_MINUTES", "access_ttl_minutes", "int", _parse_int),
    ("AUTH_REFRESH_TTL_DAYS", "refresh_ttl_days", "int", _parse_int),
    ("AUTH_REFRESH_ABSOLUTE_DAYS", "refresh_absolute_days", "int", _parse_int),
    ("AUTH_LOCKOUT_THRESHOLD", "lockout_threshold", "int", _parse_int),
    ("AUTH_LOCKOUT_MINUTES", "lockout_minutes", "int", _parse_int),
    ("AUTH_PASSWORD_MIN_LENGTH", "password_min_length", "int", _parse_int),
    ("REGISTRATION_ENABLED", "registration_enabled", "bool", _parse_bool),
    ("COOKIE_SECURE", "cookie_secure", "bool", _parse_bool),
    ("TRUSTED_PROXY_COUNT", "trusted_proxy_count", "int", _parse_int),
    ("REQUIRE_SHELL_SECRET", "require_shell_secret", "bool", _parse_bool),
    ("RATELIMIT_AUTH", "auth_rate_per_minute", "int", _parse_int),
    ("RATELIMIT_AUTH_EMAIL", "auth_email_rate_per_minute", "int", _parse_int),
)

#: Canonical `<PREFIX>_<SUFFIX>` env names of every tunable knob.
AUTH_KNOB_ENV_NAMES: tuple[str, ...] = tuple(spec[0] for spec in _KNOB_SPECS)

#: The `AuthConfig` fields that are deliberately **not** §16 knobs, each
#: with the reason it cannot be env-routed. Kit-side (never test-side) so
#: a new tunable cannot escape the S12 drift gate by joining a carve-out
#: set in a test file — it must either get a knob spec or land here with
#: a written justification (`tests/test_knob_map.py` fails otherwise).
NON_KNOB_FIELDS: dict[str, str] = {
    "iss": "code constant — the product slug is passed by the product, never read from env",
    "demo_user_id": "contract-fixed UUID (§13) — the demo principal id is not operator-tunable",
    "auth_exempt_prefixes": "structural route list, set in code per product (not a tunable)",
    "extra": "structural escape hatch for product-specific keys, not a knob",
}


def knob_overrides(
    prefix: str, getter: Callable[[str], object | None]
) -> dict[str, object]:
    """Build `AuthConfig` kwargs from Settings-backed values (ADR-0028 §3).

    `getter` receives the canonical env name (`<PREFIX>_<SUFFIX>`) and
    returns the value — or `None` when unset. Products back it with their
    pydantic `Settings` (which already merged `.env` + OS env, OS env
    winning per key) so `.env`-file values reach the kit config exactly
    like process-environment ones; the kit's own `os.environ` read stays
    the fallback layer.

    Fallback semantics (deliberate, fail-safe in every case):

    - missing/blank values fall back silently to the family defaults;
    - unparsable values are **dropped with a loud warning naming the env
      name and the offending value** — a typo degrades to the documented
      default, never to a silently mis-parsed one (`SA_COOKIE_SECURE=maybe`
      must not quietly mean `False`);
    - parseable-but-destructive bounds (a `0` lockout window, a zero rate
      limit, a password floor below §7) are refused by
      `AuthConfig.__post_init__` with `ValueError` — the config fails
      closed instead of booting with a guard disabled. The 24h access
      cap is enforced there regardless of source.
    """
    kwargs: dict[str, object] = {}
    for suffix, field_name, kind, parser in _KNOB_SPECS:
        env_name = f"{prefix}_{suffix}"
        raw = getter(env_name)
        if raw is None or raw == "":
            continue
        parsed = parser(raw)
        if parsed is None:
            logger.warning(
                "%s=%r is not a valid %s value — ignoring it; the family "
                "default for %s applies",
                env_name,
                raw,
                kind,
                field_name,
            )
            continue
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
        # One identity parser everywhere (F17): direct construction is
        # normalized exactly like <P>_IDENTITY_MODE — "Desktop"/" DESKTOP "
        # mean the same thing on every path, and junk fails closed to
        # `server` (the stricter half).
        object.__setattr__(
            self, "identity_mode", parse_identity_mode(self.identity_mode).value
        )
        if not self.iss:
            raise ValueError("iss (product slug) is required")
        if not 1 <= self.access_ttl_minutes <= MAX_ACCESS_TTL_MINUTES:
            raise ValueError(
                f"access_ttl_minutes must be 1..{MAX_ACCESS_TTL_MINUTES} (24h hard cap)"
            )
        if self.refresh_ttl_days < 1 or self.refresh_absolute_days < self.refresh_ttl_days:
            raise ValueError("refresh TTLs must satisfy 1 <= rolling <= absolute")
        # Lower bounds (F8): a knob may tune a guard, never disable it —
        # `AUTH_LOCKOUT_MINUTES=0` would disable lockout, `0` rate limits
        # would refuse every request, and a password floor below the §7
        # policy would gut the password rule. Refuse the config instead.
        if self.lockout_threshold < MIN_LOCKOUT_THRESHOLD:
            raise ValueError(f"lockout_threshold must be >= {MIN_LOCKOUT_THRESHOLD}")
        if self.lockout_minutes < MIN_LOCKOUT_MINUTES:
            raise ValueError(
                f"lockout_minutes must be >= {MIN_LOCKOUT_MINUTES} "
                "(0 would disable the lockout window)"
            )
        if self.password_min_length < MIN_PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"password_min_length must be >= {MIN_PASSWORD_MIN_LENGTH} "
                "(contract §7 floor — the knob may only tighten the policy)"
            )
        if (
            self.auth_rate_per_minute < MIN_RATE_PER_MINUTE
            or self.auth_email_rate_per_minute < MIN_RATE_PER_MINUTE
        ):
            raise ValueError(
                f"auth rate limits must be >= {MIN_RATE_PER_MINUTE} per minute "
                "(0 would refuse every request)"
            )
        if self.trusted_proxy_count < 0:
            raise ValueError("trusted_proxy_count must be >= 0")

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

        `iss` (the product slug) is a code constant, not env. Every
        knob — `<PREFIX>_IDENTITY_MODE` included — is read through the
        §16 knob map (same table as `knob_overrides`, so both
        configuration paths cover identical names) and parsed by the one
        family parsers (`parse_identity_mode` normalizes the entrypoint
        mode). Fallback semantics are `knob_overrides`': missing/blank ⇒
        family defaults silently; unparsable ⇒ dropped with a loud
        warning naming the env name and value; destructive bounds ⇒
        `ValueError` from `__post_init__` (which also enforces the 24h
        access cap regardless of source).
        """

        kwargs: dict[str, object] = {
            "iss": iss,
            **knob_overrides(prefix, os.environ.get),
        }
        kwargs.update(overrides)
        return cls(**kwargs)  # type: ignore[arg-type]
