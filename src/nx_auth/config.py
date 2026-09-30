from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

DEFAULT_ACCESS_TTL_MINUTES = 60
MAX_ACCESS_TTL_MINUTES = 24 * 60
DEFAULT_REFRESH_TTL_DAYS = 7
DEFAULT_REFRESH_ABSOLUTE_DAYS = 30
DEFAULT_LOCKOUT_THRESHOLD = 5
DEFAULT_LOCKOUT_MINUTES = 15
DEFAULT_PASSWORD_MIN_LENGTH = 10


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
        """Read `<P>_AUTH_*` env vars (init-time configuration).

        `iss` (the product slug) is a code constant, not env. Missing/
        unparseable values fall back to the family defaults — never to an
        insecure value (the 24h access cap is enforced by
        `__post_init__` regardless of source).
        """

        def _int(name: str, default: int) -> int:
            raw = os.environ.get(f"{prefix}_{name}")
            try:
                return int(raw) if raw else default
            except ValueError:
                return default

        def _bool(name: str, default: bool) -> bool:
            raw = os.environ.get(f"{prefix}_{name}")
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        identity_raw = os.environ.get(f"{prefix}_IDENTITY_MODE", "server")
        identity: Literal["server", "desktop"] = (
            "desktop" if identity_raw == "desktop" else "server"
        )
        kwargs: dict[str, object] = {
            "iss": iss,
            "identity_mode": identity,
            "access_ttl_minutes": _int("AUTH_ACCESS_TTL_MINUTES", DEFAULT_ACCESS_TTL_MINUTES),
            "refresh_ttl_days": _int("AUTH_REFRESH_TTL_DAYS", DEFAULT_REFRESH_TTL_DAYS),
            "refresh_absolute_days": _int(
                "AUTH_REFRESH_ABSOLUTE_DAYS", DEFAULT_REFRESH_ABSOLUTE_DAYS
            ),
            "lockout_threshold": _int("AUTH_LOCKOUT_THRESHOLD", DEFAULT_LOCKOUT_THRESHOLD),
            "lockout_minutes": _int("AUTH_LOCKOUT_MINUTES", DEFAULT_LOCKOUT_MINUTES),
            "registration_enabled": _bool("REGISTRATION_ENABLED", True),
            "cookie_secure": _bool("COOKIE_SECURE", False),
            "trusted_proxy_count": _int("TRUSTED_PROXY_COUNT", 0),
        }
        kwargs.update(overrides)
        return cls(**kwargs)  # type: ignore[arg-type]
