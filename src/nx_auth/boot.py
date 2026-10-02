"""Production boot guards (ADR-0028): refuse unsafe config at startup.

Parameterized lift of the family fail-soft-in-dev / abort-in-prod policy
(career's `app/core/boot.py` is the donor; health's config validators
encode the same rule): key material in, product names out. Products call
`validate_boot_config` from their lifespan and log the returned warnings.

Checks run **only in production** (`production=True` mirrors
`APP_ENV=production`); dev/test boots freely. What is enforced:

- the three-or-none key-pin rule (identity-auth §8) — partial pins fail
  closed, all three must be distinct;
- weak/placeholder key refusal (the kit blocklist plus a product
  extension hook for committed test-fixture values);
- `DATA_KEY` must be usable Fernet material (including
  `<P>_DATA_KEY_PREVIOUS` rotation entries);
- no pinned ring at all: fatal on a server (keys are env/DB-config
  there), a loud warning on desktop (generated 0600 `auth_keys.json`);
- `DEBUG` / `DEMO_MODE` refuse to boot in production (§13: demo
  instances are never production).

Never wired into `install()` — an explicit import, like `atrest`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from enum import StrEnum

from nx_auth.instance import IdentityMode

# Known dev/test material — never production (identity-auth §8). Products
# extend this via `weak_secrets=` with their own committed fixture values.
DEFAULT_WEAK_SECRETS: frozenset[str] = frozenset(
    {
        "changeme",
        "change-me",
        "dev",
        "dev-key",
        "dev-only-change-me",
        "example",
        "insecure",
        "not-a-secret",
        "placeholder",
        "replace-me",
        "secret",
        "secret-key",
        "test",
        "test-key",
        "todo",
    }
)

_MIN_KEY_CHARS = 32  # matches KeyRing's weak-secret floor


class BootConfigError(Exception):
    """Fatal configuration problem — the app must not boot."""


class _KeyRole(StrEnum):
    SESSION = "session"
    REFRESH = "refresh"
    DATA = "data"


def _check_fernet(value: str) -> str | None:
    """Return an error message when `value` is not usable Fernet material."""
    from cryptography.fernet import Fernet

    try:
        Fernet(value.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        return f"must be usable Fernet material ({exc})"
    return None


def validate_boot_config(
    *,
    production: bool,
    identity_mode: IdentityMode | str,
    session_key: str | None = None,
    refresh_key: str | None = None,
    data_key: str | None = None,
    data_key_previous: Sequence[str] = (),
    key_env_prefix: str = "AUTH",
    debug: bool = False,
    demo_mode: bool = False,
    weak_secrets: Iterable[str] = (),
    require_pinned_keys_on_server: bool = True,
) -> list[str]:
    """Validate config; raise `BootConfigError` on fatal problems.

    Returns non-fatal warnings for the caller to log. Only enforces when
    `production` — dev/test always returns `[]`.

    `key_env_prefix` names the pins in messages (`<P>_SESSION_KEY` …);
    `weak_secrets` adds product-specific known-bad values to the kit
    blocklist (committed test fixtures).
    """
    if not production:
        return []

    # Blocklist matching is case- and whitespace-insensitive (F10): a
    # case-variant paste of a long committed fixture key must not evade
    # the hook — `KeyRing` normalizes its placeholder check the same way.
    blocked = frozenset(
        secret.strip().lower()
        for secret in DEFAULT_WEAK_SECRETS | frozenset(weak_secrets)
    )
    pins: list[tuple[str, str | None]] = [
        (f"{key_env_prefix}_{role.upper()}_KEY", value)
        for role, value in (
            (_KeyRole.SESSION, session_key),
            (_KeyRole.REFRESH, refresh_key),
            (_KeyRole.DATA, data_key),
        )
    ]
    fatal: list[str] = []
    warnings: list[str] = []

    provided = [value for _, value in pins if value]
    if provided and len(provided) < 3:
        missing = [name for name, value in pins if not value]
        fatal.append(
            f"partial key pin: {', '.join(missing)} is missing — provide all "
            f"three of {key_env_prefix}_SESSION_KEY/{key_env_prefix}_REFRESH_KEY/"
            f"{key_env_prefix}_DATA_KEY or none (identity-auth §8)"
        )
    for name, value in pins:
        if not value:
            continue
        normalized = value.strip()
        if normalized.lower() in blocked or len(normalized) < _MIN_KEY_CHARS:
            fatal.append(
                f"{name} is a known dev/test value or shorter than "
                f"{_MIN_KEY_CHARS} characters — pin a long random value, or "
                "unset all three to let auth_keys.json generate per-instance keys."
            )
    if data_key:
        problem = _check_fernet(data_key)
        if problem:
            fatal.append(f"{key_env_prefix}_DATA_KEY {problem}")
    for index, prior in enumerate(data_key_previous, start=1):
        problem = _check_fernet(prior)
        if problem:
            fatal.append(f"{key_env_prefix}_DATA_KEY_PREVIOUS entry {index}: {problem}")
    if len(provided) == 3 and len({value.strip() for value in provided}) != 3:
        fatal.append(
            f"{key_env_prefix}_SESSION_KEY/{key_env_prefix}_REFRESH_KEY/"
            f"{key_env_prefix}_DATA_KEY must be distinct values (identity-auth §8)"
        )

    if not provided:
        if str(identity_mode) == IdentityMode.DESKTOP.value:
            warnings.append(
                "no pinned key ring — per-instance keys live in the generated "
                "0600 auth_keys.json (identity-auth §8)"
            )
        elif require_pinned_keys_on_server:
            fatal.append(
                f"{key_env_prefix}_SESSION_KEY/{key_env_prefix}_REFRESH_KEY/"
                f"{key_env_prefix}_DATA_KEY are missing — production servers pin "
                "per-instance keys via env or the deployment .env "
                "(identity-auth §8: server = env/DB-config with a weak-secret "
                "boot guard)"
            )

    if demo_mode:
        # identity-auth §13: production entrypoints abort on demo config.
        fatal.append(
            "DEMO_MODE=true is not allowed in production (identity-auth §13) — "
            "demo instances are explicitly badged, isolated, and never production."
        )
    if debug:
        fatal.append("DEBUG=true is not allowed in production.")

    if fatal:
        raise BootConfigError("; ".join(fatal))
    return warnings
