from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from nx_auth.cookies import new_csrf_token
from nx_auth.principal import Principal
from nx_auth.protocols import UserRecord
from nx_auth.tokens import (
    AuthMode,
    TokenKind,
    mint_token,
    new_jti,
    now_utc,
    sha256_hex,
)

if TYPE_CHECKING:
    from nx_auth.install import AuthKit


def device_hint(user_agent: str | None, *, max_length: int = 200) -> str | None:
    """Sanitized device hint for `auth_sessions.client_label` (§5/§12):
    the request's `User-Agent` with control characters stripped and
    whitespace collapsed, capped at the column width. `None` when
    nothing printable remains — callers fall back to the flow label."""
    if not user_agent:
        return None
    printable = "".join(ch for ch in user_agent if ch.isprintable())
    cleaned = " ".join(printable.split())[:max_length]
    return cleaned or None


def issue_session(
    kit: AuthKit,
    user: UserRecord,
    *,
    auth_mode: AuthMode,
    label: str,
    client_label: str | None = None,
    with_refresh: bool = True,
) -> tuple[str, str | None, str]:
    """Create one sign-in: an `auth_sessions` family row (unless the
    caller is DIM, which mints a session per boot instead), the access
    token, the refresh token, and a fresh CSRF token.

    The refresh `jti` is generated here so its hash — never the token —
    is what the family row stores (contract §5). `client_label` is
    the device hint (typically derived from the request's `User-Agent`);
    when absent the flow label ("login", "register", …) is stored.
    """
    now = now_utc()
    family_id: str | None = None
    refresh_token: str | None = None
    if with_refresh:
        refresh_jti = new_jti()
        family_id = kit.sessions.create(
            user_id=user.id,
            refresh_jti_hash=sha256_hex(refresh_jti),
            expires_at=now + timedelta(seconds=kit.config.refresh_ttl_seconds),
            absolute_expires_at=now + timedelta(seconds=kit.config.refresh_absolute_seconds),
            client_label=client_label or label,
        )
        refresh_token = mint_token(
            kit.ring,
            kit.config,
            kind=TokenKind.REFRESH,
            sub=user.id,
            ver=user.token_version,
            auth_mode=auth_mode,
            family_id=family_id,
            now=now,
            jti=refresh_jti,
        )
    access_token = mint_token(
        kit.ring,
        kit.config,
        kind=TokenKind.SESSION,
        sub=user.id,
        ver=user.token_version,
        auth_mode=auth_mode,
        family_id=family_id,
        now=now,
    )
    return access_token, refresh_token, new_csrf_token()


def principal_from_user(
    user: UserRecord, *, auth_mode: AuthMode, family_id: str | None = None
) -> Principal:
    return Principal(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_admin=user.is_admin,
        is_active=user.is_active,
        ver=user.token_version,
        auth_mode=auth_mode,
        family_id=family_id,
    )
