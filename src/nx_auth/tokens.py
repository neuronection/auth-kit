import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt

from nx_auth.config import AuthConfig
from nx_auth.keys import KeyRing

ALGORITHM = "HS256"
REQUIRED_CLAIMS = ["iss", "sub", "token_kind", "auth_mode", "ver", "iat", "exp", "jti"]


class TokenKind(StrEnum):
    SESSION = "session"
    REFRESH = "refresh"
    API = "api"
    INVITE = "invite"
    DOWNLOAD = "download"


class AuthMode(StrEnum):
    LOCAL_BOOT = "local-boot"
    PASSWORD = "password"
    OIDC = "oidc"
    DEMO = "demo"


class TokenError(Exception):
    """Invalid / expired / wrong-kind / wrong-key token — maps to 401."""


def _key_for(ring: KeyRing, kind: TokenKind) -> str:
    if kind is TokenKind.SESSION:
        return ring.session_key
    if kind is TokenKind.REFRESH:
        return ring.refresh_key
    raise TokenError(
        f"{kind.value} tokens are not signed by the kit core — pass an explicit key "
        "(product-specific kinds: api/invite/download)"
    )


def now_utc() -> datetime:
    return datetime.now(UTC)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_jti() -> str:
    return str(uuid.uuid4())


def mint_token(
    ring: KeyRing,
    config: AuthConfig,
    *,
    kind: TokenKind,
    sub: str,
    ver: int,
    auth_mode: AuthMode,
    family_id: str | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
    extra: dict[str, Any] | None = None,
    key: str | None = None,
    jti: str | None = None,
) -> str:
    """Mint a contract token (contract §8).

    Session tokens are signed with `SESSION_KEY`, refresh tokens with
    `REFRESH_KEY` — verifying either under the wrong key fails, which is
    exactly what the key-separation test asserts. `family_id` (`fid`)
    links both tokens of a sign-in to their `auth_sessions` row so
    rotation and logout can address it; products may add claims via
    `extra` (health: tenant_id/scope), never rename the standard ones.
    """
    base = now if now is not None else now_utc()
    if ttl_seconds is None:
        ttl_seconds = config.access_ttl_seconds if kind is TokenKind.SESSION else (
            config.refresh_ttl_seconds if kind is TokenKind.REFRESH else 3600
        )
    signing_key = key if key is not None else _key_for(ring, kind)
    payload: dict[str, Any] = {
        "iss": config.iss,
        "sub": str(sub),
        "token_kind": kind.value,
        "auth_mode": auth_mode.value,
        "ver": ver,
        "iat": base,
        "exp": base + timedelta(seconds=ttl_seconds),
        "jti": jti if jti is not None else new_jti(),
    }
    if family_id is not None:
        payload["fid"] = family_id
    if extra:
        for claim in ("iss", "sub", "token_kind", "auth_mode", "ver", "iat", "exp", "jti", "fid"):
            if claim in extra:
                raise TokenError(f"extra claims may not override {claim}")
        payload.update(extra)
    return jwt.encode(payload, signing_key, algorithm=ALGORITHM)


def verify_token(
    ring: KeyRing,
    config: AuthConfig,
    *,
    kind: TokenKind,
    token: str,
    key: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a token of exactly `kind` under its own key (never another)."""
    signing_key = key if key is not None else _key_for(ring, kind)
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[ALGORITHM],
            issuer=config.iss,
            options={"require": REQUIRED_CLAIMS},
            leeway=0,
        )
    except jwt.PyJWTError as error:
        raise TokenError(str(error)) from error
    if claims.get("token_kind") != kind.value:
        raise TokenError(f"expected {kind.value}, got {claims.get('token_kind')}")
    if now is not None:
        exp = datetime.fromtimestamp(float(claims["exp"]), UTC)
        if now >= exp:
            raise TokenError("token expired")
    return claims


def family_id_of(claims: dict[str, Any]) -> str:
    fid = claims.get("fid")
    if not isinstance(fid, str) or not fid:
        raise TokenError("missing fid claim")
    return fid
