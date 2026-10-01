from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Request

from nx_auth.cookies import cookie_names
from nx_auth.instance import can_accept_demo, can_accept_local_boot, read_state
from nx_auth.principal import Principal
from nx_auth.tokens import AuthMode, TokenError, TokenKind, verify_token

if TYPE_CHECKING:
    from nx_auth.install import AuthKit
    from nx_auth.protocols import UserRecord


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer " and header[7:].strip():
        return header[7:].strip()
    return None


def _unauthorized(detail: str, *, bearer: bool) -> HTTPException:
    headers = {"WWW-Authenticate": "Bearer"} if bearer else None
    return HTTPException(status_code=401, detail=detail, headers=headers)


def authenticate_session(kit: AuthKit, token: str) -> Principal | None:
    """Verify an access token against live instance state and the live
    user row. Returns `None` on *any* failure — callers decide how to
    report (HTTP middleware/deps map it to 401; WebSocket closes).

    This is the single verification path: HTTP middleware, `deps`, and
    the WS handshake must never implement their own rules.
    """
    try:
        claims = verify_token(kit.ring, kit.config, kind=TokenKind.SESSION, token=token)
    except TokenError:
        return None
    state = read_state(kit.instance, kit.config.identity_mode)
    try:
        auth_mode = AuthMode(str(claims.get("auth_mode", "")))
    except ValueError:
        return None
    if auth_mode is AuthMode.LOCAL_BOOT and not can_accept_local_boot(state):
        return None
    if auth_mode is AuthMode.DEMO and not can_accept_demo(state):
        return None
    user: UserRecord | None = kit.users.get(str(claims["sub"]))
    if user is None or not user.is_active or user.token_version != int(claims["ver"]):
        return None
    fid = claims.get("fid")
    return Principal(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_admin=user.is_admin,
        is_active=user.is_active,
        ver=user.token_version,
        auth_mode=auth_mode,
        family_id=str(fid) if isinstance(fid, str) and fid else None,
    )


def _resolve(request: Request, *, strict: bool) -> Principal | None:
    kit: AuthKit = request.app.state.auth
    # Enforced API requests arrive with the principal already verified by
    # SessionAuthMiddleware (scope state) — reuse it, never re-verify.
    cached = getattr(request.state, "nx_principal", None)
    if isinstance(cached, Principal):
        return cached
    # Cookie first, Bearer §9 fallback (the flag selects the 401 flavor).
    token = request.cookies.get(cookie_names(kit.config).access)
    bearer_used = False
    if token is None:
        token = _bearer_token(request)
        bearer_used = token is not None

    principal = authenticate_session(kit, token) if token is not None else None
    if principal is not None:
        return principal
    if strict:
        detail = "Invalid or expired session" if token is not None else "Not authenticated"
        raise _unauthorized(detail, bearer=bearer_used)
    return None


def get_optional_principal(request: Request) -> Principal | None:
    """For endpoints that behave differently signed-in vs anonymous —
    never raises on missing/invalid credentials (they become anonymous)."""
    return _resolve(request, strict=False)


def get_current_user(request: Request) -> Principal:
    """The family session dependency: cookie or Bearer session token,
    verified against live instance state and the live user row
    (401 unauthenticated/invalid, 403 for authorization)."""
    principal = _resolve(request, strict=True)
    if principal is None:  # pragma: no cover - strict path always raises
        raise _unauthorized("Not authenticated", bearer=False)
    return principal


def require_admin(principal: Principal = Depends(get_current_user)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return principal


def client_ip_from_request(request: Request, kit: AuthKit) -> str:
    """Client identity for limits/audit: rightmost-N trusted proxy hops (§7)."""
    from nx_auth.ratelimit import client_ip

    forwarded = request.headers.get("x-forwarded-for")
    host = request.client.host if request.client else None
    return client_ip(host, forwarded, kit.config.trusted_proxy_count)


def auth_rate_guard(
    request: Request, kit: AuthKit, *, with_email: str | None = None
) -> None:
    """Per-IP + per-email auth-flow rate limits (§7/§16) — 429 + Retry-After.

    Covers every endpoint where a caller can guess secrets: the `/auth`
    flows **and** the password-confirming account/instance actions (S17) —
    a hijacked session must not get unlimited guesses anywhere.
    """
    allowed, retry = kit.ip_limiter.allow(f"ip:{client_ip_from_request(request, kit)}")
    if allowed and with_email is not None:
        allowed, retry = kit.email_limiter.allow(f"email:{with_email.lower()}")
    if not allowed:
        raise HTTPException(
            status_code=429, detail="Too many requests", headers={"Retry-After": str(retry)}
        )
