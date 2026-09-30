from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from nx_auth.cookies import clear_session_cookies, cookie_names, new_csrf_token, set_session_cookies
from nx_auth.deps import get_current_user
from nx_auth.instance import can_accept_demo, can_accept_registration
from nx_auth.lockout import LockoutState, is_locked, register_failure
from nx_auth.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
    verify_password_or_dummy,
)
from nx_auth.principal import Principal
from nx_auth.protocols import AtomicRotateStore, EmailAlreadyExists, UserRecord
from nx_auth.ratelimit import client_ip
from nx_auth.session_flow import device_hint, issue_session
from nx_auth.tokens import (
    AuthMode,
    TokenError,
    TokenKind,
    family_id_of,
    mint_token,
    new_jti,
    now_utc,
    sha256_hex,
    verify_token,
)

if TYPE_CHECKING:
    from nx_auth.install import AuthKit

GENERIC_LOGIN_ERROR = "Invalid email or password"

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    full_name: str = Field(default="", max_length=200)


class LoginIn(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


def _kit(request: Request) -> AuthKit:
    kit: AuthKit = request.app.state.auth
    return kit


def _client_ip(request: Request, kit: AuthKit) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    host = request.client.host if request.client else None
    return client_ip(host, forwarded, kit.config.trusted_proxy_count)


def _limit(request: Request, kit: AuthKit, *, with_email: str | None = None) -> None:
    allowed, retry = kit.ip_limiter.allow(f"ip:{_client_ip(request, kit)}")
    if allowed and with_email is not None:
        allowed, retry = kit.email_limiter.allow(f"email:{with_email.lower()}")
    if not allowed:
        raise HTTPException(
            status_code=429, detail="Too many requests", headers={"Retry-After": str(retry)}
        )


def _respond(
    kit: AuthKit,
    user: UserRecord,
    *,
    status_code: int,
    tokens: tuple[str, str | None, str],
) -> JSONResponse:
    access, refresh, csrf = tokens
    response = JSONResponse(status_code=status_code, content=user.public)
    set_session_cookies(
        response, kit.config, access_token=access, refresh_token=refresh, csrf_token=csrf
    )
    return response


@router.post("/register")
def register(body: RegisterIn, request: Request) -> JSONResponse:
    kit = _kit(request)
    # §11.3: open desktop instances mount no self-signup — the guard
    # precedes rate limiting and the registration toggle so an `open`
    # instance answers identically to an absent route (404). Additional
    # users on personal devices come from the admin surface (§12).
    if not can_accept_registration(kit.state):
        raise HTTPException(status_code=404, detail="Not found")
    email = body.email.lower().strip()
    _limit(request, kit, with_email=email)
    if not kit.config.registration_enabled:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    try:
        check_policy(body.password, kit.config.password_min_length)
    except PasswordPolicyError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    try:
        user = kit.users.create(
            email=email,
            password_hash=hash_password(body.password),
            full_name=body.full_name.strip(),
        )
    except EmailAlreadyExists as error:
        raise HTTPException(status_code=409, detail="Email already registered") from error
    kit.ensure_profile(user.id)
    kit.record(actor=_client_ip(request, kit), action="auth.register", resource=user.id)
    return _respond(
        kit,
        user,
        status_code=201,
        tokens=issue_session(
            kit,
            user,
            auth_mode=AuthMode.PASSWORD,
            label="register",
            client_label=device_hint(request.headers.get("user-agent")),
        ),
    )


@router.post("/login")
def login(body: LoginIn, request: Request) -> JSONResponse:
    kit = _kit(request)
    # NOTE: /login stays mounted on `open` instances by design — password
    # holders created via the admin surface must authenticate for the
    # open→authenticated transition (§4); unknown creds get the generic
    # 401 either way.
    email = body.email.lower().strip()
    _limit(request, kit, with_email=email)
    user = kit.users.get_by_email(email)
    if user is None:
        verify_password_or_dummy(body.password, None)
        kit.record(
            actor=_client_ip(request, kit), action="auth.login", resource=email, outcome="denied"
        )
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    state = LockoutState(
        failed_login_attempts=user.failed_login_attempts,
        locked_until=user.locked_until,
        threshold=kit.config.lockout_threshold,
        lockout_minutes=kit.config.lockout_minutes,
    )
    if is_locked(state):
        raise HTTPException(status_code=423, detail="Account locked; try again later")
    if not verify_password_or_dummy(body.password, user.password_hash):
        failed = register_failure(state)
        kit.users.set_login_failures(user.id, failed.failed_login_attempts, failed.locked_until)
        kit.record(
            actor=_client_ip(request, kit), action="auth.login", resource=user.id, outcome="denied"
        )
        if is_locked(failed):
            raise HTTPException(status_code=423, detail="Account locked; try again later")
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    if not user.is_active:
        # Only revealed past the password check (§18.9: deactivated ⇒
        # 401 everywhere) — no enumeration, and a dead session is never
        # issued.
        kit.record(actor=user.id, action="auth.login", resource=user.id, outcome="denied")
        raise HTTPException(status_code=401, detail="Account deactivated")
    kit.users.reset_login_failures(user.id)
    kit.ensure_profile(user.id)
    kit.record(actor=user.id, action="auth.login", resource=user.id)
    return _respond(
        kit,
        user,
        status_code=200,
        tokens=issue_session(
            kit,
            user,
            auth_mode=AuthMode.PASSWORD,
            label="login",
            client_label=device_hint(request.headers.get("user-agent")),
        ),
    )


def _deny_refresh_reuse(kit: AuthKit, user: UserRecord, family_id: str) -> None:
    """Reuse of a rotated refresh token (or a lost concurrent-rotation
    race): revoke the whole family and bump token_version —
    family-wide sign-out, contract §8."""
    kit.sessions.revoke_all_for_user(user.id)
    kit.users.bump_token_version(user.id)
    kit.record(actor=user.id, action="auth.refresh", resource=family_id, outcome="reuse-denied")


@router.post("/refresh")
def refresh(request: Request) -> JSONResponse:
    kit = _kit(request)
    _limit(request, kit)
    names = cookie_names(kit.config)
    token = request.cookies.get(names.refresh)
    bearer = request.headers.get("authorization", "")
    if token is None and bearer[:7].lower() == "bearer ":
        token = bearer[7:].strip() or None
    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        claims = verify_token(kit.ring, kit.config, kind=TokenKind.REFRESH, token=token)
        family_id = family_id_of(claims)
        auth_mode = AuthMode(str(claims["auth_mode"]))
    except (TokenError, ValueError) as error:
        raise HTTPException(status_code=401, detail="Not authenticated") from error
    user = kit.users.get(str(claims["sub"]))
    if user is None or not user.is_active or user.token_version != int(claims["ver"]):
        raise HTTPException(status_code=401, detail="Not authenticated")
    family = kit.sessions.get(family_id)
    if family is None or family.user_id != user.id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if family.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    now = now_utc()
    if now >= family.absolute_expires_at or now >= family.expires_at:
        kit.sessions.revoke(family_id)
        raise HTTPException(status_code=401, detail="Not authenticated")
    expected_hash = sha256_hex(str(claims["jti"]))
    if expected_hash != family.refresh_jti_hash:
        _deny_refresh_reuse(kit, user, family_id)
        raise HTTPException(status_code=423, detail="Session revoked")
    new_refresh_jti = new_jti()
    refresh_token = mint_token(
        kit.ring,
        kit.config,
        kind=TokenKind.REFRESH,
        sub=user.id,
        ver=user.token_version,
        auth_mode=auth_mode,
        family_id=family_id,
        jti=new_refresh_jti,
    )
    new_expires_at = min(
        now + timedelta(seconds=kit.config.refresh_ttl_seconds), family.absolute_expires_at
    )
    sessions = kit.sessions
    if isinstance(sessions, AtomicRotateStore):
        rotated = sessions.rotate_if_current(
            family_id,
            expected_refresh_jti_hash=expected_hash,
            new_refresh_jti_hash=sha256_hex(new_refresh_jti),
            expires_at=new_expires_at,
        )
        if not rotated:
            # Lost the rotation race (or revoked concurrently): the
            # same answer as reuse detection — the family dies.
            _deny_refresh_reuse(kit, user, family_id)
            raise HTTPException(status_code=423, detail="Session revoked")
    else:
        sessions.rotate(family_id, sha256_hex(new_refresh_jti), new_expires_at)
    access_token = mint_token(
        kit.ring,
        kit.config,
        kind=TokenKind.SESSION,
        sub=user.id,
        ver=user.token_version,
        auth_mode=auth_mode,
        family_id=family_id,
    )
    response = JSONResponse(status_code=200, content=user.public)
    set_session_cookies(
        response,
        kit.config,
        access_token=access_token,
        refresh_token=refresh_token,
        csrf_token=new_csrf_token(),
    )
    kit.record(actor=user.id, action="auth.refresh", resource=family_id)
    return response


@router.post("/logout")
def logout(request: Request, principal: Principal = Depends(get_current_user)) -> JSONResponse:
    kit = _kit(request)
    if principal.family_id:
        kit.sessions.revoke(principal.family_id)
    kit.record(actor=principal.user_id, action="auth.logout", resource=principal.user_id)
    response = JSONResponse(status_code=200, content={"detail": "Signed out"})
    clear_session_cookies(response, kit.config)
    return response


@router.post("/logout-all")
def logout_all(request: Request, principal: Principal = Depends(get_current_user)) -> JSONResponse:
    kit = _kit(request)
    revoked = kit.sessions.revoke_all_for_user(principal.user_id)
    kit.users.bump_token_version(principal.user_id)
    kit.record(actor=principal.user_id, action="auth.logout_all", resource=principal.user_id)
    response = JSONResponse(
        status_code=200, content={"detail": "Signed out everywhere", "revoked": revoked}
    )
    clear_session_cookies(response, kit.config)
    return response


@router.get("/me")
def me(principal: Principal = Depends(get_current_user)) -> dict[str, object]:
    return {
        "id": principal.user_id,
        "email": principal.email,
        "full_name": principal.full_name,
        "is_admin": principal.is_admin,
        "is_active": principal.is_active,
    }


@router.post("/demo")
def demo_login(request: Request) -> JSONResponse:
    kit = _kit(request)
    if not can_accept_demo(kit.state):
        raise HTTPException(status_code=404, detail="Not found")
    user = kit.users.get(kit.config.demo_user_id)
    if user is None:
        try:
            user = kit.users.create(
                email=f"{kit.config.demo_user_id}@demo.local",
                password_hash=None,
                full_name="Demo",
                user_id=kit.config.demo_user_id,
                # §13: the demo principal never bootstraps admin — without
                # this, demo-login on a fresh instance would create user #1
                # and the first-user-admin rule would hand anonymous visitors
                # the admin surface (password resets = account takeover).
                is_admin=False,
            )
        except EmailAlreadyExists:
            existing = kit.users.get_by_email(f"{kit.config.demo_user_id}@demo.local")
            if existing is None:
                raise HTTPException(status_code=500, detail="demo user unavailable") from None
            user = existing
    if not user.is_active:
        # §18.9: deactivated ⇒ 401 everywhere — the demo bootstrap must
        # not mint a session the middleware rejects on every request.
        kit.record(actor="demo", action="auth.demo_login", resource=user.id, outcome="denied")
        raise HTTPException(status_code=401, detail="Account deactivated")
    kit.ensure_profile(user.id)
    kit.record(actor="demo", action="auth.demo_login", resource=user.id)
    return _respond(
        kit,
        user,
        status_code=200,
        tokens=issue_session(kit, user, auth_mode=AuthMode.DEMO, label="demo"),
    )
