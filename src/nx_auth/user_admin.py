"""User management surface (contract §12): account self-service on
`/api/v1/me` and the admin user/instance API on `/api/v1/admin`.

Mounted by `install()` at the §12 paths — deliberately **not** under
`/api/v1/auth` (those paths are exact). Both routers require a session:
they are outside `auth_exempt_prefixes`, so `SessionAuthMiddleware`
rejects anonymous callers before routing and `get_current_user` /
`require_admin` pin the principal per handler.

Responses are `PublicUser`-style dicts — never password hashes, login
counters, or lockout stamps (§12). Error semantics follow §7: 404 hides
existence, 403 = authenticated but not allowed, password policy failures
are 422 (register-route style).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from nx_auth.cookies import clear_session_cookies, set_session_cookies
from nx_auth.deps import auth_rate_guard, get_current_user, require_admin
from nx_auth.instance import (
    InstanceMode,
    TransitionResult,
    effective_auth_mode,
    request_transition,
)
from nx_auth.lockout import LockoutState, is_locked, register_failure
from nx_auth.passwords import (
    PasswordPolicyError,
    check_policy,
    hash_password,
    verify_password_or_dummy,
)
from nx_auth.principal import Principal
from nx_auth.protocols import SessionRecord, UserRecord
from nx_auth.session_flow import device_hint, issue_session

if TYPE_CHECKING:
    from nx_auth.install import AuthKit

GENERIC_PASSWORD_ERROR = "Invalid password"

me_router = APIRouter(prefix="/api/v1/me", tags=["me"])
admin_router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class AccountDeleteIn(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class AdminUserUpdateIn(BaseModel):
    is_active: bool | None = None
    is_admin: bool | None = None


class AdminPasswordResetIn(BaseModel):
    new_password: str = Field(min_length=1, max_length=1024)


class InstanceUpdateIn(BaseModel):
    auth_mode: Literal["open", "authenticated"] | None = None
    password: str = Field(min_length=1, max_length=1024)


def _kit(request: Request) -> AuthKit:
    kit: AuthKit = request.app.state.auth
    return kit


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _session_entry(record: SessionRecord, current_family: str | None) -> dict[str, object]:
    return {
        "id": record.id,
        "client_label": record.client_label,
        "created_at": _iso(record.created_at),
        "expires_at": _iso(record.expires_at),
        "revoked_at": _iso(record.revoked_at),
        "current": record.id == current_family,
    }


def _admin_user(user: UserRecord, activity_count: int) -> dict[str, object]:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "created_at": _iso(user.created_at),
        "activity_count": activity_count,
    }


def _verify_password(kit: AuthKit, user: UserRecord, password: str) -> None:
    """Password re-verification with the §7 lockout on the same counter
    as login (S17): a hijacked session gets no unlimited guesses at these
    confirmation flows. Wrong answers are the same generic 403 (§10) until
    the threshold locks the account (423)."""
    state = LockoutState(
        failed_login_attempts=user.failed_login_attempts,
        locked_until=user.locked_until,
        threshold=kit.config.lockout_threshold,
        lockout_minutes=kit.config.lockout_minutes,
    )
    if is_locked(state):
        raise HTTPException(status_code=423, detail="Account locked; try again later")
    if not verify_password_or_dummy(password, user.password_hash):
        failed = register_failure(state)
        kit.users.set_login_failures(
            user.id, failed.failed_login_attempts, failed.locked_until
        )
        if is_locked(failed):
            raise HTTPException(status_code=423, detail="Account locked; try again later")
        raise HTTPException(status_code=403, detail=GENERIC_PASSWORD_ERROR)
    kit.users.reset_login_failures(user.id)


def _new_password(kit: AuthKit, password: str) -> str:
    try:
        check_policy(password, kit.config.password_min_length)
    except PasswordPolicyError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return hash_password(password)


# ---------------------------------------------------------------------------
# /api/v1/me — account self-service
# ---------------------------------------------------------------------------


@me_router.get("/sessions")
def list_my_sessions(
    request: Request, principal: Principal = Depends(get_current_user)
) -> list[dict[str, object]]:
    kit = _kit(request)
    return [
        _session_entry(record, principal.family_id)
        for record in kit.sessions.list_for_user(principal.user_id)
    ]


@me_router.delete("/sessions/{family_id}", status_code=204)
def revoke_my_session(
    family_id: str, request: Request, principal: Principal = Depends(get_current_user)
) -> Response:
    kit = _kit(request)
    row = kit.sessions.get(family_id)
    # 404 hides existence (§7): unknown and foreign families look alike.
    if row is None or row.user_id != principal.user_id:
        raise HTTPException(status_code=404, detail="Not found")
    kit.sessions.revoke(family_id)
    kit.record(actor=principal.user_id, action="auth.session_revoke", resource=family_id)
    response = Response(status_code=204)
    if family_id == principal.family_id:
        clear_session_cookies(response, kit.config)
    return response


@me_router.patch("/password")
def change_password(
    body: PasswordChangeIn, request: Request, principal: Principal = Depends(get_current_user)
) -> JSONResponse:
    kit = _kit(request)
    user = kit.users.get(principal.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth_rate_guard(request, kit, with_email=user.email)
    _verify_password(kit, user, body.current_password)
    new_hash = _new_password(kit, body.new_password)
    kit.users.set_password(user.id, new_hash)
    # Global sign-out of every other session (§8 `ver`), then issue a
    # fresh family for this caller — same code path as login's cookie
    # issuance — so the client stays signed in.
    kit.users.bump_token_version(user.id)
    updated = kit.users.get(user.id)
    if updated is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail="user unavailable")
    kit.record(actor=user.id, action="auth.password_change", resource=user.id)
    tokens = issue_session(
        kit,
        updated,
        auth_mode=principal.auth_mode,
        label="password-change",
        client_label=device_hint(request.headers.get("user-agent")),
    )
    response = JSONResponse(status_code=200, content=updated.public)
    set_session_cookies(
        response,
        kit.config,
        access_token=tokens[0],
        refresh_token=tokens[1],
        csrf_token=tokens[2],
    )
    return response


@me_router.delete("", status_code=204)
def delete_me(
    body: AccountDeleteIn, request: Request, principal: Principal = Depends(get_current_user)
) -> Response:
    kit = _kit(request)
    user = kit.users.get(principal.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth_rate_guard(request, kit, with_email=user.email)
    _verify_password(kit, user, body.password)
    kit.users.delete(user.id)
    kit.record(actor=principal.user_id, action="auth.account_delete", resource=principal.user_id)
    response = Response(status_code=204)
    clear_session_cookies(response, kit.config)
    return response


# ---------------------------------------------------------------------------
# /api/v1/admin — user management + instance mode (require_admin)
# ---------------------------------------------------------------------------


@admin_router.get("/users")
def list_users(
    request: Request, principal: Principal = Depends(require_admin)
) -> list[dict[str, object]]:
    kit = _kit(request)
    counts = kit.users.activity_counts()
    return [_admin_user(user, counts.get(user.id, 0)) for user in kit.users.list()]


@admin_router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    body: AdminUserUpdateIn,
    request: Request,
    principal: Principal = Depends(require_admin),
) -> dict[str, object]:
    kit = _kit(request)
    target = kit.users.get(user_id)
    # 404 hides existence (§7): unknown ids look like foreign ones.
    if target is None:
        raise HTTPException(status_code=404, detail="Not found")
    if user_id == principal.user_id and (body.is_admin is False or body.is_active is False):
        # §12 guard rails: no self-demotion, no self-deactivation.
        raise HTTPException(
            status_code=403, detail="Admins cannot demote or deactivate themselves"
        )
    loses_admin = (body.is_admin is False and target.is_admin) or (
        body.is_active is False and target.is_admin
    )
    if loses_admin and kit.users.count_admins() <= 1:
        # §12 guard rail: the instance never loses its last admin.
        raise HTTPException(status_code=403, detail="Cannot remove the last admin")
    changed = False
    if body.is_active is not None and body.is_active != target.is_active:
        kit.users.set_active(user_id, body.is_active)
        changed = True
    if body.is_admin is not None and body.is_admin != target.is_admin:
        kit.users.set_admin(user_id, body.is_admin)
        changed = True
    if changed:
        # Effective change ⇒ global sign-out of the target (§12 `ver`).
        kit.users.bump_token_version(user_id)
    kit.record(actor=principal.user_id, action="admin.user_update", resource=user_id)
    updated = kit.users.get(user_id)
    if updated is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Not found")
    return _admin_user(updated, kit.users.activity_counts().get(user_id, 0))


@admin_router.post("/users/{user_id}/reset-password", status_code=204)
def reset_user_password(
    user_id: str,
    body: AdminPasswordResetIn,
    request: Request,
    principal: Principal = Depends(require_admin),
) -> Response:
    kit = _kit(request)
    if kit.users.get(user_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    new_hash = _new_password(kit, body.new_password)
    kit.users.set_password(user_id, new_hash)
    kit.users.set_login_failures(user_id, 0, None)  # clear lockout (§7)
    kit.users.bump_token_version(user_id)
    kit.record(actor=principal.user_id, action="admin.password_reset", resource=user_id)
    return Response(status_code=204)


@admin_router.post("/users/{user_id}/force-logout", status_code=204)
def force_logout_user(
    user_id: str, request: Request, principal: Principal = Depends(require_admin)
) -> Response:
    kit = _kit(request)
    if kit.users.get(user_id) is None:
        raise HTTPException(status_code=404, detail="Not found")
    kit.users.bump_token_version(user_id)
    kit.record(actor=principal.user_id, action="admin.force_logout", resource=user_id)
    return Response(status_code=204)


@admin_router.patch("/instance")
def update_instance(
    body: InstanceUpdateIn, request: Request, principal: Principal = Depends(require_admin)
) -> JSONResponse:
    """`auth_mode` transitions per contract §4.5 (audited).

    `password` re-verifies the caller's current password (403 on
    mismatch, generic). Exception per §4.5: an `open → authenticated`
    transition performed by the password-less implicit owner *sets*
    credentials for that owner ("it becomes a normal admin user") —
    re-verification cannot apply to a row without a password, and
    requiring one first would make the §4.5 transition unreachable.
    `authenticated → open` additionally needs the explicit `auth_mode`
    in the body (the §4.5 "explicit confirmation"), is refused while
    other user rows exist, and revokes every session. Server entrypoints
    never run `open` (§4.4).
    """
    kit = _kit(request)
    state = kit.state
    current = effective_auth_mode(state)
    target = InstanceMode(body.auth_mode) if body.auth_mode is not None else None
    caller = kit.users.get(principal.user_id)
    if caller is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth_rate_guard(request, kit, with_email=caller.email)
    # `password` is verified first (§12 "admin + password"): every
    # wrong-credential answer is the same generic 403, whatever the mode
    # request.
    setting_owner_credentials = (
        target is InstanceMode.AUTHENTICATED
        and current is InstanceMode.OPEN
        and caller.password_hash is None
    )
    new_owner_hash: str | None = None
    if setting_owner_credentials:
        new_owner_hash = _new_password(kit, body.password)
    else:
        _verify_password(kit, caller, body.password)
    if target is InstanceMode.OPEN and kit.config.identity_mode == "server":
        raise HTTPException(status_code=403, detail="server instances never run open access")
    owner = kit.users.get_by_email(kit.owner_email) or caller
    owner_has_password = setting_owner_credentials or owner.password_hash is not None
    result = TransitionResult(mode=current)
    if target is not None:
        other_user_count = sum(1 for user in kit.users.list() if user.id != principal.user_id)
        result = request_transition(
            state,
            target,
            other_user_count=other_user_count,
            owner_has_password=owner_has_password,
            password_confirmed=True,
        )
        if result.error is not None or result.mode is None:
            raise HTTPException(status_code=403, detail=result.error or "not allowed")
    if setting_owner_credentials and new_owner_hash is not None:
        # §4.5: `open → authenticated` sets credentials for the implicit
        # owner (it becomes a normal admin user) — only now that the
        # transition is definitely happening.
        kit.users.set_password(owner.id, new_owner_hash)
        if not owner.is_admin:
            kit.users.set_admin(owner.id, True)
    opening = result.mode is InstanceMode.OPEN and state.auth_mode is not InstanceMode.OPEN
    if opening:
        # §4.5: `authenticated → open` revokes every session (§5
        # logout-all semantics: rows revoked + `ver` bumped).
        for user in kit.users.list():
            kit.sessions.revoke_all_for_user(user.id)
            kit.users.bump_token_version(user.id)
    if target is not None and result.mode is not None and result.mode is not state.auth_mode:
        kit.instance.set("auth_mode", result.mode.value)
    kit.record(
        actor=principal.user_id,
        action="admin.instance_transition",
        resource=result.mode.value if result.mode is not None else "",
    )
    fresh = kit.state
    response = JSONResponse(
        status_code=200,
        content={
            "auth_mode": effective_auth_mode(fresh).value,
            "demo_mode": fresh.demo_mode,
        },
    )
    if opening:
        clear_session_cookies(response, kit.config)
    return response
