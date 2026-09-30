from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

from nx_auth.audit import AuditEvent, AuditSink, NullAuditSink
from nx_auth.config import AuthConfig
from nx_auth.cookies import DEFAULT_CSRF_EXEMPT_PREFIXES, CsrfMiddleware, cookie_names
from nx_auth.instance import InstanceState, read_state
from nx_auth.keys import KeyRing
from nx_auth.protocols import EmailAlreadyExists, ProfileStore, UserRecord
from nx_auth.ratelimit import RateLimiter
from nx_auth.shell import ShellSecretMiddleware

if TYPE_CHECKING:
    from nx_auth.protocols import InstanceStore, SessionStore, UserStore


@dataclass
class AuthKit:
    """Everything the auth surface needs, registered on `app.state.auth`
    by `install()` — handlers and dependencies reach it per request."""

    config: AuthConfig
    ring: KeyRing
    users: UserStore
    sessions: SessionStore
    instance: InstanceStore
    profiles: ProfileStore | None = None
    audit: AuditSink = field(default_factory=NullAuditSink)
    shell_secret: str | None = None
    owner_email: str = "owner@local"
    ip_limiter: RateLimiter = field(default_factory=RateLimiter)
    email_limiter: RateLimiter = field(default_factory=RateLimiter)

    @property
    def state(self) -> InstanceState:
        return read_state(self.instance, self.config.identity_mode)

    def record(
        self, *, actor: str, action: str, resource: str = "", outcome: str = "ok"
    ) -> None:
        self.audit.record(
            AuditEvent(actor=actor, action=action, resource=resource, outcome=outcome)
        )

    def ensure_profile(self, user_id: str) -> None:
        if self.profiles is None:
            return
        if self.profiles.count_for(user_id) == 0:
            self.profiles.create(user_id=user_id, name="Default", is_default=True)

    def provision_owner(self) -> UserRecord:
        """DIM implicit owner (contract §11): password-less local
        admin + Default profile, idempotent, no wizard, no email."""
        existing = self.users.get_by_email(self.owner_email)
        if existing is not None:
            return existing
        try:
            created = self.users.create(
                email=self.owner_email, password_hash=None, is_admin=True
            )
        except EmailAlreadyExists:
            raced = self.users.get_by_email(self.owner_email)
            if raced is None:  # pragma: no cover - defensive
                raise
            return raced
        return created


def install(
    app: FastAPI,
    *,
    config: AuthConfig,
    ring: KeyRing,
    users: UserStore,
    sessions: SessionStore,
    instance: InstanceStore,
    profiles: ProfileStore | None = None,
    audit: AuditSink | None = None,
    shell_secret: str | None = None,
    shell_exempt_prefixes: tuple[str, ...] = (),
    owner_email: str = "owner@local",
) -> AuthKit:
    """Wire the family auth surface onto a FastAPI app.

    - mounts `/api/v1/auth/*` (contract §12 paths);
    - mounts `/api/v1/auth/desktop/exchange` **only** in
      `identity_mode=desktop` — the server entrypoint has no route;
    - mounts `/api/v1/me/*` (account self-service) and
      `/api/v1/admin/*` (user management, instance mode) at their exact
      §12 paths — both require a session;
    - adds the double-submit CSRF middleware (cookies);
    - adds the shell-secret middleware when `require_shell_secret`;
      `shell_exempt_prefixes` lists navigation-served content routes
      (PDF iframes, `<img>`) that skip the shell token but must stay
      session-authenticated and owner-scoped.
    """
    from nx_auth.dim import router as desktop_router
    from nx_auth.router import router as auth_router
    from nx_auth.user_admin import admin_router, me_router

    kit = AuthKit(
        config=config,
        ring=ring,
        users=users,
        sessions=sessions,
        instance=instance,
        profiles=profiles,
        audit=audit if audit is not None else NullAuditSink(),
        shell_secret=shell_secret,
        owner_email=owner_email,
        ip_limiter=RateLimiter(per_minute=config.auth_rate_per_minute),
        email_limiter=RateLimiter(per_minute=config.auth_email_rate_per_minute),
    )
    app.state.auth = kit
    app.include_router(auth_router)
    app.include_router(me_router)
    app.include_router(admin_router)
    if config.identity_mode == "desktop":
        app.include_router(desktop_router)
    app.add_middleware(
        CsrfMiddleware,
        cookie_name=cookie_names(config).csrf,
        exempt_prefixes=DEFAULT_CSRF_EXEMPT_PREFIXES,
    )
    from nx_auth.enforcement import SessionAuthMiddleware

    app.add_middleware(
        SessionAuthMiddleware, kit=kit, exempt_prefixes=config.auth_exempt_prefixes
    )
    if config.require_shell_secret:
        if not shell_secret:
            raise ValueError(
                "require_shell_secret=True needs a per-boot secret "
                "(nx_auth.shell.generate_shell_secret())"
            )
        app.add_middleware(
            ShellSecretMiddleware,
            secret=shell_secret,
            exempt_prefixes=shell_exempt_prefixes,
        )
    return kit


def audit_rows(engine: Any) -> list[dict[str, str]]:
    """Test/ops helper: read the `audit_events` table back as dicts."""
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from nx_auth.sqlalchemy_stores import AuditEventRow

    factory = sessionmaker(engine)
    with factory() as session:
        rows = session.scalars(select(AuditEventRow)).all()
        return [
            {
                "actor": row.actor,
                "action": row.action,
                "resource": row.resource,
                "outcome": row.outcome,
            }
            for row in rows
        ]
