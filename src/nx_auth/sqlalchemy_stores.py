import threading
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from nx_auth.audit import AuditEvent, AuditSink
from nx_auth.lockout import ensure_aware
from nx_auth.protocols import EmailAlreadyExists, SessionRecord, UserRecord

JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")
# Native uuid on PostgreSQL, CHAR(32) hex elsewhere (contract §5:
# "TEXT on SQLite, native uuid on Postgres — both share semantics").
_UUID = Uuid(as_uuid=False)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    full_name: Mapped[str] = mapped_column(String(200), default="", server_default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    oidc_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AuthSessionRow(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        _UUID, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    refresh_jti_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    client_label: Mapped[str] = mapped_column(String(200), default="", server_default="")
    # Product-added column (§5 allows additions): the device list (§12)
    # shows when each family was created.
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ProfileRow(Base):
    __tablename__ = "profiles"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        _UUID, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    preferences: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE, default=dict, server_default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class InstanceSettingRow(Base):
    __tablename__ = "instance_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource: Mapped[str] = mapped_column(String(500), default="", server_default="")
    tenant_id: Mapped[str | None] = mapped_column(_UUID, nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


def create_all(engine: Any) -> None:
    """Convenience DDL for tests and quickstarts — production consumers
    ship an Alembic revision of these tables instead."""
    Base.metadata.create_all(engine)


def _user_record(row: UserRow) -> UserRecord:
    return UserRecord(
        id=str(row.id),
        email=str(row.email),
        password_hash=row.password_hash,
        full_name=row.full_name,
        is_active=row.is_active,
        is_admin=row.is_admin,
        failed_login_attempts=row.failed_login_attempts,
        locked_until=ensure_aware(row.locked_until),
        token_version=row.token_version,
        created_at=ensure_aware(row.created_at),
    )


def _session_record(row: AuthSessionRow) -> SessionRecord:
    return SessionRecord(
        id=str(row.id),
        user_id=row.user_id,
        refresh_jti_hash=row.refresh_jti_hash,
        expires_at=ensure_aware(row.expires_at) or datetime.min.replace(tzinfo=UTC),
        absolute_expires_at=ensure_aware(row.absolute_expires_at)
        or datetime.min.replace(tzinfo=UTC),
        revoked_at=ensure_aware(row.revoked_at),
        client_label=row.client_label,
        created_at=ensure_aware(row.created_at),
    )


class SqlUserStore:
    """Reference `UserStore` over a **synchronous** SQLAlchemy session
    factory (contract §3 schema). FastAPI runs the kit's sync
    handlers in the threadpool; async consumers hand in their own
    adapter implementing the same protocol."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory
        self._create_lock = threading.Lock()

    def get(self, user_id: str) -> UserRecord | None:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            return _user_record(row) if row is not None else None

    def get_by_email(self, email: str) -> UserRecord | None:
        with self._factory() as session:
            row = session.scalar(select(UserRow).where(UserRow.email == email.lower()))
            return _user_record(row) if row is not None else None

    def count(self) -> int:
        with self._factory() as session:
            return int(session.scalar(select(func.count()).select_from(UserRow)) or 0)

    def create(
        self,
        *,
        email: str,
        password_hash: str | None,
        full_name: str = "",
        is_admin: bool | None = None,
        user_id: str | None = None,
    ) -> UserRecord:
        normalized = email.lower().strip()
        # First-user-admin race guard (health's bootstrap pattern, in-process
        # edition): serialize creation so two concurrent registers cannot both
        # observe zero users. Multi-process consumers add a DB advisory lock.
        with self._create_lock, self._factory() as session:
            exists = session.scalar(
                select(UserRow.id).where(UserRow.email == normalized)
            )
            if exists is not None:
                raise EmailAlreadyExists(normalized)
            first = session.scalar(select(func.count()).select_from(UserRow)) or 0
            # is_admin: None lets §12's first-user-admin bootstrap apply;
            # an explicit False (demo principal, §13) is honored even when
            # this would be user #1 — the demo identity must never bootstrap
            # admin privileges.
            effective_admin = int(first) == 0 if is_admin is None else is_admin
            row = UserRow(
                id=user_id or str(uuid.uuid4()),
                email=normalized,
                password_hash=password_hash,
                full_name=full_name,
                is_admin=effective_admin,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _user_record(row)

    def set_login_failures(
        self, user_id: str, failed: int, locked_until: datetime | None
    ) -> None:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            if row is not None:
                row.failed_login_attempts = failed
                row.locked_until = locked_until
                session.commit()

    def reset_login_failures(self, user_id: str) -> None:
        self.set_login_failures(user_id, 0, None)

    def bump_token_version(self, user_id: str) -> int:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            if row is None:
                return 0
            updated = row.token_version + 1
            row.token_version = updated
            session.commit()
            return updated

    def set_password(self, user_id: str, password_hash: str) -> None:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            if row is not None:
                row.password_hash = password_hash
                session.commit()

    def list(self) -> list[UserRecord]:
        with self._factory() as session:
            rows = session.scalars(
                select(UserRow).order_by(UserRow.created_at.asc(), UserRow.id.asc())
            ).all()
            return [_user_record(row) for row in rows]

    def set_active(self, user_id: str, is_active: bool) -> None:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            if row is not None:
                row.is_active = is_active
                session.commit()

    def set_admin(self, user_id: str, is_admin: bool) -> None:
        with self._factory() as session:
            row = session.get(UserRow, user_id)
            if row is not None:
                row.is_admin = is_admin
                session.commit()

    def count_admins(self) -> int:
        with self._factory() as session:
            return int(
                session.scalar(
                    select(func.count()).select_from(UserRow).where(UserRow.is_admin.is_(True))
                )
                or 0
            )

    def delete(self, user_id: str) -> None:
        # Explicit cascade in the same transaction (contract §12:
        # "cascade delete (DB-level ON DELETE)" — this reference store
        # does not rely on the SQLite foreign_keys pragma being on).
        with self._factory() as session:
            for model in (AuthSessionRow, ProfileRow):
                session.execute(delete(model).where(model.user_id == user_id))
            session.execute(delete(UserRow).where(UserRow.id == user_id))
            session.commit()

    def activity_counts(self) -> dict[str, int]:
        """Reference stores carry no product content — products
        override with their own count (contract §12)."""
        return {}


class SqlSessionStore:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create(
        self,
        *,
        user_id: str,
        refresh_jti_hash: str,
        expires_at: datetime,
        absolute_expires_at: datetime,
        client_label: str = "",
    ) -> str:
        row = AuthSessionRow(
            id=str(uuid.uuid4()),
            user_id=user_id,
            refresh_jti_hash=refresh_jti_hash,
            expires_at=expires_at,
            absolute_expires_at=absolute_expires_at,
            client_label=client_label,
        )
        with self._factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def get(self, family_id: str) -> SessionRecord | None:
        with self._factory() as session:
            row = session.get(AuthSessionRow, family_id)
            return _session_record(row) if row is not None else None

    def rotate(self, family_id: str, refresh_jti_hash: str, expires_at: datetime) -> None:
        with self._factory() as session:
            row = session.get(AuthSessionRow, family_id)
            if row is not None and row.revoked_at is None:
                row.refresh_jti_hash = refresh_jti_hash
                row.expires_at = expires_at
                session.commit()

    def rotate_if_current(
        self,
        family_id: str,
        *,
        expected_refresh_jti_hash: str,
        new_refresh_jti_hash: str,
        expires_at: datetime,
    ) -> bool:
        """Compare-and-swap rotation (`AtomicRotateStore`): a single
        conditional UPDATE that fires only when the stored hash equals
        `expected_refresh_jti_hash` and the family is not revoked, so
        concurrent refreshes with the same token cannot both win."""
        with self._factory() as session:
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(AuthSessionRow)
                    .where(
                        AuthSessionRow.id == family_id,
                        AuthSessionRow.revoked_at.is_(None),
                        AuthSessionRow.refresh_jti_hash == expected_refresh_jti_hash,
                    )
                    .values(refresh_jti_hash=new_refresh_jti_hash, expires_at=expires_at)
                ),
            )
            session.commit()
            return result.rowcount == 1

    def revoke(self, family_id: str) -> None:
        with self._factory() as session:
            row = session.get(AuthSessionRow, family_id)
            if row is not None and row.revoked_at is None:
                row.revoked_at = datetime.now(UTC)
                session.commit()

    def revoke_all_for_user(self, user_id: str) -> int:
        with self._factory() as session:
            rows = session.scalars(
                select(AuthSessionRow).where(
                    AuthSessionRow.user_id == user_id, AuthSessionRow.revoked_at.is_(None)
                )
            ).all()
            for row in rows:
                row.revoked_at = datetime.now(UTC)
            session.commit()
            return len(rows)

    def list_for_user(self, user_id: str) -> list[SessionRecord]:
        with self._factory() as session:
            rows = session.scalars(
                select(AuthSessionRow)
                .where(AuthSessionRow.user_id == user_id)
                .order_by(AuthSessionRow.created_at.desc(), AuthSessionRow.id.desc())
            ).all()
            return [_session_record(row) for row in rows]


class SqlProfileStore:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create(
        self,
        *,
        user_id: str,
        name: str,
        is_default: bool,
        preferences: dict[str, object] | None = None,
    ) -> str:
        row = ProfileRow(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=name,
            is_default=is_default,
            preferences=dict(preferences or {}),
        )
        with self._factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def count_for(self, user_id: str) -> int:
        with self._factory() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(ProfileRow)
                    .where(ProfileRow.user_id == user_id)
                )
                or 0
            )


class SqlInstanceStore:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def get(self, key: str) -> str | None:
        with self._factory() as session:
            row = session.get(InstanceSettingRow, key)
            return row.value if row is not None else None

    def set(self, key: str, value: str) -> None:
        with self._factory() as session:
            row = session.get(InstanceSettingRow, key)
            if row is None:
                session.add(InstanceSettingRow(key=key, value=value))
            else:
                row.value = value
                row.updated_at = datetime.now(UTC)
            session.commit()


class SqlAuditSink(AuditSink):
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def record(self, event: AuditEvent) -> None:
        row = AuditEventRow(
            actor=str(event.actor),
            action=event.action,
            resource=event.resource,
            tenant_id=event.tenant_id,
            outcome=event.outcome,
            created_at=event.timestamp(),
        )
        with self._factory() as session:
            session.add(row)
            session.commit()
