from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


class EmailAlreadyExists(Exception):
    """Register hit an existing email — maps to 409 (generic enough: the
    caller already proved control of the address by attempting to use
    it; enumeration by *absence* stays impossible via dummy-hash login)."""


@dataclass(frozen=True)
class UserRecord:
    id: str
    email: str
    password_hash: str | None
    full_name: str
    is_active: bool
    is_admin: bool
    failed_login_attempts: int
    locked_until: datetime | None
    token_version: int
    created_at: datetime | None = None

    @property
    def public(self) -> dict[str, object]:
        """`PublicUser` (contract §12) — never hashes/counters/stamps."""
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
        }


@dataclass(frozen=True)
class SessionRecord:
    id: str
    user_id: str
    refresh_jti_hash: str
    expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None
    client_label: str
    created_at: datetime | None = None


@runtime_checkable
class UserStore(Protocol):
    def get(self, user_id: str) -> UserRecord | None: ...

    def get_by_email(self, email: str) -> UserRecord | None: ...

    def count(self) -> int: ...

    def create(
        self,
        *,
        email: str,
        password_hash: str | None,
        full_name: str = "",
        is_admin: bool | None = None,
        user_id: str | None = None,
    ) -> UserRecord: ...
    # is_admin semantics: None = unspecified (§12 first-user-admin
    # bootstrap applies), False = explicitly never admin (demo principal),
    # True = force admin (DIM owner).

    def set_login_failures(
        self, user_id: str, failed: int, locked_until: datetime | None
    ) -> None: ...

    def reset_login_failures(self, user_id: str) -> None: ...

    def bump_token_version(self, user_id: str) -> int: ...

    def set_password(self, user_id: str, password_hash: str) -> None: ...

    def list(self) -> list[UserRecord]:
        """Every user row, oldest first (admin listing, §12)."""
        ...

    def set_active(self, user_id: str, is_active: bool) -> None: ...

    def set_admin(self, user_id: str, is_admin: bool) -> None: ...

    def count_admins(self) -> int: ...

    def delete(self, user_id: str) -> None:
        """Remove the user and everything hanging off it (§12: cascade
        delete — sessions and profiles go with the row)."""
        ...

    def activity_counts(self) -> dict[str, int]:
        """Product-defined activity per user (user_id → count) for the
        admin listing; the reference store may return {}."""
        ...


@runtime_checkable
class SessionStore(Protocol):
    def create(
        self,
        *,
        user_id: str,
        refresh_jti_hash: str,
        expires_at: datetime,
        absolute_expires_at: datetime,
        client_label: str = "",
    ) -> str: ...

    def get(self, family_id: str) -> SessionRecord | None: ...

    def rotate(self, family_id: str, refresh_jti_hash: str, expires_at: datetime) -> None: ...

    def revoke(self, family_id: str) -> None: ...

    def revoke_all_for_user(self, user_id: str) -> int: ...

    def list_for_user(self, user_id: str) -> list[SessionRecord]:
        """Every family row of one user (revoked included), newest
        first — the device list (§12 `GET /api/v1/me/sessions`)."""
        ...


@runtime_checkable
class AtomicRotateStore(Protocol):
    def rotate_if_current(
        self,
        family_id: str,
        *,
        expected_refresh_jti_hash: str,
        new_refresh_jti_hash: str,
        expires_at: datetime,
    ) -> bool:
        """Atomically rotate the family's refresh token hash only if the
        stored hash still equals `expected_refresh_jti_hash` and the
        family is not revoked (compare-and-swap) — two concurrent
        refreshes with the same token cannot both win the rotation.
        Returns whether the rotation happened; `False` means the stored
        hash was superseded (race lost) or the family is (now) revoked,
        and the caller must treat it exactly like token reuse."""
        ...


@runtime_checkable
class ProfileStore(Protocol):
    def create(
        self,
        *,
        user_id: str,
        name: str,
        is_default: bool,
        preferences: dict[str, object] | None = None,
    ) -> str: ...

    def count_for(self, user_id: str) -> int: ...


@runtime_checkable
class InstanceStore(Protocol):
    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...
