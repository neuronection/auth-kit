from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class LockoutState:
    failed_login_attempts: int
    locked_until: datetime | None
    threshold: int
    lockout_minutes: int


def ensure_aware(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; normalize to aware UTC before comparing."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def is_locked(state: LockoutState, now: datetime | None = None) -> bool:
    current = now if now is not None else datetime.now(UTC)
    locked_until = ensure_aware(state.locked_until)
    return locked_until is not None and locked_until > current


def register_failure(state: LockoutState, now: datetime | None = None) -> LockoutState:
    """One failed login: count+1; crossing the threshold locks for the window."""
    current = now if now is not None else datetime.now(UTC)
    failed = state.failed_login_attempts + 1
    locked_until = ensure_aware(state.locked_until)
    if failed >= state.threshold:
        locked_until = current + timedelta(minutes=state.lockout_minutes)
    return LockoutState(
        failed_login_attempts=failed,
        locked_until=locked_until,
        threshold=state.threshold,
        lockout_minutes=state.lockout_minutes,
    )


def register_success(state: LockoutState) -> LockoutState:
    return LockoutState(
        failed_login_attempts=0,
        locked_until=None,
        threshold=state.threshold,
        lockout_minutes=state.lockout_minutes,
    )
