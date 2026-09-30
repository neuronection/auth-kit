"""`SqlSessionStore` semantics beyond the endpoint flows: the
compare-and-swap rotation capability (`AtomicRotateStore`,
identity-auth §8) that closes the concurrent-refresh race — the router
refresh path uses it whenever the store implements it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from nx_auth.sqlalchemy_stores import SqlSessionStore, create_all


def _store() -> SqlSessionStore:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    create_all(engine)
    return SqlSessionStore(sessionmaker(engine))


def _new_family(store: SqlSessionStore) -> str:
    now = datetime.now(UTC)
    return store.create(
        user_id=str(uuid4()),
        refresh_jti_hash="expected-hash",
        expires_at=now + timedelta(minutes=5),
        absolute_expires_at=now + timedelta(days=7),
    )


def test_rotate_if_current_rotates_when_hash_matches() -> None:
    store = _store()
    family = _new_family(store)
    later = datetime.now(UTC) + timedelta(minutes=10)
    assert store.rotate_if_current(
        family,
        expected_refresh_jti_hash="expected-hash",
        new_refresh_jti_hash="rotated-hash",
        expires_at=later,
    )
    row = store.get(family)
    assert row is not None
    assert row.refresh_jti_hash == "rotated-hash"
    assert row.expires_at == later
    assert row.revoked_at is None


def test_rotate_if_current_stale_hash_loses_and_leaves_row_unchanged() -> None:
    store = _store()
    family = _new_family(store)
    original = store.get(family)
    assert original is not None
    assert not store.rotate_if_current(
        family,
        expected_refresh_jti_hash="superseded-hash",
        new_refresh_jti_hash="raced-hash",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    row = store.get(family)
    assert row is not None
    assert row.refresh_jti_hash == original.refresh_jti_hash
    assert row.expires_at == original.expires_at


def test_rotate_if_current_refuses_revoked_family() -> None:
    store = _store()
    family = _new_family(store)
    store.revoke(family)
    assert not store.rotate_if_current(
        family,
        expected_refresh_jti_hash="expected-hash",
        new_refresh_jti_hash="rotated-hash",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    row = store.get(family)
    assert row is not None
    assert row.revoked_at is not None
    assert row.refresh_jti_hash == "expected-hash"


def test_rotate_if_current_unknown_family_returns_false() -> None:
    store = _store()
    assert not store.rotate_if_current(
        str(uuid4()),
        expected_refresh_jti_hash="expected-hash",
        new_refresh_jti_hash="rotated-hash",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
