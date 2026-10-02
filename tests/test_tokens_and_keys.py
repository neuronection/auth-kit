import logging
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nx_auth.config import AuthConfig
from nx_auth.keys import KeyRing
from nx_auth.testing import forge_token, make_test_keyring
from nx_auth.tokens import AuthMode, TokenError, TokenKind, mint_token, verify_token

pytestmark = pytest.mark.contract  # identity-auth §18 contract cases
CONFIG = AuthConfig(iss="testkit")


def _mint(kind: TokenKind, **kwargs: object) -> str:
    return mint_token(
        make_test_keyring(),
        CONFIG,
        kind=kind,
        sub="user-1",
        ver=1,
        auth_mode=AuthMode.PASSWORD,
        **kwargs,  # type: ignore[arg-type]
    )


def test_key_separation_refresh_never_verifies_as_session() -> None:
    ring = make_test_keyring()
    refresh = _mint(TokenKind.REFRESH, family_id="fam-1")
    with pytest.raises(TokenError):
        verify_token(ring, CONFIG, kind=TokenKind.SESSION, token=refresh)
    with pytest.raises(TokenError):
        verify_token(ring, CONFIG, kind=TokenKind.SESSION, token=refresh, key=ring.session_key)


def test_kind_mismatch_same_key_rejected() -> None:
    ring = make_test_keyring()
    session = _mint(TokenKind.SESSION, family_id="fam-1")
    with pytest.raises(TokenError, match="expected refresh"):
        verify_token(ring, CONFIG, kind=TokenKind.REFRESH, token=session, key=ring.session_key)


def test_forged_wrong_secret_rejected() -> None:
    ring = make_test_keyring()
    forged = forge_token(
        "attacker-key-0123456789abcdefghijklmnopqrst",
        {
            "iss": "testkit",
            "sub": "user-1",
            "token_kind": "session",
            "auth_mode": "password",
            "ver": 1,
            "iat": 0,
            "exp": 4102444800,
            "jti": "forged",
        },
    )
    with pytest.raises(TokenError):
        verify_token(ring, CONFIG, kind=TokenKind.SESSION, token=forged)


def test_expired_access_rejected() -> None:
    past = datetime.now(UTC) - timedelta(hours=2)
    expired = _mint(TokenKind.SESSION, now=past)
    with pytest.raises(TokenError):
        verify_token(make_test_keyring(), CONFIG, kind=TokenKind.SESSION, token=expired)


def test_extra_claims_cannot_override_contract_claims() -> None:
    with pytest.raises(TokenError):
        _mint(TokenKind.SESSION, extra={"sub": "someone-else", "tenant_id": "t1"})


def test_product_kinds_not_signed_by_core() -> None:
    with pytest.raises(TokenError, match="not signed by the kit core"):
        _mint(TokenKind.API)


def test_config_enforces_24h_access_cap_and_refresh_ordering() -> None:
    with pytest.raises(ValueError):
        AuthConfig(iss="x", access_ttl_minutes=24 * 60 + 1)
    with pytest.raises(ValueError):
        AuthConfig(iss="x", refresh_ttl_days=31, refresh_absolute_days=30)
    with pytest.raises(ValueError):
        AuthConfig(iss="")


def test_keyring_requires_three_distinct_keys() -> None:
    with pytest.raises(ValueError):
        KeyRing(session_key="a", refresh_key="a", data_key="b")
    with pytest.raises(ValueError):
        KeyRing(session_key="", refresh_key="b", data_key="c")


def test_keyring_rejects_whitespace_padded_duplicate_keys() -> None:
    """F10: distinctness compares trimmed values — a padded copy of one
    key is not a second key."""
    session = "session-key-0123456789abcdefghijklmnopqrstuv"
    with pytest.raises(ValueError, match="distinct"):
        KeyRing(session_key=session, refresh_key=f"  {session}\t", data_key="y" * 32)


def test_keyring_accepts_padded_but_distinct_keys() -> None:
    """Positive counterpart: padding alone never rejects genuinely
    distinct keys."""
    ring = KeyRing(
        session_key="  session-key-0123456789abcdefghijklmnopqrstuv",
        refresh_key="refresh-key-0123456789abcdefghijklmnopqrstuv",
        data_key="y" * 32,
    )
    assert ring.session_key.startswith("  ")


def test_keyring_refuses_weak_secrets() -> None:
    """§8 weak-secret boot guard: every construction path (env, file,
    direct) funnels through KeyRing.__post_init__, so weak material can
    never enter a ring — 'dev'-style operator keys are forgeable tokens
    waiting to happen."""
    strong = "x" * 48
    # too short (< 32 chars) — the common operator footguns
    for weak in ("dev", "changeme", "secret-key", "a" * 31):
        with pytest.raises(ValueError, match="too weak"):
            KeyRing(session_key=weak, refresh_key=strong, data_key=strong + "d")
    # known placeholder literals, cased/whitespace-padded (exact-match
    # after normalization — belt to the length floor's suspenders)
    for weak in ("  PLACEHOLDER  ", "\tInsecure\n", "TODO"):
        with pytest.raises(ValueError, match="too weak"):
            KeyRing(session_key=strong, refresh_key=weak, data_key=strong + "d")
    # the guard covers the data key too (empty → weak → distinct order)
    with pytest.raises(ValueError, match="too weak"):
        KeyRing(session_key=strong, refresh_key=strong + "r", data_key="todo")
    # 32+ non-placeholder chars and generated rings (43 chars of entropy) pass
    KeyRing(session_key=strong, refresh_key=strong + "r", data_key="y" * 32)
    KeyRing.generate()


def test_keyring_env_roundtrip_and_partial_env_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("KIT_SESSION_KEY", raising=False)
    monkeypatch.delenv("KIT_REFRESH_KEY", raising=False)
    monkeypatch.delenv("KIT_DATA_KEY", raising=False)
    assert KeyRing.from_env("KIT") is None
    generated = KeyRing.load_or_generate(tmp_path / "secret.key", "KIT")
    again = KeyRing.load_or_generate(tmp_path / "secret.key", "KIT")
    assert generated == again
    mode = stat.S_IMODE(os.stat(tmp_path / "secret.key").st_mode)
    assert mode == 0o600
    monkeypatch.setenv("KIT_SESSION_KEY", "only-one")
    with pytest.raises(ValueError, match="partial key env"):
        KeyRing.from_env("KIT")


def test_all_three_env_keys_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KIT_SESSION_KEY", "s-env-value-0123456789abcdefghijklmnopq")
    monkeypatch.setenv("KIT_REFRESH_KEY", "r-env-value-0123456789abcdefghijklmnopq")
    monkeypatch.setenv("KIT_DATA_KEY", "d-env-value-0123456789abcdefghijklmnopq")
    ring = KeyRing.from_env("KIT")
    assert ring is not None
    assert ring.session_key.endswith("q")


def test_load_for_config_dir_resolution(tmp_path: Path) -> None:
    """ADR-0028 §5: env pins > 0600 auth_keys.json in the config dir > generate."""
    ring = KeyRing.load_for("SA", tmp_path)
    persisted = tmp_path / "auth_keys.json"
    assert persisted.is_file()
    assert stat.S_IMODE(persisted.stat().st_mode) == 0o600
    assert KeyRing.load_for("SA", tmp_path) == ring


def test_load_for_settings_backed_pins(tmp_path: Path) -> None:
    """Explicit pins (Settings merged .env + OS env) win over the file."""
    pinned = (
        "s-pin-0123456789abcdefghijklmnopqrstuv",
        "r-pin-0123456789abcdefghijklmnopqrstuv",
        "d-pin-0123456789abcdefghijklmnopqrstuv",
    )
    ring = KeyRing.load_for("SA", tmp_path, pinned=pinned)
    assert ring.session_key == pinned[0]
    assert not (tmp_path / "auth_keys.json").exists()
    # all-None falls through to file/generate
    fallback = KeyRing.load_for("SA", tmp_path, pinned=(None, None, None))
    assert fallback != ring
    assert (tmp_path / "auth_keys.json").exists()


def test_load_for_partial_pins_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="partial key pin"):
        KeyRing.load_for(
            "SA",
            tmp_path,
            pinned=("only-session-0123456789abcdefghijklmnopq", None, None),
        )


# --- F11: auth_keys.json permissions (0600 from the first byte) -------


def test_save_to_file_is_0600_and_leaves_no_temp_litter(tmp_path: Path) -> None:
    """F11: the file is created 0600 via os.open and renamed into place
    — never created world-readable and chmodded afterwards."""
    ring = make_test_keyring()
    target = tmp_path / "auth_keys.json"
    ring.save_to_file(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert KeyRing.from_file(target) == ring
    assert [entry.name for entry in tmp_path.iterdir()] == ["auth_keys.json"]


def test_save_to_file_tightens_a_loose_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "auth_keys.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o644)
    make_test_keyring().save_to_file(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_from_file_warns_and_repairs_loose_permissions(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """F11: a 0644 auth_keys.json still loads (the repair is hygiene,
    not a refusal) but is warned about and repaired to 0600 in place."""
    ring = make_test_keyring()
    target = tmp_path / "auth_keys.json"
    ring.save_to_file(target)
    os.chmod(target, 0o644)
    with caplog.at_level(logging.WARNING):
        loaded = KeyRing.from_file(target)
    assert loaded == ring
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert any(
        str(target) in record.message and "0600" in record.message
        for record in caplog.records
    )


def test_from_file_leaves_a_0600_file_untouched(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Positive counterpart: a correct file loads with no warning and no
    permission change."""
    ring = make_test_keyring()
    target = tmp_path / "auth_keys.json"
    ring.save_to_file(target)
    with caplog.at_level(logging.WARNING):
        loaded = KeyRing.from_file(target)
    assert loaded == ring
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert caplog.records == []
