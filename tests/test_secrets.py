"""``nx_auth.secrets`` — the store + resolver façade matrix (plan 60 D2).

Pins the frozen contract: probe-or-fail backend selection (a null or
read-only keyring is never trusted), the keyring → sealed file → env order,
values sealed **before** either backend, plaintext tolerance for legacy
entries without ever re-sealing a read, ``None`` vs the typed errors,
prior-key decryption of a rotated envelope, env names byte-identical to
health's deployed contract, redaction, and the invariants that decide the
security story: env never shadows a stored value, ``backend_name()`` never
reports ``env``, no plaintext in a log line or an exception, and no key
material is resolved, generated or written here.

No test touches a real keyring: backends are in-memory doubles installed
in ``sys.modules``, except the one case that proves the real
``keyring.backends.null`` is rejected — it is configured with the null
backend, which stores nothing anywhere.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import json
import re
import stat
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

import nx_auth.secrets as secrets
from nx_auth.atrest import ENCRYPTED_PREFIX, SecretCipher, decrypt_secret, encrypt_secret

# Fixed test-only key material (tests/test_atrest.py pattern — never a real key).
PRIMARY = base64.urlsafe_b64encode(b"\x11" * 32).decode("ascii")
PREVIOUS = base64.urlsafe_b64encode(b"\x22" * 32).decode("ascii")
OTHER = base64.urlsafe_b64encode(b"\x33" * 32).decode("ascii")

STUDY_SERVICE = "StudyAssistant"
HEALTH_SEED_SERVICE = "health-assistant/seed-sources"
HEALTH_SSO_SERVICE = "health-assistant/tenant-sso"
SEED_PREFIX = "HA_SEED_SOURCE_SECRET"
SSO_PREFIX = "HA_SSO_CLIENT_SECRET"

SECRET = "s3cr3t-value-do-not-log-42"


class PasswordDeleteError(Exception):
    """Stand-in for ``keyring.errors.PasswordDeleteError``."""


class _MemKeyring:
    """An in-memory keyring package double (behavior switches per case)."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.writes: list[str] = []
        self.services: set[str] = set()
        self.threads: set[str] = set()
        self.usable = True
        self.readable = True
        self.discards = False

    def get_password(self, service_name: str, username: str) -> str | None:
        self.threads.add(threading.current_thread().name)
        self.services.add(service_name)
        if not self.readable:
            raise RuntimeError("Secret Service is locked")
        return self.data.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.threads.add(threading.current_thread().name)
        self.services.add(service_name)
        if not self.usable:
            raise RuntimeError("backend is read-only")
        if self.discards:
            return
        self.writes.append(password)
        self.data[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        self.threads.add(threading.current_thread().name)
        if not self.readable:
            raise RuntimeError("Secret Service is locked")
        if (service_name, username) not in self.data:
            raise PasswordDeleteError("no such password")
        del self.data[(service_name, username)]

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = ModuleType("keyring")
        errors = ModuleType("keyring.errors")
        vars(errors).update({"PasswordDeleteError": PasswordDeleteError})
        vars(module).update(
            {
                "errors": errors,
                "get_password": self.get_password,
                "set_password": self.set_password,
                "delete_password": self.delete_password,
            }
        )
        monkeypatch.setitem(sys.modules, "keyring", module)
        monkeypatch.setitem(sys.modules, "keyring.errors", errors)

@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Every case starts with no usable keyring package and a cold cache."""
    monkeypatch.setitem(sys.modules, "keyring", None)
    secrets.reset_caches()
    yield
    secrets.reset_caches()


def _sealer(key: str = PRIMARY, previous: list[str] | None = None) -> SecretCipher:
    return secrets.cipher(data_key=key, previous=previous or [])


def _sealed(value: str, key: str = PRIMARY) -> str:
    sealed = encrypt_secret(value, _sealer(key))
    assert sealed is not None
    return sealed


def _file_with(path: Path, entries: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, separators=(",", ":")), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Keyring backend
# ---------------------------------------------------------------------------


def test_keyring_roundtrip_seals_before_storing(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)

    assert secrets.get("demo", service=STUDY_SERVICE, sealer=_sealer()) is None
    secrets.set("demo", SECRET, service=STUDY_SERVICE, sealer=_sealer())

    stored = keyring.data[(STUDY_SERVICE, "demo")]
    assert stored.startswith(ENCRYPTED_PREFIX)
    assert SECRET not in stored
    assert secrets.get("demo", service=STUDY_SERVICE, sealer=_sealer()) == SECRET
    assert secrets.backend_name(service=STUDY_SERVICE) == "keyring"

    secrets.delete("demo", service=STUDY_SERVICE)
    assert (STUDY_SERVICE, "demo") not in keyring.data
    assert secrets.get("demo", service=STUDY_SERVICE, sealer=_sealer()) is None


def test_keyring_probe_rejects_a_discarding_null_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyring = _MemKeyring()
    keyring.discards = True
    keyring.install(monkeypatch)
    store_path = tmp_path / "secrets.json"

    assert secrets.backend_name(service=STUDY_SERVICE) == "none"
    assert secrets.backend_name(service=STUDY_SERVICE, store_path=store_path) == "file"

    secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    assert keyring.data == {}
    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == SECRET
    )


def test_keyring_probe_rejects_a_read_only_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyring = _MemKeyring()
    keyring.usable = False
    keyring.install(monkeypatch)

    probe_path = tmp_path / "secrets.json"
    assert secrets.backend_name(service=STUDY_SERVICE, store_path=probe_path) == "file"
    assert secrets.backend_name(service=STUDY_SERVICE) == "none"


def test_locked_keyring_read_falls_through_to_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    secrets.set("demo", SECRET, service=HEALTH_SSO_SERVICE, sealer=_sealer())
    assert secrets.get("demo", service=HEALTH_SSO_SERVICE, sealer=_sealer()) == SECRET

    keyring.readable = False
    monkeypatch.setenv(f"{SSO_PREFIX}_DEMO", "env-credential")
    assert (
        secrets.get(
            "demo", service=HEALTH_SSO_SERVICE, env_prefix=SSO_PREFIX, sealer=_sealer()
        )
        == "env-credential"
    )


def test_probe_failure_is_non_fatal_for_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = _MemKeyring()
    keyring.usable = False
    keyring.readable = False
    keyring.install(monkeypatch)
    monkeypatch.setenv(f"{SEED_PREFIX}_DEMO", "env-credential")

    assert secrets.backend_name(service=HEALTH_SEED_SERVICE) == "none"
    assert (
        secrets.get("demo", service=HEALTH_SEED_SERVICE, env_prefix=SEED_PREFIX) == "env-credential"
    )
    with pytest.raises(secrets.SecretNotFound):
        secrets.get("missing", service=HEALTH_SEED_SERVICE, env_prefix=SEED_PREFIX, required=True)


def test_missing_keyring_package_selects_none() -> None:
    assert secrets.backend_name(service=STUDY_SERVICE) == "none"
    assert secrets.get("demo", service=STUDY_SERVICE) is None
    with pytest.raises(secrets.SecretStoreUnavailable):
        secrets.set("demo", SECRET, service=STUDY_SERVICE)


def test_reset_caches_reprobes(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.discards = True
    keyring.install(monkeypatch)
    assert secrets.backend_name(service=STUDY_SERVICE) == "none"

    keyring.discards = False
    assert secrets.backend_name(service=STUDY_SERVICE) == "none"
    secrets.reset_caches()
    assert secrets.backend_name(service=STUDY_SERVICE) == "keyring"


def test_selection_is_per_service(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    assert secrets.backend_name(service=HEALTH_SEED_SERVICE) == "keyring"
    assert secrets.backend_name(service=HEALTH_SSO_SERVICE) == "keyring"
    assert keyring.services == {HEALTH_SEED_SERVICE, HEALTH_SSO_SERVICE}


def test_real_keyring_null_backend_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    keyring = pytest.importorskip("keyring")
    null = pytest.importorskip("keyring.backends.null")

    keyring.set_keyring(null.Keyring())
    probe_path = tmp_path / "secrets.json"

    assert secrets.backend_name(service=STUDY_SERVICE) == "none"
    assert secrets.backend_name(service=STUDY_SERVICE, store_path=probe_path) == "file"


# ---------------------------------------------------------------------------
# Sealed file backend
# ---------------------------------------------------------------------------


def test_sealed_file_shape_and_mode(tmp_path: Path) -> None:
    store_path = tmp_path / "data" / "secrets.json"
    secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())

    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600
    raw = json.loads(store_path.read_text(encoding="utf-8"))
    assert set(raw) == {"demo"}
    assert raw["demo"].startswith(ENCRYPTED_PREFIX)
    assert SECRET not in store_path.read_text(encoding="utf-8")
    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == SECRET
    )


def test_sealed_file_is_study_compatible(tmp_path: Path) -> None:
    """A file study wrote before adoption resolves unchanged (same shape)."""
    store_path = _file_with(tmp_path / "secrets.json", {"oauth/github": _sealed("legacy")})
    assert (
        secrets.get("oauth/github", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == "legacy"
    )


def test_sealed_file_mode_is_repaired_on_read(tmp_path: Path) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET)})
    store_path.chmod(0o644)

    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == SECRET
    )
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600


def test_read_only_file_still_serves_reads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET)})

    def _read_only(self: object, ref: str, value: str) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(secrets._FileStore, "set", _read_only)

    assert secrets.backend_name(service=STUDY_SERVICE, store_path=store_path) == "none"
    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == SECRET
    )
    with pytest.raises(secrets.SecretStoreUnavailable):
        secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path)


def test_store_path_none_disables_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(secrets.SecretStoreUnavailable):
        secrets.set("demo", SECRET, service=HEALTH_SSO_SERVICE, sealer=_sealer())
    assert list(tmp_path.iterdir()) == []


def test_delete_removes_from_the_file(tmp_path: Path) -> None:
    store_path = tmp_path / "secrets.json"
    secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    secrets.set("keep", "other", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())

    secrets.delete("demo", service=STUDY_SERVICE, store_path=store_path)
    raw = json.loads(store_path.read_text(encoding="utf-8"))
    assert set(raw) == {"keep"}
    secrets.delete("demo", service=STUDY_SERVICE, store_path=store_path)


def test_delete_removes_the_slot_from_both_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed("from-file")})

    secrets.set("demo", "from-keyring", service=STUDY_SERVICE, sealer=_sealer())
    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        == "from-keyring"
    )

    secrets.delete("demo", service=STUDY_SERVICE, store_path=store_path)

    assert (STUDY_SERVICE, "demo") not in keyring.data
    assert json.loads(store_path.read_text(encoding="utf-8")) == {}
    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
        is None
    )


# ---------------------------------------------------------------------------
# Precedence and the environment fallback
# ---------------------------------------------------------------------------


def test_precedence_keyring_then_file_then_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed("from-file")})
    monkeypatch.setenv(f"{SEED_PREFIX}_DEMO", "from-env")

    def resolve() -> str | None:
        return secrets.get(
            "demo",
            service=HEALTH_SEED_SERVICE,
            env_prefix=SEED_PREFIX,
            store_path=store_path,
            sealer=_sealer(),
        )

    assert resolve() == "from-file"
    secrets.set("demo", "from-keyring", service=HEALTH_SEED_SERVICE, sealer=_sealer())
    assert resolve() == "from-keyring"

    keyring.data.clear()
    assert resolve() == "from-file"

    store_path.unlink()
    assert resolve() == "from-env"


def test_env_cannot_shadow_a_stored_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET, PRIMARY)})
    monkeypatch.setenv(f"{SSO_PREFIX}_DEMO", "env-credential")

    assert (
        secrets.get(
            "demo",
            service=HEALTH_SSO_SERVICE,
            env_prefix=SSO_PREFIX,
            store_path=store_path,
            sealer=_sealer(OTHER),
        )
        is None
    )
    with pytest.raises(secrets.SecretUndecryptable):
        secrets.get(
            "demo",
            service=HEALTH_SSO_SERVICE,
            env_prefix=SSO_PREFIX,
            store_path=store_path,
            sealer=_sealer(OTHER),
            required=True,
        )


@pytest.mark.parametrize(
    ("prefix", "slot", "expected"),
    [
        (SEED_PREFIX, "demo", "HA_SEED_SOURCE_SECRET_DEMO"),
        (SEED_PREFIX, "My-Slot", "HA_SEED_SOURCE_SECRET_MY_SLOT"),
        (SEED_PREFIX, "sso.prod/1", "HA_SEED_SOURCE_SECRET_SSO_PROD_1"),
        (SSO_PREFIX, "tenant-a", "HA_SSO_CLIENT_SECRET_TENANT_A"),
        (SSO_PREFIX, ".leading", "HA_SSO_CLIENT_SECRET__LEADING"),
    ],
)
def test_env_name_folding_matches_health(prefix: str, slot: str, expected: str) -> None:
    """health's own formula (seed/sso ``env_var_for_slot``), byte for byte."""
    health = prefix + "_" + re.sub(r"[^A-Za-z0-9]+", "_", slot).upper()
    assert health == expected
    assert secrets._env_var_for_slot(prefix, slot) == expected


@pytest.mark.parametrize("slot", ["demo", "My-Slot", "sso.prod/1", ".leading", "a b c"])
def test_env_fallback_reads_the_deployed_name(
    monkeypatch: pytest.MonkeyPatch, slot: str
) -> None:
    monkeypatch.setenv(secrets._env_var_for_slot(SSO_PREFIX, slot), "deployed-value")
    assert (
        secrets.get(slot, service=HEALTH_SSO_SERVICE, env_prefix=SSO_PREFIX) == "deployed-value"
    )
    assert secrets.get(slot, service=HEALTH_SSO_SERVICE) is None


def test_env_prefix_none_never_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{SEED_PREFIX}_DEMO", "env-credential")
    assert secrets.get("demo", service=HEALTH_SEED_SERVICE) is None
    assert secrets.get("demo", service=HEALTH_SEED_SERVICE, required=False) is None


def test_backend_name_never_reports_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{SEED_PREFIX}_DEMO", "env-credential")
    assert secrets.backend_name(service=HEALTH_SEED_SERVICE) == "none"
    assert secrets.backend_name(service=HEALTH_SEED_SERVICE, env_prefix=SEED_PREFIX) == "none"


def test_service_names_are_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    for service in (STUDY_SERVICE, HEALTH_SEED_SERVICE, HEALTH_SSO_SERVICE):
        secrets.set("demo", SECRET, service=service, sealer=_sealer())
        assert secrets.get("demo", service=service, sealer=_sealer()) == SECRET
    assert keyring.services == {STUDY_SERVICE, HEALTH_SEED_SERVICE, HEALTH_SSO_SERVICE}


# ---------------------------------------------------------------------------
# Values: sealing, tolerance, rotation, required-ness
# ---------------------------------------------------------------------------


def test_missing_value_is_none_but_required_raises() -> None:
    assert secrets.get("demo", service=STUDY_SERVICE) is None
    assert secrets.get("", service=STUDY_SERVICE) is None
    assert secrets.get(None, service=STUDY_SERVICE) is None
    with pytest.raises(secrets.SecretNotFound):
        secrets.get("demo", service=STUDY_SERVICE, required=True)
    with pytest.raises(secrets.SecretNotFound):
        secrets.get(None, service=STUDY_SERVICE, required=True)


def test_legacy_plaintext_returns_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    keyring.data[(STUDY_SERVICE, "demo")] = "legacy-plaintext-token"

    assert secrets.get("demo", service=STUDY_SERVICE, sealer=_sealer()) == "legacy-plaintext-token"
    assert (
        secrets.get("demo", service=STUDY_SERVICE, sealer=_sealer(), required=True)
        == "legacy-plaintext-token"
    )
    assert keyring.data[(STUDY_SERVICE, "demo")] == "legacy-plaintext-token"


def test_encrypted_value_without_a_sealer_is_undecryptable(
    tmp_path: Path,
) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET)})
    assert secrets.get("demo", service=STUDY_SERVICE, store_path=store_path) is None
    with pytest.raises(secrets.SecretUndecryptable):
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, required=True)


def test_wrong_key_is_none_or_typed_error(tmp_path: Path) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET, PRIMARY)})

    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer(OTHER))
        is None
    )
    with pytest.raises(secrets.SecretUndecryptable):
        secrets.get(
            "demo",
            service=STUDY_SERVICE,
            store_path=store_path,
            sealer=_sealer(OTHER),
            required=True,
        )


def test_prior_key_decrypts_an_old_envelope(tmp_path: Path) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET, PREVIOUS)})
    rotated = _sealer(PRIMARY, previous=[PREVIOUS])

    assert (
        secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=rotated)
        == SECRET
    )
    assert (
        secrets.get(
            "demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer(PRIMARY)
        )
        is None
    )


def test_set_without_a_sealer_stores_plaintext(tmp_path: Path) -> None:
    store_path = tmp_path / "secrets.json"
    secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path)

    assert json.loads(store_path.read_text(encoding="utf-8"))["demo"] == SECRET
    assert secrets.get("demo", service=STUDY_SERVICE, store_path=store_path) == SECRET


def test_empty_stored_value_is_absent(tmp_path: Path) -> None:
    store_path = _file_with(tmp_path / "secrets.json", {"demo": ""})
    assert secrets.get("demo", service=STUDY_SERVICE, store_path=store_path) is None


def test_set_rejects_an_empty_slot() -> None:
    with pytest.raises(ValueError):
        secrets.set("", SECRET, service=STUDY_SERVICE)
    with pytest.raises(ValueError):
        secrets.delete("", service=STUDY_SERVICE)


# ---------------------------------------------------------------------------
# Writes fail closed
# ---------------------------------------------------------------------------


def test_set_write_failure_raises_without_switching_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    store_path = tmp_path / "secrets.json"
    assert secrets.backend_name(service=STUDY_SERVICE, store_path=store_path) == "keyring"

    keyring.usable = False
    with pytest.raises(secrets.SecretStoreUnavailable) as caught:
        secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    assert SECRET not in str(caught.value)
    assert not store_path.exists()


def test_delete_without_a_backend_raises() -> None:
    with pytest.raises(secrets.SecretStoreUnavailable):
        secrets.delete("demo", service=STUDY_SERVICE)


def test_probe_reports_the_writable_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)

    secrets.probe(service=STUDY_SERVICE)
    assert any(w.startswith("probe-") for w in keyring.writes)

    keyring.writes.clear()
    secrets.probe(service=STUDY_SERVICE, sealer=_sealer())
    assert keyring.writes != []
    assert all(w.startswith(ENCRYPTED_PREFIX) for w in keyring.writes)


def test_probe_without_a_backend_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(secrets.SecretStoreUnavailable):
        secrets.probe(service=HEALTH_SSO_SERVICE)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Async adapter, cipher, redaction
# ---------------------------------------------------------------------------


def test_get_async_matches_get_and_runs_off_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    secrets.set("demo", SECRET, service=STUDY_SERVICE, sealer=_sealer())
    keyring.threads.clear()

    value = asyncio.run(
        secrets.get_async("demo", service=STUDY_SERVICE, sealer=_sealer(), required=True)
    )
    assert value == SECRET
    assert threading.main_thread().name not in keyring.threads


def test_get_async_propagates_the_typed_errors() -> None:
    with pytest.raises(secrets.SecretNotFound):
        asyncio.run(secrets.get_async("demo", service=STUDY_SERVICE, required=True))


def test_cipher_wraps_the_atrest_cipher() -> None:
    rotated = secrets.cipher(data_key=PRIMARY, previous=[PREVIOUS])
    assert isinstance(rotated, SecretCipher)
    assert rotated.primary_tag == _sealer().primary_tag
    assert decrypt_secret(encrypt_secret("fresh", rotated), rotated) == "fresh"
    assert decrypt_secret(_sealed("old", PREVIOUS), rotated) == "old"


def test_redact_secret_masks_every_occurrence() -> None:
    text = f"GET https://user:{SECRET}@host/?k={SECRET} failed"
    redacted = secrets.redact_secret(text, SECRET)
    assert SECRET not in redacted
    assert redacted.count("***") == 2
    assert secrets.redact_secret(text, None) == text[:400]
    assert secrets.redact_secret("x" * 1000, SECRET, cap=10) == "x" * 10
    assert secrets.redact_secret("", SECRET) == ""


def test_no_plaintext_in_logs_or_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    keyring = _MemKeyring()
    keyring.install(monkeypatch)
    store_path = _file_with(tmp_path / "secrets.json", {"demo": _sealed(SECRET, PRIMARY)})

    with caplog.at_level("DEBUG"):
        assert (
            secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer(OTHER))
            is None
        )
        keyring.usable = False
        with pytest.raises(secrets.SecretStoreUnavailable) as caught:
            secrets.set("demo", SECRET, service=STUDY_SERVICE, sealer=_sealer())
        with pytest.raises(secrets.SecretUndecryptable) as undecryptable:
            secrets.get(
                "demo",
                service=STUDY_SERVICE,
                store_path=store_path,
                sealer=_sealer(OTHER),
                required=True,
            )

    assert SECRET not in caplog.text
    assert SECRET not in str(caught.value)
    assert SECRET not in str(undecryptable.value)
    assert "demo" in caplog.text


# ---------------------------------------------------------------------------
# No key material
# ---------------------------------------------------------------------------


def test_module_resolves_no_key_material(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Injected keys only: no KeyRing, no key load, no key file written."""
    source = Path(secrets.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    code = source.replace(ast.get_docstring(tree, clean=False) or "", "", 1)
    for forbidden in ("auth_keys", "KeyRing", "load_for", "generate_key", "nx_auth.keys"):
        assert forbidden not in code

    monkeypatch.chdir(tmp_path)
    store_path = tmp_path / "data" / "secrets.json"
    secrets.set("demo", SECRET, service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    secrets.get("demo", service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    secrets.probe(service=STUDY_SERVICE, store_path=store_path, sealer=_sealer())
    secrets.backend_name(service=STUDY_SERVICE, store_path=store_path)

    written = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file())
    assert written == ["data/secrets.json"]
