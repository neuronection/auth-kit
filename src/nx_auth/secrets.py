"""Secret store + resolver façade — where a named secret lives.

One implementation of the family "secret slot" contract (plan 60 D2,
ADR-0027/ADR-0028): a product names a secret *slot* and a keyring
*service*; this module resolves the value from the best backend that
actually works, and never invents one. The product owns the slot names,
the service names, the env prefixes and the value caps — the kit owns
storage, resolution and redaction.

Two surfaces over one backend set:

* **store** (study) — :func:`set`, :func:`delete`, :func:`probe`,
  :func:`backend_name`, :func:`cipher`, :func:`reset_caches`;
* **resolver** (health) — :func:`get`, :func:`get_async`.

Backends and precedence (frozen):

1. **OS keyring** — ``keyring.get_password(service, slot)``, trusted only
   after a round-trip probe. ``keyring.backends.null`` *accepts writes and
   silently discards them*, and a locked Secret Service or a read-only
   backend fails the same way: a backend that does not round-trip is never
   selected, because silently losing a credential is worse than refusing
   one.
2. **Sealed file** — ``store_path`` (study's ``<data_dir>/secrets.json``,
   mode ``0600``), a JSON map of ``{"<slot>": "enc::<fernet-token>"}``
   written atomically. Inert without the sealing key.
3. **Environment** — ``<env_prefix>_<slot>`` for deployment-provided
   secrets in server products (health). Read-only, never reported as a
   backend by :func:`backend_name`, and it **never shadows** a stored
   value: a stored-but-undecryptable envelope fails closed instead of
   quietly resolving from the environment. ``env_prefix=None`` disables
   the fallback entirely (study's no-plaintext-fallback doctrine).

Nothing writable ⇒ ``SecretStoreUnavailable``; nothing stored and nothing
in the environment ⇒ ``None`` (or ``SecretNotFound`` with
``required=True``). Backend selection is memoized per process and cleared
by :func:`reset_caches`.

Key material is **injected**: :func:`cipher` wraps
:class:`nx_auth.atrest.SecretCipher` (no second cipher, no fork) and the
caller builds it from its own §8 resolution. This module never loads a
key ring from disk, never writes ``auth_keys.json``, never generates key
material and never touches a signing key — it only seals and opens
strings with the cipher it is handed. Decryption accepts prior keys via
the ring, so a rotated envelope still resolves.

Values are sealed **before** they reach a backend (a keyring entry is
``enc::``, not plaintext), which is the whole point: a credential dump
from the keyring or the sealed file yields ciphertext. Legacy plaintext
entries are returned verbatim (study's pre-adoption tolerance) — never
re-sealed on read, never guessed. When no sealer is passed to
:func:`set`, the value is stored as given (plaintext); that exists only
for read-tolerance of pre-adoption stores and is never a default.

No plaintext ever leaves this module through a log record, an exception
message or a repr: diagnostics name the service, the slot and the backend,
and :func:`redact_secret` is the helper hosts use to scrub a secret out of
an upstream message before it is logged or persisted.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import logging
import os
import re
import stat
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

from nx_auth.atrest import (
    MASK_MARKER,
    SecretCipher,
    decrypt_secret,
    encrypt_secret,
    is_encrypted,
)

logger = logging.getLogger(__name__)

__all__ = [
    "SecretCipher",  # re-exported: callers build sealers without a second import
    "SecretError",
    "SecretNotFound",
    "SecretStoreUnavailable",
    "SecretUndecryptable",
    "backend_name",
    "cipher",
    "delete",
    "get",
    "get_async",
    "probe",
    "redact_secret",
    "reset_caches",
    "set",
]

_NO_BACKEND = "none"
_FILE_MODE = 0o600
# Same ref study's pre-adoption backend used, so an existing store gains no
# second transient entry name (the value is a pid, the ref is inert).
_PROBE_REF = "__backend_probe__"
_ENV_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")

_STORE_LOCK = threading.Lock()
_STORES: dict[tuple[str, str | None], _Store] = {}


# ---------------------------------------------------------------------------
# Errors — closed vocabulary, no secret in any message
# ---------------------------------------------------------------------------


class SecretError(Exception):
    """Base class for every typed secret failure."""


class SecretNotFound(SecretError):
    """No value for the slot in any readable backend (``required=True``)."""


class SecretUndecryptable(SecretError):
    """A stored envelope could not be opened (missing/wrong/rotated key)."""


class SecretStoreUnavailable(SecretError):
    """No writable backend, or a backend refused the write (fail closed)."""


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class _Store(Protocol):
    """A writable storage backend (keyring or sealed file)."""

    name: str

    def get(self, ref: str) -> str | None: ...

    def set(self, ref: str, value: str) -> None: ...

    def delete(self, ref: str) -> None: ...


class _KeyringModule(Protocol):
    """The slice of the ``keyring`` package this module uses."""

    def get_password(self, service_name: str, username: str) -> str | None: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def delete_password(self, service_name: str, username: str) -> None: ...


def _keyring_module() -> _KeyringModule | None:
    """The keyring package, or ``None`` when it is absent or unusable.

    A missing package is a supported deployment (health's Docker is
    env-only, study's server keeps the sealed file); a package that raises
    at import (a broken backend plugin) is treated the same way rather than
    taking the process down with it.
    """
    try:
        module = importlib.import_module("keyring")
    except Exception:
        return None
    return cast("_KeyringModule", module)


def _missing_delete_error() -> type[BaseException] | None:
    """``keyring.errors.PasswordDeleteError`` when the package provides it."""
    try:
        module = importlib.import_module("keyring.errors")
    except Exception:
        return None
    candidate = getattr(module, "PasswordDeleteError", None)
    if isinstance(candidate, type) and issubclass(candidate, BaseException):
        return candidate
    return None


class _KeyringStore:
    """The OS keyring under one service name.

    Reads never raise: a backend that locks or disappears after selection
    must fall through to the next source instead of failing a request
    (plan 60 D2 — probe/read failure is non-fatal for ``get``). Writes
    propagate so :func:`set` can refuse loudly.
    """

    name = "keyring"

    def __init__(
        self,
        module: _KeyringModule,
        service: str,
        missing_delete: type[BaseException] | None,
    ) -> None:
        self._keyring = module
        self._service = service
        self._missing_delete = missing_delete

    def get(self, ref: str) -> str | None:
        try:
            value = self._keyring.get_password(self._service, ref)
        except Exception as exc:
            logger.debug(
                "secret read under service %r from the keyring backend failed (%s)",
                self._service,
                type(exc).__name__,
            )
            return None
        return value if isinstance(value, str) else None

    def set(self, ref: str, value: str) -> None:
        self._keyring.set_password(self._service, ref, value)

    def delete(self, ref: str) -> None:
        try:
            self._keyring.delete_password(self._service, ref)
        except Exception as exc:
            if self._missing_delete is not None and isinstance(exc, self._missing_delete):
                return
            raise


class _FileStore:
    """The 0600 sealed file — the server/Docker backend.

    Same shape study's ``secrets.json`` already has: a flat JSON map of
    ``slot -> "enc::<token>"``. The file is inert without the sealing key,
    writes are atomic (tmp + replace) and serialized under a lock, and the
    mode is enforced at every write (a pre-existing group/world-readable
    file is repaired on read). One writer per file is assumed.
    """

    name = "file"

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def _load(self) -> dict[str, str]:
        self._repair_mode()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(ref): value for ref, value in raw.items() if isinstance(value, str)}

    def _repair_mode(self) -> None:
        try:
            mode = stat.S_IMODE(self._path.stat().st_mode)
        except OSError:
            return
        if mode & 0o077:
            logger.warning(
                "%s is group/world-readable (mode %04o) — stored secrets must "
                "be 0600; repairing in place",
                self._path,
                mode,
            )
            with contextlib.suppress(OSError):
                os.chmod(self._path, _FILE_MODE)

    def _save(self, data: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(f"{self._path.name}.tmp")
        try:
            tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
            os.chmod(tmp, _FILE_MODE)
            os.replace(tmp, self._path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise

    def get(self, ref: str) -> str | None:
        with self._lock:
            return self._load().get(ref)

    def set(self, ref: str, value: str) -> None:
        with self._lock:
            data = self._load()
            data[ref] = value
            self._save(data)

    def delete(self, ref: str) -> None:
        with self._lock:
            data = self._load()
            if ref in data:
                del data[ref]
                self._save(data)


class _NoStore:
    """Nothing is writable — every write fails closed, never a silent no-op."""

    name = _NO_BACKEND

    def get(self, ref: str) -> str | None:
        return None

    def set(self, ref: str, value: str) -> None:
        raise SecretStoreUnavailable(
            "no usable secret store: the OS keyring is unavailable and no "
            "sealed-file path is writable — refusing to store the credential "
            "anywhere else (fail closed, no plaintext fallback)"
        )

    def delete(self, ref: str) -> None:
        raise SecretStoreUnavailable(
            "no usable secret store: refusing to report a deletion that no "
            "backend performed (fail closed)"
        )


_NO_STORE = _NoStore()


# ---------------------------------------------------------------------------
# Backend selection (probe-or-fail, memoized per process)
# ---------------------------------------------------------------------------


def _roundtrip(store: _Store, payload: str) -> bool:
    """True only if a write is actually readable back.

    The probe is the trust decision: a null backend accepts and discards,
    a read-only backend refuses, a locked Secret Service raises — all three
    must end in "not selected".
    """
    try:
        store.set(_PROBE_REF, payload)
        back = store.get(_PROBE_REF)
    except Exception as exc:
        logger.debug(
            "secret backend %r failed its write probe (%s)", store.name, type(exc).__name__
        )
        return False
    finally:
        with contextlib.suppress(Exception):
            store.delete(_PROBE_REF)
    return back == payload


def _build_store(service: str, store_path: Path | None) -> _Store:
    probe = f"probe-{os.getpid()}"
    module = _keyring_module()
    if module is not None:
        candidate = _KeyringStore(module, service, _missing_delete_error())
        if _roundtrip(candidate, probe):
            return candidate
    if store_path is not None:
        file_store = _FileStore(Path(store_path))
        if _roundtrip(file_store, probe):
            return file_store
    return _NO_STORE


def _store_for(service: str, store_path: Path | None) -> _Store:
    key = (service, None if store_path is None else str(store_path))
    with _STORE_LOCK:
        cached = _STORES.get(key)
    if cached is not None:
        return cached
    built = _build_store(service, store_path)
    with _STORE_LOCK:
        return _STORES.setdefault(key, built)


def reset_caches() -> None:
    """Forget the selected backend(s) — the next call re-probes.

    Tests swap key material and fake backends between cases; a host that
    installs a keyring backend at runtime calls this once afterwards.
    """
    with _STORE_LOCK:
        _STORES.clear()


def backend_name(
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
) -> str:
    """The writable backend in use: ``keyring`` | ``file`` | ``none``.

    Diagnostics only, never a secret. The environment is a read-only
    fallback, so it is **never** reported here — ``none`` with a working
    env fallback is an expected health deployment. ``env_prefix`` is
    accepted for signature symmetry and ignored.
    """
    return _store_for(service, store_path).name


def probe(
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
    sealer: SecretCipher | None = None,
) -> None:
    """Round-trip the writable backend; raise if it cannot hold a secret.

    With a ``sealer`` the probe stores a *sealed* envelope, so the round
    trip covers the exact form :func:`set` writes. ``SecretStoreUnavailable``
    means "this host cannot persist secrets" — a deployment diagnostic, not
    a request-path call. ``env_prefix`` is accepted and ignored (env is
    read-only).
    """
    store = _store_for(service, store_path)
    if store.name == _NO_BACKEND:
        raise SecretStoreUnavailable(
            f"no writable secret backend for service {service!r}: the OS "
            "keyring is unavailable and no sealed-file path is configured"
        )
    payload = _seal(f"probe-{os.getpid()}", sealer)
    if not _roundtrip(store, payload):
        raise SecretStoreUnavailable(
            f"the {store.name} secret backend for service {service!r} did not "
            "round-trip a probe write (read-only, locked or discarding writes)"
        )


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _missing(*, service: str, slot: str | None, required: bool) -> None:
    if required:
        raise SecretNotFound(f"no secret for slot {slot!r} under service {service!r}")


def _open(
    stored: str,
    *,
    service: str,
    slot: str,
    required: bool,
    sealer: SecretCipher | None,
) -> str | None:
    if not is_encrypted(stored):
        return stored
    try:
        return decrypt_secret(stored, sealer)
    except ValueError:
        logger.warning(
            "secret for slot %r under service %r could not be decrypted "
            "(wrong or rotated DATA_KEY? add the prior key to the ring)",
            slot,
            service,
        )
        if required:
            raise SecretUndecryptable(
                f"the stored secret for slot {slot!r} under service {service!r} "
                "could not be decrypted (missing, wrong or rotated key)"
            ) from None
        return None


def _read_stored(service: str, store_path: Path | None, slot: str) -> str | None:
    """The stored value for ``slot``: selected backend first, then the file.

    Reads follow the frozen order without trusting more than the probe did:
    the *selected* keyring is read (a backend that failed its probe is not
    consulted — the plan's "probe failure falls through"), and the sealed
    file is read whenever a ``store_path`` exists, even when it is not
    writable (a read-only mount still serves existing secrets; only writes
    need the probe). The environment is the caller's last step.
    """
    selected = _store_for(service, store_path)
    if selected.name != _NO_BACKEND:
        stored = selected.get(slot) or None
        if stored is not None:
            return stored
    if store_path is not None and selected.name != "file":
        stored = _FileStore(Path(store_path)).get(slot) or None
        if stored is not None:
            return stored
    return None


def get(
    slot: str | None,
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
    required: bool = False,
    sealer: SecretCipher | None = None,
) -> str | None:
    """Resolve a secret slot to its value (keyring → sealed file → env).

    ``slot`` is a *name*, never a value, and this module does not validate
    its grammar (health's seed and SSO slots differ; study's keys are not
    slots at all) — products normalize before calling. ``env_prefix=None``
    disables the environment fallback; when given, the variable is
    ``f"{env_prefix}_{slot}"`` with every non-alphanumeric run folded to
    ``_`` and uppercased.

    Returns the plaintext, or ``None`` when nothing holds a value and the
    value could not be opened and ``required=False``. Raises
    :class:`SecretNotFound` for a missing value with ``required=True`` and
    :class:`SecretUndecryptable` when a stored envelope cannot be opened
    (never a guess, never a fallback to the environment). Read failures of
    an already-selected backend fall through to the next source instead of
    raising, so a locked keyring degrades to the file and then the env
    fallback. The sealed file is read whenever ``store_path`` is given,
    even when it is not the writable backend (a read-only mount still
    serves existing secrets).
    """
    if not slot:
        _missing(service=service, slot=slot, required=required)
        return None
    stored = _read_stored(service, store_path, slot)
    if stored is not None:
        return _open(
            stored, service=service, slot=slot, required=required, sealer=sealer
        )
    if env_prefix is not None:
        from_env = os.environ.get(_env_var_for_slot(env_prefix, slot))
        if from_env:
            return from_env
    _missing(service=service, slot=slot, required=required)
    return None


async def get_async(
    slot: str | None,
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
    required: bool = False,
    sealer: SecretCipher | None = None,
) -> str | None:
    """:func:`get` on a worker thread — same parameters, same contract.

    Keyring backends block (Secret Service / DBus / a file store), so every
    request-path resolution must stay off the event loop.
    """
    return await asyncio.to_thread(
        get,
        slot,
        service=service,
        env_prefix=env_prefix,
        store_path=store_path,
        required=required,
        sealer=sealer,
    )


def _env_var_for_slot(env_prefix: str, slot: str) -> str:
    """The frozen env name: ``<env_prefix>_<slot>``, folded and uppercased.

    Each half is folded separately (every non-alphanumeric run → ``_``) so
    the name is **byte-identical to health's deployed
    ``HA_SEED_SOURCE_SECRET_<SLOT>`` / ``HA_SSO_CLIENT_SECRET_<SLOT>``
    contract for every slot, including one that starts with punctuation**
    (health folds only the slot; folding the joined string would collapse
    the separator into a leading ``_`` of the slot). Pass the prefix
    without a trailing underscore — the kit adds it.
    """
    folded_prefix = _ENV_NON_ALNUM.sub("_", env_prefix).upper()
    folded_slot = _ENV_NON_ALNUM.sub("_", slot).upper()
    return f"{folded_prefix}_{folded_slot}"


# ---------------------------------------------------------------------------
# Store surface
# ---------------------------------------------------------------------------


def _seal(value: str, sealer: SecretCipher | None) -> str:
    if sealer is None:
        return value
    sealed = encrypt_secret(value, sealer)
    assert sealed is not None
    return sealed


def set(
    slot: str,
    value: str,
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
    sealer: SecretCipher | None = None,
) -> None:
    """Store ``value`` under ``slot``, sealed before it reaches a backend.

    With a ``sealer`` the value is wrapped as ``enc::<token>`` first, so
    even the keyring holds ciphertext; ``sealer=None`` stores plaintext and
    exists only for read-tolerance of pre-adoption stores — it is never the
    default. The probed keyring wins when it is the selected backend,
    otherwise the sealed file; with neither, :class:`SecretStoreUnavailable`
    (a failed write raises the same — no silent success, no silent backend
    switch). ``env_prefix`` is accepted for signature symmetry and ignored:
    the environment is a read-only fallback for deployment-provided
    secrets.
    """
    if not slot:
        raise ValueError("slot must be a non-empty secret name")
    payload = _seal(value, sealer)
    store = _store_for(service, store_path)
    try:
        store.set(slot, payload)
    except SecretStoreUnavailable:
        raise
    except Exception as exc:
        logger.warning(
            "secret write for slot %r under service %r failed on the %s "
            "backend (%s)",
            slot,
            service,
            store.name,
            type(exc).__name__,
        )
        raise SecretStoreUnavailable(
            f"the {store.name} secret backend for service {service!r} rejected "
            f"the write ({type(exc).__name__})"
        ) from None


def delete(
    slot: str,
    *,
    service: str,
    env_prefix: str | None = None,
    store_path: Path | None = None,
    sealer: SecretCipher | None = None,
) -> None:
    """Remove ``slot`` from every writable source :func:`get` can read.

    That is the selected backend **and** the sealed file, so a revocation
    cannot leave the value resolvable through the other source. Deleting an
    absent slot is a no-op (keys are idempotent), but a host with no
    writable backend raises :class:`SecretStoreUnavailable`, and so does a
    backend that refuses: a revocation that silently did nothing would leave
    a credential live. ``env_prefix`` / ``sealer`` are accepted for
    signature symmetry and ignored — the environment is not deletable and
    deletion needs no key.
    """
    if not slot:
        raise ValueError("slot must be a non-empty secret name")
    selected = _store_for(service, store_path)
    targets: list[_Store] = []
    if selected.name != _NO_BACKEND:
        targets.append(selected)
    if store_path is not None and selected.name != "file":
        targets.append(_FileStore(Path(store_path)))
    if not targets:
        raise SecretStoreUnavailable(
            f"no writable secret backend for service {service!r}: refusing to "
            "report a deletion that no backend performed (fail closed)"
        )
    for store in targets:
        try:
            store.delete(slot)
        except SecretStoreUnavailable:
            raise
        except Exception as exc:
            logger.warning(
                "secret delete for slot %r under service %r failed on the %s "
                "backend (%s)",
                slot,
                service,
                store.name,
                type(exc).__name__,
            )
            raise SecretStoreUnavailable(
                f"the {store.name} secret backend for service {service!r} rejected "
                f"the deletion ({type(exc).__name__})"
            ) from None


def cipher(*, data_key: str, previous: Sequence[str] = ()) -> SecretCipher:
    """The at-rest cipher over injected key material.

    A thin constructor over :class:`nx_auth.atrest.SecretCipher` (never a
    second implementation): ``previous`` carries decryption-only rotation
    keys, so an envelope sealed before a rotation still opens. The kit does
    not resolve the key — the host passes its own §8 ``data_key``.
    """
    return SecretCipher(data_key, previous=previous)


def redact_secret(text: str, secret: str | None, *, cap: int = 400) -> str:
    """A bounded, secret-free rendering of an upstream failure message.

    Masks every occurrence of the resolved secret (a transport that echoes
    a URL credential or an auth header back must not carry it into a log
    line, an error field or an API response) and caps the length — error
    text is a bounded field, never a raw dump.
    """
    out = text or ""
    if secret:
        out = out.replace(secret, MASK_MARKER)
    return out[:cap]
