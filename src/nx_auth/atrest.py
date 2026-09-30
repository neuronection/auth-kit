"""At-rest secret encryption (Fernet) — the DATA_KEY cipher.

One implementation of the at-rest contract for the Neuronection family
of products: MultiFernet rotation ring, ``_kid`` key fingerprints, and
per-row ``context`` binding. The golden-vector suite
(``tests/fixtures/atrest_golden_vectors.json``) regression-locks the
ciphertext format: values produced by the pre-consolidation
implementation of this contract must decrypt here with identical
plaintext, context and ``_kid``.

Two value shapes:

* **tagged values** — ``{"_encrypted": "<fernet-token>", "_kid": "<tag>"}``
  (JSONB config fields; :class:`SecretCipher`).
* **strings** — ``"enc::<fernet-token>"`` (``encrypt_secret`` /
  ``decrypt_secret``).

Key rotation (runbook — dropping a prior key early is permanent
ciphertext loss):

1. set ``<P>_DATA_KEY_PREVIOUS`` to the old key (comma-separated for
   multiple), move the new key into ``<P>_DATA_KEY``;
2. backfill by ``_kid`` (re-encrypt entries whose tag is a prior key's);
3. **census: zero entries with a stale ``_kid``**;
4. only then drop the prior key.

Integrity note (the tolerance tradeoff): Fernet authenticates its
ciphertext, but a *tolerant read* accepts un-encrypted values verbatim —
a database writer who swaps a stored secret for chosen plaintext bypasses
that authentication (e.g. re-points a webhook secret they know).
``allow_plaintext_read`` / ``allow_plaintext_write`` default to the
historical tolerant behavior for adoption compatibility; production
deployments run the backfill and flip strict (dev/test keeps the
loud-warning fallback so local flows never need pre-seeded keys).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from collections.abc import Sequence
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger(__name__)

SECRET_MARKER = "_encrypted"
KEY_ID_MARKER = "_kid"
ENCRYPTED_PREFIX = "enc::"
MASK_MARKER = "***"

# Length to which a key is truncated for the ``_kid`` tag. Short enough to be
# a cheap fingerprint, long enough to distinguish keys in practice.
_KEY_TAG_LEN = 8


def _key_tag(key: str | bytes) -> str:
    """A short, stable fingerprint of a Fernet key (not security-sensitive)."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    # Fernet keys are base64url; take the first chars as the tag.
    return hashlib.sha256(key).hexdigest()[:_KEY_TAG_LEN]


def _normalize_fernet_key(key: str) -> bytes:
    """Canonical padded Fernet encoding of a DATA_KEY family entry.

    The family accepts both the padded ``Fernet.generate_key()``
    form and the kit's unpadded token form — the same 32 key bytes
    either way. Normalizing here keeps the ring usable with either
    spelling without changing any ciphertext: a Fernet token depends
    only on the key bytes, and the padded form round-trips to itself.
    """
    import base64

    padded = key + "=" * (-len(key) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(raw) != 32:
        raise ValueError(
            "DATA_KEY family entry must be 32-byte urlsafe-base64 key "
            "material (a Fernet key)"
        )
    return base64.urlsafe_b64encode(raw)


class SecretCipher:
    """Fernet wrapper for encrypting tagged fields inside ``user_config``.

    Uses :class:`~cryptography.fernet.MultiFernet` so a rotation is non-
    disruptive: the first key in the list is the primary (used to encrypt),
    the rest are accepted for decryption only. The key material comes from
    the product's own §8 resolution (``KeyRing.data_key`` or the ``<P>_DATA_KEY``
    env family — see :func:`cipher_from_env`).
    """

    def __init__(
        self,
        key: str | bytes | None,
        *,
        previous: Sequence[str | bytes] | None = None,
    ) -> None:
        keys: list[str | bytes] = []
        if not key:
            raise RuntimeError(
                "DATA_KEY is not configured. Set it (a Fernet "
                "key, base64 32 bytes) to use integrations that store secrets."
            )
        keys.append(key)
        for prev in previous or []:
            if prev and prev not in keys:
                keys.append(prev)
        # Canonical padded spelling per entry: identical to the input for
        # the standard ``Fernet.generate_key()`` form (the historical ring
        # spelling), so ``_kid`` tags stay stable across key-family
        # migrations.
        canonical = [
            _normalize_fernet_key(k).decode("ascii") if isinstance(k, str) else k
            for k in keys
        ]
        self._multi = MultiFernet([Fernet(k) for k in canonical])
        self._primary = Fernet(canonical[0])
        self._primary_tag = _key_tag(canonical[0])

    @property
    def primary_tag(self) -> str:
        """The ``_kid`` fingerprint of the current (encrypting) key."""
        return self._primary_tag

    @classmethod
    def from_env(cls, prefix: str) -> SecretCipher:
        """Ring from ``<P>_DATA_KEY`` + ``<P>_DATA_KEY_PREVIOUS`` (comma-separated).

        Products with their own Settings keep using them and construct
        directly; this is the uniform env story for everyone else.
        """
        key = os.environ.get(f"{prefix}_DATA_KEY") or None
        previous = [
            k.strip()
            for k in (os.environ.get(f"{prefix}_DATA_KEY_PREVIOUS") or "").split(",")
            if k.strip()
        ]
        return cls(key, previous=previous)

    def encrypt_raw(self, plaintext: str) -> str:
        """Encrypt a bare string to a bare Fernet token (rotation-ring aware)."""
        return self._primary.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt_raw(self, token: str) -> str:
        """Decrypt a bare Fernet token via the ring (primary, then priors)."""
        try:
            return self._multi.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as e:
            raise ValueError(
                "Encrypted value could not be decrypted "
                "(key missing/rotated? add the prior key to DATA_KEY_PREVIOUS)."
            ) from e

    def encrypt_value(self, value: Any, *, context: str | None = None) -> dict[str, str]:
        """Encrypt a single value -> ``{"_encrypted": "<token>", "_kid": "<tag>"}``.

        ``context`` (e.g. the owning ``integration_id``) is folded into the
        plaintext envelope so the resulting ciphertext can't be replayed into
        a different row — :meth:`decrypt_value` rejects a mismatch. Pass the
        same context on decrypt.
        """
        if value is None:
            return {}
        if isinstance(value, (dict, list)):
            payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        else:
            payload = str(value)
        token = self._primary.encrypt(self._envelope(payload, context)).decode("utf-8")
        return {SECRET_MARKER: token, KEY_ID_MARKER: self._primary_tag}

    def decrypt_value(
        self,
        wrapped: Any,
        *,
        context: str | None = None,
        allow_plaintext_read: bool = True,
    ) -> Any:
        """Inverse of :meth:`encrypt_value`.

        With ``allow_plaintext_read=True`` (adoption default), non-wrapper
        values are returned unchanged so legacy plaintext configs keep
        working — see the module docstring for the integrity cost. With
        ``False``, a non-empty non-wrapper value raises. ``None``, ``""``,
        ``{}`` and ``[]`` always pass through (nothing to decrypt).
        Raises :class:`ValueError` if the value can't be decrypted (key
        mismatch / rotated) or if the context doesn't match the one used at
        encrypt time.
        """
        if not isinstance(wrapped, dict) or SECRET_MARKER not in wrapped:
            if allow_plaintext_read or wrapped in (None, "", {}, []):
                return wrapped
            raise ValueError(
                "Secret value is not encrypted (plaintext tolerance is off)."
            )
        token = wrapped[SECRET_MARKER].encode("utf-8")
        try:
            plaintext = self._multi.decrypt(token).decode("utf-8")
        except InvalidToken as e:
            raise ValueError(
                "Encrypted config value could not be decrypted "
                "(key missing/rotated? add the prior key to DATA_KEY_PREVIOUS)."
            ) from e
        value_str, stored_context = self._split_envelope(plaintext)
        # Constant-time compare: the envelope is inside the authenticated
        # ciphertext, but keep the bar high — no plaintext string compares
        # on security-relevant values.
        if (
            stored_context is not None
            and context is not None
            and not hmac.compare_digest(stored_context, context)
        ):
            raise ValueError(
                "Encrypted config value was encrypted for a different "
                "context (integration/row mismatch)."
            )
        try:
            return json.loads(value_str)
        except (ValueError, json.JSONDecodeError):
            return value_str

    # --- envelope helpers -------------------------------------------------

    @staticmethod
    def _envelope(payload: str, context: str | None) -> bytes:
        """Pack ``payload`` with an optional AAD-like context tag.

        Format: ``ctx:<context>\n<payload>`` when context is given, else the
        raw payload. Fernet has no native AAD, so we bind the context into
        the plaintext (verified on decrypt). A value encrypted *without* a
        context decrypts to its raw payload regardless of the decrypt-time
        context, preserving compatibility with pre-rotation values.
        """
        if context:
            return f"ctx:{context}\n{payload}".encode()
        return payload.encode("utf-8")

    @staticmethod
    def _split_envelope(plaintext: str) -> tuple[str, str | None]:
        if plaintext.startswith("ctx:"):
            newline = plaintext.find("\n")
            if newline != -1:
                ctx = plaintext[4:newline]
                return plaintext[newline + 1 :], ctx
        return plaintext, None


# --- string layer (`enc::` values) ---------------------------------------

def is_encrypted(value: str | None) -> bool:
    """True if the stored value is in the encrypted ``enc::<token>`` form."""
    if not value:
        return False
    return value.startswith(ENCRYPTED_PREFIX)


def encrypt_secret(
    plaintext: str | None,
    cipher: SecretCipher | None = None,
    *,
    allow_plaintext_write: bool = False,
) -> str | None:
    """Encrypt a secret string -> ``"enc::<token>"`` (None/"" pass through).

    Already-encrypted input passes through unchanged. With no cipher and
    ``allow_plaintext_write=True`` (dev/test fallback), the value is stored
    in plaintext with a loud warning; production flips strict and raises.
    """
    if plaintext is None:
        return None
    if plaintext == "":
        return ""
    if is_encrypted(plaintext):
        return plaintext
    if cipher is None:
        if allow_plaintext_write:
            logger.warning(
                "DATA_KEY not set — storing secret in PLAINTEXT "
                "(dev/test only). Set the key (Fernet, base64 32 bytes) for prod."
            )
            return plaintext
        raise RuntimeError(
            "Refusing to store a secret in plaintext: DATA_KEY "
            "is not configured."
        )
    return f"{ENCRYPTED_PREFIX}{cipher.encrypt_raw(plaintext)}"


def decrypt_secret(
    stored: str | None,
    cipher: SecretCipher | None = None,
    *,
    allow_plaintext_read: bool = True,
) -> str | None:
    """Decrypt a stored value produced by :func:`encrypt_secret`.

    Returns the plaintext. With ``allow_plaintext_read=True``, input not in
    encrypted form (legacy plaintext) returns verbatim — the module
    docstring names the integrity cost. ``False`` raises instead. An
    ``enc::`` value that cannot be decrypted with any ring key raises
    :class:`ValueError` — callers should surface this as a config error
    rather than silently masking.
    """
    if stored is None:
        return None
    if stored == "":
        return ""
    if not is_encrypted(stored):
        if allow_plaintext_read:
            return stored
        raise ValueError("Secret value is not encrypted (plaintext tolerance is off).")
    if cipher is None:
        raise ValueError("Secret is encrypted but DATA_KEY is not configured")
    return cipher.decrypt_raw(stored[len(ENCRYPTED_PREFIX) :])
