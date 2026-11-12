"""Opaque credential core — mint, parse, verify (plan 60 D3, contract §8).

The family's **opaque** credentials (personal access tokens, feed tokens,
capture tokens) are not JWTs: they are high-entropy secrets whose only
persisted form is a SHA-256 digest, optionally with a short **lookup
prefix** so a verifier can find the row before comparing hashes. Three
products hand-roll this today; this module is the one implementation.

Two shapes over one contract:

* **branded** (health) — ``mint(brand="ha_pat")`` returns
  ``ha_pat_<12 lowercase hex>_<token_urlsafe(32)>``: the hex segment is
  the generated ``prefix`` (``prefix_bytes`` bytes, default 6 ⇒ 12 chars)
  and is stored in its own column for an indexed lookup.
* **brandless** (career, study) — ``mint()`` returns
  ``token_urlsafe(32)`` with no prefix segment; those products look a row
  up by digest and use ``mint``/``verify`` only.

The product owns everything around the credential: the brand, the storage
schema and prefix column, tenant/role/permission/patient scope, audit,
revocation, rotation hand-off and the refusal matrix. This module owns the
byte format, the SHA-256 digest and the constant-time comparison — and
nothing else.

**No key material.** An opaque credential is not signed, encrypted or
derived from a key: the plaintext is pure CSPRNG output and the stored
form is a plain SHA-256 digest. There is no keying story to get wrong, and
no key ring is loaded, resolved or generated here.

**No plaintext leaves this module** except the mint return value itself.
Nothing is logged, no exception message carries a credential, and
:func:`verify` compares digests only — never a plaintext string, never
with ``==``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

__all__ = ["mint", "parse", "verify"]

# ``token_urlsafe`` alphabet (RFC 4648 §5) — a secret segment is only
# accepted when it stays inside it.
_URLSAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
# The generated prefix segment is lowercase hex, never uppercase.
_LOWER_HEX = frozenset("0123456789abcdef")

_SECRET_BYTES = 32
"""Entropy of the secret segment in bytes (``token_urlsafe`` input)."""


def _digest(plaintext: str) -> str:
    """The stored form of an opaque credential: SHA-256 hex of the full value."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _check_arguments(brand: str | None, prefix_bytes: int) -> None:
    """Reject arguments that cannot express a parseable credential."""
    if not isinstance(prefix_bytes, int) or prefix_bytes < 1:
        raise ValueError("prefix_bytes must be a positive integer")
    if brand is None:
        return
    if not brand:
        raise ValueError("brand must be a non-empty label or None")
    if brand.endswith("_"):
        raise ValueError("brand must not end with '_': mint inserts the separators")


def mint(
    *, brand: str | None = None, prefix_bytes: int = 6
) -> tuple[str, str | None, str]:
    """Mint one opaque credential.

    Args:
        brand: Leading label for a branded credential (health:
            ``"ha_pat"``). The separator underscores are inserted by this
            function, so the brand carries no trailing underscore. ``None``
            mints a bare ``token_urlsafe(32)`` with no prefix.
        prefix_bytes: Bytes of the generated lookup prefix (``prefix_bytes``
            bytes ⇒ ``2 * prefix_bytes`` lowercase hex characters).
            Ignored when ``brand`` is ``None``.

    Returns:
        ``(plaintext, prefix, sha256_hash)``. ``prefix`` is the lookup
        segment to store in the product's prefix column, or ``None`` for a
        brandless credential. ``sha256_hash`` is the hex digest of the
        **full** plaintext — the only form that may be stored. The
        plaintext is returned exactly once and is never recoverable
        afterwards.

    Raises:
        ValueError: If ``prefix_bytes`` is not a positive integer, ``brand``
            is an empty string, or ``brand`` ends with ``_`` (the trailing
            separator is inserted by this function).
    """
    _check_arguments(brand, prefix_bytes)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    if brand is None:
        plaintext = secret
        return plaintext, None, _digest(plaintext)
    prefix = secrets.token_hex(prefix_bytes)
    plaintext = f"{brand}_{prefix}_{secret}"
    return plaintext, prefix, _digest(plaintext)


def parse(
    bearer: str, *, brand: str | None = None, prefix_bytes: int = 6
) -> tuple[str | None, str] | None:
    """Split a presented credential into its lookup prefix and digest.

    Parsing is **format-only and strict**: it decides nothing about
    validity, liveness or ownership — the product looks up the prefix (or
    the digest), compares with :func:`verify` and applies its own policy.

    With a ``brand``, the value must be exactly
    ``<brand>_<2 * prefix_bytes lowercase hex>_<urlsafe secret>``; a
    wrong brand, a prefix of the wrong width, uppercase/other-than-hex
    characters, an empty prefix or an empty/non-urlsafe secret answer
    ``None``. A product that used to accept any non-empty prefix (health's
    pre-adoption ``token_prefix_of``) therefore rejects junk earlier and
    records no arbitrary prefix for it.

    Without a brand, any non-blank value answers ``(None, digest)``; blank
    values answer ``None``. The digest is computed over the value exactly
    as presented (callers trim transport whitespace first), so it only
    ever matches a hash minted from the identical string.

    A non-``str`` value (``None``, bytes, a header object) answers
    ``None``: parsing is total over untrusted input and never raises
    ``AttributeError``.

    Args:
        bearer: The presented credential (a bearer value).
        brand: The product's label; ``None`` for a bare credential.
        prefix_bytes: The prefix width the product minted with.

    Returns:
        ``(prefix, sha256_hash)`` — ``prefix`` is ``None`` for a brandless
        credential — or ``None`` when the value cannot have been minted by
        this module in this shape.

    Raises:
        ValueError: If ``prefix_bytes`` is not a positive integer, ``brand``
            is an empty string, or ``brand`` ends with ``_``.
    """
    _check_arguments(brand, prefix_bytes)
    if not isinstance(bearer, str) or not bearer.strip():
        return None
    if brand is None:
        return None, _digest(bearer)
    stem = f"{brand}_"
    if not bearer.startswith(stem):
        return None
    prefix, sep, secret = bearer[len(stem) :].partition("_")
    if not sep or not prefix or not secret:
        return None
    if len(prefix) != 2 * prefix_bytes or not _LOWER_HEX.issuperset(prefix):
        return None
    if not _URLSAFE.issuperset(secret):
        return None
    return prefix, _digest(bearer)


def verify(stored_hash: str, presented_hash: str) -> bool:
    """Compare a stored digest with a presented one in constant time.

    Both arguments are digests (from the product's column and from
    :func:`parse`) — never plaintext. An empty digest on either side
    answers ``False``: a missing stored hash must not match a missing
    presented one. A comparison that cannot be performed (non-ASCII text,
    bytes against text, a non-string value) also answers ``False``: the
    contract is ``bool`` and a malformed bearer must fail closed.

    Args:
        stored_hash: The digest loaded from the product's storage.
        presented_hash: The digest computed from the presented credential.

    Returns:
        ``True`` only when both digests are equal.
    """
    if not stored_hash or not presented_hash:
        return False
    try:
        return hmac.compare_digest(stored_hash, presented_hash)
    except Exception:
        # compare_digest raises TypeError for non-ASCII text and mismatched
        # types; any comparison failure is a non-match, never an exception.
        return False
