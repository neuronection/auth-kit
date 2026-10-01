"""At-rest cipher tests — the security matrix for nx_auth.atrest.

The golden vectors in ``fixtures/atrest_golden_vectors.json`` were
produced by the pre-consolidation implementation of this contract, with
the fixed test-only keys below (0x11/0x22 byte patterns — never real
keys). They regression-lock the ciphertext format: any change to padding
normalization, ``_kid`` derivation, or the envelope layout breaks these
first — before a rotation ever depends on it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nx_auth.atrest import (
    ENCRYPTED_PREFIX,
    KEY_ID_MARKER,
    MASK_MARKER,
    SECRET_MARKER,
    SecretCipher,
    _key_tag,
    _normalize_fernet_key,
    decrypt_secret,
    encrypt_secret,
    is_encrypted,
)

FIXTURES = Path(__file__).parent / "fixtures" / "atrest_golden_vectors.json"
VECTORS = json.loads(FIXTURES.read_text(encoding="utf-8"))["cases"]

# Fixed test-only key material (see module docstring).
PRIMARY = "ERERERERERERERERERERERERERERERERERERERERERE="
PREVIOUS = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="

# Regression-locked fingerprints: sha256 of the canonical padded spelling,
# truncated to 8. If these change, every existing _kid-driven rotation
# backfill breaks — see docs/atrest.md "kid stability".
PRIMARY_TAG = "7ab7b6c0"
PREVIOUS_TAG = "753c6837"


def _ring() -> SecretCipher:
    return SecretCipher(PRIMARY, previous=[PREVIOUS])


def _reference_expected(value: object) -> object:
    """Mirror of the reference implementation's value round-trip semantics.

    dict/list are JSON-serialized with compact separators; everything else
    is str()-ified; decrypt returns json.loads when the result parses as
    JSON, else the raw string (reference ``decrypt_value`` behavior — note
    bools stringify to ``"True"``/``"False"`` and stay strings).
    """
    if isinstance(value, (dict, list)):
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    else:
        payload = str(value)
    try:
        return json.loads(payload)
    except ValueError:
        return payload


# ---------------------------------------------------------------------------
# 1/7. Golden vectors + _kid stability (ciphertext-format lock)
# ---------------------------------------------------------------------------

def test_golden_vectors_value_layer_decrypt_identically() -> None:
    ring = _ring()
    for case in VECTORS:
        if case["layer"] != "value":
            continue
        decrypted = ring.decrypt_value(case["wrapped"], context=case["context"])
        assert decrypted == _reference_expected(case["plaintext"]), case


def test_golden_vectors_string_layer_decrypt_identically() -> None:
    ring = _ring()
    for case in VECTORS:
        if case["layer"] != "string":
            continue
        assert decrypt_secret(case["stored"], ring) == case["plaintext"], case
        assert case["stored"].startswith(ENCRYPTED_PREFIX)


def test_kid_tags_are_stable_and_match_the_fingerprint_contract() -> None:
    """`_kid` == sha256(canonical padded key)[:8] — locked to the reference implementation's."""
    assert _key_tag(_normalize_fernet_key(PRIMARY).decode("ascii")) == PRIMARY_TAG
    assert _key_tag(_normalize_fernet_key(PREVIOUS).decode("ascii")) == PREVIOUS_TAG
    ring = _ring()
    assert ring.primary_tag == PRIMARY_TAG
    for case in VECTORS:
        if case["layer"] != "value":
            continue
        expected = PRIMARY_TAG if case["key_role"] != "previous" else PREVIOUS_TAG
        assert case["wrapped"][KEY_ID_MARKER] == expected, case


def test_golden_ciphertexts_from_the_previous_key_decrypt_via_the_ring() -> None:
    ring = _ring()
    only_primary = SecretCipher(PRIMARY, previous=[])
    for case in VECTORS:
        if case["key_role"] != "previous":
            continue
        assert ring.decrypt_value(case["wrapped"], context=case["context"]) == case["plaintext"]
        with pytest.raises(ValueError, match="could not be decrypted"):
            only_primary.decrypt_value(case["wrapped"], context=case["context"])


# ---------------------------------------------------------------------------
# 2. Rotation ring — directionality, dedupe, wrong key
# ---------------------------------------------------------------------------

def test_primary_encrypts_only_previous_decrypts_only() -> None:
    sealed_by_previous = SecretCipher(PREVIOUS, previous=[])
    ring = _ring()
    wrapped = sealed_by_previous.encrypt_value("old", context="row-1")
    assert wrapped[KEY_ID_MARKER] == PREVIOUS_TAG
    assert ring.decrypt_value(wrapped, context="row-1") == "old"

    fresh = ring.encrypt_value("new", context="row-1")
    assert fresh[KEY_ID_MARKER] == PRIMARY_TAG
    with pytest.raises(ValueError, match="could not be decrypted"):
        SecretCipher(PREVIOUS, previous=[]).decrypt_value(fresh, context="row-1")


def test_wrong_key_raises_never_garbage() -> None:
    unrelated = SecretCipher("m" * 43 + "=", previous=[])
    ring = _ring()
    wrapped = ring.encrypt_value("secret", context=None)
    with pytest.raises(ValueError, match="could not be decrypted"):
        unrelated.decrypt_value(wrapped)


def test_previous_list_dedupes_and_rejects_self_rotation_mistakes() -> None:
    ring = SecretCipher(PRIMARY, previous=[PREVIOUS, PREVIOUS, PRIMARY])
    assert ring.decrypt_value(ring.encrypt_value("x")) == "x"
    with pytest.raises(ValueError):
        SecretCipher("short", previous=[])  # not key material


def test_string_layer_rotation_ring() -> None:
    sealed_old = f"{ENCRYPTED_PREFIX}{SecretCipher(PREVIOUS, previous=[]).encrypt_raw('old')}"
    assert decrypt_secret(sealed_old, _ring()) == "old"
    with pytest.raises(ValueError, match="could not be decrypted"):
        decrypt_secret(sealed_old, SecretCipher(PRIMARY, previous=[]))


# ---------------------------------------------------------------------------
# 3. Context binding (cut-and-paste rejection)
# ---------------------------------------------------------------------------

def test_context_mismatch_rejected() -> None:
    ring = _ring()
    wrapped = ring.encrypt_value("patient-secret", context="integration-A")
    with pytest.raises(ValueError, match="different context"):
        ring.decrypt_value(wrapped, context="integration-B")
    # same context and the no-context decrypt path pass
    assert ring.decrypt_value(wrapped, context="integration-A") == "patient-secret"
    assert ring.decrypt_value(wrapped) == "patient-secret"


def test_contextless_values_stay_contextless() -> None:
    ring = _ring()
    wrapped = ring.encrypt_value("v", context=None)
    assert ring.decrypt_value(wrapped, context="anything") == "v"


# ---------------------------------------------------------------------------
# 4. Plaintext flag & tamper case (the named integrity tradeoff)
# ---------------------------------------------------------------------------

def test_tamper_case_tolerant_reads_accept_swapped_plaintext_strict_rejects() -> None:
    """A DB writer swaps an envelope for chosen plaintext: tolerant reads
    accept it verbatim (Fernet authentication bypassed — module docstring),
    strict reads raise. The tradeoff is pinned; production flips strict
    after the backfill."""
    ring = _ring()
    swapped = "attacker-known-webhook-secret"
    assert ring.decrypt_value(swapped) == swapped  # tolerant default
    with pytest.raises(ValueError, match="plaintext tolerance is off"):
        ring.decrypt_value(swapped, allow_plaintext_read=False)
    # empties pass through in both modes
    empties: tuple[object, ...] = (None, "", {}, [])
    for empty in empties:
        assert ring.decrypt_value(empty, allow_plaintext_read=False) == empty
    # string layer mirrors it
    assert decrypt_secret(swapped, ring) == swapped
    with pytest.raises(ValueError, match="plaintext tolerance is off"):
        decrypt_secret(swapped, ring, allow_plaintext_read=False)


def test_encrypt_secret_dev_fallback_and_strict_write() -> None:
    assert encrypt_secret("plain", None, allow_plaintext_write=True) == "plain"
    with pytest.raises(RuntimeError, match="Refusing to store"):
        encrypt_secret("plain", None, allow_plaintext_write=False)
    assert encrypt_secret(None, None, allow_plaintext_write=True) is None
    assert encrypt_secret("", None, allow_plaintext_write=True) == ""


# ---------------------------------------------------------------------------
# 5. Weak / missing keys (composes with the KeyRing boot guard)
# ---------------------------------------------------------------------------

def test_missing_or_malformed_key_material_refused() -> None:
    with pytest.raises(RuntimeError, match="DATA_KEY is not configured"):
        SecretCipher(None)
    for bad in ("short", "not-base64!!!", "AAAA"):  # wrong decoded length
        with pytest.raises(ValueError):
            SecretCipher(bad, previous=[])


def test_unpadded_token_spelling_produces_the_same_kid() -> None:
    """The kit's token_urlsafe spelling normalizes to the padded form —
    same key bytes, same ciphertext format, same _kid."""
    import base64

    unpadded = base64.urlsafe_b64encode(bytes([0x11] * 32)).decode("ascii").rstrip("=")
    assert SecretCipher(unpadded, previous=[]).primary_tag == PRIMARY_TAG


# ---------------------------------------------------------------------------
# 6. No secret material in repr/str/logs/exceptions
# ---------------------------------------------------------------------------

def test_no_key_or_plaintext_leaks_in_repr_logs_or_errors(caplog: pytest.LogCaptureFixture) -> None:
    ring = _ring()
    plaintext = "super-secret-value-12345"
    wrapped = ring.encrypt_value(plaintext, context="row-1")
    assert plaintext not in repr(ring)
    assert PRIMARY not in repr(ring)
    for bad_input in ({"_encrypted": "garbage-not-a-token"},):
        with pytest.raises(ValueError) as excinfo:
            ring.decrypt_value(bad_input, allow_plaintext_read=False)
        message = str(excinfo.value)
        assert plaintext not in message
        assert PRIMARY not in message
        assert "garbage-not-a-token" not in message
    # the dev-fallback warning names no values
    encrypt_secret(plaintext, None, allow_plaintext_write=True)
    assert plaintext not in caplog.text
    assert wrapped[SECRET_MARKER]


# ---------------------------------------------------------------------------
# misc invariants
# ---------------------------------------------------------------------------

def test_is_encrypted_and_mask_marker_shapes() -> None:
    assert is_encrypted(f"{ENCRYPTED_PREFIX}abc")
    assert not is_encrypted("abc")
    assert not is_encrypted("")
    assert not is_encrypted(None)
    assert MASK_MARKER == "***"


def test_wrapper_shape_is_exactly_the_frozen_format() -> None:
    wrapped = _ring().encrypt_value("v", context="c")
    assert set(wrapped) == {SECRET_MARKER, KEY_ID_MARKER}
    assert wrapped[SECRET_MARKER].startswith("gAAAAA")  # Fernet version byte
