"""``nx_auth.opaque`` — the opaque credential core (plan 60 D3).

Pins the frozen interface and the formats both adopter shapes rely on:
health's golden ``ha_pat_<12 lowercase hex>_<token_urlsafe(32)>``, the
brandless ``token_urlsafe(32)`` used by career and study, the exact-width
lowercase-hex prefix, strict parsing (a wrong brand, width, alphabet or a
missing segment is ``None`` — never an arbitrary prefix), the digest
computed over the **full** plaintext, uniqueness of every minted value, and
a ``verify`` that delegates to ``hmac.compare_digest`` over digests instead
of comparing plaintext (or strings with ``==``).

The module is also pinned as *policy-free*: it imports nothing but
``hashlib``, ``hmac`` and ``secrets`` — no storage, tenant, key or logging
module can sneak in behind the contract.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import inspect
import re
import secrets
from pathlib import Path

import pytest

import nx_auth.opaque as opaque

HEALTH_BRAND = "ha_pat"
HEALTH_RE = r"^ha_pat_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$"
BRANDLESS_RE = r"^[A-Za-z0-9_-]{43}$"
HEX64_RE = r"^[0-9a-f]{64}$"
LOWER_HEX = frozenset("0123456789abcdef")

_module_file = getattr(opaque, "__file__", None)
assert _module_file is not None
MODULE_SOURCE = Path(_module_file).read_text(encoding="utf-8")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_branded(value: str) -> tuple[str | None, str]:
    parsed = opaque.parse(value, brand=HEALTH_BRAND)
    assert parsed is not None
    return parsed


# --- mint: format, entropy, prefix ---------------------------------------


def test_health_golden_format() -> None:
    plaintext, prefix, digest = opaque.mint(brand=HEALTH_BRAND)

    match = re.fullmatch(HEALTH_RE, plaintext)
    assert match is not None, plaintext
    assert match.group(1) == prefix
    assert len(prefix or "") == 12
    assert re.fullmatch(HEX64_RE, digest) is not None
    assert digest == _sha256(plaintext)


def test_brandless_format() -> None:
    plaintext, prefix, digest = opaque.mint()

    assert prefix is None
    assert re.fullmatch(BRANDLESS_RE, plaintext) is not None
    assert digest == _sha256(plaintext)


@pytest.mark.parametrize("prefix_bytes", [1, 4, 6, 12, 16])
def test_prefix_width_and_hex(prefix_bytes: int) -> None:
    plaintext, prefix, _digest_value = opaque.mint(
        brand=HEALTH_BRAND, prefix_bytes=prefix_bytes
    )

    assert prefix is not None
    assert len(prefix) == 2 * prefix_bytes
    assert set(prefix) <= LOWER_HEX
    secret = plaintext[len(f"{HEALTH_BRAND}_{prefix}_") :]
    assert secret
    assert plaintext == f"{HEALTH_BRAND}_{prefix}_{secret}"


def test_mint_with_fixed_entropy_pins_the_golden_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deterministic mint: the exact bytes health/career/study will store."""
    monkeypatch.setattr(secrets, "token_hex", lambda n: "ab" * n)
    monkeypatch.setattr(secrets, "token_urlsafe", lambda n: "A" * 43)

    branded, prefix, digest = opaque.mint(brand=HEALTH_BRAND)
    assert branded == "ha_pat_abababababab_" + "A" * 43
    assert prefix == "abababababab"
    assert digest == _sha256(branded)

    plain, no_prefix, plain_digest = opaque.mint()
    assert plain == "A" * 43
    assert no_prefix is None
    assert plain_digest == _sha256(plain)


def test_secret_segment_entropy_and_uniqueness() -> None:
    seen_plaintexts: set[str] = set()
    seen_hashes: set[str] = set()
    seen_prefixes: set[str] = set()
    for _ in range(500):
        plaintext, prefix, digest = opaque.mint(brand=HEALTH_BRAND)
        matching = re.fullmatch(HEALTH_RE, plaintext)
        assert matching is not None
        secret = matching.group(2)
        assert secret.isascii()
        assert len(secret) >= 43
        assert prefix != secret
        seen_plaintexts.add(plaintext)
        seen_hashes.add(digest)
        if prefix is not None:
            seen_prefixes.add(prefix)

    assert len(seen_plaintexts) == 500
    assert len(seen_hashes) == 500
    # A prefix is only 48 bits: a collision is expected by design (the digest
    # compare resolves it), so this bounds the count instead of requiring
    # every prefix to be distinct.
    assert len(seen_prefixes) >= 495


def test_brandless_mints_are_unique() -> None:
    values = [opaque.mint()[0] for _ in range(500)]
    assert len(set(values)) == 500


def test_mint_rejects_arguments_that_cannot_parse() -> None:
    with pytest.raises(ValueError):
        opaque.mint(prefix_bytes=0)
    with pytest.raises(ValueError):
        opaque.mint(prefix_bytes=-1)
    with pytest.raises(ValueError):
        opaque.mint(brand="")
    with pytest.raises(ValueError):
        opaque.parse("whatever", brand="")
    with pytest.raises(ValueError):
        opaque.parse("whatever", prefix_bytes=0)


@pytest.mark.parametrize("brand", ["ha_pat_", "_", "career_token__"])
def test_trailing_underscore_brand_is_rejected(brand: str) -> None:
    """The kit inserts the separators: a trailing ``_`` mints ``brand__``."""
    with pytest.raises(ValueError):
        opaque.mint(brand=brand)
    with pytest.raises(ValueError):
        opaque.parse("whatever", brand=brand)


def test_trailing_underscore_brand_error_carries_no_credential_material() -> None:
    with pytest.raises(ValueError) as error:
        opaque.mint(brand="ha_pat_")
    assert "ha_pat" not in str(error.value)


# --- parse: strict, format-only ------------------------------------------


def test_parse_branded_round_trip() -> None:
    plaintext, prefix, digest = opaque.mint(brand=HEALTH_BRAND)

    assert opaque.parse(plaintext, brand=HEALTH_BRAND) == (prefix, digest)


def test_parse_accepts_urlsafe_secret_with_separators() -> None:
    prefix = "0123456789ab"
    plaintext = f"{HEALTH_BRAND}_{prefix}_a-b_C-D_9"

    assert opaque.parse(plaintext, brand=HEALTH_BRAND) == (prefix, _sha256(plaintext))


def test_parse_brandless_returns_none_prefix() -> None:
    plaintext, _prefix, digest = opaque.mint()

    assert opaque.parse(plaintext) == (None, digest)


def test_parse_brandless_does_not_trim() -> None:
    padded = "  " + "A" * 43 + "  "

    assert opaque.parse(padded) == (None, _sha256(padded))


@pytest.mark.parametrize("blank", ["", " ", "   ", "\t", "\n ", " \r\n"])
def test_parse_rejects_blank(blank: str) -> None:
    assert opaque.parse(blank) is None
    assert opaque.parse(blank, brand=HEALTH_BRAND) is None


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="none"),
        pytest.param(b"", id="empty-bytes"),
        pytest.param(b"ha_pat_0123456789ab_" + b"A" * 43, id="branded-bytes"),
        pytest.param(bytearray(b"A" * 43), id="bytearray"),
        pytest.param(123, id="int"),
        pytest.param(object(), id="object"),
    ],
)
def test_parse_rejects_non_str_without_raising(value: object) -> None:
    assert opaque.parse(value) is None  # type: ignore[arg-type]
    assert opaque.parse(value, brand=HEALTH_BRAND) is None  # type: ignore[arg-type]


INVALID_BRANDED = [
    pytest.param("hb_pat_0123456789ab_" + "A" * 43, id="wrong-brand"),
    pytest.param("hap at_0123456789ab_" + "A" * 43, id="brand-with-space"),
    pytest.param("ha_pat0123456789ab_" + "A" * 43, id="missing-brand-separator"),
    pytest.param("ha_pat_0123456789AB_" + "A" * 43, id="uppercase-hex"),
    pytest.param("ha_pat_0123456789az_" + "A" * 43, id="non-hex"),
    pytest.param("ha_pat_0123456789a_" + "A" * 43, id="prefix-too-short"),
    pytest.param("ha_pat_0123456789abc_" + "A" * 43, id="prefix-too-long"),
    pytest.param("ha_pat__" + "A" * 43, id="empty-prefix"),
    pytest.param("ha_pat_0123456789ab_", id="missing-secret"),
    pytest.param("ha_pat_0123456789ab", id="missing-secret-separator"),
    pytest.param("ha_pat", id="brand-only"),
    pytest.param("ha_pat_", id="brand-and-underscore"),
    pytest.param("ha_pat_0123456789ab_se cret", id="secret-with-space"),
    pytest.param("ha_pat_0123456789ab_sec+ret", id="secret-not-urlsafe"),
    pytest.param("ha_pat_0123456789ab_sec/ret", id="secret-with-slash"),
    pytest.param("A" * 43, id="brandless-value"),
    pytest.param("x" * 100_000, id="oversize-garbage"),
]


@pytest.mark.parametrize("bearer", INVALID_BRANDED)
def test_parse_branded_rejects_malformed(bearer: str) -> None:
    assert opaque.parse(bearer, brand=HEALTH_BRAND) is None


def test_parse_has_no_secret_length_policy() -> None:
    """The core owns the shape, not a cap: hosts cap the request size."""
    prefix = "0123456789ab"
    long_secret = "A" * 5000

    assert opaque.parse(f"{HEALTH_BRAND}_{prefix}_{long_secret}", brand=HEALTH_BRAND) == (
        prefix,
        _sha256(f"{HEALTH_BRAND}_{prefix}_{long_secret}"),
    )


def test_parse_requires_the_minted_prefix_width() -> None:
    plaintext, _prefix, _digest_value = opaque.mint(brand=HEALTH_BRAND, prefix_bytes=4)

    assert opaque.parse(plaintext, brand=HEALTH_BRAND, prefix_bytes=4) is not None
    assert opaque.parse(plaintext, brand=HEALTH_BRAND) is None
    assert opaque.parse(plaintext, brand=HEALTH_BRAND, prefix_bytes=8) is None


def test_parse_never_raises_on_arbitrary_input() -> None:
    for bearer in ["\x00", "ha_pat_\x00_" + "A" * 43, "😀" * 10, "a" * 10_000, "_-_"]:
        assert opaque.parse(bearer, brand=HEALTH_BRAND) is None


def test_parse_is_format_only_not_liveness() -> None:
    plaintext, prefix, digest = opaque.mint(brand=HEALTH_BRAND)
    other = opaque.mint(brand=HEALTH_BRAND)

    parsed = _parse_branded(plaintext)
    assert parsed == (prefix, digest)
    assert opaque.verify(parsed[1], _parse_branded(other[0])[1]) is False


# --- digest stability and rotation hand-off -------------------------------


def test_hash_stability() -> None:
    first = opaque.parse("A" * 43)
    second = opaque.parse("A" * 43)
    third = opaque.parse("A" * 44)

    assert first is not None
    assert second is not None
    assert third is not None
    assert first == second
    assert first != third
    assert first[1] == _sha256("A" * 43)


def test_rotation_hand_off_verifies_only_the_new_digest() -> None:
    old_plaintext, old_prefix, old_digest = opaque.mint(brand=HEALTH_BRAND)
    new_plaintext, new_prefix, new_digest = opaque.mint(brand=HEALTH_BRAND)

    stored_column = new_digest
    assert opaque.verify(stored_column, _parse_branded(new_plaintext)[1]) is True

    stale = _parse_branded(old_plaintext)
    assert opaque.verify(stored_column, stale[1]) is False
    assert old_prefix != new_prefix
    assert old_digest != new_digest


# --- verify: constant-time over digests ---------------------------------


def test_verify_compares_digests_via_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def fake(stored: str, presented: str) -> bool:
        calls.append((stored, presented))
        return False

    monkeypatch.setattr(hmac, "compare_digest", fake)

    digest = opaque.mint()[2]
    assert opaque.verify(digest, digest) is False
    assert calls == [(digest, digest)]


def test_verify_accepts_equal_and_rejects_different() -> None:
    digest = opaque.mint()[2]
    other = opaque.mint()[2]

    assert opaque.verify(digest, digest) is True
    assert opaque.verify(digest, other) is False
    assert opaque.verify(digest, digest[:-1]) is False
    assert opaque.verify(digest, digest.upper()) is False


@pytest.mark.parametrize("presented", ["", " "])
def test_verify_rejects_empty_presented(presented: str) -> None:
    assert opaque.verify(opaque.mint()[2], presented) is False


def test_verify_rejects_two_empty_digests() -> None:
    assert opaque.verify("", "") is False


@pytest.mark.parametrize("presented", ["é", "pässwort", "🔑" + "A" * 40])
def test_verify_rejects_non_ascii_without_raising(presented: str) -> None:
    """``hmac.compare_digest`` raises on non-ASCII; the contract is bool."""
    digest = opaque.mint()[2]

    assert opaque.verify(digest, presented) is False


def test_verify_rejects_non_ascii_on_both_sides() -> None:
    assert opaque.verify("é", "é") is False


def test_verify_fails_closed_when_compare_digest_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(stored: str, presented: str) -> bool:
        raise TypeError("cannot compare")

    monkeypatch.setattr(hmac, "compare_digest", boom)

    digest = opaque.mint()[2]
    assert opaque.verify(digest, digest) is False


def test_verify_never_matches_a_plaintext_against_a_digest() -> None:
    """``verify`` takes the digests ``parse`` produced — never the credential."""
    plaintext, _prefix, digest = opaque.mint(brand=HEALTH_BRAND)

    assert opaque.verify(plaintext, digest) is False
    assert opaque.verify(digest, plaintext) is False
    assert opaque.verify(digest, _parse_branded(plaintext)[1]) is True


# --- no plaintext, no policy, no key material ---------------------------


def test_argument_errors_carry_no_credential_material() -> None:
    with pytest.raises(ValueError) as mint_error:
        opaque.mint(brand="")
    with pytest.raises(ValueError) as parse_error:
        opaque.parse("ha_pat_0123456789ab_" + "A" * 43, prefix_bytes=0)

    for message in (str(mint_error.value), str(parse_error.value)):
        assert "ha_pat" not in message
        assert "A" * 43 not in message
        assert len(message) < 200


def test_public_surface_is_exactly_three_functions() -> None:
    assert opaque.__all__ == ["mint", "parse", "verify"]
    assert callable(opaque.mint)
    assert callable(opaque.parse)
    assert callable(opaque.verify)


def test_module_imports_only_hashing_and_entropy() -> None:
    tree = ast.parse(MODULE_SOURCE)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module not in (None, "__future__"):
            imported.add(node.module.split(".")[0])

    assert imported == {"hashlib", "hmac", "secrets"}


def test_module_touches_no_storage_or_key_surface() -> None:
    tree = ast.parse(MODULE_SOURCE)
    names: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)

    assert names.isdisjoint({"open", "environ", "getenv", "load_for", "get_password"})
    assert attributes.isdisjoint({"getenv", "environ", "load_for", "get_password"})
    assert "logger" not in names


def test_interface_signature_is_keyword_branded() -> None:
    mint_params = inspect.signature(opaque.mint).parameters
    parse_params = inspect.signature(opaque.parse).parameters
    verify_params = inspect.signature(opaque.verify).parameters

    assert list(mint_params) == ["brand", "prefix_bytes"]
    assert mint_params["brand"].kind is inspect.Parameter.KEYWORD_ONLY
    assert mint_params["brand"].default is None
    assert mint_params["prefix_bytes"].default == 6
    assert list(parse_params) == ["bearer", "brand", "prefix_bytes"]
    assert parse_params["bearer"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parse_params["brand"].kind is inspect.Parameter.KEYWORD_ONLY
    assert list(verify_params) == ["stored_hash", "presented_hash"]


def test_product_shapes_round_trip() -> None:
    """The three adopter shapes, end to end, with no product policy."""
    health = opaque.mint(brand=HEALTH_BRAND)
    career = opaque.mint()
    study = opaque.mint()

    health_parsed = _parse_branded(health[0])
    career_parsed = opaque.parse(career[0])
    study_parsed = opaque.parse(study[0])

    assert health_parsed[0] == health[1]
    assert career_parsed is not None and career_parsed[0] is None
    assert study_parsed is not None and study_parsed[0] is None
    assert opaque.verify(health[2], health_parsed[1])
    assert opaque.verify(career[2], career_parsed[1])
    assert opaque.verify(study[2], study_parsed[1])
