# Opaque credentials (`nx_auth.opaque`)

The family's **opaque** credentials — personal access tokens, feed tokens,
capture tokens — are not JWTs. They are high-entropy random secrets whose
only persisted form is a SHA-256 digest, optionally with a short **lookup
prefix** so a verifier can find the row before comparing digests (plan 60
D3, contract §8; the `pat` token kind is already law).

Three products hand-roll this today; `nx_auth.opaque` is the one
implementation. It owns the **byte format, the digest and the constant-time
comparison** — and nothing else.

## Surface

| Function | Purpose |
|---|---|
| `mint(*, brand=None, prefix_bytes=6) -> (plaintext, prefix \| None, sha256_hash)` | Mint one credential |
| `parse(bearer, *, brand=None, prefix_bytes=6) -> (prefix \| None, sha256_hash) \| None` | Split a presented value into its lookup prefix and digest |
| `verify(stored_hash, presented_hash) -> bool` | Constant-time digest comparison |

## Format

**Branded** (health — `brand="ha_pat"`, `prefix_bytes=6`):

```
ha_pat_<12 lowercase hex>_<token_urlsafe(32)>
       └─ lookup prefix ─┘ └─ secret ──────┘
```

- The brand carries **no trailing underscore**; the kit inserts the
  separators: `f"{brand}_{prefix}_{secret}"`. `mint` and `parse` reject a
  brand ending in `_` with `ValueError`: health's `PAT_TOKEN_PREFIX`
  constant includes its separator (`"ha_pat_"`), and passing it unchanged
  would mint `ha_pat__<prefix>_<secret>` — unparseable under the real
  brand. Pass the label (`"ha_pat"`), not the prefix constant.
- The prefix is `secrets.token_hex(6)` — 6 CSPRNG bytes, 12 lowercase hex
  characters — returned **separately** so the product stores it in its
  indexed prefix column.
- The secret is `secrets.token_urlsafe(32)` (32 bytes ⇒ 43 URL-safe
  characters, alphabet `A–Z a–z 0–9 - _`).

**Brandless** (career, study — `mint()`):

```
<token_urlsafe(32)>
```

No brand, no prefix segment, no prefix column. The plaintext *is* the
secret; `parse` answers `(None, digest)`.

The digest is `sha256(plaintext).hexdigest()` over the **full** plaintext —
brand, prefix and secret included — never over the secret alone. A value
minted by one product shape never matches a row of the other.

## Hash at rest

The product owns storage: its table, its prefix column, its revocation
state, unique index and migrations. The only form that may be stored is
the returned `sha256_hash` (and, for health, the `prefix`). The plaintext
is returned to the caller exactly once and is not recoverable afterwards.

```python
# health — prefix lookup, then constant-time digest compare
plaintext, prefix, digest = mint(brand="ha_pat")
row = session.scalar(select(ApiToken).where(ApiToken.token_prefix == prefix))
if row is None or not verify(row.token_hash, digest) or not row.is_live:
    return None

# career / study — digest-only lookup
plaintext, _, digest = mint()
row = session.scalar(select(CaptureToken).where(CaptureToken.token_hash == digest))
```

A digest-only lookup is a database equality compare on a 256-bit value: it
is safe by construction (an attacker cannot produce a preimage), and the
kit's `verify` exists for the prefix-lookup path, where a prefix collision
is expected by design and the final compare must be constant-time.

## Parse strictness

`parse` is **format-only and strict**. With a `brand` it requires exactly:

1. the exact brand followed by `_`;
2. exactly `2 * prefix_bytes` characters, all **lowercase** hex (`0–9a–f`);
3. `_`;
4. a **non-empty** secret inside the URL-safe alphabet (`A–Z a–z 0–9 - _`).

Anything else — wrong brand, wrong width, uppercase or non-hex prefix, an
empty prefix, a missing separator, an empty secret, a non-URL-safe secret —
answers `None`. It does not accept an arbitrary non-empty prefix, which is
the one behavior change for health: its pre-adoption `token_prefix_of`
returned whatever sat between the first two underscores, so a malformed
bearer could be recorded with a junk prefix. With `parse` such a bearer is
rejected before any audit record or query.

Without a brand, any non-blank value answers `(None, digest)` and blank
values answer `None`. A non-`str` value (`None`, bytes, a header object)
also answers `None`: `parse` is total over untrusted input and never
raises `AttributeError`. The digest is computed over the value exactly as
presented — callers trim transport whitespace first, and a padded value
simply never matches a stored digest.

`parse` applies **no length policy** on the secret and decides nothing
about liveness, ownership, scope or revocation. Hosts cap request size;
the product applies its own policy after the lookup.

## Verify

`verify(stored_hash, presented_hash)` is `hmac.compare_digest` over the two
digests: constant-time, never a plaintext comparison, never `==`. An empty
digest on either side answers `False`, so a missing stored hash cannot
match a missing presented one. A comparison `hmac.compare_digest` cannot
perform — non-ASCII text, bytes against text — also answers `False`:
`verify` is total and fail-closed, never raising out of the auth path. It
compares what it is handed — callers pass the digest from `parse`, not a
credential.

## What the product keeps

The kit deliberately stops at the bytes. Each product keeps:

| Concern | Owner |
|---|---|
| Brand, prefix width, token label | product |
| Table, prefix column, unique index, migrations | product |
| Tenant / role / permission / patient scope | product |
| Audit events, last-used stamping, revocation, expiry | product |
| Rotate-and-retire hand-off, list/revoke UI | product |
| Rate limits and refusal matrix | product |
| Byte format, SHA-256 digest, constant-time compare | **kit** |

There is no `intersect` here, no permission model, no tenant filter, no
audit sink and no key material: an opaque credential is pure CSPRNG output
with a plain digest, so there is nothing to sign, encrypt or derive from a
key, and this module never loads a key ring or touches a signing key.

### Adoption notes

**health (branded adopter).** `mint(brand="ha_pat")` reproduces
`ha_pat_<12 hex>_<token_urlsafe(32)>` exactly; keep the prefix column.
Replace the local `generate_token`/`hash_token`/`token_prefix_of` with
`mint`/`parse`/`verify`. **Keep the existing `.strip()`** of the incoming
bearer and pass the **stripped** value to `parse` —
`parse(value.strip(), brand="ha_pat")` — because the digest is computed
over exactly what `parse` receives; parsing the raw padded header would
never match a stored digest. The brand argument is the bare `"ha_pat"`
label, not health's `PAT_TOKEN_PREFIX == "ha_pat_"`: the latter ends in
`_` and is rejected with `ValueError` (it would mint
`ha_pat__<prefix>_<secret>`). `parse` replaces both the lookup-segment
extraction and the digest, so `resolve_principal` keeps one prefix query
and one constant-time compare.

Behavior delta to record for the **security team**: malformed bearers no
longer yield an arbitrary prefix. The `api_token.denied` audit row's
`token_prefix` is now **`null`** for such a bearer (health previously
stored whatever sat between the first two underscores), so audit queries,
dashboards and any non-null assumption on `token_prefix` must tolerate
`null`; no lookup or audit record ever carries a junk prefix.

**career / study (brandless adopters).** `mint()` + `verify()`/digest
equality reproduce `token_urlsafe(32)` + `sha256` with no schema change,
no prefix column and no dual lookup. `parse` is available for the
`(None, digest)` shape but not needed by a digest-only resolver.

Prefix-lookup conformance for career/study is a **separate migration
plan** — not part of the opaque core, and not implied by adopting it.

## Security invariants (test-pinned)

1. The plaintext is CSPRNG output: `token_hex(prefix_bytes)` for the prefix
   and `token_urlsafe(32)` for the secret — never a counter, timestamp,
   UUID or derived value.
2. The stored form is a SHA-256 digest of the full plaintext; no plaintext
   is stored, logged, returned by `parse`, or included in an exception.
3. `verify` delegates to `hmac.compare_digest` and is never a plaintext
   comparison or `==`; two empty digests are not a match, and a comparison
   that raises (non-ASCII text, mismatched types) is a `False`. Both
   `parse` and `verify` are total: they answer `None`/`False` instead of
   raising on malformed input.
4. A branded `parse` accepts only the exact generated shape — exact width,
   lowercase hex, URL-safe non-empty secret — so no arbitrary prefix
   reaches a lookup or an audit record.
5. No key material, storage, tenant, database, audit or policy module is
   imported: the module imports only `hashlib`, `hmac` and `secrets`.
6. Every mint is unique; a collision in the prefix segment is expected and
   resolved by the constant-time digest compare, not by trusting the prefix.

**Rollback.** The module is additive — remove it; no product schema or
format changes when it is absent.
