# At-rest secrets (`nx_auth.atrest`)

One Fernet implementation for secrets at rest: the `DATA_KEY` family —
key material that **encrypts and never signs** (the signing keys live in
[`tokens-and-cookies.md`](tokens-and-cookies.md)). Products import this
module around their own key resolution; nothing here reads Settings,
env vars, or the database on its own.

## Two value shapes

| Shape | Stored form | API | Typical use |
|---|---|---|---|
| Tagged value | `{"_encrypted": "<fernet-token>", "_kid": "<tag>"}` | `SecretCipher.encrypt_value` / `decrypt_value` | JSONB config columns (integration secrets, provider keys) |
| String | `"enc::<fernet-token>"` | `encrypt_secret` / `decrypt_secret` | single-string columns |

## Key model

- **Primary key** (`<P>_DATA_KEY`, or whatever the product's §8
  resolution calls it) — the only key that *encrypts*.
- **Prior keys** (`<P>_DATA_KEY_PREVIOUS`, comma-separated) — accepted
  for *decryption only*, so ciphertext written before a rotation keeps
  decrypting. Duplicate and self-referential entries are ignored.
- **Key spellings** — both the padded `Fernet.generate_key()` form and
  the unpadded 43-character token form are accepted; they are the same
  32 key bytes. The canonical padded spelling is what `_kid` fingerprints
  (see below).
- Weak or malformed key material is refused at cipher construction
  (wrong decoded length raises); strength/placeholder checking for
  operator-supplied keys belongs to the product's key boot guard.

`SecretCipher.from_env("<PREFIX>")` builds the ring from
`<PREFIX>_DATA_KEY` + `<PREFIX>_DATA_KEY_PREVIOUS`; products with their
own config objects construct `SecretCipher(key, previous=[...])` directly.

## `_kid` stability contract

`_kid` is `sha256(canonical_padded_key)[:8]` — a non-secret fingerprint
recording which key sealed a value. **Rotation backfills find stale
values by `_kid`**, so the derivation is part of the stored format: if it
ever changed, every existing tag would stop matching its key and
backfills would silently orphan ciphertext. The golden-vector suite
(`tests/fixtures/atrest_golden_vectors.json`) locks the derivation to
known-good values (`7ab7b6c0`/`753c6837` under the fixed test keys).

## Context binding (cut-and-paste defense)

`encrypt_value(value, context="…")` folds an owner tag (e.g. the
integration id) into the plaintext envelope; `decrypt_value` rejects a
mismatch. This stops an attacker with database write access from copying
one row's secret blob into another row (multi-tenant JSONB columns). A
value sealed *without* context decrypts under any context, preserving
values written before contexts were used. The comparison is
constant-time.

## Rotation runbook

> **Dropping a prior key early is permanent ciphertext loss.** Follow
> the order exactly.

1. Move the current key into `<P>_DATA_KEY_PREVIOUS` (append,
   comma-separated); put the new key in `<P>_DATA_KEY`. New writes now
   seal under the new key; everything old keeps decrypting.
2. Backfill: re-encrypt every stored value whose `_kid` is a prior key's
   fingerprint (tagged values and `enc::` strings alike). Backfills must
   be idempotent — skip or compare `_kid` before re-encrypting each row.
3. **Census gate:** count values per `_kid`. The count for every prior
   key's tag must be **zero** before proceeding.
4. Only then remove the prior key from `<P>_DATA_KEY_PREVIOUS`.
5. Verify: application smoke test + one decrypt probe per secret
   surface (integration config, provider keys).

## Threat model

**Protects against**

- **Database/backup disclosure** — stolen dumps contain only Fernet
  ciphertext; keys live outside the database (env/keyring/secret store).
- **Cut-and-paste replay** — context binding rejects a ciphertext moved
  to a different row/owner.
- **Key rotation data loss** — the `_kid` + prior-key ring lets values
  be re-sealed incrementally without an outage or a flag day.
- **Silent format drift** — golden vectors + `_kid` stability tests fail
  the build if the stored format ever changes.

**Does not protect against**

- **Process memory / runtime compromise** — an attacker inside the app
  process reads plaintext as the app does.
- **Log leakage of plaintext** — this module never logs values, but
  callers can; the no-leak tests cover this module's own surfaces only.
- **Key theft** — the cipher cannot distinguish the legitimate key
  holder from a thief; key storage policy is the product's §8 boot guard.
- **Ciphertext truncation/tampering** — Fernet is authenticated
  (tampering raises), but see the tolerance tradeoff below.

### The plaintext-tolerance tradeoff (integrity)

Fernet authenticates its ciphertext — but a **tolerant read** accepts
un-encrypted values verbatim. A database writer (SQL injection, hostile
backup restore) who swaps a stored secret for chosen plaintext therefore
bypasses that authentication: the application will use the attacker's
value as a "decrypted" secret (e.g. re-point a webhook secret to one the
attacker knows).

`allow_plaintext_read=True` (the default) keeps pre-encryption values
working during migration; `False` raises on any non-empty un-encrypted
value. The same applies to writes (`allow_plaintext_write`, dev/test
fallback only). **Production posture: run the backfill, then flip
strict** — tolerance is a migration affordance, not a steady state.

## API reference

```python
from nx_auth.atrest import (
    SecretCipher, encrypt_secret, decrypt_secret, is_encrypted,
    SECRET_MARKER, KEY_ID_MARKER, ENCRYPTED_PREFIX, MASK_MARKER,
)

cipher = SecretCipher(key, previous=[old_key])     # or SecretCipher.from_env("CAREER")

# tagged values (JSONB columns)
wrapped = cipher.encrypt_value({"token": "s3cret"}, context="integration-42")
# -> {"_encrypted": "gAAAAA…", "_kid": "7ab7b6c0"}
value = cipher.decrypt_value(wrapped, context="integration-42")

# string columns
stored = encrypt_secret("s3cret", cipher)          # -> "enc::gAAAAA…"
plain = decrypt_secret(stored, cipher)
```

- `SecretCipher.encrypt_raw` / `decrypt_raw` expose bare Fernet tokens
  for callers that own their own envelope format.
- `decrypt_value` / `decrypt_secret` accept `allow_plaintext_read=False`
  for strict mode; `encrypt_secret` accepts `allow_plaintext_write=True`
  for the dev/test fallback (logs a loud warning, never in production).
- `MASK_MARKER` (`"***"`) is the client round-trip marker products use
  to mean "keep the stored secret" on update endpoints.

## Maintenance rules

- The stored format is **frozen**: envelope layout, `enc::` prefix,
  `_kid` derivation. New capability goes around the format, never into
  it; golden vectors must keep passing unmodified.
- Never hand-roll encrypt/decrypt in a product — extend this module
  (with tests) instead, so every product inherits the fix.
- Exceptions raised here never contain key material, plaintext, or
  tokens; keep it that way (there are tests).
