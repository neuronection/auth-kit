# Secret store + resolver (`nx_auth.secrets`)

One façade for "where does this named secret live?" — the store study
owns and the resolver health asks. A product names a
*slot* and a keyring *service*; the kit picks the best backend that
actually works, seals what it stores and never invents a value.

The product keeps its policy: slot grammars, service names, env
prefixes, value caps, normalization and every typed refusal at the call
site. The kit keeps storage, resolution, redaction and the backend
probe.

## Surface

| Function | Purpose |
|---|---|
| `get(slot, *, service, env_prefix=None, store_path=None, required=False, sealer=None) -> str \| None` | Resolve a slot (resolver surface) |
| `await get_async(...)` | `get` on a worker thread — same parameters, same contract |
| `set(slot, value, *, service, env_prefix=None, store_path=None, sealer=None)` | Store a value, sealed when a sealer is given |
| `delete(slot, *, service, env_prefix=None, store_path=None, sealer=None)` | Remove a slot from the selected backend and the sealed file |
| `probe(*, service, env_prefix=None, store_path=None, sealer=None)` | Round-trip the writable backend, or raise |
| `backend_name(*, service, env_prefix=None, store_path=None) -> str` | `keyring` \| `file` \| `none` — never `env` |
| `reset_caches()` | Forget the selected backend(s); the next call re-probes |
| `cipher(*, data_key, previous=()) -> SecretCipher` | The at-rest cipher over injected key material |
| `redact_secret(text, secret, *, cap=400) -> str` | Mask a secret out of an upstream message |

Errors: `SecretNotFound`, `SecretUndecryptable`, `SecretStoreUnavailable`
(all under `SecretError`). `env_prefix` / `sealer` are accepted on the
calls that ignore them so one signature serves both surfaces.

Frozen values (a compatibility test pins them):

| Product | `service` | `env_prefix` | `store_path` |
|---|---|---|---|
| study | `StudyAssistant` | `None` | `<data_dir>/secrets.json` |
| health seed sources | `health-assistant/seed-sources` | `HA_SEED_SOURCE_SECRET` | `None` |
| health tenant SSO | `health-assistant/tenant-sso` | `HA_SSO_CLIENT_SECRET` | `None` |

## Precedence

```
selected keyring  →  sealed file (store_path)  →  <env_prefix>_<SLOT>
```

- **The keyring is trusted only after a round-trip probe** (write, read
  back, delete). `keyring.backends.null` accepts writes and silently
  discards them; a read-only backend and a locked Secret Service fail the
  same way. A backend that does not round-trip is never selected —
  silently losing a credential is worse than refusing to store it. Each
  probe uses a random per-process ref (`__backend_probe__<pid>_<hex>`),
  never a fixed slot name, so a host value called `__backend_probe__` is
  not touched.
- Selection is memoized per process, per `(service, store_path)`, and
  cleared by `reset_caches()`.
- The **environment is read-only** and is never reported by
  `backend_name()`: `none` with a working env fallback is a normal health
  deployment. `env_prefix=None` disables the fallback (study's
  no-plaintext-fallback doctrine).
- The sealed file is read whenever `store_path` is given, even when it is
  not the writable backend — a read-only mount still serves existing
  secrets, and only writes need the probe.
- **The environment never shadows a stored value.** A stored-but-
  undecryptable envelope fails closed (`None`, or `SecretUndecryptable`
  with `required=True`) instead of quietly resolving from the env.

## Backends

**Keyring** — `keyring.get_password(service, slot)` under the product's
service name. The package is **optional at runtime**: a missing (or
import-broken) `keyring` selects `none` without raising. Reads never
raise — a backend that locks after selection falls through to the next
source. Entry names are slots; values are `enc::` envelopes.

**Sealed file** — `store_path`, a flat JSON map
`{"<slot>": "enc::<fernet-token>"}` (exactly study's `secrets.json`
shape, so a pre-adoption file resolves unchanged). Writes use an
exclusive `mkstemp` temp file (created `0600`, no symlink following) in
the store directory, fsync the fd, then `os.replace` — atomic, no
predictable `<store>.tmp`, and serialized under a lock. The mode is
`0600` on every write, and a pre-existing group/world-readable file is
repaired on read. The first resolution creates an empty file when this
backend is selected. One writer per file is assumed.

**Environment** — `<env_prefix>_<SLOT>`, the slot folded with every
non-alphanumeric run → `_`, uppercased, byte-identical to health's
deployed `HA_SEED_SOURCE_SECRET_<SLOT>` / `HA_SSO_CLIENT_SECRET_<SLOT>`
names. Pass the prefix **without** a trailing underscore; the kit adds
it. Values are returned verbatim (deployment-provided plaintext, never a
store).

## Key material is injected

`cipher(data_key, previous)` wraps `nx_auth.atrest.SecretCipher` — one
cipher, no fork. The host builds the sealer from its own §8 resolution
(study: `KeyRing.data_key` + `data_key_previous()`; health:
`SecretCipher.from_settings()`) and passes it as `sealer`.

`nx_auth.secrets` **never** loads a key ring, resolves a `DATA_KEY`,
generates key material, writes `auth_keys.json` or touches a signing key.
It seals and opens strings with the cipher it is handed. Prior keys ride
the ring, so an envelope sealed before a rotation still opens.

## Values

- `set(..., sealer=…)` seals **before** either backend: a keyring entry
  is `enc::`, not plaintext, and a storage dump yields ciphertext.
- `set(..., sealer=None)` stores plaintext. That exists only for
  read-tolerance of pre-adoption stores; it is never a default.
- `get` decrypts `enc::`, returns a legacy plaintext entry verbatim
  (never re-sealed on read, never guessed) and treats an empty stored
  value as absent.
- Nothing writable ⇒ `set`/`delete`/`probe` raise `SecretStoreUnavailable`;
  a write that fails after a passing probe raises the same — no silent
  success and no silent backend switch. `delete` clears the slot from the
  **selected** backend **and** the sealed file (`store_path`) — and from
  nothing else, so a revocation cannot leave the value resolvable through
  the other source. The environment is not deletable (`env_prefix` is
  accepted and ignored), and a keyring that failed its probe was never
  selected: a value already sitting in it is not cleared by `delete` and
  stays in the OS store until it is removed with the keyring's own
  tooling (and the credential is rotated).
- `required=True` turns "missing" into `SecretNotFound` and "cannot open"
  into `SecretUndecryptable`. `required=False` answers `None` for both.

## Redaction

`redact_secret(text, secret, *, cap=400)` replaces every occurrence of
the resolved secret with `***` and caps the result. Call it on any
upstream message (transport errors echo URLs, headers and token-endpoint
error bodies) before it reaches a log line, a `last_error` column or an
API response. It is the kit's single redaction helper — hosts do not keep
their own copy.

## Security invariants (test-pinned)

1. No plaintext in a log record, exception message or returned diagnostic
   — the messages name the service, the slot and the backend only.
2. Values are sealed before storage; the keyring never receives plaintext
   for a sealed write.
3. A null / read-only / locked keyring is never selected; a probe failure
   is non-fatal for `get` (fall through) and fatal for `set` (raise).
4. `backend_name()` never reports `env`; env cannot shadow a stored value.
5. The sealed file is always `0600`; a wider pre-existing mode is
   repaired.
6. No key material is resolved, generated or written by this module.
7. A read is never a write: reads may use a read-only backend, writes
   never fall back to a second backend.

## Adoption notes

**study (store adopter, phase 2).** Replace the private backends in
`backend/app/core/secrets.py` with the kit and keep the thin adapter
(`get_secret` / `set_secret` / `delete_secret` / `store_backend` /
`reset_secret_caches`) so the ~52 call sites and the deployment-mode
tests keep working: `store_path=<data_dir>/secrets.json`,
`env_prefix=None`, `service="StudyAssistant"`,
`sealer=cipher(data_key=keyring().data_key, previous=data_key_previous())`.
The file shape and the `enc::` values are already compatible. Semantic
deltas to review in the adapter: an empty stored value resolves to
`None`, and `delete` on a host with no writable backend raises
`SecretStoreUnavailable` (a revocation that silently did nothing would
leave a credential live).

**health (resolver adopter, phase 2).** Keep the slot guards (SSO
`is_valid_slot`, seed slot normalization/caps) and the typed refusals at
the call sites; the module resolves
`get(slot, service=…, env_prefix="HA_SEED_SOURCE_SECRET" | "HA_SSO_CLIENT_SECRET",
sealer=SecretCipher.from_settings())`. `store_path=None` keeps keyring
and env only; `backend_name()` answers `keyring|none`, which is the
expected pair in Docker (no boot assertion needed). Resolution stays
fail-closed: `None` (or `SecretNotFound`) means the caller raises
`SECRET_MISSING` / `sso_client_secret_missing`.

**Deployment.** `keyring` is a **dev/test extra**, not a runtime
dependency: production hosts may not have it (health's Docker is
env-only). A host that wants the keyring backend installs the package
and lets the probe decide. `uv.lock` is not authoritative for CI — the
gate installs `pip install -e ".[dev]"` and resolves the `keyring`
dev/test extra there, so a lock that predates the extra changes nothing
about what CI runs.

**Rollback.** The module is additive — remove it; no product changed in
the phase that introduced it.
