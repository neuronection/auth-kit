# Provider-delegation OAuth (`nx_auth.oauth`)

One implementation of delegated-provider OAuth for every Python family
host — study, health, career (plan 52 §13; ADR-0052 §3 + §12; the
posture is ADR-0042 §2/§3/§6 generalized to class D/S). Authorization
code + **PKCE S256** only: bind a provider account the user delegated,
never an app login. The module is **opt-in**, **stdlib-only**, and
performs **no I/O on its own** — network, state persistence, and sealed
persistence are all injected seams, so tests never touch a socket and
hosts keep their own runtimes (health's Redis, study's loopback).

```
host (browser/callback routes — host policy)
  │  authorize() ──▶ AuthorizationOffer(authorize_url, record)
  │  store.consume(state, principal_id=…) ──▶ StateRecord     (single-use, bound)
  │  exchange_code(client, code=…, verifier=record.code_verifier, transport=…)
  │  client.store(binding_id, tokens)                          (sealed)
  └─ TokenClient.access(binding_id) ──▶ live access token       (single-flight)
```

## The four injected seams

| Seam | Protocol | Reference impl | Host plugs |
|---|---|---|---|
| Token endpoint | `TokenTransport` (`post_form`) | — (fakes in `nx_auth.testing`) | a ~10-line httpx adapter (below), or the polite runtime |
| Bind-flow state | `StateStore` (`issue`/`consume`/`discard`) | `InMemoryStateStore` | Redis (`GETDEL` for the atomic consume), SQL (`DELETE … RETURNING`) |
| Sealed persistence | `SealedStore` (`get`/`set`/`delete`) | `InMemorySealedStore` | the host's JSONB column / 0600 file — pointers, never plaintext |
| Custody cipher | `SecretCipher` (`nx_auth.atrest`) | — | `SecretCipher(key, previous=[…])` or `from_env("<P>")` |

An httpx adapter is the host's whole network story:

```python
class HttpxTransport:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def post_form(self, url, data, *, headers=None):
        r = self._client.post(url, data=data, headers=headers, timeout=30.0)
        try:
            payload = r.json()
        except ValueError:
            payload = None
        return TokenResponse.from_raw(status_code=r.status_code, payload=payload)
```

## Bind flow: state is single-use, expiring, principal-bound

The Rev 3 E12 law (plan 52 §10): a bind flow's `state` is **bound to the
authenticated principal** — the anti-bind-CSRF measure. "One in-flight
flow per account" alone is not sufficient; an attacker's callback must
not complete against a victim's binding.

```python
offer = authorize(client, store=states, principal_id=current_user.id,
                  scopes=provider_scopes,          # verbatim catalog strings
                  redirect_uri="https://app.example/oauth/callback")

# callback route — same principal that started the flow:
record = states.consume(callback_state, principal_id=current_user.id)
#   → invalid    : unknown / replayed / foreign-principal nonce (fail closed)
#   → not-ready  : the ~10 min window lapsed (STATE_TTL_SECONDS = 600)
#   → canceled   : the flow was discarded (user aborted — use states.discard)
tokens = exchange_code(client, code=callback_code,
                       code_verifier=record.code_verifier,
                       redirect_uri=record.redirect_uri, transport=transport)
client.store(binding_id, tokens)   # sealed immediately — custody below
```

`consume` is atomic single-use (the reference store pops under a lock;
a Redis host must use `GETDEL` or equivalent) — a replayed state answers
`invalid` even for the legitimate principal, because the record is
destroyed on the first consume, successful or not.

### Authorize URL: scopes are data, quirks are data

`build_authorize_url` emits `response_type=code`, PKCE `S256`, and the
**verbatim** scope list from the provider catalog row — never
paraphrased. `prompt="consent"` forces the consent screen (scope growth
**re-consents**, ADR-0042 clause 4); `access_type="offline"` is how a
Google server-side flow obtains a refresh token at all. `extra_params`
is provider-quirk **data** (the row's `extraAuthParams`) and wins over
the conveniences when they collide.

## Refresh: single-flight, bounded, rotation-safe

`TokenClient` owns the per-binding policy — never hand-roll a loop:

- **Never serves a known-expired token.** `access()` refreshes first
  when the stored token is expired or inside its skew window (default
  60 s — ADR-0052 §3: "never sends a token known to be expired").
- **Single-flight.** Concurrent refreshes of one binding await one
  attempt: the loser re-reads the vault (the leader persisted before
  unlocking) or adopts the leader's typed failure within
  `flight_window` (default 30 s). One `invalid_grant` burns exactly one
  provider round-trip, then *stops* — followers get the same
  `needs-auth` without re-running the doom.
- **Bounded, jittered retry.** Only `retryable` errors retry
  (`unreachable`, `rate-limited`): full-jitter exponential backoff
  (`base_delay * 2^n`, capped at `max_delay`), `Retry-After` honored
  when capped. `max_attempts` (default 3) then raises the last typed
  error — no infinite retry, ever (ADR-0042 §6).
- **Rotation-crash safety.** The fresh grant is persisted through
  `TokenVault.rotate` — **one atomic sealed write** — so the old record
  survives untouched until the new grant is durable (ADR-0042 clause
  6). A failing write raises typed `not-ready` and leaves the old grant
  sealed; after the flight window the host retry path can re-attempt,
  and a provider that already invalidated the old token answers
  `invalid_grant` → `needs-auth` → re-bind (the documented broken-chain
  posture). When a provider omits a `refresh_token` (not rotated), the
  old one is carried forward — omission is not revocation.

`invalid_grant` maps to `needs-auth` and the host **stops**: surface the
re-bind card, notify once, no further calls. `insufficient_scope` maps
to `needs-secret` (fresh consent screen, never a silent retry).

## Custody: the sealed-slot law

Tokens live **only** inside `SecretCipher.encrypt_value(...,
context="oauth:<binding-id>")` envelopes (ADR-0052 §2: no token-shaped
column anywhere). The per-binding context is the at-rest cut-and-paste
defense: a ciphertext copied to another binding fails decryption with a
typed `needs-secret` — fail closed, re-bind. `TokenVault(store,
cipher=None)` refuses every operation (`needs-secret`): **no keyring ⇒
no custody ⇒ no binding**, no plaintext fallback (ADR-0042 clause 3).

The no-leak law is enforced in code, not by review discipline:

- `TokenSet`, `OAuthClient`, `StateRecord` carry **masked reprs**
  (presence + length only — `access_token=<str len=112>`);
- every `OAuthError.detail` is scrubbed at construction: values the
  call site put on the wire are replaced with `<redacted>`, URL query
  strings are stripped (plan 52 §10 E12), length is capped at 500;
- token responses are normalized into `TokenSet` — the raw body text is
  never carried, unknown provider fields are dropped (`id_token`
  refused; only a small `provider_extra` allowlist round-trips);
- the kit ships the assertion: `nx_auth.testing.assert_no_token_leak`
  scans `str()`/`repr()` of anything you hand it. Hosts re-run it
  against their own surfaces (config rows, logs, audit, notifications —
  ADR-0042 clause 3's never-in-any-form list).

Unbind (ADR-0052 §3): revoke at the provider best-effort (a host
transport call), `vault.clear(binding_id)`, delete the binding row.

## Typed errors

`OAuthError` is the only exception the module raises; `code` is closed
vocabulary (anything else is refused at construction), `retryable` is a
marker with a per-code default, `grant_error` keeps the provider's RFC
6749 string verbatim (a protocol identifier, not a raw exception
string), `retry_after` carries a throttling hint.

| code | meaning | retryable | maps from |
|---|---|---|---|
| `needs-auth` | grant lost — stop, re-bind card | no | `invalid_grant`, no stored grant |
| `needs-secret` | consent/credential problem | no | `invalid_client`, `insufficient_scope`, custody failure, no cipher |
| `needs-config` | deployment config missing | no | no client id, no endpoint URL |
| `invalid` | caller/protocol misuse | no | replayed/foreign/unknown bind state |
| `rate-limited` | throttled | yes | 429, `slow_down` |
| `unreachable` | network/5xx/timeout | yes | transport errors, 5xx |
| `provider` | malformed/unexpected response | no | non-JSON, missing `access_token`, unknown grant errors |
| `not-ready` | flow lapsed or local persistence failed | no | expired state; vault write failure (explicitly `retryable`) |
| `canceled` | user aborted | no | `access_denied`, `discard()` |

## Host checklist (the family drift gate)

Every Python host adopting the module re-asserts, on its own surfaces:

1. bind-CSRF refused — a callback consumed under a different
   `principal_id` fails `invalid` and the record is gone;
2. no token material in `last_error`/logs/audit rows
   (`assert_no_token_leak`);
3. refresh-failure posture — `invalid_grant` ⇒ `needs-auth` stop;
   transient ⇒ bounded backoff, counted failures;
4. custody — nothing token-shaped outside the sealed envelope, and the
   envelope decrypts only under its own binding context.
