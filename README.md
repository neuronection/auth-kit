# Neuronection Auth Kit

The security layer of the Neuronection assistant family: opt-in modules
with one implementation each — the family auth contract (per-kind
sessions with **key separation**, password accounts (bcrypt, lockout,
rate limits, generic errors), refresh rotation with **reuse detection**,
cookie sessions + double-submit CSRF, **DB-authoritative instance
access modes** with a fail-closed default, Desktop Identity Mode
(auto-login, no login page), an audit hook, a tenants interface, the
`nx_auth.atrest` Fernet cipher for **secrets at rest** (rotation ring,
`_kid` fingerprints, per-row context binding), the `nx_auth.oauth`
**provider-delegation OAuth** module (PKCE, principal-bound state,
single-flight refresh, sealed token custody), the `nx_auth.secrets`
**secret store + resolver** façade (probe-or-fail keyring → sealed file →
env), the `nx_auth.opaque` **opaque credential core** (branded/prefix or
bare tokens, SHA-256 at rest, constant-time compare), and the shared
security test kit.

[![Status](https://img.shields.io/badge/status-0.5.1-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## Install

```bash
pip install neuronection-auth-kit        # or: uv add neuronection-auth-kit
```

## Quick start

```python
from pathlib import Path

from fastapi import FastAPI
from nx_auth import AuthConfig, KeyRing, install
from nx_auth.shell import generate_shell_secret
from nx_auth.sqlalchemy_stores import (
    SqlInstanceStore, SqlProfileStore, SqlSessionStore, SqlUserStore, create_all,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///app.db")
create_all(engine)                      # or your own Alembic revision
factory = sessionmaker(engine)

app = FastAPI()
kit = install(
    app,
    config=AuthConfig(iss="myapp", identity_mode="server"),
    ring=KeyRing.load_or_generate(Path("secret.key"), "APP"),
    users=SqlUserStore(factory),
    sessions=SqlSessionStore(factory),
    profiles=SqlProfileStore(factory),
    instance=SqlInstanceStore(factory),
    shell_secret=generate_shell_secret(),   # desktop entrypoints only
)
```

That mounts the contract's `/api/v1/auth/*` surface, the CSRF
middleware, and the session dependencies (`get_current_user`,
`require_admin`). Desktop entrypoints set
`AuthConfig(identity_mode="desktop")` (or `APP_IDENTITY_MODE=desktop`)
which additionally mounts `POST /api/v1/auth/desktop/exchange` — the
per-boot, shell-secret-gated, zero-setup login.

### Instance modes (the no-bypass rule)

`instance_settings.auth_mode` (`open` | `authenticated`) is read **from
the database on every request**. Unknown ⇒ `authenticated`. Env/CLI can
only set it while initializing an empty DB; afterwards only an
authenticated admin action changes it (guard rails live in
`nx_auth.instance.request_transition`). `local-boot` tokens are valid
only on `open` desktop instances; `demo` identities only on
`demo_mode=true` instances.

## Security test kit

```python
from nx_auth.testing import CONTRACT_CASES, make_test_app, csrf_headers, forge_token
```

`CONTRACT_CASES` is the family's 18-case security checklist (token
forgery/replay/expiry, lockout, cookie flags + CSRF, instance-mode
bypasses and init rules, admin guard, demo rejection, key separation,
boot guards, the §16 knob map, password-confirming actions). The kit's
own suite proves every kit-reachable case; consumers re-run the
product-level ones (profile binding, WS origin) in their repos.

## Provider-delegation OAuth (opt-in, plan 52 §13)

```python
from nx_auth.oauth import OAuthClient, TokenClient, TokenVault, authorize, InMemoryStateStore
from nx_auth.atrest import SecretCipher

client = OAuthClient(
    client_id="…",                            # host/deployment config — never a shipped secret
    token_url="https://oauth2.googleapis.com/token",
    redirect_uri="https://app.example/oauth/callback",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    scopes=("https://www.googleapis.com/auth/calendar",),   # verbatim catalog strings
)
states = InMemoryStateStore()                 # hosts plug Redis/SQL behind StateStore
vault = TokenVault(my_sealed_store, cipher=SecretCipher.from_env("APP"))

offer = authorize(client, store=states, principal_id=user.id)   # bind flow begins
# … callback: states.consume(state, principal_id=user.id) → exchange_code(…) → client.store(…)
access_token = TokenClient(client, vault=vault, transport=my_transport).access(binding_id)
```

PKCE S256, state that is **single-use, expiring, and bound to the
authenticated principal** (the Rev 3 E12 anti-bind-CSRF law), typed
closed-error mapping (`invalid_grant` → `needs-auth` **stop**),
single-flight refresh with bounded full-jitter retry, rotation-crash
safety (new grant persisted before the old is discarded), and sealed
custody over `nx_auth.atrest`. No network of its own — inject a
`TokenTransport` (hosts wrap httpx). Public clients need no secret;
confidential ones MAY pass one. See [docs/oauth.md](docs/oauth.md).

## Secret store + resolver (opt-in, plan 60 D2)

```python
from nx_auth import secrets

sealer = secrets.cipher(data_key=data_key, previous=previous_keys)   # injected keys

secrets.set("github", token, service="StudyAssistant",
            store_path=data_dir / "secrets.json", sealer=sealer)     # sealed before storage
value = secrets.get("github", service="StudyAssistant",
                    store_path=data_dir / "secrets.json", sealer=sealer)

# server product: keyring when it round-trips, else the env fallback
value = await secrets.get_async("tenant-a",
                                service="health-assistant/tenant-sso",
                                env_prefix="HA_SSO_CLIENT_SECRET",   # HA_SSO_CLIENT_SECRET_TENANT_A
                                sealer=sealer)                       # None when missing
```

One façade for the store study owns and the resolver health asks: the
backend is **probed before it is trusted** (`keyring.backends.null`
accepts and silently discards writes), values are sealed **before** they
reach the keyring or the `0600` sealed file, the environment is a
read-only fallback that never shadows a stored value, and nothing
writable fails closed with `SecretStoreUnavailable`. Key material is
always injected — the kit never loads a key ring, writes
`auth_keys.json` or touches a signing key. See
[docs/secrets.md](docs/secrets.md).

## Opaque credentials (opt-in, plan 60 D3)

```python
from nx_auth.opaque import mint, parse, verify

plaintext, prefix, digest = mint(brand="ha_pat")   # ha_pat_<12 hex>_<urlsafe32>
plaintext, prefix, digest = mint()                  # token_urlsafe(32); prefix is None

parsed = parse(presented, brand="ha_pat")           # (prefix, digest) | None
if parsed is None or not verify(row.token_hash, parsed[1]):
    raise PermissionError

plaintext, _, digest = mint()                       # digest-only products
row = session.scalar(select(Token).where(Token.token_hash == digest))
```

Personal access tokens, feed tokens and capture tokens are **not** JWTs:
they are CSPRNG secrets whose only stored form is a SHA-256 digest. Health
adds a 12-hex lookup prefix (`brand="ha_pat"`, `prefix_bytes=6`); career
and study mint bare `token_urlsafe(32)` values with no prefix column.
`parse` is format-only and strict (exact brand, exact lowercase-hex
prefix width, non-empty URL-safe secret), answers `None` for a non-string
or blank value, and `verify` is `hmac.compare_digest` over digests —
never plaintext, never `==`, with any comparison error a `False`. A brand
ending in `_` is rejected (the kit inserts the separators).

The kit owns the byte format, the digest and the constant-time compare.
The product keeps its table, prefix column, tenant/role/permission scope,
audit, revocation and refusal matrix; there is no storage, policy or key
material here. See
[docs/opaque-credentials.md](docs/opaque-credentials.md).

## Scope

- **In:** local auth (password), sessions, cookies/CSRF, instance
  modes, DIM, audit hook, tenants interface, opaque credential core,
  test kit.
- **Out (demand-gated):** OIDC delegation, passkeys, TOTP — extension
  points reserved, no contract change needed when they land.
- Stores are **synchronous** (SQLAlchemy sync sessions; FastAPI runs
  handlers in the threadpool). Async-native apps implement
  `nx_auth.protocols` with their own session machinery.
- No roles table by design (that needs a contract change); products'
  tenant/role stacks stay behind `nx_auth.tenants`' interface.

## Documentation

The normative contract (claims, lifetimes, cookie names, instance-mode
invariants, API paths) is the family identity guideline; this package
implements it. `AGENTS.md` maps the modules.

### Contract cross-reference

Where each contract section is implemented (docs win on any
disagreement):

| Contract § | Kit surface | Doc |
|---|---|---|
| §5 normative rows (users/sessions) | `protocols.py`, `sqlalchemy_stores.py` | [identity-model.md](docs/identity-model.md) |
| §6 profiles | `ProfileStore`, `kit.ensure_profile` | [identity-model.md](docs/identity-model.md) |
| §7 passwords/lockout/rate limits | `passwords.py`, `lockout.py`, `ratelimit.py` | [security.md](docs/security.md) |
| §7 rate limits + response headers (plan 21) | `ratelimit.py` (Counter/`RateLimitPolicy`/middleware), `headers.py` | [security.md](docs/security.md) |
| §8 token claims & lifetimes | `tokens.py`, `keys.py` | [tokens-and-cookies.md](docs/tokens-and-cookies.md) |
| §8 at-rest (`DATA_KEY` family) | `atrest.py` | [atrest.md](docs/atrest.md) |
| §8 opaque credentials — PAT/feed/capture, hash at rest (plan 60 D3) | `opaque.py` | [opaque-credentials.md](docs/opaque-credentials.md) |
| §8/§17 secret slots — store + resolver (plan 60 D2) | `secrets.py` | [secrets.md](docs/secrets.md) |
| §3/§12 provider-delegation OAuth (ADR-0052, plan 52) | `oauth.py` | [oauth.md](docs/oauth.md) |
| §9 user-client (Bearer) class | `deps.py`, `enforcement.py` | [enforcement.md](docs/enforcement.md) |
| §10 cookies, CSRF, WS | `cookies.py`, `enforcement.py` | [tokens-and-cookies.md](docs/tokens-and-cookies.md), [enforcement.md](docs/enforcement.md) |
| §11 shell gate | `shell.py`, `dim.py` | [desktop-mode.md](docs/desktop-mode.md) |
| §12 admin/self-service surface | `user_admin.py` | [endpoints.md](docs/endpoints.md) |
| §13 demo rules | `instance.can_accept_demo`, `POST /auth/demo` | [identity-model.md](docs/identity-model.md) |
| §15 profile binding (product layer) | `kit.ensure_profile` support | [enforcement.md](docs/enforcement.md) |
| §16 config naming | `AuthConfig.from_env` | [integration.md](docs/integration.md) |
| §18 test kit | `testing.py` | [testing.md](docs/testing.md) |

Detailed docs live in [`docs/`](docs/README.md):

- [architecture.md](docs/architecture.md) — role, module map, design rules
- [integration.md](docs/integration.md) — `install()`, `AuthConfig`, stores, envs
- [identity-model.md](docs/identity-model.md) — users, sessions, profiles, instance modes
- [tokens-and-cookies.md](docs/tokens-and-cookies.md) — key separation, claims, cookies, CSRF, rotation
- [endpoints.md](docs/endpoints.md) — the full route surface + error shapes
- [enforcement.md](docs/enforcement.md) — middleware, `authenticate_session`, Bearer, WS
- [desktop-mode.md](docs/desktop-mode.md) — DIM, shell gate, loopback rule
- [security.md](docs/security.md) — passwords, lockout, rate limits, audit, threat model
- [oauth.md](docs/oauth.md) — provider-delegation OAuth: PKCE, bind-state law, refresh, custody
- [secrets.md](docs/secrets.md) — secret store + resolver: backends, precedence, sealed values, adoption
- [opaque-credentials.md](docs/opaque-credentials.md) — opaque credentials: format, prefix, hash at rest, parse strictness
- [testing.md](docs/testing.md) — the test kit, `CONTRACT_CASES`, drift gates

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup and verification gates, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations. Security
reports go through [SECURITY.md](SECURITY.md), never public issues.

## License

Apache-2.0 — see [LICENSE](LICENSE).
