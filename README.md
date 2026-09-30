# Neuronection Auth Kit

The identity & authentication layer of the Neuronection assistant
family: one implementation of the family auth contract — per-kind
sessions with **key separation**, password accounts (bcrypt, lockout,
rate limits, generic errors), refresh rotation with **reuse detection**,
cookie sessions + double-submit CSRF, **DB-authoritative instance
access modes** with a fail-closed default, Desktop Identity Mode
(auto-login, no login page), an audit hook, a tenants interface, the
`nx_auth.atrest` Fernet cipher for **secrets at rest** (rotation ring,
`_kid` fingerprints, per-row context binding), and the shared security
test kit.

[![Status](https://img.shields.io/badge/status-0.2.0-blue.svg)](CHANGELOG.md)
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

`CONTRACT_CASES` is the family's 12-case security checklist (token
forgery/replay/expiry, lockout, cookie flags + CSRF, instance-mode
bypasses, admin guard, demo rejection, key separation). The kit's own
suite proves every kit-reachable case; consumers re-run the
product-level ones (profile binding, WS origin) in their repos.

## Scope

- **In:** local auth (password), sessions, cookies/CSRF, instance
  modes, DIM, audit hook, tenants interface, test kit.
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
| §8 token claims & lifetimes | `tokens.py`, `keys.py` | [tokens-and-cookies.md](docs/tokens-and-cookies.md) |
| §8 at-rest (`DATA_KEY` family) | `atrest.py` | [atrest.md](docs/atrest.md) |
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
- [testing.md](docs/testing.md) — the test kit, `CONTRACT_CASES`, drift gates

## License

Apache-2.0 — see [LICENSE](LICENSE).
