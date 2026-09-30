# Integration

## Install

```bash
pip install neuronection-auth-kit        # or: uv add neuronection-auth-kit
```

Development in the family workspace uses a path source:

```toml
# pyproject.toml
[tool.uv.sources]
neuronection-auth-kit = { path = "../auth-kit", editable = true }
```

> **CI note:** the path source resolves locally only. Before a product
> can build from a clean clone on CI, the kit must be published (git
> ref or registry) and the source switched. Coordinate with the family
> maintainer; a git-ref dependency keeps CI simple.

## `install()`

```python
from pathlib import Path

from fastapi import FastAPI
from nx_auth import AuthConfig, KeyRing, install
from nx_auth.shell import generate_shell_secret
from nx_auth.sqlalchemy_stores import (
    SqlInstanceStore,
    SqlProfileStore,
    SqlSessionStore,
    SqlUserStore,
    create_all,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///app.db")
create_all(engine)                 # or your own migration
factory = sessionmaker(engine)

app = FastAPI()
kit = install(
    app,
    config=AuthConfig(iss="study", identity_mode="server"),
    ring=KeyRing.load_or_generate(Path("secret.key"), "SA"),
    users=SqlUserStore(factory),
    sessions=SqlSessionStore(factory),
    profiles=SqlProfileStore(factory),
    instance=SqlInstanceStore(factory),
    shell_secret=None,             # desktop entrypoints only (see desktop-mode.md)
)
```

`install()` returns the `AuthKit` handle:

| Member | Purpose |
|---|---|
| `kit.config` | the effective `AuthConfig` |
| `kit.ring` | the `KeyRing` |
| `kit.state` | live `InstanceState` (auth_mode / demo_mode) |
| `kit.shell_secret` | the per-boot secret or `None` (gate disarmed) |
| `kit.record(actor, action, resource, …)` | write an audit event through the configured `AuditSink` |
| `kit.ensure_profile(user_id)` | auto-provision the Default profile (§6) |
| `kit.provision_owner()` | create/return the implicit desktop owner (DIM) |

What gets mounted (in order): the `auth`, `me`, and `admin` routers (plus
the desktop router when `identity_mode="desktop"`), `CsrfMiddleware`,
`SessionAuthMiddleware`, and — only when a `shell_secret` is provided —
`ShellSecretMiddleware`. Endpoint dependencies are available as
`nx_auth.deps.get_current_user`, `require_admin`,
`get_optional_principal`.

`shell_exempt_prefixes` (install-time, default empty) lists
navigation-served content routes (PDF iframes, `<img>` subresources)
that skip the shell token because browsers cannot set custom headers on
navigations . Contract rule for every exempt route:
safe-method GET, session-authenticated, owner-scoped with 404 for
foreign ids. Session minting and state-changing routes are never
exempt. See [desktop-mode.md](desktop-mode.md).

## `AuthConfig` reference

| Field | Default | Notes |
|---|---|---|
| `iss` | — (required) | product slug, stamped into every token (`iss` claim) |
| `identity_mode` | `"server"` | `"desktop"` mounts the DIM exchange; env `<P>_IDENTITY_MODE` also selects it |
| `access_ttl_minutes` | `60` | hard-capped at 24h by `__post_init__` |
| `refresh_ttl_days` | `7` | rolling refresh lifetime |
| `refresh_absolute_days` | `30` | absolute cap on the session family; `refresh_absolute_days >= refresh_ttl_days` enforced |
| `lockout_threshold` | `5` | consecutive failures before lock |
| `lockout_minutes` | `15` | lock window; locked logins answer **423** |
| `password_min_length` | `10` | policy floor; bcrypt's 72-byte input cap is also enforced (422) |
| `registration_enabled` | `True` | closed ⇒ `POST /register` refuses (invite/first-admin flows own account creation) |
| `cookie_secure` | `False` | `True` ⇒ `__Host-` cookie names + `Secure` flags (TLS deployments) |
| `trusted_proxy_count` | `0` | how many X-Forwarded-For hops to trust for client IP (rate limits / audit) |
| `require_shell_secret` | `False` | desktop: gate `/api/*` behind `X-Shell-Token` (§11) |
| `demo_user_id` | `"00000000-…d0e0"` | fixed UUID of the demo identity (§13) |

| `auth_rate_per_minute` | `10` | per-IP rate limit on auth flows |
| `auth_email_rate_per_minute` | `30` | per-account (email) bucket |
| `auth_exempt_prefixes` | `("/api/v1/auth/", "/api/v1/health", "/api/docs", "/api/v1/shell/rendered")` | prefixes `SessionAuthMiddleware` leaves open |
| `extra` | `{}` | free-form config bag for product extensions |

Derived: `access_ttl_seconds`, `refresh_ttl_seconds`,
`refresh_absolute_seconds`. `AuthConfig.from_env(prefix, iss, **overrides)`
reads the following init-time envs (missing/unparseable values fall
back to the safe defaults):

| Env | Field |
|---|---|
| `<P>_IDENTITY_MODE` | `identity_mode` |
| `<P>_AUTH_ACCESS_TTL_MINUTES` | `access_ttl_minutes` |
| `<P>_AUTH_REFRESH_TTL_DAYS` | `refresh_ttl_days` |
| `<P>_AUTH_REFRESH_ABSOLUTE_DAYS` | `refresh_absolute_days` |
| `<P>_AUTH_LOCKOUT_THRESHOLD` | `lockout_threshold` |
| `<P>_AUTH_LOCKOUT_MINUTES` | `lockout_minutes` |
| `<P>_REGISTRATION_ENABLED` | `registration_enabled` |
| `<P>_COOKIE_SECURE` | `cookie_secure` |
| `<P>_TRUSTED_PROXY_COUNT` | `trusted_proxy_count` |

(`iss` is a code constant, not env.) **Known gap:** the
`<P>_RATELIMIT_*` / password-min knobs have no env yet — code defaults
only; pass them via `AuthConfig(...)`/`from_env(..., **overrides)` until
the knobs land.

## Key ring

`KeyRing` holds the per-kind HMAC keys (see
[tokens-and-cookies.md](tokens-and-cookies.md)). `KeyRing.load_or_generate(path, prefix)`
persists a JSON file and reads `<PREFIX>_SESSION_KEY` / `<PREFIX>_REFRESH_KEY` /
`<PREFIX>_DATA_KEY` environment overrides first. **In containers, pin
the three keys via env** — a recreated container without a mounted
config dir would otherwise rotate keys and invalidate every session.

## Stores (consumer-owned schema)

Implement the protocols in `nx_auth.protocols` against your own models:

| Protocol | Core operations |
|---|---|
| `UserStore` | `get`, `get_by_email`, `count`, `create`, `set_login_failures`, `reset_login_failures`, `bump_token_version`, `set_password`, `list`, plus the §12 surface (`set_active`, `set_admin`, `count_admins`, `delete`, `activity_counts`, `list_for_user`) |
| `SessionStore` | `create`, `get_by_refresh_hash`, `rotate`, `revoke`, `revoke_all_for_user`, `list_for_user`, `touch` |
| `ProfileStore` | `ensure_default` / `count_for` (Default-profile auto-provisioning, §6) |
| `InstanceStore` | `get`, `set` (the `instance_settings` rows) |

Records: `UserRecord(id, email, password_hash, full_name, is_active,
is_admin, failed_login_attempts, locked_until, token_version,
created_at)` — `user.public` renders the §12 `PublicUser` shape and
never exposes hashes/counters/stamps. `SessionRecord(id, user_id,
refresh_jti_hash, expires_at, absolute_expires_at, revoked_at,
client_label, created_at)`.

`nx_auth.sqlalchemy_stores` ships reference implementations plus
`create_all(engine)`; products typically copy the mapping and add
migrations. Kit ORM classes must not be added to a product's
`DeclarativeBase` metadata (registry isolation).

## First boot

`instance_settings` is written **only when the table is empty** — from
the env value when legal (`open` is refused on a server entrypoint and
silently becomes `authenticated`), else the §4 default (`open` on
desktop, `authenticated` on server). Afterwards the row is authoritative
and changes go through `nx_auth.instance.request_transition` (admin
action, guard-railed). Call it through your own `PATCH /api/v1/admin/instance`
endpoint — the kit does not expose mode changes on the auth router.

## Upgrading between kit versions

The family doctrine is **no backwards compatibility** — kit upgrades
may tighten behavior without deprecation shims. Consumer-impacting
changes so far (see `CHANGELOG.md` for the full log):

| Change | Consumer impact |
|---|---|
| Configured-name cookie resolution | middleware/deps read only the configured access-cookie name; apps must stop assuming `__Host-nx_access` is consulted first |
| Bearer session tokens on enforced routes | cookie-less §9 clients now work on enforced `/api/*`; if a product wants to keep them out, restrict at its own layer |
| 72-byte bcrypt cap → 422 | password forms should surface the policy error; legacy >72-byte passwords hash-truncated before (bcrypt semantics) — users may need to re-set |
| CAS refresh rotation | concurrent refresh no longer double-rotates; client code that raced two refreshes now sees one 423 on the loser — acceptable, retry through login |
| DIM loopback rule | shell-less dev exchange 403s non-loopback callers — remote-dev over tunnels is fine (loopback peer), routable binds are not |
| Deactivated users ⇒ 401 everywhere | `is_active=False` now kills live sessions on next request, not just login |

Upgrading checklist for a product: bump the dependency → run the
contract drift gate (`pytest -m contract`) → re-run the product suite →
check `CHANGELOG.md` for rows above. Destructive schema changes are
sanctioned pre-release (dev DBs recreate).
