# Architecture

## Role in the family

`neuronection-auth-kit` is the shared identity core for the Neuronection
assistant products (study-, career-, health-, desktop-assistant). The
**contract and its test kit are the coupling** — products integrate the
kit's routers, middleware, and protocols, while owning their own ORM
models and adapter code. The kit never imports product code and never
creates its own ORM tables in a product's metadata (two
`DeclarativeBase` registries cannot share foreign keys; consumers
adapt to the kit's protocols — see
[sqlalchemy_stores](../src/nx_auth/sqlalchemy_stores.py) for the
reference implementation).

```
product app (FastAPI)
│
├─ install(app, config, ring, users, sessions, profiles, instance, …)
│    ├─ routers:  auth (/api/v1/auth/*) · me (/api/v1/me) · admin (/api/v1/admin)
│    │            └─ desktop (/api/v1/auth/desktop/exchange) — desktop identity only
│    ├─ middleware (outermost first):
│    │    ShellSecretMiddleware   — §11 X-Shell-Token gate (shell-attached desktop)
│    │    SessionAuthMiddleware   — session enforcement on /api/* (+ Bearer §9)
│    │    CsrfMiddleware          — double-submit CSRF on non-safe methods
│    └─ deps exposed on the kit: get_current_user · require_admin · get_optional_principal
│
└─ product routes read the verified Principal (scope state / Depends)
   and bind profiles (contract §15) on top of it.
```

## Module map

| Module | Responsibility |
|---|---|
| `config.py` | `AuthConfig` — TTLs, lockout, password policy, rate limits, cookie mode, exempt prefixes, env loading (`from_env`) |
| `keys.py` | `KeyRing` — per-kind HMAC keys (SESSION/REFRESH/DATA), `generate_key` |
| `tokens.py` | `TokenKind` / `AuthMode`, `mint_token`, `verify_token`, `family_id_of`, `TokenError` |
| `cookies.py` | Cookie names (`nx_*`, `__Host-nx_*`), set/clear/parse, `CsrfMiddleware` |
| `session_flow.py` | `issue_session` (family row + rotation), `device_hint`, `principal_from_user` |
| `passwords.py` | Policy check (min length, 72-byte bcrypt cap), bcrypt hash/verify, dummy-hash verify |
| `lockout.py` | Failure counting, `is_locked`, 5×15-style thresholds |
| `ratelimit.py` | Per-IP and per-email fixed windows, `client_ip` with trusted-proxy awareness |
| `instance.py` | `InstanceMode`, `InstanceState`, `effective_auth_mode`, `request_transition` (admin-only mode changes) |
| `dim.py` | Desktop Identity Mode exchange (§11) |
| `shell.py` | Per-boot shell secret, `ShellSecretMiddleware`, `shell_token_matches` |
| `deps.py` | `authenticate_session` (the single verification path), request dependencies |
| `enforcement.py` | `SessionAuthMiddleware` — cookie-or-Bearer enforcement with configured-name cookie resolution |
| `router.py` | `/api/v1/auth/*` flows (register, login, refresh, logout, me, demo) |
| `user_admin.py` | `/api/v1/me` self-service + `/api/v1/admin` guard-railed management |
| `principal.py` | `Principal` — the verified caller; the only identity endpoints should trust |
| `protocols.py` | Store protocols + `UserRecord` / `SessionRecord` |
| `sqlalchemy_stores.py` | Reference SQLAlchemy stores + `create_all` |
| `tenants.py` | Multi-tenant helpers (`require_tenant`, `RoleResolver`, `RoleChecker`) |
| `atrest.py` | DATA_KEY cipher — rotation ring, `_kid` fingerprints, context binding ([atrest.md](atrest.md)) |
| `audit.py` | `AuditSink` / `NullAuditSink`, `kit.record(...)` |
| `testing.py` | The security test kit (`make_test_app`, `CONTRACT_CASES`, `forge_token`, …) |
| `install.py` | `AuthKit` handle + `install()` wiring |

## Design rules

1. **Fail closed.** Unknown instance mode ⇒ `authenticated`; missing
   session ⇒ 401; unresolvable ownership ⇒ deny; deactivated user ⇒ 401
   everywhere; rotation reuse ⇒ family revoked. There is no path where
   a missing or malformed credential is treated as success.
2. **One verification path.** Every surface (middleware, dependencies,
   WebSocket handshakes) resolves identity through
   `authenticate_session` — instance rules, `ver`, and `is_active` are
   checked in exactly one place.
3. **Key separation.** SESSION, REFRESH, and DATA keys are distinct; a
   token minted under one kind never verifies under another. `DATA_KEY`
   signs no JWTs at all (it powers the at-rest cipher —
   [atrest.md](atrest.md)).
4. **Consumer-owned storage.** The kit defines protocols; products own
   schema, migrations, and adapters. The reference SQLAlchemy stores are
   a copy-able implementation, not a requirement.
5. **No backwards compatibility.** The family pre-release doctrine: the
   contract may break and tighten; products converge on the newest
   contract with destructive migrations where needed. Deprecation
   shims are not part of this codebase.
6. **Nothing secret is persisted.** Refresh `jti` hashes (never the
   tokens), bcrypt password hashes (≥12 rounds), hashed/rotatable shell
   secrets. Error surfaces are generic (no user enumeration).
