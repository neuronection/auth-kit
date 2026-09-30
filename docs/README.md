# neuronection-auth-kit — documentation

The identity & authentication layer of the Neuronection assistant
family: one implementation of the family auth contract,
consumed by every product backend.

## Reading order

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | Where the kit sits, the module map, the design rules (consumer-owned stores, fail-closed defaults, no backwards compatibility) |
| [integration.md](integration.md) | Installing and wiring the kit: `install()`, `AuthConfig` reference, key ring + envs, store protocols, what gets mounted |
| [identity-model.md](identity-model.md) | Users, session families, profiles, instance access modes, demo mode, tenants |
| [tokens-and-cookies.md](tokens-and-cookies.md) | Key separation, the token contract (claims, kinds, TTLs), cookie names/flags, double-submit CSRF, refresh rotation with reuse detection |
| [endpoints.md](endpoints.md) | The complete route surface: auth flows, `/me` self-service, `/admin` guard-railed management, Desktop Identity Mode exchange |
| [enforcement.md](enforcement.md) | `SessionAuthMiddleware`, the single `authenticate_session` path, the Bearer user-client class, exemptions, WebSocket guidance |
| [desktop-mode.md](desktop-mode.md) | Desktop Identity Mode: the shell secret (§11), the per-boot exchange, and the shell-less dev shape (loopback-only) |
| [security.md](security.md) | Password policy, lockout, rate limits, audit stream, threat-model notes and the known gap list |
| [testing.md](testing.md) | The shared security test kit: `make_test_app`, `CONTRACT_CASES`, token forging, cookie assertions, consumer drift gates |

## The contract in one paragraph

Tokens are per-kind and key-separated (SESSION/REFRESH/DATA families),
signed HS256, and carry `iss`, `sub` (user id), `token_kind`,
`auth_mode`, `ver` (token version), `iat`/`exp`, `jti`, and optionally
`fid` (session family). Browsers hold sessions in `nx_*` cookies with
double-submit CSRF; non-browser clients use `Authorization: Bearer`.
Refresh tokens rotate on every use; replaying a rotated token revokes
the whole family and bumps the user's `ver`. Instance access mode
(`open` / `authenticated`) is read from the database on every request,
is init-only after first boot, and fails closed. Desktop entrypoints
boot login-free through a per-boot, shell-secret-gated exchange — and
when no shell is attached (dev), that exchange answers loopback callers
only.

This kit implements the family identity contract; the pages in `docs/`
restate every rule it enforces (contract sections are cited in code as
`§N` — README's contract map links each section to its page). Where code
and docs disagree, docs win.
