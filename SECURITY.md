# Security Policy

## Reporting a vulnerability

Report privately via **GitHub Security Advisories** (Security tab →
*Report a vulnerability*). Do not open a public issue for security
reports. You can expect an initial response within 7 days.

## Scope

In scope: this library's code and test kit (`src/nx_auth/`, `tests/`),
its published artifacts (PyPI/git releases), and its CI pipelines.
Out of scope: consuming applications' deployments, key storage
infrastructure, and product-specific auth surfaces built on the
`protocols.py` interfaces.

## Baseline guarantees (enforced in CI where possible)

- Secrets never committed; `.env` is gitignored; `.env.example` is
  value-free. Test keys come from `nx_auth.testing` — never real ones.
- Key material is per-purpose: session/refresh/data keys are distinct,
  independently generated, never derived from one another; weak or
  placeholder keys are refused at construction.
- Passwords: bcrypt with cost ≥ 12, dummy-hash verification parity
  (no user enumeration by timing), lockout with generic errors.
- Tokens: HS256 with pinned algorithms, per-kind keys, refresh rotation
  with reuse detection (replay revokes the token family).
- Secrets at rest ([`docs/atrest.md`](docs/atrest.md)): authenticated
  Fernet encryption; exceptions never contain key material or plaintext.
- CI: lint + strict type checks + tests, gitleaks secret scanning,
  pip-audit dependency advisories, Dependabot.

## Threat model (this library)

| Surface | Answers |
|---|---|
| Auth surface | `/api/v1/auth/*` flows; unauthenticated endpoints are register/login/refresh/demo only, all rate-limited (sliding windows, trusted-proxy-aware client IP); lockout 5×15 |
| Instance mode | `auth_mode`/`demo_mode` live in the database, read per request (fail-closed to `authenticated`); changes are admin-gated, password-confirmed, audited, and revoke sessions |
| Session storage | cookies `nx_*` / `__Host-nx_*` (HttpOnly, SameSite=Lax, Secure under TLS), refresh scoped to the auth path, double-submit CSRF; server-side `auth_sessions` families with rotation + reuse detection |
| Trust boundaries | desktop shell ↔ backend (per-boot shell secret, loopback-only shell-less dev); client ↔ server (cookie or Bearer); tool/agentic boundaries are the consuming product's responsibility |
| Data isolation | ownership scoping is the consuming product's; the kit provides `tenants.py` interfaces (hidden-404, `require_tenant`) and per-record ownership guards in admin routes |
| Secrets at rest | `nx_auth.atrest` — Fernet under `DATA_KEY`, rotation ring + `_kid` fingerprints; plaintext-tolerant reads are dev/test migration affordances (see the integrity note in atrest.md) |
| Audit | `AuditSink` records auth/admin events; the reference store is append-only; the default `NullAuditSink` is deliberately inert — products must wire a sink in production |
| Admin surface | first-created user bootstraps admin; admin actions are guard-railed (no self-demotion/deactivation, no last-admin removal) and bump token versions |
| Deployment exposure | the library binds nothing itself; desktop entrypoints use the shell-gated exchange, server deployments terminate TLS upstream and set `TRUSTED_PROXY_COUNT` deliberately |

## Supported versions

The latest `main` and the most recent release tag receive security fixes.
