# AGENTS.md — Neuronection Auth Kit

The family identity & authentication library (Python): the reference
implementation of the shared auth contract — per-kind JWTs with strict
key separation, password accounts (bcrypt, lockout, sliding-window rate
limits, generic errors), `auth_sessions` rotation with reuse detection,
cookie sessions + double-submit CSRF, **DB-authoritative instance access
modes** (open / authenticated, fail-closed), Desktop Identity Mode
exchange, an audit hook, a tenants *interface* (products keep their own
implementations), the `nx_auth.atrest` Fernet cipher for secrets at
rest, and the shared security test kit (`CONTRACT_CASES`).

Normative sources: the family identity contract (§8 tokens, §10 cookies,
§12 API surface, §18 test kit — README's contract map links each cited
section to the docs page that restates it). `CONTRACT_CASES` in
`src/nx_auth/testing.py` enumerates the §18 cases; products enforce
them via `pytest -m contract` drift gates.

Consumed by the family's product repos; products may also align to the
contract without adopting this code. The normative contract (claims,
lifetimes, cookies, instance-mode invariants, test checklist) is
restated in this repo's `docs/` — behavior in this repo follows it;
where they disagree, fix the code.

## Non-negotiable rules

1. **Never commit untested code.** Run `scripts/verify.sh` before every
   commit (ruff + mypy strict + pytest must all be green).
2. **Contract first.** This package implements a written contract:
   changes to observable auth behavior change the contract docs in the
   same commit, and new token kinds/claims require a contract proposal
   first (never ad-hoc claims).
3. **Docstrings on public APIs** (Google-style). Inline comments only
   for non-obvious *why* (security rationale, subtle invariants) — never
   narration of what the code does.
4. **Never commit secrets.** `.env` is gitignored, `.env.example`
   documents variables value-free. Test keys come from
   `nx_auth.testing.make_test_keyring()` — never real ones.
5. **Never push to a remote unless explicitly asked.**
6. **This repo is public** — never reference internal family
   infrastructure in committed files (agent wiring lives in gitignored
   local config).

## Repo map

```
src/nx_auth/
├── config.py           AuthConfig (+ <P>_AUTH_* env reading, 24h access cap)
├── keys.py             KeyRing: session/refresh/data, env > 0600 file > generate
├── tokens.py           mint/verify per kind, key-separated, contract claims
├── passwords.py        bcrypt ≥12, dummy-hash verify, ≥10-char policy
├── lockout.py          pure lockout state (threshold/window)
├── ratelimit.py        sliding windows + trusted-proxy client_ip
├── cookies.py          cookie trio + double-submit CsrfMiddleware
├── shell.py            per-boot shell secret + middleware (desktop)
├── instance.py         instance modes, fail-closed read, transition guard rails
├── protocols.py        UserRecord/SessionRecord + store protocols
├── sqlalchemy_stores.py reference stores + users/auth_sessions/profiles/
│                       instance_settings/audit_events models
├── session_flow.py     issue one sign-in (family row + token pair + CSRF)
├── deps.py             get_current_user / get_optional_principal / require_admin
├── router.py           /api/v1/auth/* (register, login, refresh, logout,
│                       logout-all, me, demo)
├── dim.py              /api/v1/auth/desktop/exchange (desktop entrypoint only)
├── install.py          AuthKit + install() wiring
├── audit.py            AuditEvent / AuditSink
├── tenants.py          interface only: hidden-404, require_tenant, RoleChecker
├── principal.py        Principal (the only thing endpoints trust)
├── user_admin.py       /api/v1/me/* + /api/v1/admin/* (user management, §12)
├── atrest.py           DATA_KEY cipher: rotation ring, _kid, context binding
└── testing.py          CONTRACT_CASES + forge/make_test_app/cookie+CSRF helpers
tests/                  the contract test suite (contract §18 subset)
```

## Build & test

```bash
uv venv .venv && uv pip install -e ".[dev]"   # bootstrap once
./scripts/verify.sh                            # ruff + mypy strict + pytest
```

## Conventions

- **Sync handlers + sync stores** (FastAPI runs them in the threadpool).
  Async-native consumers implement the `protocols.py` interfaces with
  their own sessions — see README "Scope".
- The SQLAlchemy models ARE the family schema (users, auth_sessions,
  profiles, instance_settings, audit_events): consumers may **add**
  columns, never rename/retype/drop.
- Semver via `scripts/version_manager.py`; `CHANGELOG.md` follows Keep
  a Changelog (both under `## [Unreleased]`).
- License: Apache-2.0.
