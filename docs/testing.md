# Testing

`nx_auth.testing` is the family's shared security test kit. The kit's
own suite proves every kit-reachable contract case; products re-run the
product-level cases against their mounted kit.

## The contract cases

`CONTRACT_CASES` is the family's 12-case security checklist (family
guideline §18). Drift gates in every product CI re-run the applicable
cases as `pytest -m contract`:

| # | Case |
|---|---|
| 1 | forged / wrong-secret / kind-mismatch tokens rejected |
| 2 | expired access ⇒ 401; refresh path recovers |
| 3 | refresh rotation; replay of rotated token ⇒ family revoked + `ver` bump |
| 4 | lockout: N failures ⇒ 423, unlocks after window |
| 5 | cookie flags exact; CSRF enforced on cookie-authenticated POSTs; WS Origin checked |
| 6 | instance mode: authenticated DB + desktop ⇒ login required; env flip cannot disable auth; unknown mode fails closed; exchange absent unless open desktop; local-boot rejected when authenticated |
| 7 | admin guard: non-admin ⇒ 403; last-admin rails hold |
| 8 | profile binding: cross-user `X-Profile-Id` ⇒ 403; absent ⇒ 400 (server); exempt paths; Default auto-provisioned |
| 9 | `is_active=false` ⇒ 401 everywhere; deletion cascades fully |
| 10 | login error generic; no user enumeration (dummy-hash timing) |
| 11 | demo principal on non-demo instance ⇒ 401; demo seeder refuses non-demo targets |
| 12 | key separation: refresh verifies under `SESSION_KEY` ⇒ rejected; `DATA_KEY` decrypts no JWTs |

Cases 8 and the WS half of 5 are product-layer (profile binding, WS
origin/ownership) — the kit proves the primitives; products prove their
scoping.

## Toolkit API

```python
from nx_auth.testing import (
    CONTRACT_CASES,
    assert_cookie_flags,
    csrf_headers,
    forge_token,
    make_test_app,
    make_test_keyring,
)
```

| Helper | Purpose |
|---|---|
| `make_test_app(auth_mode=…, identity_mode=…, demo=…, registration=…, cookie_secure=…, shell_secret=…, require_shell_secret=…, lockout_threshold=…, rate_per_minute=…)` | batteries-included app: in-memory SQLite, reference stores, audit sink, `install()` applied. `auth_mode=None` simulates a fresh DB (fail-closed ⇒ authenticated) |
| `make_test_keyring()` | deterministic ring for token tests |
| `forge_token(key, claims, algorithm=…)` | mint malformed/foreign tokens for rejection tests (wrong key, wrong kind, stale `ver`, expired…) |
| `assert_cookie_flags(lines, name, http_only=…, secure=…, path=…)` | exact cookie-flag assertions (case-insensitive `SameSite`) |
| `csrf_headers(client)` | the `X-CSRF-Token` echo for non-safe requests |

## Writing a drift gate

Products tag their contract tests and run them in CI:

```python
import pytest

@pytest.mark.contract  # §18.3 — rotated-refresh replay ⇒ 423, family revoked, ver bump
def test_refresh_replay_revokes_family_and_bumps_ver(raw_client):
    ...
```

```ini
# pytest.ini
[pytest]
markers =
    contract: family contract §18 contract drift cases
```

```bash
pytest -m contract          # the CI drift gate
```

Guidelines for kit-adjacent tests:

- **Authenticate the way the product does.** Test clients that mint
  sessions should go through `issue_session` / the kit stores (or a
  shared fixture) — never hand-roll JWT claims.
- **Both gate states for DIM** (see [desktop-mode.md](desktop-mode.md)):
  shell-attached (token match/mismatch) and shell-less (loopback vs
  non-loopback via `TestClient(app, client=(…))`).
- **Cookie flag assertions are case-insensitive** — Starlette
  serializes `SameSite=lax` lowercase.
- **Anonymous behavior** needs an anonymous/raw client fixture; the
  common auto-authenticated fixtures would mask 401s.
- **SQLite naive datetimes** — normalize with `nx_auth.lockout.ensure_aware`
  before comparing, or comparisons raise.
- **UUID columns bind strings** when `as_uuid=False` — raw SQL must
  write/compare the dash-stripped hex form.

## Running the kit's own suite

```bash
cd auth-kit && ./scripts/verify.sh     # ruff + mypy strict + pytest
```

The suite covers the full checklist: token/cookie/CSRF mechanics
(`test_tokens_and_keys`, `test_cookies_csrf`), flows and rotation
(`test_auth_flow`, `test_session_store`), lockout and policy units
(`test_units`), instance-mode no-bypass + DIM states
(`test_instance_modes`), enforcement cookie/Bearer resolution
(`test_enforcement`), and the §12 surface (`test_user_management`).
