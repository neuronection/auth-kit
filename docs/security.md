# Security notes

## Passwords

- Policy check (`nx_auth.passwords.check_policy`): minimum length
  (default 10, `AuthConfig.password_min_length`) and a **72-byte**
  input cap (bcrypt's limit), enforced as UTF-8 bytes — violations
  raise `PasswordPolicyError` ⇒ **422**. Enforced at register, password
  change, and admin reset.
- Hashing: bcrypt, ≥12 rounds (`hash_password`).
- Verification: `verify_password_or_dummy` compares against a
  precomputed dummy hash when the user does not exist — login timing
  does not reveal whether an email exists (case 10). Error text is
  uniformly `Invalid email or password`.

## Lockout

`nx_auth.lockout` counts consecutive failures per account
(`failed_login_attempts`, `locked_until`):

- `lockout_threshold` failures (default 5) inside the window ⇒ locked
  for `lockout_minutes` (default 15) ⇒ login answers **423**;
- a successful login resets the counter; locked-out attempts do not
  extend the lock silently (state is explicit in the user row);
- `ensure_aware` normalizes naive SQLite datetimes on read (offset
  comparisons crash otherwise).

## Rate limits

`nx_auth.ratelimit.RateLimiter` — fixed windows on auth flows:

| Bucket | Default | Config |
|---|---|---|
| per client IP | 10/min | `auth_rate_per_minute` |
| per email (account) | 30/min | `auth_email_rate_per_minute` |

`client_ip(...)` honors `trusted_proxy_count` hops of
`X-Forwarded-For` — set it to the number of proxies you actually run
(0 = socket address). Trusting more hops than you run lets callers
spoof their IP and evade the limits.

**Known limitation:** counters are in-process. Behind multiple replicas
the effective budget multiplies per replica — a shared limit store is a
tracked gap (S-P5) before scaling out.

## Token & session security

- Key separation (SESSION/REFRESH/DATA) — cross-kind verification
  fails (case 12). Pin the three keys via env in containers.
- Refresh tokens rotate on use; replay revokes the family + bumps
  `ver` (theft detection). Rotation is compare-and-swap — concurrent
  refreshes cannot double-rotate.
- `ver` bumping is the global kill switch: password change, admin
  reset, force-logout, role change, and logout-all all bump it, and
  every authenticated request re-checks it.
- Cookies: `HttpOnly` access/refresh, `SameSite=lax`, `__Host-` +
  `Secure` in TLS mode; CSRF double-submit on every non-safe
  cookie-authenticated request; stale jars cleared at bootstrap.
- Deactivated accounts (`is_active=false`) are refused on **every**
  authenticated surface — not just at login.

## Desktop / DIM hardening

- The exchange exists only on desktop-identity entrypoints.
- Shell-attached: `X-Shell-Token` (per-boot, secret-compared in
  constant time) on every gated request.
- Shell-less (dev): **loopback callers only** — a mis-bound dev server
  cannot hand owner sessions to remote callers (403).
- `local-boot` dies when the instance leaves `open`; mode flips are
  admin-only and never launch-time.

## Audit

`kit.record(actor, action, resource, outcome=…)` writes through the
configured `AuditSink` (`NullAuditSink` by default; products supply
their own row sink — `nx_auth.install.audit_rows(engine)` is a
reference extractor).

### Kit action vocabulary

| Action | When | `resource` | `outcome` |
|---|---|---|---|
| `auth.register` | account created | new user id (actor = client IP) | — |
| `auth.login` | successful login | user id | — |
| `auth.login` | failed / unknown email | user id or the email (actor = client IP) | `denied` |
| `auth.refresh` | successful rotation | family id | — |
| `auth.refresh` | replay of rotated token | family id | `reuse-denied` |
| `auth.logout` / `auth.logout_all` | sign-out flows | user id | — |
| `auth.session_revoke` | `DELETE /me/sessions/{id}` | family id | — |
| `auth.password_change` | `PATCH /me/password` | user id | — |
| `auth.account_delete` | `DELETE /me` | user id | — |
| `auth.demo_login` | demo sign-in (denied on non-demo) | demo user id | `denied` |
| `auth.desktop_exchange` | DIM boot exchange | owner id | — |
| `admin.user_update` | role/status change | target user id | — |
| `admin.password_reset` | admin-set password | target user id | — |
| `admin.force_logout` | forced family revocation | target user id | — |
| `admin.instance_transition` | `PATCH /admin/instance` | instance | — |

`actor` is the acting user id — or the **client IP** for
pre-authentication denials (there is no user yet). Products are
expected to record **reads** as well as writes on their own surfaces
(contract §20) — the kit's sink is the transport, not the
policy.

## Threat-model notes

Assumed adversaries:

| Adversary | Defense |
|---|---|
| Network attacker (no TLS) | products terminate TLS; `cookie_secure` enforces `__Host-`/`Secure` cookies; HSTS is the product's reverse proxy |
| Stolen refresh token | rotation + replay detection revokes the family and kills the access tokens too |
| Stolen access token | short TTL (60 min default) + `ver` bump kill switch + per-family logout |
| CSRF / ambient cookie abuse | double-submit CSRF + `SameSite=lax` + cookie-less Bearer exempt by design |
| Cross-app cookie confusion on shared hosts | configured-name cookie resolution; stale-jar clearing at bootstrap |
| Brute force | lockout + dual rate-limit buckets + generic errors + dummy-hash timing |
| Local dev misbinding | loopback-only DIM when the shell gate is disarmed |
| Insider with DB access | DB is the trust root by design; keys live outside the DB (env/keyring) |

## Known gaps (tracked, not shipped silently)

1. Multi-replica rate limiting / lockout requires a shared store (S-P5).
2. Password breach screening (S-P3) and email verify/reset flows (S-P4)
   are planned, not present — password auth is the only factor unless a
   product adds TOTP (health does; kit core does not yet, S-P2).
3. WebAuthn/passkeys (S-P1) and OIDC (S-P7) are demand-gated.
4. External penetration testing (S-P6) gates any public-internet
   deployment.

Report security issues to the family maintainer (see the repo's
`SECURITY.md`).
