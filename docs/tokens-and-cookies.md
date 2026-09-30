# Tokens & cookies

## Key separation

`KeyRing` holds three independent HMAC keys (HS256):

| Key | Signs | Never does |
|---|---|---|
| `SESSION_KEY` | access (`session`) tokens | verify refresh tokens |
| `REFRESH_KEY` | refresh tokens | verify access tokens |
| `DATA_KEY` | nothing JWT-shaped | it powers the at-rest cipher ([atrest.md](atrest.md)) |

A refresh token presented where a session token is expected — or signed
with the wrong key — fails verification (case 12). Minting with
`mint_token(..., key=…)` exists for tests only.

## Token contract

`mint_token(ring, config, kind=…, sub=…, ver=…, auth_mode=…, family_id=…, …)`
produces the standard claim set:

| Claim | Meaning |
|---|---|
| `iss` | product slug (`AuthConfig.iss`) |
| `sub` | user id (UUID string) |
| `token_kind` | `session` \| `refresh` \| `local-boot` \| `demo` (`TokenKind`) |
| `auth_mode` | the instance mode the token was minted under (`AuthMode`) |
| `ver` | the user's `token_version` at mint time |
| `iat` / `exp` | minted-at / expiry (TTLs from `AuthConfig`) |
| `jti` | unique token id (refresh `jti` is stored hashed in the family row) |
| `fid` | session-family id (when `family_id` is given) |

Products may add claims through `extra` (health: `tenant_id`, `scope`)
— `extra` can never override a standard claim (`TokenError`).

`verify_token(ring, config, token, kind=…, auth_mode=…, …)` checks
signature, kind, expiry, and instance-mode admissibility and returns the
claims; any mismatch raises `TokenError`. `family_id_of(claims)` reads
`fid`.

### TTLs

| Token | Default | Source |
|---|---|---|
| access | 60 min (hard cap 24h) | `access_ttl_minutes` |
| refresh (rolling) | 7 days | `refresh_ttl_days` |
| family (absolute) | 30 days | `refresh_absolute_days` |

## Cookies

`cookie_names(config)` resolves the **configured** triple:

| Role | `cookie_secure=False` | `cookie_secure=True` |
|---|---|---|
| access | `nx_access` | `__Host-nx_access` |
| refresh | `nx_refresh` | `__Host-nx_refresh` |
| csrf | `nx_csrf` | `nx_csrf` (readable by JS — cannot be `__Host-`) |

Flags: `HttpOnly` on access+refresh (never on CSRF), `SameSite=lax`,
`Path` scoped (`/` for access/CSRF, `/api/v1/auth` for refresh),
`Secure` in TLS mode. `set_session_cookies` / `clear_session_cookies`
own the writes; tests assert exact flags via
`nx_auth.testing.assert_cookie_flags` (Starlette serializes
`SameSite=lax` lowercase — assert case-insensitively).

**Configured-name resolution.** The enforcement layer and
`authenticate_session` read the access cookie by its configured name
only. A cookie under the *other* TLS mode's name is inert: cookies
ignore ports, so such a cookie can only come from another family app on
the same host or an earlier deployment mode — it must never shadow the
live session (it used to; that was a bug).

**Clearing stale jars.** Bootstrap flows (login/register) should clear
the whole family (`nx_access`, `nx_refresh`, `nx_csrf` at `/` and
`/api/v1/auth`) before minting — a dead previous session or another
family app's cookie on the same host would otherwise trip the CSRF
gate. The `__Host-nx_access` clear must carry `Secure` and only run in
a secure context: the `__Host-` prefix rules reject any other write.

## Double-submit CSRF

- The `nx_csrf` token is readable by JavaScript and issued beside every
  session.
- Every **non-safe** request (`POST`/`PUT`/`PATCH`/`DELETE`) carrying
  cookies must echo it in `X-CSRF-Token`; `CsrfMiddleware` rejects
  mismatches with **403**.
- The check is cookie-conditional: cookie-less Bearer clients (§9) are
  not subject to it — they hold no ambient credentials.
- Bootstrap paths (`/api/v1/auth/login`, `/register`) are path-aware
  CSRF-exempt so a stale foreign jar can be replaced without first
  clearing it.

## Refresh rotation

`POST /api/v1/auth/refresh`:

1. verify the refresh token (REFRESH key, kind, expiry, `ver`);
2. compare-and-swap the family's stored `jti` hash — a concurrent second
   refresh cannot rotate twice;
3. on match: mint a new refresh + access pair, update the family, set
   fresh cookies;
4. on **mismatch** (the presented token was already rotated out): treat
   it as theft — revoke the whole family, bump the user's `ver`, answer
   **423**.

Logout revokes the row; logout-all revokes every row for the user and
bumps `ver` (family-wide sign-out). Both are admin/user self-service
actions, never launch-time.
