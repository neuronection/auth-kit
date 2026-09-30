# Endpoints

All kit routes are mounted under `/api/v1/…` by `install()`. The auth
router is exempt from session enforcement (it *is* the authentication);
everything else is enforced (see [enforcement.md](enforcement.md)).

## `/api/v1/auth` — auth flows

| Method & path | Auth | Behavior |
|---|---|---|
| `POST /register` | — | create account (when `registration_enabled`), start a session family, set cookies. The first user created on an instance bootstraps admin (§12, applies when `is_admin` is left unspecified); the demo principal and explicit `is_admin=False` creations never do (§13). **404 on `open` instances** (§11.3 — personal devices have no self-signup; users come from the admin surface). 422 on password-policy violations. |
| `POST /login` | — | verify password (dummy-hash compare on unknown users — no enumeration), enforce lockout (**423** when locked), rotate failure counters, issue session family + cookies. Generic `Invalid email or password` on failure. Mounted on `open` instances too: password holders created via the admin surface must authenticate for the open→authenticated transition (§4). |
| `POST /refresh` | refresh cookie / body | rotation with reuse detection (see [tokens-and-cookies.md](tokens-and-cookies.md)); replay ⇒ family revoked + `ver` bump + **423**. |
| `POST /logout` | session | revoke the current family, clear cookies. |
| `POST /logout-all` | session | revoke every family for the user, bump `ver`, clear cookies. |
| `GET /me` | session | the `PublicUser` shape (`id`, `email`, `full_name`, `is_admin`, `is_active`) — never hashes/counters. |
| `POST /demo` | — | demo login — answers only on `demo_mode=true` instances (else 401/404), mints the fixed `demo_user_id` identity (never admin, even as user #1). |
| `POST /desktop/exchange` | shell token / loopback | Desktop Identity Mode only — see [desktop-mode.md](desktop-mode.md). 404 on server entrypoints. |

Register and login are rate-limited per IP and per email
(`auth_rate_per_minute` / `auth_email_rate_per_minute`), and both are
path-aware CSRF-exempt (stale-jar replacement).

## `/api/v1/me` — self-service (session required)

| Method & path | Behavior |
|---|---|
| `GET /sessions` | list the user's session families (device labels from `User-Agent`; the current family is marked) |
| `DELETE /sessions/{family_id}` | revoke one family (204) — used for "sign out this device" |
| `PATCH /password` | change password (current password confirmed, policy-checked); other families die and the caller is re-cookied into a fresh family |
| `DELETE /me` | delete the account (password confirmed, 204); cascades fully |

## `/api/v1/admin` — guard-railed management (admin required)

| Method & path | Behavior |
|---|---|
| `GET /users` | user listing with activity counts (§12 `PublicUser` rows + counts) |
| `PATCH /users/{user_id}` | activate/deactivate, promote/demote — guard rails: no self-demotion, no self-deactivation, no last-admin demotion; role/status changes bump `ver` (sessions die) |
| `POST /users/{user_id}/reset-password` | admin-set new password (policy-checked, min length enforced); forces logout of the target's families |
| `POST /users/{user_id}/force-logout` | revoke all of the target's families + `ver` bump |
| `PATCH /instance` | instance-mode transition via `request_transition` — admin **and** password confirmation; guard-railed (see below) |

Non-admins get **403** (case 7). All admin actions write audit rows.

### Instance transitions

`nx_auth.instance.request_transition` is the only mode-change path:

- target must be a known mode (unknown ⇒ refusal);
- `open` on a server entrypoint is refused;
- the change is an admin action with password confirmation at the
  endpoint layer;
- products surface it as `PATCH /api/v1/admin/instance`
  (`{"auth_mode": "…"}`).

**Special case (contract §4.5):** when the *password-less
implicit owner* (DIM) performs an `open → authenticated` transition,
the request's `password` **sets** that owner's credentials — the owner
becomes a normal admin user. Re-verification cannot apply to a row
without a password; every other caller must send their current password
(403 on mismatch, generic error).

## Request bodies

| Endpoint | Body |
|---|---|
| `POST /auth/register` | `{"email" (3..320), "password" (1..1024), "full_name" (≤200, default "")}` |
| `POST /auth/login` | `{"email", "password"}` |
| `POST /auth/refresh` | empty (identity rides the refresh cookie) |
| `PATCH /me/password` | `{"current_password", "new_password"}` |
| `DELETE /me` | `{"password"}` |
| `PATCH /admin/users/{id}` | `{"is_active"?, "is_admin"?}` (both nullable; omitted = unchanged) |
| `POST /admin/users/{id}/reset-password` | `{"new_password"}` |
| `PATCH /admin/instance` | `{"auth_mode"? ("open"\|"authenticated"), "password"}` |

Password policy (min length, 72-byte cap) is enforced on every
password field server-side — body-level `min_length=1` is transport
validation only, not the policy.

## Response shapes

Session-minting endpoints (`register`, `login`, `refresh`, `demo`,
`desktop/exchange`) answer with the **`PublicUser`** body and set the
cookie family (`nx_access`, `nx_refresh`, `nx_csrf`) — tokens never
appear in the body:

```json
{ "id": "…uuid…", "email": "user@example.com", "full_name": "…",
  "is_admin": false, "is_active": true }
```

| Endpoint | Body |
|---|---|
| `GET /auth/me` | `PublicUser` (from the verified principal) |
| `GET /me/sessions` | `[{ "id", "client_label", "created_at", "expires_at", "revoked_at", "current" }]` |
| `GET /admin/users` | `[{ "id", "email", "full_name", "is_admin", "is_active", "created_at", "activity_count" }]` |
| `POST /admin/users/{id}/reset-password`, `force-logout`, `DELETE …` | 204, empty |
| `PATCH /admin/instance` | `PublicUser`/state JSON + audited transition |

## Worked example

```bash
# register (sets the cookie family in the jar)
curl -c jar -X POST localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery"}'
# → 201 {"id":"…","email":"me@example.com","full_name":"","is_admin":false,"is_active":true}

# authenticated call (cookie) — no CSRF needed for GET
curl -b jar localhost:8000/api/v1/auth/me

# non-safe call needs the double-submit echo
CSRF=$(grep nx_csrf jar | awk '{print $NF}')
curl -b jar -X POST localhost:8000/api/v1/me/password \
  -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"current_password":"correct-horse-battery","new_password":"a-longer-new-passphrase"}'
```

## Error shapes

| Status | Used for |
|---|---|
| 400 | malformed request (e.g. bad profile binding header at the product layer) |
| 401 | missing/invalid session, deactivated user, wrong credentials, demo/local-boot on the wrong instance |
| 403 | CSRF mismatch, non-admin on admin routes, wrong tenant/ownership, non-loopback DIM caller |
| 404 | DIM exchange on server entrypoints; foreign resource ids (products must 404 foreign ids so they are indistinguishable from missing ones) |
| 422 | password policy violations (min length, 72-byte bcrypt cap), schema validation |
| 423 | locked account; refresh-token replay (family revoked) |

Login/register errors are deliberately generic (case 10) — response
shape, status, and timing must not reveal whether an email exists.
