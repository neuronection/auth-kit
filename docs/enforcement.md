# Enforcement

## The single verification path

`nx_auth.deps.authenticate_session(kit, token) -> Principal | None` is
the one place identity is resolved. It verifies:

1. the token signature under the **session** key and its `token_kind`;
2. expiry (`iat`/`exp`);
3. the live user row exists and `is_active` (deactivated ⇒ 401
   everywhere — case 9);
4. `ver` matches the user's current `token_version` (global revocation);
5. instance-mode admissibility (`local-boot` only on `open` desktop,
   `demo` only on `demo_mode=true`).

`Principal` (`nx_auth.principal`) is the verified caller — `user_id`,
`email`, `full_name`, `is_admin`, `is_active`, `ver`. Endpoints must
trust it (or the request dependencies built on it) and never raw
headers/cookies.

## `SessionAuthMiddleware`

Mounted by `install()` for every request. For HTTP it:

1. skips `auth_exempt_prefixes` (auth flows, health probe, docs, render
   beacon by default — extend via `AuthConfig`);
2. reads the access cookie **by its configured name**
   (`cookie_names(config).access`) — a cookie under the other TLS
   mode's name is inert and never shadows the live session;
3. falls back to `Authorization: Bearer <session token>` for cookie-less
   clients (§9 "User client" class: CLI / MCP / scripts);
4. verifies through `authenticate_session` and stashes the
   `Principal` in scope state as `nx_principal` for endpoint
   dependencies;
5. answers **401** when neither credential is present/valid.

WebSocket handshakes cannot carry custom headers in browsers —
products authenticate the handshake from the session cookie (and check
`Origin`) in their `/ws` endpoint, reusing `authenticate_session`
exactly like the middleware.

## Request dependencies

```python
from nx_auth.deps import get_current_user, get_optional_principal, require_admin

@app.get("/api/v1/thing")
def thing(principal: Principal = Depends(get_current_user)): ...
```

| Dependency | Behavior |
|---|---|
| `get_current_user` | the `Principal` or 401 (with the right `WWW-Authenticate` flavor for Bearer callers) |
| `get_optional_principal` | `Principal | None` — for surfaces that personalize but admit anonymous callers |
| `require_admin` | `get_current_user` + `is_admin` or 403 |

Both read the scope-stashed principal when the middleware ran; they
fall back to their own resolution otherwise (e.g. in tests mounting the
router standalone).

## Shell-token gate (§11)

With `require_shell_secret=True` **and** a configured `shell_secret`,
`ShellSecretMiddleware` demands `X-Shell-Token: <per-boot secret>` on
`/api/*` (the browser SPA receives it as `?shell=` from the desktop
shell). Two request classes cannot carry the header and are exempt:
`/ws` (browsers cannot set WS handshake headers — the session cookie
carries identity there instead) and product-listed
`shell_exempt_prefixes` (navigation-served content — PDF iframes,
`<img>`). The exempt-route contract: safe-method GET,
session-authenticated, owner-scoped with 404 for foreign ids — the
exemption skips the token, never the session check. See
[desktop-mode.md](desktop-mode.md).

## CSRF interplay

`CsrfMiddleware` gates non-safe cookie-authenticated requests with the
double-submit token. It deliberately does **not** apply to cookie-less
Bearer clients — they hold no ambient credential, so there is nothing
for CSRF to protect. The two middleware are complementary: CSRF guards
*ambient* credentials (browsers), the session check guards *all*
requests.

## Product-layer scoping (what the kit does NOT do)

- **Profile binding** (`X-Profile-Id`, guideline §15) is product policy
  layered on top of the `Principal` — the kit provisions the Default
  profile but products enforce per-route scoping (400 absent on server,
  403 foreign, exempt paths).
- **Resource ownership** must be enforced by products against the
  principal's user id/profiles — including **WebSocket topics**:
  subscribe requests must resolve to resources the caller owns,
  fail-closed (study's `/ws` is the reference implementation).
- **Id hygiene:** foreign ids should answer 404, not 403, when the
  resource type is user-visible (indistinguishable from missing).

## Multi-replica note

Lockout counters and rate-limit windows are per-process (reference
implementations). Behind replicas, put the `<P>_RATELIMIT_*`-style
knobs behind a shared store before scaling horizontally — until then,
treat per-instance limits as a per-replica budget (tracked gap S-P5).
