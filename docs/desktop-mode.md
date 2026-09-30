# Desktop Identity Mode

DIM is the family's zero-setup desktop login: the shipped pywebview
shell boots the local app with **no login page**, while every
server-shaped deployment keeps full authentication.

## The two halves

1. **Entry declaration** — the desktop entrypoint sets
   `AuthConfig(identity_mode="desktop")` (or `SA_IDENTITY_MODE=desktop`).
   Only then does `install()` mount
   `POST /api/v1/auth/desktop/exchange`; server entrypoints never route
   it (404).
2. **Per-boot shell gate (§11)** — the shell generates a per-boot
   secret (`nx_auth.shell.generate_shell_secret`), passes it to
   `install(shell_secret=…)` and to the SPA as `?shell=`, and sends it
   as `X-Shell-Token` on every API call. `ShellSecretMiddleware`
   enforces it when `require_shell_secret=True`. Two documented
   exemptions from the token (browsers cannot set custom headers on
   those requests): `/ws` (handshake — covered by the Origin check and
   the session cookie) and, product-listed
   **navigation-served content routes** (PDF iframes, `<img>`):

   ```python
   install(..., shell_secret=secret,
           shell_exempt_prefixes=("/api/v1/blobs",))
   ```

   Contract rule for every exempt route: safe-method GET,
   session-authenticated, and owner-scoped with 404 for foreign ids —
   the exemption skips the shell token ONLY, never the session check.
   Session minting (`/auth/desktop/exchange`) and state-changing routes
   are never exempt.

## The exchange

`POST /api/v1/auth/desktop/exchange` mints the implicit **owner**
(`kit.provision_owner()` — a password-less admin account) and starts a
`local-boot` session family. Order of checks:

1. `identity_mode` must be `desktop` — else 404 (the route does not
   exist on servers);
2. **who may call it:**
   - shell-attached (`kit.shell_secret` configured): the
     `X-Shell-Token` must match the per-boot secret — else 403;
   - shell-less (no secret configured, the dev shape below): the TCP
     peer must be **loopback** (`127.0.0.1`, `::1`, `localhost`) — else
     403. A remote caller can never receive the implicit owner;
3. `can_accept_local_boot(state)` — the instance must still be
   `auth_mode=open` — else 404. Once an admin flips the instance to
   `authenticated`, the exchange closes permanently (mode changes are
   never launch-time), and outstanding `local-boot` tokens die with the
   next `authenticate_session` call.

Sessions minted here carry `auth_mode=local-boot`, `label="desktop"`,
no refresh token (`with_refresh=False` — a desktop boot is one session
per process).

## Shell-less desktop dev

Development runs the backend under plain uvicorn + a vite dev server,
with no pywebview shell to hold or carry the secret. In that shape:

- `shell_secret` is **not** configured ⇒ the §11 gate is *disarmed*
  (the SPA needs no `X-Shell-Token`);
- the exchange still works — **loopback callers only** (rule 2 above);
- the instance is expected to be `auth_mode=open`, so the dev SPA boots
  straight into the implicit owner with no accounts;
- a local profile stamped `authenticated` by older runs keeps it
  (init-only!) — the app shows its login gate even though the shell
  gate is disarmed. `./scripts/run-dev.sh --reset` re-initializes the
  profile open.

Products wire the flag as `SA_SHELL=1` / `CAREER_SHELL=1`, set by their
`shell.py` before `create_app`, and log loudly when booting desktop
identity **without** an attached shell ("the X-Shell-Token gate is
DISARMED — bind the server to loopback only").

### The loopback rule is the security boundary

With the gate disarmed, the only thing between a caller and an owner
session is the loopback check. **Never bind the shell-less dev server
to a routable interface** (e.g. `CA_DEV_HOST=0.0.0.0`): the exchange
will still refuse remote callers (403), but the rest of the unauthenticated
dev surface would be network-visible. SSH port-forwards are supported —
the peer is loopback from the server's perspective.

### Testing both states

The contract requires both gate states to be tested (see
[testing.md](testing.md)):

- shell-attached: correct token ⇒ 200; wrong/missing token ⇒ 403;
- shell-less: loopback ⇒ 200 (implicit owner); non-loopback ⇒ 403;
- any state: `auth_mode=authenticated` ⇒ exchange answers 404.

`TestClient(app, client=("127.0.0.1", 50000))` simulates a loopback
caller; `client=("203.0.113.9", 50000)` a remote one.

## Android / machine bridges

DIM is unrelated to the product-side machine credentials (HMAC
`X-Api-Signature` bridges, SMART `api` tokens). Those remain the
product's surface and are unaffected by DIM lifecycle.
