# Changelog

All notable changes to **neuronection-auth-kit** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] — 2026-10-02

### Security
- **Stored `open` is coerced on every server boot (§4.4, F6).** A DB
  storing `auth_mode="open"` — exactly the state the study B1 bug
  produced — booted silently open on a server entrypoint: the §4.4
  `open → authenticated` coercion only ran while seeding an empty DB.
  `initialize_instance` now applies it to the *stored* row too — the row
  is rewritten to `authenticated`, the same loud `§4.4` operator warning
  fires, and one `instance.auth_mode_coerced` audit event is written
  through the new injected `audit=` `AuditSink` parameter (optional —
  the coercion and warning never depend on it). Desktop keeps a stored
  `open` untouched and stored `authenticated` stays a pure no-op, both
  pinned by tests.
- **Weak-secret matching is case-insensitive; key distinctness ignores
  padding (F10).** `validate_boot_config` matched its weak/placeholder
  blocklist case-sensitively while `KeyRing` normalizes case — a
  case-variant paste of a long committed fixture key evaded the product
  `weak_secrets` hook. Blocklist matching now compares stripped,
  lowercased values, and the distinctness checks (boot pins and `KeyRing`
  construction) compare trimmed values (case stays significant — keys
  are byte strings).
- **`auth_keys.json` is never world-readable (F11).** `save_to_file`
  created the file with the default umask and chmodded afterwards — a
  brief world-readable window over live key material — and `from_file`
  loaded a 0644 file silently. Writes now go through
  `os.open(..., 0o600)` + `os.replace` (atomic: 0600 from the first
  byte, no partial file for a concurrent reader, a previously loose mode
  cannot survive a re-save), and loading a group/world-readable file
  warns loudly and repairs it to 0600 in place (documented warn+repair
  choice — the keys still load; a failing chmod warns, never dies).

### Added
- **Checklist ↔ tests binding (F9).** `CONTRACT_CASE_TESTS` (in
  `nx_auth.testing`) names the proving kit test modules per checklist
  row, and `tests/test_contract_checklist.py` fails the suite loudly
  when a row loses its tests, a proving module disappears, or a
  `contract`-marked test module proves no row — the checklist a product
  copies can no longer drift from the tests that pin it.

### Changed
- **Knob values no longer fail open on typos or destructive bounds (F8).**
  Every unparsable knob value is dropped with a warning naming the env
  name and the offending value — on both routing paths (OS env and
  Settings-backed) — and the documented fallback to the family default
  is unchanged. Parseable-but-destructive bounds are refused at
  construction (`ValueError`): `lockout_threshold >= 1`,
  `lockout_minutes >= 1` (a `0` window disabled lockout),
  `password_min_length >= 10` (the §7 family floor — the knob may only
  tighten it), auth rate limits `>= 1` per minute, and
  `trusted_proxy_count >= 0`.
- **The §16 knob map covers every `AuthConfig` tunable (S12/F7).**
  `identity_mode` (`<P>_IDENTITY_MODE`) and `require_shell_secret`
  (`<P>_REQUIRE_SHELL_SECRET`) join `AUTH_KNOB_ENV_NAMES`/`_KNOB_SPECS`;
  the fields that cannot be env-routed (`iss`, `demo_user_id`,
  `auth_exempt_prefixes`, `extra`) are excluded **kit-side** in
  `NON_KNOB_FIELDS`, a dict of field → stated reason. The test-local
  `_NON_KNOB_FIELDS` carve-out is gone. *Migration note for products:*
  passing `identity_mode=`/`require_shell_secret=` explicitly alongside
  `**knob_overrides(...)` now raises a duplicate-kwarg `TypeError` —
  drop the explicit kwargs (the map routes them) when re-pinning.
- **One identity-mode parser (F17).** `parse_identity_mode` is the
  single family parser: `AuthConfig.from_env` reads `<P>_IDENTITY_MODE`
  through the knob map, `validate_boot_config` parses with it, and
  `AuthConfig.__post_init__` normalizes direct construction —
  `SA_IDENTITY_MODE=Desktop` no longer splits the semantics of `DESKTOP`,
  and junk fails closed to `server` everywhere.
- **Family security checklist: 15 → 18 rows (F9).** `CONTRACT_CASES`
  gains the §4 *init* rows — S1 (`open` seeded on server ⇒ coerced, and
  a stored `open` row coerced at boot with the warning + audit event),
  S2 (unknown `AUTH_MODE` env ⇒ seeded `authenticated`), S4 (`demo_mode`
  written explicitly at init) — and case 6 regains its
  `authenticated → open` transition-guard clause (refused while other
  users exist and without the current password). Mirrored in family
  guideline §18.
- **Family tool-config parity (plan 20 Phase 7):** ruff config matches
  the product family byte-for-byte (py312, full rule set), the pytest
  config carries the `contract` marker, contract-case test files are
  marked (41 selected) and CI runs `pytest -m contract`. Requires
  Python ≥3.12 (family floor).

### Fixed
- Docs: "the family's 12-case security checklist" → 18; the
  `docs/testing.md` case table lists all 18 rows (init rows included)
  and the test inventory covers every test module (F17).


## [0.3.1] — 2026-10-01

### Security
- **Password-confirming actions share login's defenses (S17, contract
  §7):** `PATCH /api/v1/admin/instance`, `PATCH /api/v1/me/password` and
  `DELETE /api/v1/me` re-verify the caller's password **against the same
  lockout counter as login** — every wrong answer counts (423 once the
  threshold trips; success resets) and every call rides the auth rate
  limit (per-IP + per-account, 429 + `Retry-After`). Previously a
  hijacked session could grind the password at the default rate limit
  with no lockout. Contract case 15 + §18 row.

## [0.3.0] — 2026-10-01

### Added
- **Identity glue (ADR-0028, contract §4):** `IdentityMode`
  (StrEnum `server|desktop`, parsing fails closed to `server`) and
  `initialize_instance(store, *, identity_mode, auth_mode_env,
  demo_mode_env, product=…)` — the single family implementation of the
  init-only rules: §4.4 `open`-on-server coercion with a loud warning,
  unknown `AUTH_MODE` fails closed to `authenticated`, post-init env/CLI
  flips are ignored loudly, `demo_mode` is written explicitly either
  way. (`nx_auth.instance`)
- **`nx_auth.boot` — production boot guards:** `validate_boot_config(...)`
  (parameterized lift of the family fail-soft-in-dev / abort-in-prod
  policy): three-or-none key pins, weak/short key refusal with a product
  `weak_secrets=` extension hook, Fernet-material checks for
  `DATA_KEY` + rotation entries, distinct-pins rule, unpinned keys fatal
  on a server / generated `auth_keys.json` on desktop, and
  `DEBUG`/`DEMO_MODE` refusing production boot. `BootConfigError` on
  fatal problems.
- **§16 knob map:** `AUTH_KNOB_ENV_NAMES` + `knob_overrides(prefix,
  getter)` route Settings-backed values into `AuthConfig.from_env`
  overrides, so `.env`-file values reach the kit config exactly like OS
  environment ones (contract case §18.14).
- **`KeyRing.load_for(product, config_dir, *, pinned=None)`** — the
  family-standard resolution: Settings-backed pins (env **and** the
  deployment `.env`, OS env winning per key) > env pins
  all-three-or-none > 0600 `auth_keys.json` > generate.
- Contract cases **13** (boot guards) and **14** (knob map) in
  `CONTRACT_CASES` + the family §18 checklist.

### Changed
- `AuthConfig.from_env` now reads `<P>_RATELIMIT_AUTH`,
  `<P>_RATELIMIT_AUTH_EMAIL` and `<P>_AUTH_PASSWORD_MIN_LENGTH` from env
  (previously code defaults only) and shares one parse path with
  `knob_overrides`; unparseable values fall back to the family defaults
  as documented (previously an unparseable bool read as `False`).

### Fixed
- `[tool.mypy] python_version` was the package version (`0.2.0`) — an
  invalid interpreter spec mypy warned about on every run. Now `3.11`
  (matching `requires-python`).

## [0.2.0] — 2026-09-30

### Added
- **`nx_auth.atrest` — secrets at rest:** one Fernet cipher for the
  DATA_KEY contract: MultiFernet rotation ring, `_kid` key fingerprints
  (drive rotation backfills), per-row `context` binding (cut-and-paste
  rejection), string (`enc::`) and tagged-value (`{"_encrypted", "_kid"}`)
  shapes, with golden-vector fixtures locking the stored format.
  `allow_plaintext_read` / `allow_plaintext_write` make the plaintext-
  tolerance tradeoff explicit (dev/test migration affordance; production
  flips strict after backfill). Threat model + rotation runbook in
  `docs/atrest.md`.
- **User management + account self-service (contract §12):** `me_router` (`/api/v1/me`) + `admin_router`
  (`/api/v1/admin`) mounted by `install()` at the exact contract paths —
  sessions list/revoke (device labels from the User-Agent), self-serve
  password change (other sessions die, caller re-cookied), `DELETE /me`
  (password confirmed), admin users listing with activity counts,
  activate/promote with guard rails (no self-demotion/deactivation, no
  last-admin demotion, `ver` bumps), admin reset-password +
  force-logout, and `PATCH /admin/instance` (admin + password,
  §4.5 `request_transition` guard wired — previously unused).
  `UserStore`/`SessionStore` protocols gain `list`, `set_active`,
  `set_admin`, `count_admins`, `delete`, `activity_counts`,
  `list_for_user`; records gain `created_at`.
- **Session enforcement middleware** (`SessionAuthMiddleware`): every
  `/api/*` request needs a valid session cookie — verified through the
  single `authenticate_session` path (instance rules included), the
  verified `Principal` is stashed in scope state for endpoint
  dependencies, and `AuthConfig.auth_exempt_prefixes` keeps auth flows,
  the health probe, docs, and the render beacon reachable. Mounted by
  `install()` between CSRF and the shell secret.

### Fixed
- **Demo principal never bootstraps admin (contract §13).**
  `UserStore.create` previously computed `is_admin = is_admin or
  (first user)` — so `POST /api/v1/auth/demo` on a fresh demo instance
  created the anonymous demo identity as user #1 with `is_admin=True`,
  exposing the admin surface (incl. password resets ⇒ account takeover)
  to any visitor. `is_admin` is now tri-state: `None` (default) lets the
  §12 first-user-admin bootstrap apply to real registrations, `False`
  is honored verbatim (the demo principal passes it), `True` forces
  admin (DIM owner unchanged). Documented tradeoff: on a demo instance
  whose demo principal was created first, a later registration is no
  longer user #1 and does not bootstrap admin either — public demos run
  with registration disabled regardless. Regression-tested in
  `test_instance_modes.py` (demo login as first user ⇒ non-admin ⇒
  admin routes 403; first real registration on a non-demo instance
  still bootstraps admin).
- **Session enforcement resolves the access cookie by its configured
  name** (`cookie_names(config).access`), not "`__Host-` first". The
  old order let a stale `__Host-nx_access` from a TLS-mode run of a
  family app on the same host (cookies ignore ports) shadow the live
  `nx_access` session and 401 every enforced request. Mirrors what
  `deps.py` already did; covered by both shadow-direction tests in
  `test_enforcement.py`.
- **Shell-less desktop dev exchange:** the §11 shell-token
  check applies only when a shell secret is configured — a dev server
  without one mints the implicit owner to any loopback caller.
- **72-byte bcrypt cap enforced as policy (422):** passwords longer
  than 72 **UTF-8 bytes** (bcrypt's input limit — multibyte passwords
  counted per byte, not per character) crashed register, password
  change, and admin reset with an unhandled 500; `check_policy` now
  rejects them (`MAX_PASSWORD_BYTES`, contract §7) and
  `hash_password` carries a defensive guard so no call path can reach
  bcrypt with oversized input. Login with an oversized password keeps
  the generic 401.
- **Deactivated accounts cannot log in:** `login` and the demo
  bootstrap now refuse `is_active=false` users with 401 after the
  password check (§18.9 "401 everywhere") — previously they received
  200 + fresh cookies that 401'd on every subsequent request. Audited
  as `auth.login`/`auth.demo_login` with outcome `denied`.
- **CSRF exempt prefix matches the demo route:** the exemption listed
  `/api/v1/auth/demo-login` but the route is `POST /api/v1/auth/demo`
  — a cookie-holding client hitting the demo bootstrap without
  `X-CSRF-Token` got a spurious 403. The prefix now matches the route
  (contract §10/§12).
- **Concurrent refresh rotation is atomic:** refresh rotation was
  read-check-write; two concurrent refreshes with the same token could
  both return 200 and the loser's token then tripped reuse detection
  (spurious family-wide sign-out). `SqlSessionStore` gains
  `rotate_if_current` (single conditional UPDATE — compare-and-swap)
  behind a new `AtomicRotateStore` protocol; the router uses it when
  available and treats a lost race exactly like reuse (423 + family
  revoked + `ver` bump). Stores without the capability keep today's
  behavior.
- **Native uuid columns:** `users`/`auth_sessions`/`profiles`/
  `audit_events` id and FK columns now use SQLAlchemy `Uuid` (native
  uuid on PostgreSQL, CHAR(32) hex elsewhere) instead of `String(36)` —
  contract conformance (contract §5). Databases are
  recreated (greenfield); record builders coerce to `str` so both
  dialects share semantics.
- **Shell middleware leaves `/ws` alone:** browsers cannot set custom
  headers on a WebSocket handshake — the per-boot secret guards `/api/*`
  only; WS keeps the Origin check and, once instance enforcement lands,
  the session cookie.

### Security
- **Weak-secret boot guard (§8).** `KeyRing` now refuses to construct
  with any key shorter than 32 chars or matching a placeholder literal
  ("dev", "changeme", …) — every path (env, file, direct) funnels
  through `__post_init__`, so a forgeable operator key can never enter a
  ring. `from_env` also reports the partial-env shape error before
  strength, so misconfiguration diagnoses stay precise.
- **DNS-rebinding defense on the shell-less DIM exchange.** The
  loopback-peer rule alone let a public page rebound to `127.0.0.1:port`
  mint an owner session (the browser keeps a loopback TCP peer but sends
  the attacker's domain in `Host`/`Origin`). The disarmed-gate shape now
  additionally requires the `Host` header to name the loopback listener
  (with optional port, IPv6 bracket form included). Same 403 as a bad
  shell token — no signal about which layer refused. SSH port-forward
  remote dev is unaffected (Host stays `127.0.0.1:<port>`).
- **No self-registration on `open` instances (§11.3).** `/register`
  answers 404 while the live instance mode is `open` (guard precedes
  rate limiting and the registration toggle) — personal desktop devices
  have no anonymous signup surface to probe, pre-provision, or CSRF;
  additional users come from the admin surface (§12). `/login` stays
  mounted on `open` instances by design: password holders created via
  admin must authenticate for the open→authenticated transition flow.

## [0.1.0] — 2026-09-24

### Added
- **Core (the family contract reference implementation):** per-kind JWTs with
  key separation (`SESSION`/`REFRESH`/`DATA`, env > 0600 file >
  generated), contract claims + `fid` family binding; password accounts
  (bcrypt ≥12, dummy-hash verify, ≥10-char policy, threshold lockout,
  sliding-window rate limits with trusted-proxy client IP);
  `auth_sessions` rotation with reuse detection (family revoke + `ver`
  bump); cookie sessions + double-submit CSRF middleware; DB-authoritative
  instance access modes with fail-closed reads and transition guard
  rails; Desktop Identity Mode exchange (desktop entrypoint only,
  per-boot shell secret, `local-boot` minting); demo principal rules.
- **Surface:** `/api/v1/auth/{register,login,refresh,logout,logout-all,me,demo}`
  + `POST /api/v1/auth/desktop/exchange`; dependencies
  `get_current_user` / `get_optional_principal` / `require_admin`.
- **Stores & schema:** reference SQLAlchemy implementations + the
  family normative tables (`users`, `auth_sessions`, `profiles`,
  `instance_settings`, `audit_events`).
- **Interfaces:** tenants module (hidden-404, `require_tenant`,
  `RoleChecker`) and `AuditSink` — implementations stay in products.
- **Security test kit:** `CONTRACT_CASES` (the family 12-case
  checklist), `make_test_app`, token forging, cookie/CSRF assertion
  helpers; own contract test kit (`CONTRACT_CASES`) + adversarial suite (ruff + mypy strict clean).
