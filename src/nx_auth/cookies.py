import hmac
from dataclasses import dataclass
from typing import Any

from nx_auth.config import AuthConfig

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
COOKIE_PATH_AUTH = "/api/v1/auth"


@dataclass(frozen=True)
class CookieNames:
    access: str
    refresh: str
    csrf: str


#: The unprefixed family names (pre-0.7.0). After a product adopts a
#: per-app `cookie_prefix` (co-location isolation), browsers still hold these for
#: up to the refresh absolute TTL; `LegacyCookieClearingMiddleware`
#: expires them on sight so they cannot shadow or be replayed.
LEGACY_COOKIE_NAMES: tuple[str, ...] = ("nx_access", "nx_refresh", "nx_csrf")
LEGACY_HOST_PREFIXED_ACCESS = "__Host-nx_access"


def cookie_names(config: AuthConfig) -> CookieNames:
    """Per-app prefixed cookie names (co-location isolation).

    `<prefix>access` (``__Host-<prefix>access`` under TLS — contract §9);
    `<prefix>refresh` cannot take the ``__Host-`` prefix (its Path is
    narrower than `/`), matching the table. The family default prefix
    ``nx_`` reproduces the historical names exactly.
    """
    prefix = config.cookie_prefix
    access = f"__Host-{prefix}access" if config.cookie_secure else f"{prefix}access"
    return CookieNames(access=access, refresh=f"{prefix}refresh", csrf=f"{prefix}csrf")


def session_cookie_names(config: AuthConfig) -> tuple[str, ...]:
    """Every name a *current* session may ride, both TLS variants."""
    names = cookie_names(config)
    return (
        names.access,
        f"{config.cookie_prefix}access",
        names.refresh,
    )


class LegacyCookieClearingMiddleware:
    """Expire pre-prefix `nx_*` cookies once, on sight (stale-jar retirement).

    Mounted automatically by `install()` when the config uses a
    non-default prefix. If the request carries any legacy name, the
    response gets matching expired `Set-Cookie` headers — both the plain
    and the `__Host-` access variant, and `nx_refresh` at both its
    historical Paths — so the jar cleans up on the first response after
    the upgrade instead of shadowing requests for up to ~30 days.
    Read-only otherwise: no request cookies, no headers added.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        present = [n for n in (*LEGACY_COOKIE_NAMES, LEGACY_HOST_PREFIXED_ACCESS)
                   if n in parse_cookies(headers.get("cookie"))]
        if not present:
            await self.app(scope, receive, send)
            return

        async def send_with_clearing(message: Any) -> None:
            if message["type"] == "http.response.start":
                extra: list[tuple[bytes, bytes]] = []
                for name in present:
                    for path in ("/", COOKIE_PATH_AUTH if name == "nx_refresh" else "/"):
                        extra.append(
                            (
                                b"set-cookie",
                                f"{name}=; Max-Age=0; Path={path}; SameSite=Lax".encode(
                                    "ascii"
                                ),
                            )
                        )
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        await self.app(scope, receive, send_with_clearing)


def new_csrf_token() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def set_session_cookies(
    response: Any,
    config: AuthConfig,
    *,
    access_token: str,
    refresh_token: str | None,
    csrf_token: str,
) -> None:
    names = cookie_names(config)
    secure = config.cookie_secure
    response.set_cookie(
        names.access,
        access_token,
        max_age=config.access_ttl_seconds,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    if refresh_token is not None:
        response.set_cookie(
            names.refresh,
            refresh_token,
            max_age=config.refresh_ttl_seconds,
            httponly=True,
            secure=secure,
            samesite="lax",
            path=COOKIE_PATH_AUTH,
        )
    response.set_cookie(
        names.csrf,
        csrf_token,
        max_age=config.access_ttl_seconds,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookies(response: Any, config: AuthConfig) -> None:
    names = cookie_names(config)
    secure = config.cookie_secure
    response.delete_cookie(names.access, path="/", secure=secure, samesite="lax")
    response.delete_cookie(names.refresh, path=COOKIE_PATH_AUTH, secure=secure, samesite="lax")
    response.delete_cookie(names.csrf, path="/", secure=secure, samesite="lax")


def parse_cookies(header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not header:
        return cookies
    for chunk in header.split(";"):
        name, _, value = chunk.strip().partition("=")
        if name:
            cookies[name] = value
    return cookies


#: Bootstrap paths that mint or exchange pre-session credentials. CSRF does
#: not apply to them (contract §10/§12): the browser may arrive with a
#: stale cookie jar from a previous session, and login must not 403 on it —
#: the session the bootstrap establishes is the CSRF boundary.
DEFAULT_CSRF_EXEMPT_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/register",
    "/api/v1/auth/demo",
    "/api/v1/auth/mfa",
    "/api/v1/auth/desktop/exchange",
    "/api/v1/auth/setup",
)


class CsrfMiddleware:
    """Double-submit CSRF (contract §10).

    Rule (documented so it stays intentional): outside the bootstrap
    paths, a non-safe request that **carries any auth/csrf cookie** must
    echo the `nx_csrf` cookie value in `X-CSRF-Token`. Cookie-less
    requests (login/register/exchange before a session exists, bearer
    clients) pass — they are not cookie-authenticated, so CSRF does not
    apply to them; their own rate limits do. A session cookie without a
    CSRF echo is a 403.
    """

    def __init__(
        self,
        app: Any,
        *,
        cookie_name: str,
        exempt_prefixes: tuple[str, ...] = DEFAULT_CSRF_EXEMPT_PREFIXES,
        session_cookie_names: tuple[str, ...] = LEGACY_COOKIE_NAMES + (
            LEGACY_HOST_PREFIXED_ACCESS,
        ),
    ) -> None:
        self.app = app
        self.cookie_name = cookie_name
        self.exempt_prefixes = exempt_prefixes
        self.session_cookie_names = session_cookie_names

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if any(path.startswith(prefix) for prefix in self.exempt_prefixes):
            # Bootstrap paths (login/refresh/register/...) mint or exchange
            # pre-session credentials: a stale cookie jar from a previous
            # session must not 403 the bootstrap (contract §10/§12).
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        cookies = parse_cookies(headers.get("cookie"))
        csrf_cookie = cookies.get(self.cookie_name, "")
        session_present = any(name in cookies for name in self.session_cookie_names)
        if not csrf_cookie and not session_present:
            await self.app(scope, receive, send)
            return
        presented = headers.get("x-csrf-token", "")
        if not csrf_cookie or not presented or not hmac.compare_digest(csrf_cookie, presented):
            await self._forbidden(send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _forbidden(send: Any) -> None:
        body = b'{"detail":"CSRF token missing or invalid"}'
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
