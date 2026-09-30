from __future__ import annotations

from typing import TYPE_CHECKING, Any

from nx_auth.cookies import cookie_names, parse_cookies
from nx_auth.deps import authenticate_session
from nx_auth.principal import Principal

if TYPE_CHECKING:
    from nx_auth.install import AuthKit


class SessionAuthMiddleware:
    """Per-request session enforcement for `/api/*` (contract §4/§12).

    - runs before routing (outermost after the shell secret), verifies
      the access cookie — or, cookie-less, an `Authorization: Bearer`
      session token (§9 "User client" class) — through the ONE
      verification path (`authenticate_session`) — instance rules
      included, so a `local-boot`/`demo` token is refused here too;
    - unauthenticated ⇒ 401 JSON, no body leaks;
    - the verified `Principal` is stashed in scope state so endpoint
      dependencies reuse it instead of verifying twice;
    - configured prefixes are exempt (auth flows, health probe, docs,
      the render beacon) — everything else under `/api/` requires a
      session, in `open` desktop instances as well (DIM exchanges first).
    """

    def __init__(self, app: Any, *, kit: AuthKit, exempt_prefixes: tuple[str, ...]) -> None:
        self.app = app
        self.kit = kit
        self.exempt_prefixes = exempt_prefixes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return
        if any(path.startswith(prefix) for prefix in self.exempt_prefixes):
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        cookies = parse_cookies(headers.get("cookie"))
        # Resolve by the *configured* access name (§10 — deps.py reads the
        # same way). A cookie under the other TLS mode's name is inert:
        # cookies ignore ports, so it can only come from another family
        # app (or an earlier mode flip) on this host — reading it first
        # used to let a stale foreign cookie shadow the live session.
        token = cookies.get(cookie_names(self.kit.config).access)
        if token is None:
            # Cookie-less user clients (§9: CLI / MCP / scripts) present
            # the session token as a Bearer credential instead.
            authorization = headers.get("authorization", "")
            if authorization[:7].lower() == "bearer " and authorization[7:].strip():
                token = authorization[7:].strip()
        principal: Principal | None = (
            authenticate_session(self.kit, token) if token else None
        )
        if principal is None:
            body = b'{"detail":"Not authenticated"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"www-authenticate", b'Bearer realm="api"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        scope_state = scope.setdefault("state", {})
        scope_state["nx_principal"] = principal
        await self.app(scope, receive, send)
