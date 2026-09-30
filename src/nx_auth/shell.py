import hmac
import secrets
from typing import Any

SHELL_HEADER = "x-shell-token"


def generate_shell_secret() -> str:
    """Per-boot secret (DIM, contract §11): process memory only,
    rotates every boot, never committed, never logged."""
    return secrets.token_urlsafe(32)


def shell_token_matches(provided: str | None, expected: str | None) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided, expected)


class ShellSecretMiddleware:
    """Require the per-boot shell secret on API traffic (desktop only).

    Document/static asset requests are exempt — the shell loads the SPA
    document before any fetch can carry the header; everything under
    `/api/` and `/ws` must present `X-Shell-Token`.
    """

    def __init__(
        self,
        app: Any,
        *,
        secret: str,
        exempt_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.secret = secret
        self.exempt_prefixes = exempt_prefixes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        # Only `/api/*`: documents/static load before any fetch can carry
        # the header, and `/ws` is exempt because browsers cannot set
        # custom headers on a WebSocket handshake — WS is covered by the
        # Origin check and (in authenticated mode) the session cookie.
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return
        # Navigation-served content routes (PDF iframe documents, `<img>`
        # subresources) cannot carry custom headers either — products may
        # list them here. Contract rule for every exempt route:
        # safe-method (GET), session-authenticated, and owner-scoped with
        # 404 for foreign ids. Exemption skips the shell token ONLY —
        # never the session check.
        if any(path.startswith(prefix) for prefix in self.exempt_prefixes):
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        if not shell_token_matches(headers.get(SHELL_HEADER), self.secret):
            await self._forbidden(send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _forbidden(send: Any) -> None:
        body = b'{"detail":"invalid shell token"}'
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
