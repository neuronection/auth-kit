"""Security headers — one middleware, per-product policy (plan 21 D4).

`SecurityHeadersMiddleware` applies the family baseline to every HTTP
response (`nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`
via the CSP body, `Referrer-Policy: strict-origin-when-cross-origin`);
`HeaderPolicy` carries the product's CSP choice (career's template is
the family default — web `script-src 'self'` vs desktop `'unsafe-eval'`
served **only** to a document carrying the valid per-boot `?shell=`
marker). Opt-in like the limiter: never wired into `install()`,
products mount it explicitly with their policy object.

HSTS stays at the nginx layer (ADR-0005) — except the
behind-a-TLS-proxy emission health needs (`hsts_behind_proxy`), which
only fires when the client's connection actually arrived over https.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from starlette.datastructures import MutableHeaders

#: The family CSP template (career's body, byte-for-byte). `script-src`
#: is the only slot: web deployments keep `'self'`; the desktop shell
#: document (pywebview's `evaluate_js` bridge) additionally needs
#: `'unsafe-eval'` under WebKitGTK/WebView2 page-CSP enforcement.
CSP_TEMPLATE = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
    " script-src {script}; connect-src 'self'; font-src 'self' data:; object-src 'none';"
    " frame-ancestors 'none'; base-uri 'self'"
)


def web_csp() -> str:
    """Web deployment CSP — no eval, no inline scripts (family default)."""
    return CSP_TEMPLATE.format(script="'self'")


def desktop_csp() -> str:
    """Desktop shell CSP — adds `'unsafe-eval'` for the pywebview bridge.

    Served only for the document whose `?shell=` query carries the valid
    per-boot shell token (the `desktop_marker` predicate); browsers never
    know the token, so web deployments keep the strict CSP.
    """
    return CSP_TEMPLATE.format(script="'self' 'unsafe-eval'")


@dataclass(frozen=True)
class HeaderPolicy:
    """Per-product header policy (D4): same middleware, product choices.

    - `web_csp`/`desktop_csp`: the CSP pair; `web_csp=None` emits no CSP
      (health's API+separate-SPA-origin shape).
    - `shell_param`: the query parameter carrying the per-boot desktop
      marker (`shell` family-wide).
    - `frame_overridable`: keep `X-Frame-Options` overridable per route
      (health's PDF-preview iframe relaxes to `SAMEORIGIN`).
    - `hsts_behind_proxy`: emit `Strict-Transport-Security` only when
      the client connection arrived over https (`X-Forwarded-Proto`'s
      first — client-side — hop, else the ASGI scheme).
    - `extra`: product additions appended verbatim.
    """

    web_csp: str | None = web_csp()
    desktop_csp: str | None = None
    shell_param: str = "shell"
    frame_options: str = "DENY"
    frame_overridable: bool = True
    hsts_behind_proxy: bool = False
    extra: tuple[tuple[str, str], ...] = ()

    def csp_for(self, desktop_document: bool) -> str | None:
        """The CSP for this response (`None` ⇒ emit no CSP header)."""
        if desktop_document and self.desktop_csp is not None:
            return self.desktop_csp
        return self.web_csp


def _client_scheme_https(scope: dict[str, Any]) -> bool:
    """True when the client's connection actually arrived over TLS.

    Behind a proxy the real client scheme arrives via
    `X-Forwarded-Proto` — take the first (client-side) hop only; a list
    like ``https, http`` is a proxy chain where the client was TLS.
    Emitting HSTS on a plain-HTTP response pins browsers to a possibly
    broken https listener, so plain-http never carries it.
    """
    for key, value in scope.get("headers", []):
        if key.decode("latin-1").lower() == "x-forwarded-proto":
            first_hop: str = value.decode("latin-1").split(",")[0].strip()
            return first_hop == "https"
    scheme: Any = scope.get("scheme")
    return bool(scheme == "https")


class SecurityHeadersMiddleware:
    """Attach the policy's hardened headers to every HTTP response."""

    def __init__(
        self,
        app: Any,
        *,
        policy: HeaderPolicy,
        desktop_marker: Callable[[str | None], bool] | None = None,
    ) -> None:
        self.app = app
        self.policy = policy
        self.desktop_marker = desktop_marker

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        marker: str | None = None
        if self.policy.desktop_csp is not None and self.desktop_marker is not None:
            query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
            marker = query.get(self.policy.shell_param, [None])[0]
        csp = self.policy.csp_for(
            desktop_document=bool(self.desktop_marker and self.desktop_marker(marker))
        )
        headers: list[tuple[str, str]] = [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", self.policy.frame_options),
            ("referrer-policy", "strict-origin-when-cross-origin"),
        ]
        if csp is not None:
            headers.append(("content-security-policy", csp))
        if self.policy.hsts_behind_proxy and _client_scheme_https(scope):
            headers.append(
                ("strict-transport-security", "max-age=31536000; includeSubDomains")
            )
        headers.extend(self.policy.extra)
        overridable = {"x-frame-options"} if self.policy.frame_overridable else set()

        async def send_with_headers(message: Any) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in headers:
                    if name in overridable and name in response_headers:
                        continue  # an explicit per-route value wins
                    response_headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


__all__ = [
    "CSP_TEMPLATE",
    "HeaderPolicy",
    "SecurityHeadersMiddleware",
    "desktop_csp",
    "web_csp",
]
