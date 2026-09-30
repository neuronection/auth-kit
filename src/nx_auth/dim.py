from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from nx_auth.cookies import set_session_cookies
from nx_auth.instance import can_accept_local_boot
from nx_auth.session_flow import issue_session
from nx_auth.shell import shell_token_matches
from nx_auth.tokens import AuthMode

if TYPE_CHECKING:
    from nx_auth.install import AuthKit

router = APIRouter(prefix="/api/v1/auth/desktop", tags=["auth"])

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _caller_is_loopback(request: Request) -> bool:
    """True when the TCP peer is loopback.

    The disarmed-gate shape (shell-less desktop dev) may mint
    the implicit owner to loopback callers ONLY — a network-reachable
    server in this shape would hand owner sessions to any remote caller.
    (Through an SSH port-forward the peer *is* loopback: that is the
    supported remote-dev shape.)
    """
    client = request.client
    return client is not None and client.host in _LOOPBACK_HOSTS


def _host_is_loopback(request: Request) -> bool:
    """True when the HTTP ``Host`` header names this loopback listener.

    The peer check alone does not stop DNS rebinding: a public page
    rebound to 127.0.0.1:<port> keeps a loopback *peer* while the browser
    sends the attacker's domain in ``Host`` (and ``Origin``). Requiring
    the Host to literally be a loopback name (with optional port) means
    only pages served from this listener — the SPA itself — can name it.
    """
    host = (request.headers.get("host") or "").strip().lower()
    if not host:
        return False
    if host.startswith("["):  # [::1]:8000
        hostname = host.split("]", 1)[0][1:]
    elif host.count(":") == 1:  # 127.0.0.1:8000 / localhost:8000
        hostname = host.rsplit(":", 1)[0]
    else:  # bare IPv6 literal or plain name
        hostname = host
    return hostname in _LOOPBACK_HOSTS


@router.post("/exchange")
def desktop_exchange(
    request: Request,
    x_shell_token: str | None = Header(default=None, alias="X-Shell-Token"),
) -> JSONResponse:
    """Desktop Identity Mode boot exchange (contract §11).

    Mounted **only** when `identity_mode=desktop` (install-time decision
    — the server entrypoint never routes it). Every call re-checks the
    live instance state: once the instance is `authenticated`, this
    endpoint answers 404 and `local-boot` tokens are rejected by the
    dependency layer — a mode change can never leave a login-free hole.
    """
    kit: AuthKit = request.app.state.auth
    if kit.config.identity_mode != "desktop":
        raise HTTPException(status_code=404, detail="Not found")
    # §11: the per-boot token is enforced only when a shell attached
    # (secret configured — the middleware gate and this check share it).
    # Shell-less desktop dev (gate disarmed — dev shape) configures no
    # secret — then the exchange may mint the implicit owner to loopback
    # callers ONLY: the dev server must never be network-reachable in
    # this shape (that would hand owner sessions to any remote caller).
    if kit.shell_secret is not None:
        if not shell_token_matches(x_shell_token, kit.shell_secret):
            raise HTTPException(status_code=403, detail="invalid shell token")
    elif not (_caller_is_loopback(request) and _host_is_loopback(request)):
        # Loopback peer AND loopback Host: the peer rule alone does not
        # survive DNS rebinding (a rebound public page keeps a loopback
        # peer while sending its own domain in Host/Origin); the Host
        # rule closes that. Same 403 as a bad shell token — no signal
        # about which layer refused.
        raise HTTPException(status_code=403, detail="invalid shell token")
    if not can_accept_local_boot(kit.state):
        raise HTTPException(status_code=404, detail="Not found")
    owner = kit.provision_owner()
    kit.ensure_profile(owner.id)
    access, _refresh, csrf = issue_session(
        kit, owner, auth_mode=AuthMode.LOCAL_BOOT, label="desktop", with_refresh=False
    )
    kit.record(actor=owner.id, action="auth.desktop_exchange", resource=owner.id)
    response = JSONResponse(status_code=200, content=owner.public)
    set_session_cookies(
        response, kit.config, access_token=access, refresh_token=None, csrf_token=csrf
    )
    return response
