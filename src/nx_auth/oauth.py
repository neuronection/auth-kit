"""Provider-delegation OAuth — authorization code + PKCE (plan 52 §13).

One implementation of delegated-provider OAuth for every Python family
host (study, health, career): PKCE (S256, RFC 7636) authorization code,
**session-bound single-use state** (plan 52 §10 E12 — the anti-bind-CSRF
law), code exchange, **single-flight refresh** with bounded full-jitter
retry and rotation-crash safety, and sealed token custody over
:mod:`nx_auth.atrest` (ADR-0052 §12; the posture is ADR-0042 §3/§6
generalized to class D/S by ADR-0052 §3).

The module is **stdlib-only** and performs **no I/O on its own**: network
rides an injected :class:`TokenTransport`, state persistence rides an
injected :class:`StateStore` (hosts plug Redis/SQL — health's Redis
``OAuthStateStore`` is *not* imported here), and sealed persistence rides
an injected :class:`SealedStore`. Tests pass fakes
(:class:`nx_auth.testing.FakeTokenTransport`); a host wraps ``httpx``::

    class HttpxTransport:                                   # host-side, ~10 lines
        def __init__(self, client: httpx.Client) -> None:
            self._client = client
        def post_form(self, url, data, *, headers=None):
            r = self._client.post(url, data=data, headers=headers, timeout=30.0)
            try:
                payload = r.json()
            except ValueError:
                payload = None
            return TokenResponse.from_raw(status_code=r.status_code, payload=payload)

Laws enforced in code (each pinned by ``tests/test_oauth.py``):

* **Bind state is single-use, expiring (~10 min) and bound to the
  authenticated principal** — the caller passes ``principal_id`` at
  issue time and the *same* value at consume time; a mismatched,
  replayed or expired record fails closed with a typed error
  (Rev 3 E12: "one in-flight flow per account" alone is not sufficient
  against bind-CSRF).
* **Refresh is single-flight** per binding: concurrent callers await one
  attempt; transient failures retry with bounded full-jitter backoff;
  ``invalid_grant`` maps to ``needs-auth`` and *stops* (ADR-0042 §6);
  a call is never served a token known to be expired (skew).
* **Rotation-crash safety:** a rotated refresh token is persisted in one
  atomic sealed write *before* the old record is discarded — the
  on-disk token stays the old one until the new one is durably stored
  (ADR-0042 clause 6).
* **Custody:** token values exist only inside
  ``SecretCipher.encrypt_value(..., context="oauth:<binding-id>")``
  envelopes. No token value may ever appear in an error message, repr,
  log line, or returned dict — ``TokenSet``/``OAuthClient``/
  ``StateRecord`` carry masked reprs and every error detail is
  scrubbed (known secrets redacted, URL query strings stripped per
  plan 52 §10 E12).
* **Closed typed error vocabulary** (:data:`ERROR_CODES`): at minimum
  ``needs-auth, needs-secret, needs-config, invalid, rate-limited,
  unreachable, provider, not-ready, canceled`` — no raw exception
  strings cross the boundary.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import random
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlencode

from nx_auth.atrest import SecretCipher

logger = logging.getLogger(__name__)

#: The closed typed error vocabulary — the family status conditions
#: (ADR-0042 §6 / ADR-0052 §8) plus the flow-level codes. ``OAuthError``
#: refuses anything else, so no raw exception string can cross the
#: boundary under this code.
ERROR_CODES: tuple[str, ...] = (
    "needs-auth",       # grant lost (invalid_grant / revoked) — stop, re-bind
    "needs-secret",     # consent/credentials problem (invalid_client, no cipher)
    "needs-config",     # deployment config missing (client id, endpoint URLs)
    "invalid",          # caller/protocol misuse: replayed or foreign state
    "rate-limited",     # provider throttled us (429 / slow_down)
    "unreachable",      # network / 5xx / transport timeout
    "provider",         # malformed or unexpected provider response
    "not-ready",        # flow window lapsed, or local persistence unavailable
    "canceled",         # the user aborted the flow (access_denied / discard)
)

#: Default ``retryable`` marker per code — transient codes retry under
#: the refresh policy; everything else is a stop (ADR-0042 §6).
_RETRYABLE_DEFAULTS: dict[str, bool] = {
    "needs-auth": False,
    "needs-secret": False,
    "needs-config": False,
    "invalid": False,
    "rate-limited": True,
    "unreachable": True,
    "provider": False,
    "not-ready": False,
    "canceled": False,
}

#: Bind-flow ``state`` lifetime (~10 min — the family flow timeout,
#: ADR-0042 §2 uses ~5 min for the loopback listener; class D/S flows
#: get the longer window health's Redis store already shipped).
STATE_TTL_SECONDS = 600.0

#: Access-token expiry skew: a token inside its final `skew` window is
#: treated as expired (a call is never served a token that may die
#: mid-flight — ADR-0052 §3: "never sends a token known to be expired").
DEFAULT_SKEW_SECONDS = 60.0

_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_QUERY_STRING_PATTERN = re.compile(r"(https?://[^\s?\"']+)\?[^\s\"']*")
_MAX_DETAIL_CHARS = 500

#: Provider token-response fields carried verbatim as non-secret
#: metadata (SMART's ``patient``, account labels). Anything else a
#: provider appends is *dropped*, deliberately: unknown fields must not
#: round-trip into host storage where they might be a credential
#: (``id_token`` is refused the same way — OIDC is out of scope).
_PROVIDER_EXTRA_KEYS = frozenset({"patient", "sub", "user_id", "account_label"})


def _scrub(text: str, *, known: Sequence[str] = ()) -> str:
    """Error-detail hygiene — the E12 law, applied at every boundary.

    Known secret values are replaced first (a provider echoing a token
    or a transport exception quoting a form field cannot leak), then
    every URL loses its query string (query tokens are bearer
    material), then the whole detail is truncated.
    """
    out = str(text)
    for secret in known:
        if secret:
            out = out.replace(secret, "<redacted>")
    out = _QUERY_STRING_PATTERN.sub(r"\1?<redacted>", out)
    return out[:_MAX_DETAIL_CHARS]


class OAuthError(Exception):
    """The typed OAuth failure — the only exception this module raises.

    ``code`` is one of :data:`ERROR_CODES` (validated at construction —
    the vocabulary is closed). ``retryable`` tells the refresh policy
    (and the host's status machine) whether a retry can help.
    ``grant_error`` carries the provider's RFC 6749 §5.2 ``error``
    string verbatim when one was received — a stable protocol
    identifier, never an exception string. ``retry_after`` carries the
    provider's ``Retry-After`` hint in seconds when throttled.
    ``detail`` is scrubbed at construction (secrets were redacted by
    the call site that knew them; query strings and length are capped
    here), so ``str()``/``repr()`` are log-safe by construction.
    """

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        retryable: bool | None = None,
        grant_error: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        if code not in _RETRYABLE_DEFAULTS:
            raise ValueError(
                f"unknown OAuth error code {code!r} (closed family set: {ERROR_CODES})"
            )
        self.code = code
        self.detail = _scrub(detail)
        self.retryable = _RETRYABLE_DEFAULTS[code] if retryable is None else retryable
        self.grant_error = grant_error
        self.retry_after = retry_after
        super().__init__(f"{code}: {self.detail}")

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"

    def __repr__(self) -> str:
        return (
            f"OAuthError(code={self.code!r}, retryable={self.retryable!r}, "
            f"grant_error={self.grant_error!r}, detail={self.detail!r})"
        )


# ---------------------------------------------------------------------------
# PKCE (RFC 7636) — S256 only
# ---------------------------------------------------------------------------

def new_verifier() -> str:
    """A fresh PKCE code verifier (RFC 7636 §4.1): 64 chars, RFC charset."""
    verifier = secrets.token_urlsafe(48)
    if not _VERIFIER_PATTERN.match(verifier):  # pragma: no cover - belt and braces
        raise RuntimeError("generated PKCE verifier failed the RFC 7636 §4.1 check")
    return verifier


def code_challenge(verifier: str) -> str:
    """The S256 challenge for ``verifier`` (base64url(SHA256), padding stripped).

    Rejects out-of-spec verifiers (wrong charset/length) — a verifier
    outside RFC 7636 §4.1 would silently break the exchange later.
    """
    if not _VERIFIER_PATTERN.match(verifier):
        raise ValueError(
            "PKCE verifier must be 43-128 chars of [A-Za-z0-9-._~] (RFC 7636 §4.1)"
        )
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_state() -> str:
    """An opaque CSRF ``state`` nonce (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenSet:
    """One provider grant — the sealed custody unit (ADR-0052 §2).

    ``expires_at`` is an aware UTC datetime computed from ``expires_in``
    (``None`` when the provider omitted it — the token is then treated
    as usable but unrefreshable-by-clock). ``scope`` is the provider's
    verbatim scope string (consent honesty — never paraphrased or
    normalized). ``provider_extra`` carries only whitelisted non-secret
    metadata (see :data:`_PROVIDER_EXTRA_KEYS`).

    The repr is masked: **no token value ever appears in ``str()``/
    ``repr()``** — read ``access_token``/``refresh_token`` fields only
    to put them on the wire or seal them.
    """

    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
    scope: str | None
    token_type: str = "Bearer"
    provider_extra: Mapping[str, str] = field(default_factory=dict)

    def expired(self, *, now: datetime | None = None, skew: float = 0.0) -> bool:
        """True when ``expires_at`` has passed (minus ``skew``). Without a
        stored expiry the token is treated as usable — the provider made
        it unjudgable by clock, and guessing would strand working grants."""
        if self.expires_at is None:
            return False
        current = now or datetime.now(UTC)
        return current >= self.expires_at - timedelta(seconds=skew)

    def redacted(self) -> dict[str, object]:
        """A log-safe summary: token values replaced by presence markers."""
        return {
            "token_type": self.token_type,
            "access_token": "<redacted>" if self.access_token else "absent",
            "refresh_token": "<redacted>" if self.refresh_token else "absent",
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scope": self.scope,
            "provider_extra": dict(self.provider_extra),
        }

    def __repr__(self) -> str:
        expires = self.expires_at.isoformat() if self.expires_at else None
        return (
            f"TokenSet(token_type={self.token_type!r}, "
            f"access_token=<str len={len(self.access_token)}>, "
            f"refresh_token={'present' if self.refresh_token else 'absent'}, "
            f"expires_at={expires!r}, scope={self.scope!r})"
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scope": self.scope,
            "token_type": self.token_type,
            "provider_extra": dict(self.provider_extra),
        }

    @classmethod
    def _from_payload(cls, payload: Mapping[str, Any]) -> TokenSet:
        expires_raw = payload.get("expires_at")
        expires_at: datetime | None = None
        if isinstance(expires_raw, str) and expires_raw:
            expires_at = datetime.fromisoformat(expires_raw)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
        extra = payload.get("provider_extra")
        return cls(
            access_token=str(payload["access_token"]),
            refresh_token=(
                str(payload["refresh_token"])
                if isinstance(payload.get("refresh_token"), str) and payload["refresh_token"]
                else None
            ),
            expires_at=expires_at,
            scope=(
                str(payload["scope"])
                if isinstance(payload.get("scope"), str) and payload["scope"]
                else None
            ),
            token_type=str(payload.get("token_type") or "Bearer"),
            provider_extra=dict(extra) if isinstance(extra, dict) else {},
        )


@dataclass(frozen=True)
class OAuthClient:
    """One provider client registration (ADR-0052 §3: host/deployment config).

    ``authorize_url``/``token_url`` come verbatim from the provider
    catalog row; client ids are **not secret** (they travel in a browser
    URL — ADR-0042 clause 5) but ``client_secret`` is: a confidential
    client MAY pass one for class-S deployments; a public client works
    with none (PKCE is the proof). ``extra_auth_params`` is provider
    quirk data (catalog ``extraAuthParams``) — never ``if provider ==``
    branches.
    """

    client_id: str
    token_url: str
    redirect_uri: str
    authorize_url: str = ""
    scopes: tuple[str, ...] = ()
    client_secret: str | None = None
    extra_auth_params: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"OAuthClient(client_id={self.client_id!r}, "
            f"client_secret={'<redacted>' if self.client_secret else 'absent'}, "
            f"authorize_url={self.authorize_url!r}, token_url={self.token_url!r}, "
            f"redirect_uri={self.redirect_uri!r}, scopes={self.scopes!r})"
        )


# ---------------------------------------------------------------------------
# Transport — the injected network boundary (no I/O without one)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenResponse:
    """The transport's normalized reply from a token endpoint.

    ``data`` is the parsed JSON body (``None`` when the body was not
    JSON — the body text is deliberately **not** carried: it is the one
    field that could echo token material). ``retry_after`` is the
    parsed ``Retry-After`` header hint in seconds, when present.
    """

    status_code: int
    data: Mapping[str, Any] | None = None
    retry_after: float | None = None

    @classmethod
    def from_raw(
        cls,
        *,
        status_code: int,
        payload: Any,
        retry_after: float | None = None,
    ) -> TokenResponse:
        """From a host transport's raw reply (payload may be unparsed)."""
        return cls(status_code=status_code, data=payload, retry_after=retry_after)


@runtime_checkable
class TokenTransport(Protocol):
    """The one network seam — POST a form to a token endpoint.

    Hosts adapt their pooled HTTP client (httpx/async, or the polite
    runtime) behind this; the module never opens a socket itself, so
    tests inject scripts instead. Transports own their **timeouts**
    (a hung token endpoint must surface as a transport error, which
    maps to ``unreachable``) and must not follow the response body into
    logs — return :class:`TokenResponse`, not text.
    """

    def post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        headers: Mapping[str, str] | None = None,
    ) -> TokenResponse: ...


# ---------------------------------------------------------------------------
# Typed error mapping (RFC 6749 §5.2 → the family vocabulary)
# ---------------------------------------------------------------------------

#: RFC 6749 ``error`` strings → (family code, retryable). Unknown grant
#: errors map to ``provider`` (stop — retrying a protocol violation is
#: how quota burns). ``invalid_grant`` → ``needs-auth`` **stop** is the
#: ADR-0042 §6 posture; ``insufficient_scope`` → ``needs-secret`` (a
#: fresh consent screen, never a silent retry).
_GRANT_ERROR_MAP: dict[str, tuple[str, bool]] = {
    "invalid_grant": ("needs-auth", False),
    "invalid_client": ("needs-secret", False),
    "unauthorized_client": ("needs-secret", False),
    "insufficient_scope": ("needs-secret", False),
    "access_denied": ("canceled", False),
    "slow_down": ("rate-limited", True),
    "authorization_pending": ("not-ready", True),
}


def grant_failure(
    error: str,
    description: str = "",
    *,
    retryable: bool | None = None,
) -> OAuthError:
    """Typed error for a provider ``error`` string (token body **or**
    authorize callback redirect — RFC 6749 §4.1.2.1). Hosts raising this
    for callback errors keep one mapping for the whole flow."""
    code, default_retryable = _GRANT_ERROR_MAP.get(error, ("provider", False))
    detail = f"provider rejected the request ({error})"
    if description:
        detail += f": {description[:200]}"
    return OAuthError(
        code,
        detail,
        retryable=default_retryable if retryable is None else retryable,
        grant_error=error,
    )


def _token_request(
    client: OAuthClient,
    form: dict[str, str],
    *,
    transport: TokenTransport,
    known_secrets: Sequence[str],
    now: datetime,
) -> TokenSet:
    """POST the token endpoint over the injected transport and map the
    reply to a :class:`TokenSet` or a typed error. Every failure detail
    is scrubbed against ``known_secrets`` — the values we just put on
    the wire are exactly the ones an echoing provider could leak back."""

    def fail(error: OAuthError) -> OAuthError:
        return OAuthError(
            error.code,
            _scrub(error.detail, known=known_secrets),
            retryable=error.retryable,
            grant_error=error.grant_error,
            retry_after=error.retry_after,
        )

    try:
        response = transport.post_form(
            client.token_url, form, headers={"Accept": "application/json"}
        )
    except Exception as exc:  # the transport owns its errors — wrap, scrub, keep the cause
        raise fail(
            OAuthError("unreachable", f"token endpoint unreachable: {type(exc).__name__}: {exc}")
        ) from exc

    if response.status_code == 429:
        raise fail(
            OAuthError(
                "rate-limited",
                "provider throttled the token request (429)",
                retryable=True,
                retry_after=response.retry_after,
            )
        )
    if response.status_code >= 500:
        raise fail(
            OAuthError("unreachable", f"token endpoint failed (HTTP {response.status_code})")
        )
    if 300 <= response.status_code < 400:
        raise fail(
            OAuthError(
                "provider", f"token endpoint answered a redirect (HTTP {response.status_code})"
            )
        )

    data = response.data
    if response.status_code >= 400:
        if isinstance(data, dict) and isinstance(data.get("error"), str) and data["error"]:
            description = data.get("error_description")
            raise fail(
                grant_failure(
                    data["error"],
                    description if isinstance(description, str) else "",
                )
            )
        raise fail(
            OAuthError(
                "provider", f"token endpoint rejected the request (HTTP {response.status_code})"
            )
        )
    if not isinstance(data, dict):
        raise fail(OAuthError("provider", "token endpoint returned a non-JSON body"))
    return _tokens_from_response(data, known_secrets=known_secrets, now=now)


def _tokens_from_response(
    data: Mapping[str, Any],
    *,
    known_secrets: Sequence[str],
    now: datetime,
) -> TokenSet:
    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthError(
            "provider",
            _scrub("token response carried no usable access_token", known=known_secrets),
        )
    expires_in = data.get("expires_in")
    expires_at = (
        now + timedelta(seconds=int(expires_in))
        if isinstance(expires_in, (int, float)) and expires_in > 0
        else None
    )
    scope = data.get("scope")
    token_type = data.get("token_type")
    extra = {
        key: str(value)
        for key, value in data.items()
        if key in _PROVIDER_EXTRA_KEYS and isinstance(value, (str, int, float))
    }
    return TokenSet(
        access_token=access_token,
        refresh_token=(
            data["refresh_token"]
            if isinstance(data.get("refresh_token"), str) and data["refresh_token"]
            else None
        ),
        expires_at=expires_at,
        scope=scope if isinstance(scope, str) and scope else None,
        token_type=token_type if isinstance(token_type, str) and token_type else "Bearer",
        provider_extra=extra,
    )


def _require_token_config(client: OAuthClient) -> None:
    if not client.client_id:
        raise OAuthError("needs-config", "OAuth client id is not configured for this deployment")
    if not client.token_url:
        raise OAuthError("needs-config", "OAuth token endpoint URL is not configured")


def exchange_code(
    client: OAuthClient,
    *,
    code: str,
    code_verifier: str,
    transport: TokenTransport,
    redirect_uri: str | None = None,
    now: datetime | None = None,
) -> TokenSet:
    """Exchange an authorization code for a :class:`TokenSet` (RFC 6749 §4.1.3).

    ``redirect_uri`` must be the exact value used at authorize time —
    pass the consumed :class:`StateRecord`'s ``redirect_uri``. The PKCE
    verifier authenticates a public client; a confidential client's
    secret rides the form body (Basic-auth providers are a transport
    concern). A ``code`` is single-use: a replay answers ``invalid_grant``
    → :class:`OAuthError` ``needs-auth``.
    """
    _require_token_config(client)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri or client.redirect_uri,
        "client_id": client.client_id,
    }
    if client.client_secret:
        form["client_secret"] = client.client_secret
    return _token_request(
        client,
        form,
        transport=transport,
        known_secrets=(code, code_verifier, client.client_secret or ""),
        now=now or datetime.now(UTC),
    )


def refresh_tokens(
    client: OAuthClient,
    *,
    refresh_token: str,
    transport: TokenTransport,
    now: datetime | None = None,
) -> TokenSet:
    """One refresh-token grant (RFC 6749 §6) — no retries, no custody.

    Retry/rotation policy lives in :class:`TokenClient`; hosts running
    their own loop call this directly. When the provider omits a
    ``refresh_token`` (not rotated), the returned set **carries the old
    one forward** — a missing field is not a revoked grant.
    """
    _require_token_config(client)
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client.client_id,
    }
    if client.client_secret:
        form["client_secret"] = client.client_secret
    fresh = _token_request(
        client,
        form,
        transport=transport,
        known_secrets=(refresh_token, client.client_secret or ""),
        now=now or datetime.now(UTC),
    )
    if not fresh.refresh_token:
        fresh = TokenSet(
            access_token=fresh.access_token,
            refresh_token=refresh_token,
            expires_at=fresh.expires_at,
            scope=fresh.scope,
            token_type=fresh.token_type,
            provider_extra=fresh.provider_extra,
        )
    return fresh


# ---------------------------------------------------------------------------
# Bind-flow state — single-use, expiring, principal-bound (Rev 3 E12)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StateRecord:
    """One in-flight bind flow, bound to an authenticated principal.

    ``code_verifier`` is the PKCE secret of the flow — it lives here
    (server-side), never in the browser. ``extra`` is host correlation
    data (account/binding ids as strings). The repr is masked: the
    ``state`` nonce and the verifier never appear in it.
    """

    state: str
    principal_id: str
    code_verifier: str
    expires_at: datetime
    redirect_uri: str = ""
    created_at: datetime | None = None
    extra: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        expires = self.expires_at.isoformat() if self.expires_at else None
        created = self.created_at.isoformat() if self.created_at else None
        return (
            f"StateRecord(state=<masked>, principal_id={self.principal_id!r}, "
            f"code_verifier=<str len={len(self.code_verifier)}>, "
            f"redirect_uri={self.redirect_uri!r}, expires_at={expires!r}, "
            f"created_at={created!r})"
        )


@runtime_checkable
class StateStore(Protocol):
    """Where in-flight bind flows live (the host's seam).

    ``issue`` stores a record under its ``state`` nonce; ``consume`` is
    the **atomic single-use** read-and-delete (Redis hosts: ``GETDEL``;
    SQL hosts: one ``DELETE ... RETURNING``) — two consumers can never
    both win. ``consume`` raises :class:`OAuthError`: ``invalid`` for an
    unknown/replayed/foreign-principal nonce, ``not-ready`` for an
    expired one, ``canceled`` for a discarded flow. ``discard`` kills a
    flow the user aborted so a late callback cannot complete it.
    """

    def issue(self, record: StateRecord) -> None: ...

    def consume(self, state: str, *, principal_id: str) -> StateRecord: ...

    def discard(self, state: str) -> None: ...


class InMemoryStateStore:
    """Thread-safe reference :class:`StateStore` (tests / single-process hosts).

    Single-use by ``dict.pop`` under a lock; expiring by the injected
    clock. Expiry uses ``record.expires_at`` as written at issue time.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        max_canceled: int = 1024,
    ) -> None:
        self._records: dict[str, StateRecord] = {}
        # Tombstones for discarded flows — a late callback after a user
        # cancel must answer `canceled`, not `invalid` (same failure,
        # different host action: restart vs investigate).
        self._canceled: dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_canceled = max_canceled

    def issue(self, record: StateRecord) -> None:
        with self._lock:
            self._records[record.state] = record
            self._canceled.pop(record.state, None)

    def consume(self, state: str, *, principal_id: str) -> StateRecord:
        now = self._clock()
        with self._lock:
            record = self._records.pop(state, None)  # single-use before any check
            if record is None:
                if state in self._canceled:
                    raise OAuthError("canceled", "the bind flow was discarded")
                raise OAuthError("invalid", "unknown or already-consumed bind-flow state")
            if now >= record.expires_at:
                raise OAuthError("not-ready", "the bind flow window lapsed — start again")
            if principal_id != record.principal_id:
                raise OAuthError("invalid", "bind-flow state does not belong to this principal")
            return record

    def discard(self, state: str) -> None:
        with self._lock:
            record = self._records.pop(state, None)
            if record is not None:
                self._canceled[state] = record.expires_at
                while len(self._canceled) > self._max_canceled:
                    oldest = next(iter(self._canceled))
                    self._canceled.pop(oldest, None)


@dataclass(frozen=True)
class AuthorizationOffer:
    """What :func:`authorize` hands the host: the URL to open and the
    issued flow record (its ``code_verifier`` completes the exchange)."""

    authorize_url: str
    record: StateRecord

    @property
    def state(self) -> str:
        return self.record.state


def build_authorize_url(
    client: OAuthClient,
    *,
    state: str,
    code_challenge: str,
    redirect_uri: str | None = None,
    scopes: Sequence[str] | None = None,
    prompt: str | None = None,
    access_type: str | None = None,
    extra_params: Mapping[str, str] | None = None,
) -> str:
    """The authorize URL: ``response_type=code`` + PKCE S256 + verbatim scopes.

    ``prompt``/``access_type`` are the two cross-provider conveniences
    worth naming: ``prompt="consent"`` forces the provider's consent
    screen (scope growth **re-consents** — ADR-0042 clause 4), and
    ``access_type="offline"`` is how Google issues a refresh token to a
    server-side flow at all. ``extra_params`` is provider-quirk **data**
    (the catalog row's ``extraAuthParams``) and wins over the conveniences
    when they collide. Scopes are joined verbatim — never paraphrased.
    """
    if not client.client_id:
        raise OAuthError("needs-config", "OAuth client id is not configured for this deployment")
    if not client.authorize_url:
        raise OAuthError("needs-config", "OAuth authorize endpoint URL is not configured")
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": redirect_uri or client.redirect_uri,
        "scope": " ".join(scopes if scopes is not None else client.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if prompt is not None:
        params["prompt"] = prompt
    if access_type is not None:
        params["access_type"] = access_type
    params.update(extra_params or {})
    separator = "&" if "?" in client.authorize_url else "?"
    return f"{client.authorize_url}{separator}{urlencode(params)}"


def authorize(
    client: OAuthClient,
    *,
    store: StateStore,
    principal_id: str,
    redirect_uri: str | None = None,
    scopes: Sequence[str] | None = None,
    prompt: str | None = None,
    access_type: str | None = None,
    extra_params: Mapping[str, str] | None = None,
    extra: Mapping[str, str] | None = None,
    ttl: float = STATE_TTL_SECONDS,
    now: datetime | None = None,
) -> AuthorizationOffer:
    """Begin one bind flow: issue the principal-bound state record and
    build the authorize URL.

    The host opens ``offer.authorize_url`` in the browser; the callback
    route consumes ``offer.state`` with the **same** ``principal_id``,
    then exchanges ``record.code_verifier``. ``extra`` rides the record
    (host correlation ids only — never credentials).
    """
    _require_token_config(client)
    current = now or datetime.now(UTC)
    state = new_state()
    verifier = new_verifier()
    record = StateRecord(
        state=state,
        principal_id=principal_id,
        code_verifier=verifier,
        redirect_uri=redirect_uri or client.redirect_uri,
        created_at=current,
        expires_at=current + timedelta(seconds=ttl),
        extra=dict(extra or {}),
    )
    store.issue(record)
    url = build_authorize_url(
        client,
        state=state,
        code_challenge=code_challenge(verifier),
        redirect_uri=redirect_uri,
        scopes=scopes,
        prompt=prompt,
        access_type=access_type,
        extra_params=extra_params,
    )
    return AuthorizationOffer(authorize_url=url, record=record)


# ---------------------------------------------------------------------------
# Sealed token custody over nx_auth.atrest (ADR-0052 §12)
# ---------------------------------------------------------------------------

@runtime_checkable
class SealedStore(Protocol):
    """Where sealed token envelopes live — pointers, never plaintext.

    The value is the :mod:`nx_auth.atrest` wrapper dict
    (``{"_encrypted": ..., "_kid": ...}``). ``set`` must be **atomic and
    durable in one call** (a DB commit / a 0600-file rename): that single
    write is what makes rotation crash-safe — the old record survives
    untouched until the new one is fully stored.
    """

    def get(self, binding_id: str) -> dict[str, str] | None: ...

    def set(self, binding_id: str, sealed: dict[str, str]) -> None: ...

    def delete(self, binding_id: str) -> None: ...


class InMemorySealedStore:
    """Thread-safe reference :class:`SealedStore` (tests / single-process)."""

    def __init__(self) -> None:
        self._sealed: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def get(self, binding_id: str) -> dict[str, str] | None:
        with self._lock:
            wrapped = self._sealed.get(binding_id)
            return dict(wrapped) if wrapped is not None else None

    def set(self, binding_id: str, sealed: dict[str, str]) -> None:
        with self._lock:
            self._sealed[binding_id] = dict(sealed)

    def delete(self, binding_id: str) -> None:
        with self._lock:
            self._sealed.pop(binding_id, None)


class TokenVault:
    """Seals :class:`TokenSet` values into ``SecretCipher`` envelopes.

    Each binding's envelope carries ``context="oauth:<binding-id>"`` —
    the at-rest per-row binding (docs/atrest.md): a ciphertext copied to
    another binding fails to decrypt (typed ``needs-secret``, fail
    closed). With ``cipher=None`` every operation raises ``needs-secret``:
    **no keyring ⇒ no custody ⇒ no binding** (ADR-0042 clause 3; there
    is no plaintext fallback).
    """

    def __init__(self, store: SealedStore, *, cipher: SecretCipher | None) -> None:
        self._store = store
        self._cipher = cipher

    @staticmethod
    def _context(binding_id: str) -> str:
        return f"oauth:{binding_id}"

    def _require_cipher(self) -> SecretCipher:
        if self._cipher is None:
            raise OAuthError(
                "needs-secret",
                "no DATA_KEY cipher configured — token custody is unavailable",
            )
        return self._cipher

    def seal(self, binding_id: str, tokens: TokenSet) -> None:
        """Seal ``tokens`` under the binding's context (one atomic store write)."""
        cipher = self._require_cipher()
        wrapped = cipher.encrypt_value(tokens._payload(), context=self._context(binding_id))
        try:
            self._store.set(binding_id, wrapped)
        except Exception as exc:
            raise OAuthError(
                "not-ready",
                f"sealed token persistence failed: {type(exc).__name__}",
                retryable=True,
            ) from exc

    def rotate(self, binding_id: str, tokens: TokenSet) -> None:
        """Persist a rotated grant: the same single atomic sealed write as
        :meth:`seal`, named for the refresh path — the new grant is durable
        **before** the old record ceases to exist, which is the ordering the
        rotation-crash law requires (ADR-0042 clause 6)."""
        self.seal(binding_id, tokens)

    def unseal(self, binding_id: str) -> TokenSet:
        """Read back a sealed set. Absent → ``needs-auth`` (nothing bound
        here); custody failure (context mismatch / key rotated) →
        ``needs-secret`` (fail closed, re-bind)."""
        tokens = self.find(binding_id)
        if tokens is None:
            raise OAuthError("needs-auth", "no stored token set for this binding")
        return tokens

    def find(self, binding_id: str) -> TokenSet | None:
        """Like :meth:`unseal` but ``None`` instead of ``needs-auth``."""
        cipher = self._require_cipher()
        wrapped = self._store.get(binding_id)
        if wrapped is None:
            return None
        try:
            payload = cipher.decrypt_value(
                wrapped, context=self._context(binding_id), allow_plaintext_read=False
            )
        except ValueError as exc:
            raise OAuthError(
                "needs-secret",
                f"sealed token custody check failed: {type(exc).__name__}",
            ) from exc
        if not isinstance(payload, dict) or "access_token" not in payload:
            raise OAuthError("needs-secret", "sealed token payload is malformed")
        return TokenSet._from_payload(payload)

    def has(self, binding_id: str) -> bool:
        return self._store.get(binding_id) is not None

    def clear(self, binding_id: str) -> None:
        """Delete the binding's sealed record (unbind — ADR-0052 §3)."""
        try:
            self._store.delete(binding_id)
        except Exception as exc:
            raise OAuthError(
                "not-ready", f"sealed token deletion failed: {type(exc).__name__}"
            ) from exc


# ---------------------------------------------------------------------------
# TokenClient — single-flight refresh with bounded jittered retry
# ---------------------------------------------------------------------------

class TokenClient:
    """The binding-level façade: custody + single-flight refresh policy.

    One instance serves any number of bindings (``binding_id`` — the
    host's account/link/binding row id). Laws, all pinned in tests:

    * **Never serves a known-expired token:** ``access`` refreshes first
      when ``expires_at`` is inside the ``skew`` window (default 60 s).
    * **Single-flight:** concurrent refreshes of one binding await one
      attempt — the loser re-reads the vault and adopts either the
      leader's fresh tokens or, within ``flight_window`` seconds, the
      leader's typed failure (one invalid_grant burns exactly one
      provider round-trip, then *stops* — ADR-0042 §6).
    * **Bounded, jittered retry:** only ``retryable`` errors retry
      (``unreachable``/``rate-limited``), full-jitter exponential backoff
      capped at ``max_delay``, honoring a capped ``Retry-After``.
    * **Rotation-crash safety:** a fresh grant is sealed through
      :meth:`TokenVault.rotate` — one atomic write — before anything
      else observes it; a failing write leaves the old grant intact.
    """

    def __init__(
        self,
        client: OAuthClient,
        *,
        vault: TokenVault,
        transport: TokenTransport,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        jitter: Callable[[float], float] | None = None,
        skew: float = DEFAULT_SKEW_SECONDS,
        max_attempts: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 8.0,
        flight_window: float = 30.0,
    ) -> None:
        self._client = client
        self._vault = vault
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleep = sleep
        self._monotonic = monotonic
        self._jitter = jitter or (lambda bound: random.uniform(0.0, bound))
        self._skew = skew
        self._max_attempts = max(1, max_attempts)
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._flight_window = flight_window
        self._meta = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        # One adopted failure per binding within the flight window — the
        # "stop" half of the invalid_grant posture: followers must not
        # re-run a doom the leader already recorded.
        self._failures: dict[str, tuple[float, OAuthError]] = {}

    # --- custody pass-throughs -------------------------------------------

    def store(self, binding_id: str, tokens: TokenSet) -> None:
        """Seal a fresh grant (e.g. straight from :func:`exchange_code`)."""
        self._vault.seal(binding_id, tokens)

    def load(self, binding_id: str) -> TokenSet:
        """Unseal the binding's grant (typed ``needs-auth`` when absent)."""
        return self._vault.unseal(binding_id)

    def clear(self, binding_id: str) -> None:
        self._vault.clear(binding_id)

    # --- the refresh policy ----------------------------------------------

    def access(self, binding_id: str) -> str:
        """A live access token for the binding — refreshing first when the
        stored one is expired or inside its skew window."""
        tokens = self._vault.find(binding_id)
        if tokens is not None and not tokens.expired(now=self._clock(), skew=self._skew):
            return tokens.access_token
        return self._refresh(binding_id, force=False).access_token

    def refresh(self, binding_id: str) -> TokenSet:
        """Force one single-flight refresh (provider 401 recovery)."""
        return self._refresh(binding_id, force=True)

    def _lock_for(self, binding_id: str) -> threading.Lock:
        with self._meta:
            lock = self._locks.get(binding_id)
            if lock is None:
                lock = threading.Lock()
                self._locks[binding_id] = lock
            return lock

    def _refresh(self, binding_id: str, *, force: bool) -> TokenSet:
        with self._lock_for(binding_id):
            # Re-read under the lock: the leader may have just satisfied us.
            tokens = self._vault.find(binding_id)
            if (
                not force
                and tokens is not None
                and not tokens.expired(now=self._clock(), skew=self._skew)
            ):
                return tokens
            adopted = self._adopt_failure(binding_id)
            if adopted is not None:
                raise adopted
            if tokens is None or not tokens.refresh_token:
                raise OAuthError(
                    "needs-auth", "no stored grant with a refresh token for this binding"
                )
            try:
                fresh = self._attempt(tokens.refresh_token)
                # Rotation-crash safety: one atomic sealed write persists
                # the rotated grant BEFORE the old record is discarded. A
                # failing write leaves the old grant sealed and raises
                # typed — and is adopted like any other failed attempt.
                self._vault.rotate(binding_id, fresh)
            except OAuthError as exc:
                self._remember_failure(binding_id, exc)
                raise
            self._forget_failure(binding_id)
            logger.debug(
                "oauth: refreshed binding %s (%s)",
                binding_id,
                fresh.redacted(),
            )
            return fresh

    def _attempt(self, refresh_token: str) -> TokenSet:
        """One refresh with bounded full-jitter retry on transient errors."""
        last: OAuthError | None = None
        for attempt in range(self._max_attempts):
            try:
                return refresh_tokens(
                    self._client,
                    refresh_token=refresh_token,
                    transport=self._transport,
                    now=self._clock(),
                )
            except OAuthError as exc:
                last = exc
                if not exc.retryable or attempt == self._max_attempts - 1:
                    raise
                bound = min(self._max_delay, self._base_delay * (2**attempt))
                delay = min(self._max_delay, self._jitter(bound))
                if exc.retry_after is not None:
                    delay = min(self._max_delay, max(delay, exc.retry_after))
                self._sleep(delay)
        raise last if last is not None else OAuthError(  # pragma: no cover
            "unreachable", "refresh failed"
        )

    # --- adopted failures -------------------------------------------------

    def _remember_failure(self, binding_id: str, exc: OAuthError) -> None:
        with self._meta:
            self._failures[binding_id] = (self._monotonic(), exc)

    def _forget_failure(self, binding_id: str) -> None:
        with self._meta:
            self._failures.pop(binding_id, None)

    def _adopt_failure(self, binding_id: str) -> OAuthError | None:
        with self._meta:
            entry = self._failures.get(binding_id)
            if entry is None:
                return None
            stamp, exc = entry
            if self._monotonic() - stamp > self._flight_window:
                self._failures.pop(binding_id, None)
                return None
            return exc
