"""Tenants & roles — the **interface only** (contract decision 9).

Health's tenant/SMART/FHIR stack deliberately stays in the health repo:
extracting it here would drag clinical coupling into a general-purpose
kit and violates the family's two-app rule (only one product has
tenants). What is shared is the *shape*: a principal may carry
`tenant_id`, products compare it with `require_tenant`, and restricted
roles use `RoleChecker`. Career/study never import this module.
"""

from collections.abc import Collection

from fastapi import HTTPException

from nx_auth.principal import Principal


def not_found() -> HTTPException:
    """Hidden-404: resources outside ownership/tenancy do not confirm
    existence (the multi-tenant pattern, contract §7)."""
    return HTTPException(status_code=404, detail="Not found")


def require_tenant(principal: Principal, row_tenant_id: str | None) -> None:
    """Hard tenant filter at the service edge: mismatch ⇒ 404, never 403."""
    if principal.tenant_id is None or row_tenant_id != principal.tenant_id:
        raise not_found()


class RoleResolver:
    """Consumer-supplied mapping from a principal to its role in the
    current scope (health resolves per-tenant roles; the kit has no
    roles table by design — a roles table needs a new ADR).

    Subclass in the product and return the role as a `str` (StrEnum
    values qualify); `None` means "no role in this scope".
    """

    def role_of(self, principal: Principal) -> str | None:  # pragma: no cover - base
        raise NotImplementedError


class RoleChecker:
    """FastAPI dependency factory: role gate with 404-hiding semantics.

    `allowed` accepts any string collection (StrEnum role sets included);
    unknown/unmapped principals are hidden as 404 for row-scoped routes
    (`hide=True`, health default) or rejected 403 for surface-level
    routes.
    """

    def __init__(
        self,
        resolver: RoleResolver,
        allowed: Collection[str],
        *,
        hide: bool = True,
    ) -> None:
        self._resolver = resolver
        self._allowed = allowed
        self._hide = hide

    def __call__(self, principal: Principal) -> Principal:
        role = self._resolver.role_of(principal)
        if role is not None and role in self._allowed:
            return principal
        if self._hide and role is None:
            raise not_found()
        raise HTTPException(status_code=403, detail="Insufficient role")
