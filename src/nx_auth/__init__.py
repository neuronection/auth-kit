"""Neuronection auth-kit — the family identity contract.

Layers: identity (this package's `core` surface), authorization
(`tenants` = interface only), profile (consumers own the data; the kit
owns auto-provisioning rules). Normative contract lives in the family
guidelines; this package is the reference implementation.
"""

from nx_auth.config import AuthConfig
from nx_auth.deps import get_current_user, get_optional_principal, require_admin
from nx_auth.install import AuthKit, install
from nx_auth.instance import InstanceMode, InstanceState, read_state, request_transition
from nx_auth.keys import KeyRing
from nx_auth.principal import Principal
from nx_auth.tokens import AuthMode, TokenError, TokenKind, mint_token, verify_token

__version__ = "0.1.0"

__all__ = [
    "AuthConfig",
    "AuthKit",
    "AuthMode",
    "InstanceMode",
    "InstanceState",
    "KeyRing",
    "Principal",
    "TokenError",
    "TokenKind",
    "get_current_user",
    "get_optional_principal",
    "install",
    "mint_token",
    "read_state",
    "request_transition",
    "require_admin",
    "verify_token",
    "__version__",
]
