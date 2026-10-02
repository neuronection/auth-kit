"""Neuronection auth-kit — the family identity contract.

Layers: identity (this package's `core` surface), authorization
(`tenants` = interface only), profile (consumers own the data; the kit
owns auto-provisioning rules). Normative contract lives in the family
guidelines; this package is the reference implementation.
"""

from nx_auth.boot import BootConfigError, validate_boot_config
from nx_auth.config import AUTH_KNOB_ENV_NAMES, AuthConfig, knob_overrides
from nx_auth.deps import get_current_user, get_optional_principal, require_admin
from nx_auth.install import AuthKit, install
from nx_auth.instance import (
    IdentityMode,
    InstanceMode,
    InstanceState,
    initialize_instance,
    parse_identity_mode,
    read_state,
    request_transition,
)
from nx_auth.keys import KeyRing
from nx_auth.principal import Principal
from nx_auth.tokens import AuthMode, TokenError, TokenKind, mint_token, verify_token

__version__ = "0.3.2"

__all__ = [
    "AUTH_KNOB_ENV_NAMES",
    "AuthConfig",
    "AuthKit",
    "AuthMode",
    "BootConfigError",
    "IdentityMode",
    "InstanceMode",
    "InstanceState",
    "KeyRing",
    "Principal",
    "TokenError",
    "TokenKind",
    "__version__",
    "get_current_user",
    "get_optional_principal",
    "initialize_instance",
    "install",
    "knob_overrides",
    "mint_token",
    "parse_identity_mode",
    "read_state",
    "request_transition",
    "require_admin",
    "validate_boot_config",
    "verify_token",
]
