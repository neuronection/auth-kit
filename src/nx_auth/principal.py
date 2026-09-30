from dataclasses import dataclass

from nx_auth.tokens import AuthMode


@dataclass(frozen=True)
class Principal:
    """The authenticated caller — the only thing endpoints should trust.

    Never built from client input: always verified against a session
    token AND the live user row AND the instance's current access mode.
    """

    user_id: str
    email: str
    full_name: str
    is_admin: bool
    is_active: bool
    ver: int
    auth_mode: AuthMode
    family_id: str | None = None
    tenant_id: str | None = None

    @property
    def is_demo(self) -> bool:
        return self.auth_mode is AuthMode.DEMO
