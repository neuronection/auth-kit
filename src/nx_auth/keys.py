from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

KEY_BYTES = 32
_MIN_KEY_CHARS = 32  # token_urlsafe(32) → 43 chars; anything shorter is operator-supplied weakness
_PLACEHOLDER_KEYS = frozenset(
    {"changeme", "change-me", "secret", "secret-key", "dev", "dev-key", "test", "test-key",
     "example", "placeholder", "insecure", "todo", "not-a-secret", "replace-me"}
)
_KEY_ROLES = ("session", "refresh", "data")


def generate_key() -> str:
    return secrets.token_urlsafe(KEY_BYTES)


@dataclass(frozen=True)
class KeyRing:
    """Three independent per-instance secrets (contract §8).

    `session_key` signs session tokens, `refresh_key` signs refresh
    tokens, `data_key` encrypts secrets at rest (Fernet). No key signs
    two kinds and **no key is ever derived from another** — the family
    explicitly retired JWT-derived Fernet keys and single shared
    secrets.
    """

    session_key: str
    refresh_key: str
    data_key: str

    def __post_init__(self) -> None:
        values = (self.session_key, self.refresh_key, self.data_key)
        if any(not value for value in values):
            raise ValueError("keyring requires all three keys")
        # Weak-secret boot guard (contract §8): every construction
        # path (env, file, direct) funnels through here, so a weak or
        # placeholder key can never enter a ring — generated keys are 43
        # chars of entropy, and operators must match that bar. This is
        # the kit's enforcement point for the family rule; products with
        # their own Settings keep their boot-time copy of the same check.
        for role, value in zip(_KEY_ROLES, values):
            normalized = value.strip()
            if len(normalized) < _MIN_KEY_CHARS or normalized.lower() in _PLACEHOLDER_KEYS:
                raise ValueError(
                    f"{role}_key is too weak (contract §8 weak-secret boot "
                    f"guard): keys must be at least {_MIN_KEY_CHARS} chars of "
                    "high-entropy material, e.g. "
                    '`python -c "import secrets; print(secrets.token_urlsafe(48))" '
                    "— refusing to construct the keyring"
                )
        if len(set(values)) != 3:
            raise ValueError("session/refresh/data keys must be distinct")

    @classmethod
    def generate(cls) -> KeyRing:
        return cls(session_key=generate_key(), refresh_key=generate_key(), data_key=generate_key())

    @classmethod
    def from_env(cls, prefix: str) -> KeyRing | None:
        """Per-key env precedence: `<P>_SESSION_KEY` / `<P>_REFRESH_KEY` / `<P>_DATA_KEY`."""
        values = {role: os.environ.get(f"{prefix}_{role.upper()}_KEY", "") for role in _KEY_ROLES}
        if not any(values.values()):
            return None
        # Config-shape error first (partial env), so operators get the
        # precise diagnosis; strength is enforced at construction below.
        missing = [role for role in _KEY_ROLES if not values[role]]
        if missing:
            raise ValueError(
                f"partial key env for prefix {prefix!r}: missing {missing} — "
                "provide all three or none"
            )
        return cls(
            session_key=values["session"],
            refresh_key=values["refresh"],
            data_key=values["data"],
        )

    @classmethod
    def from_file(cls, path: Path) -> KeyRing | None:
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            session_key=str(raw["session"]),
            refresh_key=str(raw["refresh"]),
            data_key=str(raw["data"]),
        )

    def save_to_file(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"session": self.session_key, "refresh": self.refresh_key, "data": self.data_key},
            indent=0,
        )
        path.write_text(payload + "\n", encoding="utf-8")
        os.chmod(path, 0o600)

    @classmethod
    def load_or_generate(cls, path: Path, prefix: str) -> KeyRing:
        """Env (all three) > file (0600, generated if absent) > fail on partial env."""
        from_env = cls.from_env(prefix)
        if from_env is not None:
            return from_env
        from_file = cls.from_file(path)
        if from_file is not None:
            return from_file
        ring = cls.generate()
        ring.save_to_file(path)
        return ring
