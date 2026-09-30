import functools

import bcrypt

MAX_PASSWORD_BYTES = 72


class PasswordPolicyError(ValueError):
    """Password rejected by policy (too short, or over the bcrypt byte
    cap) — maps to 422."""


def check_policy(password: str, min_length: int = 10) -> None:
    """Enforce the family password policy (contract §7).

    Rejects passwords shorter than `min_length` characters or longer
    than `MAX_PASSWORD_BYTES` **UTF-8 bytes** — bcrypt refuses input
    beyond 72 bytes, so the cap is measured in bytes, never characters
    (multibyte passwords count every encoded byte).
    """
    if len(password) < min_length:
        raise PasswordPolicyError(f"password must be at least {min_length} characters")
    byte_length = len(password.encode("utf-8"))
    if byte_length > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(
            f"password must be at most {MAX_PASSWORD_BYTES} bytes (bcrypt input limit)"
        )


def hash_password(password: str, *, rounds: int = 12) -> str:
    """Hash with bcrypt (≥12 rounds, family floor).

    Raises `PasswordPolicyError` for input over `MAX_PASSWORD_BYTES`
    UTF-8 bytes so no call path can reach bcrypt with oversized input.
    """
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(
            f"password must be at most {MAX_PASSWORD_BYTES} bytes (bcrypt input limit)"
        )
    if rounds < 12:
        raise ValueError("bcrypt rounds must be >= 12 (family floor)")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password("dummy-password-for-timing-parity")


def verify_password_or_dummy(password: str, password_hash: str | None) -> bool:
    """Constant-time-shaped verify: unknown users still pay one bcrypt check."""
    return verify_password(password, password_hash if password_hash is not None else _dummy_hash())
