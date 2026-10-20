"""Configuration for Module 6.

All settings have safe development defaults and can be overridden either by
constructing :class:`Settings` directly (recommended in tests) or from
environment variables via :meth:`Settings.from_env`.

Environment variables (see ``.env.example``):

=================================  ==========================================
``M6_DATABASE_PATH``               Path of this module's own SQLite file.
``M6_SESSION_TTL_MINUTES``         Absolute session lifetime (default 60).
``M6_PASSWORD_MIN_LENGTH``         Minimum new-password length (default 12).
``M6_ALLOW_ANONYMOUS_VERIFICATION`` ``true``/``false`` (default ``true``).
``M6_SESSION_TOKEN_PEPPER``        Optional secret; if set, token hashes are
                                   HMAC-SHA256 instead of plain SHA-256.
``M6_ARGON2_TIME_COST``            Argon2id iterations (default 3).
``M6_ARGON2_MEMORY_COST``          Argon2id memory in KiB (default 65536).
``M6_ARGON2_PARALLELISM``          Argon2id lanes (default 4).
=================================  ==========================================

No secret is hard-coded here. This module never reads a ``.env`` file itself;
the host application (or your shell) is responsible for exporting variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Mapping, Optional

from .exceptions import ConfigurationError

PACKAGE_DIR = Path(__file__).resolve().parent
#: Default database location: inside the package's git-ignored ``instance/``.
DEFAULT_DATABASE_PATH = PACKAGE_DIR / "instance" / "module6_access_control.db"

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings for the access-control service."""

    database_path: Path = DEFAULT_DATABASE_PATH
    session_ttl: timedelta = timedelta(minutes=60)
    password_min_length: int = 12
    password_max_length: int = 256
    allow_anonymous_public_verification: bool = True
    session_token_pepper: Optional[str] = field(default=None, repr=False)
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    def __post_init__(self) -> None:
        object.__setattr__(self, "database_path", Path(self.database_path))
        if str(self.database_path) == ":memory:":
            raise ConfigurationError(
                "In-memory databases are not supported; use a file path "
                "(tests use pytest's tmp_path)."
            )
        if self.session_ttl <= timedelta(0):
            raise ConfigurationError("session_ttl must be positive.")
        if not 8 <= self.password_min_length <= self.password_max_length:
            raise ConfigurationError("password_min_length must be >= 8 and <= max length.")
        if self.password_max_length > 1024:
            raise ConfigurationError("password_max_length must be <= 1024.")
        if self.argon2_time_cost < 1 or self.argon2_parallelism < 1:
            raise ConfigurationError("Argon2 time cost and parallelism must be >= 1.")
        if self.argon2_memory_cost < 8 * self.argon2_parallelism:
            raise ConfigurationError("Argon2 memory cost must be >= 8 * parallelism KiB.")
        if self.session_token_pepper is not None and len(self.session_token_pepper) < 16:
            raise ConfigurationError("session_token_pepper must be at least 16 characters.")

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        """Build settings from environment variables, falling back to defaults."""
        env = os.environ if env is None else env
        kwargs: dict = {}
        if env.get("M6_DATABASE_PATH"):
            kwargs["database_path"] = Path(env["M6_DATABASE_PATH"]).expanduser()
        if env.get("M6_SESSION_TTL_MINUTES"):
            kwargs["session_ttl"] = timedelta(minutes=_int(env, "M6_SESSION_TTL_MINUTES"))
        if env.get("M6_PASSWORD_MIN_LENGTH"):
            kwargs["password_min_length"] = _int(env, "M6_PASSWORD_MIN_LENGTH")
        if env.get("M6_ALLOW_ANONYMOUS_VERIFICATION"):
            kwargs["allow_anonymous_public_verification"] = _bool(
                env, "M6_ALLOW_ANONYMOUS_VERIFICATION"
            )
        if env.get("M6_SESSION_TOKEN_PEPPER"):
            kwargs["session_token_pepper"] = env["M6_SESSION_TOKEN_PEPPER"]
        for name, key in (
            ("argon2_time_cost", "M6_ARGON2_TIME_COST"),
            ("argon2_memory_cost", "M6_ARGON2_MEMORY_COST"),
            ("argon2_parallelism", "M6_ARGON2_PARALLELISM"),
        ):
            if env.get(key):
                kwargs[name] = _int(env, key)
        return cls(**kwargs)


def _int(env: Mapping[str, str], key: str) -> int:
    try:
        return int(env[key])
    except ValueError as exc:
        raise ConfigurationError(f"{key} must be an integer.") from exc


def _bool(env: Mapping[str, str], key: str) -> bool:
    value = env[key].strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigurationError(f"{key} must be true or false.")
