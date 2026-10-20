"""Argon2id password hashing (via ``argon2-cffi``).

Argon2id is a memory-hard, salted key-derivation function, the winner of the
Password Hashing Competition and the OWASP-recommended default. Each hash
embeds its own random salt and parameters, e.g.
``$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>``.
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class PasswordHasher:
    """Hash and verify passwords. Never logs or stores plaintext."""

    def __init__(self, *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4):
        self._hasher = _Argon2Hasher(
            time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
        )
        self._dummy_hash: str | None = None

    def hash(self, password: str) -> str:
        """Return a salted Argon2id hash of ``password``."""
        return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        """Return True iff ``password`` matches ``stored_hash``.

        Never raises for a wrong password or a corrupt hash; returns False.
        """
        try:
            return self._hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """True if the hash was made with outdated parameters."""
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    def burn(self, password: str = "") -> None:
        """Spend the same work as a real verification against a dummy hash.

        Used when the email is unknown so that response time does not reveal
        whether an account exists.
        """
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash("module6-timing-equalizer")
        self.verify(self._dummy_hash, password)
