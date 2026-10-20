"""Input validation and normalization helpers."""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

from .exceptions import ValidationError

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_INSTITUTION_CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,31}$")

MAX_EMAIL_LENGTH = 254


def normalize_email(value: object) -> str:
    """Return the canonical form of an email address.

    Applies Unicode NFKC normalization, trims whitespace and lower-cases the
    whole address, so ``"  Asha@Example.EDU "`` and ``"asha@example.edu"`` are
    the same account. (Lower-casing the local part is a deliberate, pragmatic
    choice: virtually no real mail provider treats it as case-sensitive.)

    Raises:
        ValidationError: if the value is not a plausible email address.
    """
    if not isinstance(value, str):
        raise ValidationError("Email must be a string.")
    email = unicodedata.normalize("NFKC", value).strip().lower()
    if (
        not email
        or len(email) > MAX_EMAIL_LENGTH
        or _CONTROL_RE.search(email)
        or email.count("@") != 1
        or not _EMAIL_RE.fullmatch(email)
    ):
        raise ValidationError("Email address is not valid.")
    return email


def validate_new_password(value: object, *, min_length: int, max_length: int) -> str:
    """Validate a password chosen for a new account.

    The policy is length-based (NIST SP 800-63B style): no composition rules,
    but a minimum length, a maximum length (to bound hashing cost) and no
    control characters.
    """
    if not isinstance(value, str):
        raise ValidationError("Password must be a string.")
    if len(value) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters.")
    if len(value) > max_length:
        raise ValidationError(f"Password must be at most {max_length} characters.")
    if not value.strip():
        raise ValidationError("Password must not be blank.")
    if _CONTROL_RE.search(value):
        raise ValidationError("Password must not contain control characters.")
    return value


def _clean_text(value: object, field: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string.")
    text = " ".join(unicodedata.normalize("NFKC", value).split())
    if not text:
        raise ValidationError(f"{field} must not be empty.")
    if len(text) > max_length:
        raise ValidationError(f"{field} must be at most {max_length} characters.")
    if _CONTROL_RE.search(text):
        raise ValidationError(f"{field} must not contain control characters.")
    return text


def validate_full_name(value: object) -> str:
    """Trim and collapse whitespace; 1–120 characters."""
    return _clean_text(value, "Full name", 120)


def validate_institution_name(value: object) -> str:
    """Trim and collapse whitespace; 1–200 characters."""
    return _clean_text(value, "Institution name", 200)


def normalize_institution_code(value: object) -> str:
    """Upper-case code of 2–32 chars: letters, digits, ``_`` and ``-``."""
    if not isinstance(value, str):
        raise ValidationError("Institution code must be a string.")
    code = value.strip().upper()
    if not _INSTITUTION_CODE_RE.fullmatch(code):
        raise ValidationError(
            "Institution code must be 2-32 characters of A-Z, 0-9, '_' or '-'."
        )
    return code


def validate_id(value: object, field: str) -> int:
    """Require a positive ``int`` (``bool`` is rejected)."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{field} must be a positive integer.")
    return value


def validate_optional_id(value: object, field: str) -> Optional[int]:
    """Like :func:`validate_id` but ``None`` is allowed."""
    return None if value is None else validate_id(value, field)
