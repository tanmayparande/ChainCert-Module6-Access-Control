"""Domain models, enums and time helpers for Module 6.

These are plain, immutable dataclasses. They are the only data types that
cross the public API boundary; no ``sqlite3.Row`` or SQL detail leaks out.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from .exceptions import PermissionDeniedError, ValidationError

#: A clock is any zero-argument callable returning a timezone-aware datetime.
#: Injecting it makes session expiry fully deterministic in tests.
Clock = Callable[[], datetime]


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def to_db_time(value: datetime) -> str:
    """Serialize an aware datetime to a fixed-width UTC ISO-8601 string.

    The fixed format means stored timestamps also sort correctly as text.
    """
    if value.tzinfo is None:
        raise ValueError("Naive datetimes are not allowed; use timezone-aware UTC.")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def from_db_time(value: Optional[str]) -> Optional[datetime]:
    """Parse a timestamp produced by :func:`to_db_time` (``None`` passes through)."""
    return None if value is None else datetime.fromisoformat(value)


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #
class Role(str, Enum):
    """The five ChainCert roles."""

    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    INSTITUTION_ADMIN = "INSTITUTION_ADMIN"
    ISSUER = "ISSUER"
    STUDENT = "STUDENT"
    PUBLIC_VERIFIER = "PUBLIC_VERIFIER"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def requires_institution(self) -> bool:
        """True if users with this role must belong to exactly one institution."""
        return self in INSTITUTION_BOUND_ROLES

    @classmethod
    def parse(cls, value: "Role | str") -> "Role":
        """Convert a string such as ``"issuer"`` into a :class:`Role`.

        Raises:
            ValidationError: if the value is not one of the five roles.
        """
        if isinstance(value, Role):
            return value
        if isinstance(value, str):
            try:
                return cls(value.strip().upper())
            except ValueError:
                pass
        raise ValidationError("Unknown role.")


#: Roles whose users always belong to one institution.
INSTITUTION_BOUND_ROLES = frozenset({Role.INSTITUTION_ADMIN, Role.ISSUER, Role.STUDENT})
#: Roles whose users never belong to an institution.
GLOBAL_ROLES = frozenset({Role.PLATFORM_ADMIN, Role.PUBLIC_VERIFIER})


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
class Action(str, Enum):
    """Every action this module can authorize. Anything else is denied."""

    MANAGE_INSTITUTIONS = "institution.manage"
    PROVISION_USER = "user.provision"
    MANAGE_USER_ROLES = "user.manage_role"
    MANAGE_USER_STATUS = "user.manage_status"
    VIEW_USERS = "user.view"
    ISSUE_CERTIFICATE = "certificate.issue"
    CORRECT_CERTIFICATE = "certificate.correct"
    ADMINISTER_CERTIFICATE_BATCH = "certificate.batch_admin"
    REVOKE_CERTIFICATE = "certificate.revoke"
    VIEW_CERTIFICATE = "certificate.view"
    VERIFY_CERTIFICATE_PUBLIC = "certificate.verify_public"
    READ_AUDIT_LOG = "audit.read"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @classmethod
    def try_parse(cls, value: object) -> Optional["Action"]:
        """Return the matching :class:`Action`, or ``None`` if unknown.

        Accepts an ``Action``, its value (``"certificate.issue"``) or its
        name (``"ISSUE_CERTIFICATE"``). Unknown input never raises; it simply
        yields ``None`` so the caller can deny by default.
        """
        if isinstance(value, Action):
            return value
        if not isinstance(value, str):
            return None
        text = value.strip()
        try:
            return cls(text)
        except ValueError:
            return cls.__members__.get(text.upper())


class AuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class DenyReason:
    """Stable, machine-readable reason codes used in AuthorizationDecision."""

    ALLOWED = "allowed"
    PUBLIC = "public_access"
    UNKNOWN_ACTION = "unknown_action"
    UNKNOWN_ROLE = "unknown_role"
    NO_PERMISSION = "role_lacks_permission"
    ANONYMOUS_NOT_PERMITTED = "anonymous_not_permitted"
    INSTITUTION_REQUIRED = "institution_scope_required"
    CROSS_INSTITUTION = "cross_institution_access"
    UNKNOWN_INSTITUTION = "unknown_institution"
    OWNER_REQUIRED = "resource_owner_required"
    NOT_RESOURCE_OWNER = "not_resource_owner"
    SELF_MODIFICATION = "self_modification_not_allowed"
    ROLE_NOT_ASSIGNABLE = "role_not_assignable"
    TARGET_NOT_MANAGEABLE = "target_not_manageable"


# --------------------------------------------------------------------------- #
# Entities
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Institution:
    id: int
    code: str
    name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class User:
    """Public view of a user account. Never contains the password hash."""

    id: int
    email: str
    full_name: str
    role: Role
    institution_id: Optional[int]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime]


@dataclass(frozen=True)
class CurrentUser:
    """An authenticated principal resolved from a valid session.

    This is what integrators receive from ``get_current_user``. Role and
    institution are read from the database on every resolution, so role
    changes and deactivations take effect immediately.
    """

    user_id: int
    email: str
    full_name: str
    role: Role
    institution_id: Optional[int]
    session_id: int
    session_expires_at: datetime


@dataclass(frozen=True)
class AuthResult:
    """Result of a successful login.

    ``session_token`` is the only copy of the raw token; the database stores
    only its hash. It is excluded from ``repr`` so it does not end up in logs.
    """

    session_token: str = field(repr=False)
    expires_at: datetime
    user: CurrentUser


@dataclass(frozen=True)
class AuthorizationDecision:
    """Outcome of an authorization check.

    Truthy when allowed, so ``if service.can_issue_certificate(...):`` works.
    ``reason`` is a :class:`DenyReason` code, safe to log or return to clients.
    """

    allowed: bool
    action: str
    reason: str
    user_id: Optional[int] = None
    role: Optional[Role] = None
    institution_id: Optional[int] = None
    resource_owner_id: Optional[int] = None

    def __bool__(self) -> bool:
        return self.allowed

    def denied(self, reason: str) -> "AuthorizationDecision":
        """Return a copy of this decision turned into a denial."""
        return replace(self, allowed=False, reason=reason)

    def raise_if_denied(self) -> "AuthorizationDecision":
        """Return ``self`` if allowed, else raise :class:`PermissionDeniedError`."""
        if not self.allowed:
            raise PermissionDeniedError(self)
        return self


@dataclass(frozen=True)
class AuditEvent:
    id: int
    occurred_at: datetime
    actor_user_id: Optional[int]
    actor_role: Optional[str]
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    institution_id: Optional[int]
    outcome: AuditOutcome
    description: str
