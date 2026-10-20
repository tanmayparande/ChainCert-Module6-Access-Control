"""ChainCert Module 6 — Access Control and Issuer Authorization.

Public API (stable)::

    from module6_access_control import AccessControlService, Settings, Action, Role

Everything importable from this package root is part of the integration
contract. Submodules not re-exported here are internal and may change.
"""

from .config import Settings
from .exceptions import (
    AccessControlError,
    AuthenticationError,
    AuthenticationRequiredError,
    AuthorizationError,
    ConfigurationError,
    ConflictError,
    DuplicateInstitutionError,
    DuplicateUserError,
    InstitutionNotFoundError,
    InvalidCredentialsError,
    InvalidSessionError,
    NotFoundError,
    PermissionDeniedError,
    UserNotFoundError,
    ValidationError,
)
from .models import (
    Action,
    AuditEvent,
    AuditOutcome,
    AuthorizationDecision,
    AuthResult,
    CurrentUser,
    DenyReason,
    Institution,
    Role,
    User,
)
from .policies import PERMISSION_MATRIX, Scope
from .service import AccessControlService

__version__ = "1.0.0"

__all__ = [
    "AccessControlService",
    "Settings",
    "Action",
    "Role",
    "Scope",
    "PERMISSION_MATRIX",
    "DenyReason",
    "AuthResult",
    "AuthorizationDecision",
    "CurrentUser",
    "User",
    "Institution",
    "AuditEvent",
    "AuditOutcome",
    "AccessControlError",
    "ValidationError",
    "ConfigurationError",
    "AuthenticationError",
    "AuthenticationRequiredError",
    "InvalidCredentialsError",
    "InvalidSessionError",
    "AuthorizationError",
    "PermissionDeniedError",
    "NotFoundError",
    "InstitutionNotFoundError",
    "UserNotFoundError",
    "ConflictError",
    "DuplicateUserError",
    "DuplicateInstitutionError",
    "__version__",
]
