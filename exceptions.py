"""Exception hierarchy for Module 6 (Access Control and Issuer Authorization).

Every exception raised deliberately by this package derives from
:class:`AccessControlError`. Each class carries an ``http_status`` hint so a
future Flask (or other) integration layer can map errors to responses without
inspecting messages.

Hierarchy::

    AccessControlError
    ├── ValidationError                 (400)  malformed or unacceptable input
    ├── AuthenticationError             (401)  caller is NOT authenticated
    │   ├── AuthenticationRequiredError        no session token supplied
    │   ├── InvalidCredentialsError            login failed (generic message)
    │   └── InvalidSessionError                token unknown/expired/revoked,
    │                                          or account/institution inactive
    ├── AuthorizationError              (403)  authenticated but NOT allowed
    │   └── PermissionDeniedError              carries the AuthorizationDecision
    ├── NotFoundError                   (404)
    │   ├── InstitutionNotFoundError
    │   └── UserNotFoundError
    ├── ConflictError                   (409)
    │   ├── DuplicateUserError
    │   └── DuplicateInstitutionError
    └── ConfigurationError              (500)  invalid settings / schema
"""

from __future__ import annotations

from typing import Any


class AccessControlError(Exception):
    """Base class for all Module 6 errors."""

    http_status: int = 500
    default_message: str = "Access control error."

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.default_message)

    @property
    def message(self) -> str:
        """Safe, user-presentable message."""
        return str(self.args[0]) if self.args else self.default_message


class ValidationError(AccessControlError, ValueError):
    """Input was malformed or violates a validation rule."""

    http_status = 400
    default_message = "Invalid input."


class ConfigurationError(AccessControlError):
    """Settings or database schema are invalid or incompatible."""

    http_status = 500
    default_message = "Access control is misconfigured."


# --------------------------------------------------------------------------- #
# Authentication (401): the caller has not proven who they are.
# --------------------------------------------------------------------------- #
class AuthenticationError(AccessControlError):
    """The request is not authenticated."""

    http_status = 401
    default_message = "Authentication required."


class AuthenticationRequiredError(AuthenticationError):
    """No session token was supplied for an operation that requires one."""

    default_message = "Authentication required."


class InvalidCredentialsError(AuthenticationError):
    """Login failed.

    The message is deliberately generic and identical for unknown emails,
    wrong passwords, deactivated accounts and deactivated institutions, so
    that callers cannot discover which accounts exist.
    """

    default_message = "Invalid email or password."


class InvalidSessionError(AuthenticationError):
    """Session token is unknown, malformed, expired, revoked, or belongs to
    a deactivated account or institution."""

    default_message = "Session is invalid or has expired."


# --------------------------------------------------------------------------- #
# Authorization (403): the caller is known but not allowed.
# --------------------------------------------------------------------------- #
class AuthorizationError(AccessControlError):
    """The authenticated caller is not permitted to perform the action."""

    http_status = 403
    default_message = "You are not permitted to perform this action."


class PermissionDeniedError(AuthorizationError):
    """Raised when an authorization decision is a denial.

    Attributes:
        decision: the :class:`~module6_access_control.models.AuthorizationDecision`
            that was denied (its ``reason`` is a stable machine-readable code).
    """

    def __init__(self, decision: Any = None, message: str | None = None) -> None:
        self.decision = decision
        super().__init__(message)

    @property
    def reason(self) -> str | None:
        """Machine-readable denial reason code, if a decision is attached."""
        return getattr(self.decision, "reason", None)


# --------------------------------------------------------------------------- #
# Not found / conflict.
# --------------------------------------------------------------------------- #
class NotFoundError(AccessControlError):
    """Referenced entity does not exist."""

    http_status = 404
    default_message = "Not found."


class InstitutionNotFoundError(NotFoundError):
    default_message = "Institution not found."


class UserNotFoundError(NotFoundError):
    default_message = "User not found."


class ConflictError(AccessControlError):
    """Operation conflicts with existing state."""

    http_status = 409
    default_message = "Conflict with existing data."


class DuplicateUserError(ConflictError):
    default_message = "A user with this email already exists."


class DuplicateInstitutionError(ConflictError):
    default_message = "An institution with this code already exists."
