"""Authorization engine: role permission + institution boundary + ownership.

The engine turns ``(principal, action, institution_id, resource_owner_id)``
into an :class:`AuthorizationDecision`. It never raises for a denial (callers
decide whether to raise) and never trusts a caller-supplied institution ID:
the ID must match the principal's own institution (resolved from the
database at session time) unless the role holds a GLOBAL permission, in which
case the institution must exist.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from typing import Optional

from .models import Action, AuthorizationDecision, CurrentUser, DenyReason, Role
from .policies import ANONYMOUS_ACTIONS, Scope, scope_for
from .repositories import InstitutionRepository
from .validators import validate_optional_id


class AuthorizationEngine:
    """Evaluates authorization decisions. Stateless apart from configuration."""

    def __init__(
        self,
        *,
        institutions: InstitutionRepository,
        allow_anonymous_public_verification: bool = True,
    ) -> None:
        self._institutions = institutions
        self._allow_anonymous = allow_anonymous_public_verification

    def evaluate(
        self,
        conn: sqlite3.Connection,
        principal: Optional[CurrentUser],
        action: object,
        *,
        institution_id: Optional[int] = None,
        resource_owner_id: Optional[int] = None,
    ) -> AuthorizationDecision:
        """Return an allow/deny decision. Deny is the default for anything unknown.

        Args:
            conn: open database connection (used to validate institution IDs).
            principal: authenticated user, or ``None`` for an anonymous caller.
            action: an :class:`Action` or its string value/name.
            institution_id: institution that owns the target resource.
            resource_owner_id: user ID that owns the target resource (for
                student-owned resources).

        Raises:
            ValidationError: if an ID argument is not a positive integer.
        """
        institution_id = validate_optional_id(institution_id, "institution_id")
        resource_owner_id = validate_optional_id(resource_owner_id, "resource_owner_id")
        parsed = Action.try_parse(action)
        role = _role_of(principal)

        decision = AuthorizationDecision(
            allowed=False,
            action=parsed.value if parsed else _safe_action_label(action),
            reason=DenyReason.NO_PERMISSION,
            user_id=principal.user_id if principal else None,
            role=role,
            institution_id=institution_id,
            resource_owner_id=resource_owner_id,
        )

        if parsed is None:
            return decision.denied(DenyReason.UNKNOWN_ACTION)

        if principal is None:
            if parsed in ANONYMOUS_ACTIONS and self._allow_anonymous:
                return _allow(decision, DenyReason.PUBLIC)
            return decision.denied(DenyReason.ANONYMOUS_NOT_PERMITTED)

        if role is None:
            return decision.denied(DenyReason.UNKNOWN_ROLE)

        scope = scope_for(role, parsed)
        if scope is None:
            return decision.denied(DenyReason.NO_PERMISSION)

        if scope is Scope.PUBLIC:
            return _allow(decision, DenyReason.PUBLIC)

        if scope is Scope.GLOBAL:
            if institution_id is not None and not self._institutions.exists(
                conn, institution_id
            ):
                return decision.denied(DenyReason.UNKNOWN_INSTITUTION)
            return _allow(decision)

        if scope is Scope.INSTITUTION:
            if institution_id is None:
                return decision.denied(DenyReason.INSTITUTION_REQUIRED)
            if principal.institution_id is None or principal.institution_id != institution_id:
                return decision.denied(DenyReason.CROSS_INSTITUTION)
            return _allow(decision)

        if scope is Scope.OWN:
            if resource_owner_id is None:
                return decision.denied(DenyReason.OWNER_REQUIRED)
            if resource_owner_id != principal.user_id:
                return decision.denied(DenyReason.NOT_RESOURCE_OWNER)
            if institution_id is not None and institution_id != principal.institution_id:
                return decision.denied(DenyReason.CROSS_INSTITUTION)
            return _allow(decision)

        return decision.denied(DenyReason.NO_PERMISSION)  # pragma: no cover


def _allow(decision: AuthorizationDecision, reason: str = DenyReason.ALLOWED) -> AuthorizationDecision:
    return replace(decision, allowed=True, reason=reason)


def _role_of(principal: Optional[CurrentUser]) -> Optional[Role]:
    if principal is None:
        return None
    role = principal.role
    if isinstance(role, Role):
        return role
    try:
        return Role(role)
    except ValueError:
        return None


def _safe_action_label(action: object) -> str:
    text = action if isinstance(action, str) else type(action).__name__
    cleaned = "".join(ch for ch in text if ch.isprintable())[:60]
    return cleaned or "<empty>"
