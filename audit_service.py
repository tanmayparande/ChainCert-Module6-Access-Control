"""Audit logging.

Records who did what, to what, in which institution, when, and with what
outcome. Descriptions are composed by this module from safe values; callers
never pass passwords, password hashes or session tokens, and descriptions are
sanitized and length-capped as a second line of defence.

Limitation: the audit table is append-only via SQLite triggers, but anyone
with direct write access to the database file can drop the triggers and edit
rows. This log is therefore *not* tamper-proof against privileged database
operators; ship events to an external append-only store if that matters.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Optional

from .models import (
    Action,
    AuditEvent,
    AuditOutcome,
    AuthorizationDecision,
    Clock,
    CurrentUser,
    Role,
)
from .policies import PRIVILEGED_ACTIONS
from .repositories import AuditRepository, InstitutionRepository

MAX_DESCRIPTION_LENGTH = 500
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


class AuditEvents:
    """Audit ``action`` names used by this module (besides ``authz.*``)."""

    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    BOOTSTRAP = "user.bootstrap_platform_admin"
    USER_PROVISION = "user.provision"
    USER_ROLE_CHANGE = "user.role_change"
    USER_DEACTIVATE = "user.deactivate"
    USER_REACTIVATE = "user.reactivate"
    USER_LIST = "user.list"
    INSTITUTION_CREATE = "institution.create"
    INSTITUTION_DEACTIVATE = "institution.deactivate"
    INSTITUTION_REACTIVATE = "institution.reactivate"
    AUDIT_READ = "audit.read"

    @staticmethod
    def for_decision(action: str) -> str:
        """Audit name for an authorization decision, e.g. ``authz.certificate.issue``."""
        return f"authz.{action}"


def sanitize_description(text: str) -> str:
    """Remove control characters (log injection) and cap the length."""
    cleaned = _CONTROL_RE.sub(" ", str(text)).strip()
    if len(cleaned) > MAX_DESCRIPTION_LENGTH:
        cleaned = cleaned[: MAX_DESCRIPTION_LENGTH - 3] + "..."
    return cleaned or "-"


class AuditService:
    """Writes and reads audit events. Access control for reads lives in the facade."""

    def __init__(
        self,
        *,
        repository: AuditRepository,
        institutions: InstitutionRepository,
        clock: Clock,
    ) -> None:
        self._repo = repository
        self._institutions = institutions
        self._clock = clock

    def record(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        outcome: AuditOutcome,
        description: str,
        actor: Optional[CurrentUser] = None,
        actor_user_id: Optional[int] = None,
        actor_role: Optional[Role | str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[object] = None,
        institution_id: Optional[int] = None,
    ) -> int:
        """Insert one audit event inside the caller's transaction."""
        if actor is not None:
            actor_user_id = actor.user_id
            actor_role = actor.role
        role_text = actor_role.value if isinstance(actor_role, Role) else actor_role

        # A caller may reference an institution that does not exist (e.g. a
        # probing request). Keep the FK valid and note the raw ID instead.
        if institution_id is not None and not self._institutions.exists(conn, institution_id):
            description = f"{description} (requested institution id {institution_id} does not exist)"
            institution_id = None

        return self._repo.insert(
            conn,
            occurred_at=self._clock(),
            actor_user_id=actor_user_id,
            actor_role=role_text,
            action=action,
            target_type=target_type,
            target_id=None if target_id is None else str(target_id)[:100],
            institution_id=institution_id,
            outcome=outcome,
            description=sanitize_description(description),
        )

    def should_record_decision(self, decision: AuthorizationDecision) -> bool:
        """Denials are always recorded; allows only for privileged actions."""
        if not decision.allowed:
            return True
        parsed = Action.try_parse(decision.action)
        return parsed in PRIVILEGED_ACTIONS

    def record_decision(
        self,
        conn: sqlite3.Connection,
        decision: AuthorizationDecision,
        *,
        detail: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[object] = None,
        force: bool = False,
    ) -> Optional[int]:
        """Record an authorization decision if policy says it should be logged."""
        if not force and not self.should_record_decision(decision):
            return None
        verb = "Allowed" if decision.allowed else "Denied"
        description = f"{verb} '{decision.action}' (reason: {decision.reason})"
        if decision.resource_owner_id is not None:
            description += f"; resource owner {decision.resource_owner_id}"
        if detail:
            description += f"; {detail}"
        return self.record(
            conn,
            action=AuditEvents.for_decision(decision.action),
            outcome=AuditOutcome.SUCCESS if decision.allowed else AuditOutcome.DENIED,
            description=description,
            actor_user_id=decision.user_id,
            actor_role=decision.role,
            target_type=target_type,
            target_id=target_id,
            institution_id=decision.institution_id,
        )

    def list_events(
        self,
        conn: sqlite3.Connection,
        *,
        institution_id: Optional[int] = None,
        actor_user_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        return self._repo.list(
            conn,
            institution_id=institution_id,
            actor_user_id=actor_user_id,
            action=action,
            limit=limit,
        )
