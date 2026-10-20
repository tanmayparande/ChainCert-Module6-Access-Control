"""Institution and user administration with enforced authorization.

Every method takes an already-authenticated :class:`CurrentUser` and enforces
permissions itself; there is no way to call these operations "around" the
policy. Pattern used throughout::

    with transaction:
        decision = engine.evaluate(...)          # role + institution scope
        decision = extra escalation checks       # assignable roles, self-edits
        if denied:  audit DENIED                 # committed
        else:       mutate + audit SUCCESS       # committed together
    raise PermissionDeniedError if denied        # after commit, so the audit row persists
"""

from __future__ import annotations

from typing import Optional

from .audit_service import AuditEvents, AuditService
from .authorization import AuthorizationEngine
from .config import Settings
from .database import Database
from .exceptions import (
    AccessControlError,
    ConflictError,
    DuplicateInstitutionError,
    DuplicateUserError,
    PermissionDeniedError,
    UserNotFoundError,
    ValidationError,
)
from .models import (
    Action,
    AuditEvent,
    AuditOutcome,
    AuthorizationDecision,
    Clock,
    CurrentUser,
    DenyReason,
    Institution,
    Role,
    User,
)
from .password_hasher import PasswordHasher
from .policies import assignable_roles
from .repositories import InstitutionRepository, SessionRepository, UserRepository
from .validators import (
    normalize_email,
    normalize_institution_code,
    validate_full_name,
    validate_id,
    validate_institution_name,
    validate_new_password,
    validate_optional_id,
)

MAX_AUDIT_PAGE = 1000


class ManagementService:
    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
        engine: AuthorizationEngine,
        users: UserRepository,
        sessions: SessionRepository,
        institutions: InstitutionRepository,
        clock: Clock,
    ) -> None:
        self._db = database
        self._settings = settings
        self._hasher = hasher
        self._audit = audit
        self._engine = engine
        self._users = users
        self._sessions = sessions
        self._institutions = institutions
        self._clock = clock

    # ------------------------------------------------------------------ #
    # Bootstrap
    # ------------------------------------------------------------------ #
    def bootstrap_platform_admin(self, *, email: str, password: str, full_name: str) -> User:
        """Create the very first platform administrator.

        Only works while no platform administrator exists; afterwards all
        accounts must be provisioned by an authorized administrator.

        Raises:
            ConflictError: a platform administrator already exists.
        """
        email_n = normalize_email(email)
        pw = self._validate_password(password)
        name = validate_full_name(full_name)
        password_hash = self._hasher.hash(pw)
        now = self._clock()
        error: Optional[AccessControlError] = None
        with self._db.transaction() as conn:
            if self._users.count_with_role(conn, Role.PLATFORM_ADMIN) > 0:
                error = ConflictError(
                    "A platform administrator already exists; use provision_user()."
                )
                self._audit.record(
                    conn,
                    action=AuditEvents.BOOTSTRAP,
                    outcome=AuditOutcome.FAILURE,
                    description="Bootstrap refused: platform administrator already exists.",
                )
            elif self._users.get_by_email(conn, email_n) is not None:
                error = DuplicateUserError()
            else:
                record = self._users.create(
                    conn,
                    email=email_n,
                    full_name=name,
                    password_hash=password_hash,
                    role=Role.PLATFORM_ADMIN,
                    institution_id=None,
                    now=now,
                )
                self._audit.record(
                    conn,
                    action=AuditEvents.BOOTSTRAP,
                    outcome=AuditOutcome.SUCCESS,
                    description="Initial platform administrator created.",
                    target_type="user",
                    target_id=record.id,
                )
        if error:
            raise error
        return record.to_public()

    # ------------------------------------------------------------------ #
    # Institutions
    # ------------------------------------------------------------------ #
    def create_institution(self, principal: CurrentUser, *, code: str, name: str) -> Institution:
        code_n = normalize_institution_code(code)
        name_n = validate_institution_name(name)
        now = self._clock()
        error: Optional[AccessControlError] = None
        result: Optional[Institution] = None
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(conn, principal, Action.MANAGE_INSTITUTIONS)
            if not decision.allowed:
                self._audit.record_decision(conn, decision, detail=f"create institution {code_n}")
            elif self._institutions.get_by_code(conn, code_n) is not None:
                error = DuplicateInstitutionError()
                self._audit.record(
                    conn,
                    action=AuditEvents.INSTITUTION_CREATE,
                    outcome=AuditOutcome.FAILURE,
                    description=f"Institution code {code_n} already exists.",
                    actor=principal,
                    target_type="institution",
                )
            else:
                result = self._institutions.create(conn, code=code_n, name=name_n, now=now)
                self._audit.record(
                    conn,
                    action=AuditEvents.INSTITUTION_CREATE,
                    outcome=AuditOutcome.SUCCESS,
                    description=f"Institution {code_n} created.",
                    actor=principal,
                    target_type="institution",
                    target_id=result.id,
                    institution_id=result.id,
                )
        _raise_if_denied(decision)
        if error:
            raise error
        assert result is not None
        return result

    def set_institution_active(
        self, principal: CurrentUser, institution_id: int, active: bool
    ) -> Institution:
        """Activate/deactivate an institution. Deactivation revokes all sessions
        of its members, and they cannot log in until it is reactivated."""
        institution_id = validate_id(institution_id, "institution_id")
        if not isinstance(active, bool):
            raise ValidationError("active must be a boolean.")
        now = self._clock()
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(
                conn, principal, Action.MANAGE_INSTITUTIONS, institution_id=institution_id
            )
            if not decision.allowed:
                self._audit.record_decision(conn, decision)
                result = None
            else:
                self._institutions.set_active(conn, institution_id, active, now)
                revoked = 0
                if not active:
                    revoked = self._sessions.revoke_all_for_institution(
                        conn, institution_id, now, "institution_deactivated"
                    )
                self._audit.record(
                    conn,
                    action=AuditEvents.INSTITUTION_REACTIVATE if active else AuditEvents.INSTITUTION_DEACTIVATE,
                    outcome=AuditOutcome.SUCCESS,
                    description=(
                        "Institution reactivated."
                        if active
                        else f"Institution deactivated; {revoked} session(s) revoked."
                    ),
                    actor=principal,
                    target_type="institution",
                    target_id=institution_id,
                    institution_id=institution_id,
                )
                result = self._institutions.get(conn, institution_id)
        _raise_if_denied(decision)
        assert result is not None
        return result

    def list_institutions(self, principal: CurrentUser) -> list[Institution]:
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(conn, principal, Action.MANAGE_INSTITUTIONS)
            if not decision.allowed:
                self._audit.record_decision(conn, decision, detail="list institutions")
                result: list[Institution] = []
            else:
                result = self._institutions.list_all(conn)
        _raise_if_denied(decision)
        return result

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    def provision_user(
        self,
        principal: CurrentUser,
        *,
        email: str,
        password: str,
        full_name: str,
        role: Role | str,
        institution_id: Optional[int] = None,
    ) -> User:
        """Create a user account.

        Platform admins may create any role. Institution admins may create
        only ISSUER and STUDENT accounts, only in their own institution.
        """
        role_p = Role.parse(role)
        email_n = normalize_email(email)
        pw = self._validate_password(password)
        name = validate_full_name(full_name)
        inst_id = validate_optional_id(institution_id, "institution_id")
        if role_p.requires_institution and inst_id is None:
            raise ValidationError(f"Role {role_p.value} requires an institution_id.")
        if not role_p.requires_institution and inst_id is not None:
            raise ValidationError(f"Role {role_p.value} must not belong to an institution.")

        now = self._clock()
        error: Optional[AccessControlError] = None
        record = None
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(
                conn, principal, Action.PROVISION_USER, institution_id=inst_id
            )
            if decision.allowed and role_p not in assignable_roles(principal.role):
                decision = decision.denied(DenyReason.ROLE_NOT_ASSIGNABLE)
            if not decision.allowed:
                self._audit.record_decision(
                    conn, decision, detail=f"requested role {role_p.value}"
                )
            else:
                inst = self._institutions.get(conn, inst_id) if inst_id else None
                if inst_id is not None and (inst is None or not inst.is_active):
                    error = ValidationError("Institution is not active.")
                elif self._users.get_by_email(conn, email_n) is not None:
                    error = DuplicateUserError()
                if error:
                    self._audit.record(
                        conn,
                        action=AuditEvents.USER_PROVISION,
                        outcome=AuditOutcome.FAILURE,
                        description=f"Provisioning failed: {error.message}",
                        actor=principal,
                        target_type="user",
                        institution_id=inst_id,
                    )
                else:
                    record = self._users.create(
                        conn,
                        email=email_n,
                        full_name=name,
                        password_hash=self._hasher.hash(pw),
                        role=role_p,
                        institution_id=inst_id,
                        now=now,
                    )
                    self._audit.record(
                        conn,
                        action=AuditEvents.USER_PROVISION,
                        outcome=AuditOutcome.SUCCESS,
                        description=f"Provisioned user with role {role_p.value}.",
                        actor=principal,
                        target_type="user",
                        target_id=record.id,
                        institution_id=inst_id,
                    )
        _raise_if_denied(decision)
        if error:
            raise error
        assert record is not None
        return record.to_public()

    def change_user_role(
        self, principal: CurrentUser, user_id: int, new_role: Role | str
    ) -> User:
        """Change a user's role within the same institution category.

        Changing between an institution-bound role (INSTITUTION_ADMIN, ISSUER,
        STUDENT) and a global role (PLATFORM_ADMIN, PUBLIC_VERIFIER) is not
        supported; provision a new account instead.
        """
        user_id = validate_id(user_id, "user_id")
        role_p = Role.parse(new_role)
        now = self._clock()
        with self._db.transaction() as conn:
            target = self._users.get(conn, user_id)
            if target is None:
                raise UserNotFoundError()
            decision = self._engine.evaluate(
                conn, principal, Action.MANAGE_USER_ROLES, institution_id=target.institution_id
            )
            decision = self._check_target(conn, principal, decision, target.id, target.role)
            if decision.allowed and role_p not in assignable_roles(principal.role):
                decision = decision.denied(DenyReason.ROLE_NOT_ASSIGNABLE)
            if decision.allowed and role_p.requires_institution != target.role.requires_institution:
                raise ValidationError(
                    "Cannot move a user between institution-bound and global roles; "
                    "provision a new account instead."
                )
            if not decision.allowed:
                self._audit.record_decision(
                    conn,
                    decision,
                    detail=f"role change {target.role.value} -> {role_p.value}",
                    target_type="user",
                    target_id=target.id,
                )
                result = None
            elif role_p == target.role:
                result = target
            else:
                self._users.update_role(conn, target.id, role_p, now)
                self._audit.record(
                    conn,
                    action=AuditEvents.USER_ROLE_CHANGE,
                    outcome=AuditOutcome.SUCCESS,
                    description=f"Role changed from {target.role.value} to {role_p.value}.",
                    actor=principal,
                    target_type="user",
                    target_id=target.id,
                    institution_id=target.institution_id,
                )
                result = self._users.get(conn, target.id)
        _raise_if_denied(decision)
        assert result is not None
        return result.to_public()

    def set_user_active(self, principal: CurrentUser, user_id: int, active: bool) -> User:
        """Activate or deactivate a user. Deactivation revokes all their sessions."""
        user_id = validate_id(user_id, "user_id")
        if not isinstance(active, bool):
            raise ValidationError("active must be a boolean.")
        now = self._clock()
        with self._db.transaction() as conn:
            target = self._users.get(conn, user_id)
            if target is None:
                raise UserNotFoundError()
            decision = self._engine.evaluate(
                conn, principal, Action.MANAGE_USER_STATUS, institution_id=target.institution_id
            )
            decision = self._check_target(conn, principal, decision, target.id, target.role)
            if not decision.allowed:
                self._audit.record_decision(
                    conn,
                    decision,
                    detail="activate user" if active else "deactivate user",
                    target_type="user",
                    target_id=target.id,
                )
                result = None
            else:
                self._users.set_active(conn, target.id, active, now)
                revoked = 0
                if not active:
                    revoked = self._sessions.revoke_all_for_user(
                        conn, target.id, now, "user_deactivated"
                    )
                self._audit.record(
                    conn,
                    action=AuditEvents.USER_REACTIVATE if active else AuditEvents.USER_DEACTIVATE,
                    outcome=AuditOutcome.SUCCESS,
                    description=(
                        "User reactivated."
                        if active
                        else f"User deactivated; {revoked} session(s) revoked."
                    ),
                    actor=principal,
                    target_type="user",
                    target_id=target.id,
                    institution_id=target.institution_id,
                )
                result = self._users.get(conn, target.id)
        _raise_if_denied(decision)
        assert result is not None
        return result.to_public()

    def list_users(
        self, principal: CurrentUser, *, institution_id: Optional[int] = None
    ) -> list[User]:
        """List users. Institution admins see only their own institution."""
        institution_id = validate_optional_id(institution_id, "institution_id")
        if institution_id is None and principal.role == Role.INSTITUTION_ADMIN:
            institution_id = principal.institution_id
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(
                conn, principal, Action.VIEW_USERS, institution_id=institution_id
            )
            self._audit.record_decision(conn, decision, detail="list users")
            users = (
                [u.to_public() for u in self._users.list(conn, institution_id=institution_id)]
                if decision.allowed
                else []
            )
        _raise_if_denied(decision)
        return users

    # ------------------------------------------------------------------ #
    # Audit log access
    # ------------------------------------------------------------------ #
    def read_audit_log(
        self,
        principal: CurrentUser,
        *,
        institution_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Return audit events, newest first.

        Platform admins may read everything (or filter by institution).
        Institution admins may read only their own institution's events.
        Everyone else is denied.
        """
        institution_id = validate_optional_id(institution_id, "institution_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_AUDIT_PAGE:
            raise ValidationError(f"limit must be an integer between 1 and {MAX_AUDIT_PAGE}.")
        if action is not None and not isinstance(action, str):
            raise ValidationError("action filter must be a string.")
        if institution_id is None and principal.role == Role.INSTITUTION_ADMIN:
            institution_id = principal.institution_id
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(
                conn, principal, Action.READ_AUDIT_LOG, institution_id=institution_id
            )
            events = (
                self._audit.list_events(
                    conn, institution_id=institution_id, action=action, limit=limit
                )
                if decision.allowed
                else []
            )
            self._audit.record_decision(conn, decision, detail="read audit log")
        _raise_if_denied(decision)
        return events

    # ------------------------------------------------------------------ #
    def _check_target(
        self,
        conn,
        principal: CurrentUser,
        decision: AuthorizationDecision,
        target_id: int,
        target_role: Role,
    ) -> AuthorizationDecision:
        """Escalation guards shared by role/status changes."""
        if not decision.allowed:
            return decision
        if target_id == principal.user_id:
            return decision.denied(DenyReason.SELF_MODIFICATION)
        if target_role not in assignable_roles(principal.role):
            return decision.denied(DenyReason.TARGET_NOT_MANAGEABLE)
        # Because nobody may demote or deactivate themselves and the caller is
        # an active platform admin, at least one active platform admin always
        # remains; no separate "last admin" check is needed.
        return decision

    def _validate_password(self, password: object) -> str:
        return validate_new_password(
            password,
            min_length=self._settings.password_min_length,
            max_length=self._settings.password_max_length,
        )


def _raise_if_denied(decision: AuthorizationDecision) -> None:
    if not decision.allowed:
        raise PermissionDeniedError(decision)
