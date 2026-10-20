"""``AccessControlService`` — the single public facade of Module 6.

Integrators should depend only on this class, the models in ``models.py`` and
the exceptions in ``exceptions.py``. Everything else is internal.

Error contract (applies to every method that takes a ``session_token``):

* :class:`~.exceptions.AuthenticationError` (HTTP 401) — the caller is not
  authenticated: token missing, malformed, unknown, expired, revoked, or the
  account/institution was deactivated.
* :class:`~.exceptions.PermissionDeniedError` (HTTP 403) — authenticated but
  not allowed. Raised by ``authorize`` and all management methods.
  The ``can_*`` / ``check_permission`` methods *return* a denied
  :class:`~.models.AuthorizationDecision` instead of raising.
* :class:`~.exceptions.ValidationError` (HTTP 400) — malformed arguments.

The certificate methods are **authorization checks only**. They never issue,
correct, revoke or store a certificate; the calling module does that after
receiving an allowed decision.
"""

from __future__ import annotations

from typing import Mapping, Optional

from .audit_service import AuditService
from .auth_service import AuthService
from .authorization import AuthorizationEngine
from .config import Settings
from .database import Database
from .exceptions import AuthenticationRequiredError
from .management_service import ManagementService
from .models import (
    Action,
    AuditEvent,
    AuthorizationDecision,
    AuthResult,
    Clock,
    CurrentUser,
    Institution,
    Role,
    User,
    utc_now,
)
from .password_hasher import PasswordHasher
from .repositories import (
    AuditRepository,
    InstitutionRepository,
    SessionRepository,
    UserRepository,
)


class AccessControlService:
    """Authentication, session management, authorization and administration."""

    def __init__(self, settings: Optional[Settings] = None, *, clock: Optional[Clock] = None):
        self._settings = settings or Settings.from_env()
        self._clock: Clock = clock or utc_now
        self._db = Database(self._settings.database_path)

        institutions = InstitutionRepository()
        users = UserRepository()
        sessions = SessionRepository()
        hasher = PasswordHasher(
            time_cost=self._settings.argon2_time_cost,
            memory_cost=self._settings.argon2_memory_cost,
            parallelism=self._settings.argon2_parallelism,
        )
        self._audit = AuditService(
            repository=AuditRepository(), institutions=institutions, clock=self._clock
        )
        self._engine = AuthorizationEngine(
            institutions=institutions,
            allow_anonymous_public_verification=self._settings.allow_anonymous_public_verification,
        )
        self._auth = AuthService(
            database=self._db,
            settings=self._settings,
            hasher=hasher,
            audit=self._audit,
            users=users,
            sessions=sessions,
            institutions=institutions,
            clock=self._clock,
        )
        self._mgmt = ManagementService(
            database=self._db,
            settings=self._settings,
            hasher=hasher,
            audit=self._audit,
            engine=self._engine,
            users=users,
            sessions=sessions,
            institutions=institutions,
            clock=self._clock,
        )

    @classmethod
    def from_env(
        cls, env: Optional[Mapping[str, str]] = None, *, clock: Optional[Clock] = None
    ) -> "AccessControlService":
        """Build the service from ``M6_*`` environment variables."""
        return cls(Settings.from_env(env), clock=clock)

    @property
    def settings(self) -> Settings:
        return self._settings

    # ================================================================== #
    # Setup
    # ================================================================== #
    def initialize_database(self) -> None:
        """Create this module's SQLite database and schema (idempotent)."""
        self._db.initialize()

    def bootstrap_platform_admin(self, *, email: str, password: str, full_name: str) -> User:
        """Create the first PLATFORM_ADMIN. Fails once one exists (ConflictError)."""
        return self._mgmt.bootstrap_platform_admin(
            email=email, password=password, full_name=full_name
        )

    # ================================================================== #
    # Authentication
    # ================================================================== #
    def authenticate(self, email: str, password: str) -> AuthResult:
        """Validate credentials and create a session.

        Returns:
            AuthResult with the raw ``session_token`` (give it to the client;
            it is never stored), ``expires_at`` and the ``user``.
        Raises:
            InvalidCredentialsError: generic failure (never says which part was wrong).
            ValidationError: non-string arguments.
        """
        return self._auth.authenticate(email, password)

    def get_current_user(self, session_token: Optional[str]) -> CurrentUser:
        """Resolve a session token to the authenticated user.

        Raises:
            AuthenticationRequiredError: token is ``None``.
            InvalidSessionError: token invalid/expired/revoked or account inactive.
        """
        return self._auth.resolve_session(session_token)

    def logout(self, session_token: Optional[str]) -> bool:
        """Invalidate a session. Returns True if a live session was revoked.

        Idempotent; never raises for a bad or already-revoked token.
        """
        return self._auth.logout(session_token)

    def purge_expired_sessions(self) -> int:
        """Housekeeping: delete expired and revoked session rows."""
        return self._auth.purge_expired_sessions()

    # ================================================================== #
    # Authorization
    # ================================================================== #
    def check_permission(
        self,
        session_token: Optional[str],
        action: Action | str,
        *,
        institution_id: Optional[int] = None,
        resource_owner_id: Optional[int] = None,
    ) -> AuthorizationDecision:
        """Evaluate a permission and return the decision (does not raise on deny).

        ``session_token=None`` evaluates as an anonymous caller; if the action
        is not anonymously permitted, :class:`AuthenticationRequiredError` is
        raised (401), not a denial (403).
        """
        principal = None if session_token is None else self.get_current_user(session_token)
        with self._db.transaction() as conn:
            decision = self._engine.evaluate(
                conn,
                principal,
                action,
                institution_id=institution_id,
                resource_owner_id=resource_owner_id,
            )
            if principal is not None:
                self._audit.record_decision(conn, decision)
        if principal is None and not decision.allowed:
            raise AuthenticationRequiredError()
        return decision

    def authorize(
        self,
        session_token: Optional[str],
        action: Action | str,
        *,
        institution_id: Optional[int] = None,
        resource_owner_id: Optional[int] = None,
    ) -> AuthorizationDecision:
        """Like :meth:`check_permission` but raises ``PermissionDeniedError`` on deny.

        Returns:
            The allowed decision.
        """
        return self.check_permission(
            session_token,
            action,
            institution_id=institution_id,
            resource_owner_id=resource_owner_id,
        ).raise_if_denied()

    def can_issue_certificate(
        self, session_token: Optional[str], institution_id: int
    ) -> AuthorizationDecision:
        """May the caller issue certificates for ``institution_id``? (check only)"""
        return self.check_permission(
            session_token, Action.ISSUE_CERTIFICATE, institution_id=institution_id
        )

    def can_correct_certificate(
        self, session_token: Optional[str], institution_id: int
    ) -> AuthorizationDecision:
        """May the caller correct certificates of ``institution_id``? (check only)"""
        return self.check_permission(
            session_token, Action.CORRECT_CERTIFICATE, institution_id=institution_id
        )

    def can_administer_batch(
        self, session_token: Optional[str], institution_id: int
    ) -> AuthorizationDecision:
        """May the caller administer certificate batches of ``institution_id``?"""
        return self.check_permission(
            session_token, Action.ADMINISTER_CERTIFICATE_BATCH, institution_id=institution_id
        )

    def can_revoke_certificate(
        self, session_token: Optional[str], institution_id: int
    ) -> AuthorizationDecision:
        """May the caller revoke certificates of ``institution_id``? (check only)"""
        return self.check_permission(
            session_token, Action.REVOKE_CERTIFICATE, institution_id=institution_id
        )

    def can_view_certificate(
        self, session_token: Optional[str], institution_id: int, owner_user_id: int
    ) -> AuthorizationDecision:
        """May the caller view a (non-public) certificate record?

        Students: only their own (``owner_user_id`` must be their user ID).
        Issuers / institution admins: any record of their own institution.
        """
        return self.check_permission(
            session_token,
            Action.VIEW_CERTIFICATE,
            institution_id=institution_id,
            resource_owner_id=owner_user_id,
        )

    def can_verify_publicly(self, session_token: Optional[str] = None) -> AuthorizationDecision:
        """Authorize read-only public verification.

        Anonymous callers are allowed unless disabled in settings. If a token
        is supplied it must be valid (an invalid token is never silently
        downgraded to anonymous).
        """
        return self.check_permission(session_token, Action.VERIFY_CERTIFICATE_PUBLIC)

    # ================================================================== #
    # Administration (all enforce authorization; raise PermissionDeniedError)
    # ================================================================== #
    def create_institution(self, session_token: Optional[str], *, code: str, name: str) -> Institution:
        return self._mgmt.create_institution(
            self.get_current_user(session_token), code=code, name=name
        )

    def set_institution_active(
        self, session_token: Optional[str], institution_id: int, active: bool
    ) -> Institution:
        return self._mgmt.set_institution_active(
            self.get_current_user(session_token), institution_id, active
        )

    def list_institutions(self, session_token: Optional[str]) -> list[Institution]:
        return self._mgmt.list_institutions(self.get_current_user(session_token))

    def provision_user(
        self,
        session_token: Optional[str],
        *,
        email: str,
        password: str,
        full_name: str,
        role: Role | str,
        institution_id: Optional[int] = None,
    ) -> User:
        return self._mgmt.provision_user(
            self.get_current_user(session_token),
            email=email,
            password=password,
            full_name=full_name,
            role=role,
            institution_id=institution_id,
        )

    def change_user_role(
        self, session_token: Optional[str], user_id: int, new_role: Role | str
    ) -> User:
        return self._mgmt.change_user_role(self.get_current_user(session_token), user_id, new_role)

    def deactivate_user(self, session_token: Optional[str], user_id: int) -> User:
        return self._mgmt.set_user_active(self.get_current_user(session_token), user_id, False)

    def reactivate_user(self, session_token: Optional[str], user_id: int) -> User:
        return self._mgmt.set_user_active(self.get_current_user(session_token), user_id, True)

    def list_users(
        self, session_token: Optional[str], *, institution_id: Optional[int] = None
    ) -> list[User]:
        return self._mgmt.list_users(
            self.get_current_user(session_token), institution_id=institution_id
        )

    def read_audit_log(
        self,
        session_token: Optional[str],
        *,
        institution_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        return self._mgmt.read_audit_log(
            self.get_current_user(session_token),
            institution_id=institution_id,
            action=action,
            limit=limit,
        )
