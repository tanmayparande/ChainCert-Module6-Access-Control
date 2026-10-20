"""Authentication and session management.

* Passwords are verified with Argon2id (see ``password_hasher.py``).
* Session tokens are 256-bit values from :mod:`secrets`; only their SHA-256
  (or HMAC-SHA256 with a configured pepper) is stored.
* Sessions have an absolute expiry and can be revoked (logout, deactivation).
* Every resolution re-reads the user and institution, so a deactivated user
  or institution loses access immediately, even with a live token.
* Login failures always raise the same generic error.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

from .audit_service import AuditEvents, AuditService
from .config import Settings
from .database import Database
from .exceptions import (
    AuthenticationRequiredError,
    InvalidCredentialsError,
    InvalidSessionError,
    ValidationError,
)
from .models import AuditOutcome, AuthResult, Clock, CurrentUser
from .password_hasher import PasswordHasher
from .repositories import InstitutionRepository, SessionRepository, UserRecord, UserRepository
from .validators import normalize_email

TOKEN_BYTES = 32  # 256 bits of entropy
_MIN_TOKEN_LENGTH = 16
_MAX_TOKEN_LENGTH = 256


class AuthService:
    """Login, session resolution and logout."""

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        hasher: PasswordHasher,
        audit: AuditService,
        users: UserRepository,
        sessions: SessionRepository,
        institutions: InstitutionRepository,
        clock: Clock,
    ) -> None:
        self._db = database
        self._settings = settings
        self._hasher = hasher
        self._audit = audit
        self._users = users
        self._sessions = sessions
        self._institutions = institutions
        self._clock = clock

    # ------------------------------------------------------------------ #
    # Token hashing
    # ------------------------------------------------------------------ #
    def hash_token(self, token: str) -> str:
        """Hash a raw session token for storage/lookup (64 hex chars).

        Tokens are high-entropy random values, so a fast hash is appropriate
        (unlike passwords). With a pepper configured, HMAC-SHA256 is used so a
        stolen database alone cannot be used to test candidate tokens.
        """
        data = token.encode("utf-8")
        pepper = self._settings.session_token_pepper
        if pepper:
            return hmac.new(pepper.encode("utf-8"), data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    # ------------------------------------------------------------------ #
    # Login
    # ------------------------------------------------------------------ #
    def authenticate(self, email: object, password: object) -> AuthResult:
        """Verify credentials and create a session.

        Raises:
            ValidationError: if ``email`` or ``password`` is not a string.
            InvalidCredentialsError: for every other failure (generic message).
        """
        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("Email and password must be strings.")

        try:
            normalized: Optional[str] = normalize_email(email)
        except ValidationError:
            normalized = None
        if normalized is None or not password or len(password) > self._settings.password_max_length:
            self._hasher.burn(password[: self._settings.password_max_length])
            with self._db.transaction() as conn:
                self._audit.record(
                    conn,
                    action=AuditEvents.LOGIN,
                    outcome=AuditOutcome.FAILURE,
                    description="Login failed: malformed credentials.",
                )
            raise InvalidCredentialsError()

        # Read phase (no write lock held during the slow hash verification).
        with self._db.transaction(write=False) as conn:
            user = self._users.get_by_email(conn, normalized)
            institution_active = self._institution_active(conn, user)

        if user is None:
            self._hasher.burn(password)
            failure: Optional[str] = "unknown account"
        elif not self._hasher.verify(user.password_hash, password):
            failure = "incorrect password"
        elif not user.is_active:
            failure = "account is deactivated"
        elif institution_active is False:
            failure = "institution is deactivated"
        else:
            failure = None

        now = self._clock()
        with self._db.transaction() as conn:
            if failure is None and user is not None:
                # Re-check under the write lock in case status changed meanwhile.
                fresh = self._users.get(conn, user.id)
                if fresh is None or not fresh.is_active or self._institution_active(conn, fresh) is False:
                    failure = "account or institution is deactivated"

            if failure is not None:
                self._audit.record(
                    conn,
                    action=AuditEvents.LOGIN,
                    outcome=AuditOutcome.FAILURE,
                    description=f"Login failed: {failure}.",
                    target_type="user" if user else "login_identifier",
                    target_id=user.id if user else _fingerprint(normalized),
                    institution_id=user.institution_id if user else None,
                )
                result: Optional[AuthResult] = None
            else:
                assert user is not None
                token = secrets.token_urlsafe(TOKEN_BYTES)
                expires_at = now + self._settings.session_ttl
                session = self._sessions.create(
                    conn,
                    user_id=user.id,
                    token_hash=self.hash_token(token),
                    created_at=now,
                    expires_at=expires_at,
                )
                self._users.touch_last_login(conn, user.id, now)
                if self._hasher.needs_rehash(user.password_hash):
                    self._users.update_password_hash(
                        conn, user.id, self._hasher.hash(password), now
                    )
                principal = _principal(user, session.id, expires_at)
                self._audit.record(
                    conn,
                    action=AuditEvents.LOGIN,
                    outcome=AuditOutcome.SUCCESS,
                    description="Login succeeded.",
                    actor=principal,
                    target_type="user",
                    target_id=user.id,
                    institution_id=user.institution_id,
                )
                result = AuthResult(session_token=token, expires_at=expires_at, user=principal)

        if result is None:
            raise InvalidCredentialsError()
        return result

    # ------------------------------------------------------------------ #
    # Session resolution
    # ------------------------------------------------------------------ #
    def resolve_session(self, session_token: object) -> CurrentUser:
        """Return the authenticated user for a session token.

        Raises:
            AuthenticationRequiredError: ``session_token`` is ``None``.
            InvalidSessionError: token malformed, unknown, expired, revoked,
                or the user/institution is deactivated.
        """
        if session_token is None:
            raise AuthenticationRequiredError()
        if (
            not isinstance(session_token, str)
            or not _MIN_TOKEN_LENGTH <= len(session_token) <= _MAX_TOKEN_LENGTH
        ):
            raise InvalidSessionError()

        token_hash = self.hash_token(session_token)
        with self._db.transaction(write=False) as conn:
            ctx = self._sessions.get_context_by_token_hash(conn, token_hash)

        now = self._clock()
        if (
            ctx is None
            # constant-time comparison of the stored hash (belt and braces)
            or not hmac.compare_digest(ctx.session.token_hash, token_hash)
            or ctx.session.revoked_at is not None
            or ctx.session.expires_at is None
            or now >= ctx.session.expires_at
            or not ctx.user.is_active
            or ctx.institution_active is False
        ):
            raise InvalidSessionError()
        return _principal(ctx.user, ctx.session.id, ctx.session.expires_at)

    # ------------------------------------------------------------------ #
    # Logout
    # ------------------------------------------------------------------ #
    def logout(self, session_token: object) -> bool:
        """Revoke the session. Returns True if a live session was revoked.

        Idempotent: unknown, malformed, expired or already-revoked tokens
        return False rather than raising.
        """
        if (
            not isinstance(session_token, str)
            or not _MIN_TOKEN_LENGTH <= len(session_token) <= _MAX_TOKEN_LENGTH
        ):
            return False
        token_hash = self.hash_token(session_token)
        now = self._clock()
        with self._db.transaction() as conn:
            session = self._sessions.get_by_token_hash(conn, token_hash)
            if (
                session is None
                or session.revoked_at is not None
                or session.expires_at is None
                or now >= session.expires_at
            ):
                return False
            self._sessions.revoke(conn, session.id, now, "logout")
            user = self._users.get(conn, session.user_id)
            self._audit.record(
                conn,
                action=AuditEvents.LOGOUT,
                outcome=AuditOutcome.SUCCESS,
                description="Logout; session revoked.",
                actor_user_id=session.user_id,
                actor_role=user.role if user else None,
                target_type="session",
                target_id=session.id,
                institution_id=user.institution_id if user else None,
            )
            return True

    def purge_expired_sessions(self) -> int:
        """Delete expired and revoked session rows. Returns rows deleted."""
        with self._db.transaction() as conn:
            return self._sessions.delete_expired_or_revoked(conn, self._clock())

    # ------------------------------------------------------------------ #
    def _institution_active(self, conn, user: Optional[UserRecord]) -> Optional[bool]:
        if user is None or user.institution_id is None:
            return None
        inst = self._institutions.get(conn, user.institution_id)
        return bool(inst and inst.is_active)


def _principal(user: UserRecord, session_id: int, expires_at) -> CurrentUser:
    return CurrentUser(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        institution_id=user.institution_id,
        session_id=session_id,
        session_expires_at=expires_at,
    )


def _fingerprint(normalized_email: str) -> str:
    """Short, non-reversible identifier for an unknown login email.

    Lets administrators correlate repeated attempts against the same unknown
    identifier without writing raw (possibly mistyped-password) input to the log.
    """
    return "sha256:" + hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:16]
