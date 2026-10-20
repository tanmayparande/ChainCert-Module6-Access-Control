"""Persistence layer: all SQL lives here.

Repositories are stateless; every method takes an open ``sqlite3.Connection``
so that services can compose several operations in one transaction. Every
statement is parameterized. Nothing in this module makes security decisions.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .models import (
    AuditEvent,
    AuditOutcome,
    Institution,
    Role,
    User,
    from_db_time,
    to_db_time,
)


# --------------------------------------------------------------------------- #
# Internal records (never returned through the public API)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class UserRecord:
    """Full user row, including the password hash. Internal use only."""

    id: int
    email: str
    full_name: str
    password_hash: str = field(repr=False)
    role: Role = Role.STUDENT
    institution_id: Optional[int] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    def to_public(self) -> User:
        return User(
            id=self.id,
            email=self.email,
            full_name=self.full_name,
            role=self.role,
            institution_id=self.institution_id,
            is_active=self.is_active,
            created_at=self.created_at,  # type: ignore[arg-type]
            updated_at=self.updated_at,  # type: ignore[arg-type]
            last_login_at=self.last_login_at,
        )


@dataclass(frozen=True)
class SessionRecord:
    id: int
    user_id: int
    token_hash: str = field(repr=False)
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None


@dataclass(frozen=True)
class SessionContext:
    """A session joined with its user and the user's institution status."""

    session: SessionRecord
    user: UserRecord
    institution_active: Optional[bool]


def _institution(row: sqlite3.Row) -> Institution:
    return Institution(
        id=row["id"],
        code=row["code"],
        name=row["name"],
        is_active=bool(row["is_active"]),
        created_at=from_db_time(row["created_at"]),  # type: ignore[arg-type]
        updated_at=from_db_time(row["updated_at"]),  # type: ignore[arg-type]
    )


def _user(row: sqlite3.Row, prefix: str = "") -> UserRecord:
    return UserRecord(
        id=row[f"{prefix}id"],
        email=row[f"{prefix}email"],
        full_name=row[f"{prefix}full_name"],
        password_hash=row[f"{prefix}password_hash"],
        role=Role(row[f"{prefix}role"]),
        institution_id=row[f"{prefix}institution_id"],
        is_active=bool(row[f"{prefix}is_active"]),
        created_at=from_db_time(row[f"{prefix}created_at"]),
        updated_at=from_db_time(row[f"{prefix}updated_at"]),
        last_login_at=from_db_time(row[f"{prefix}last_login_at"]),
    )


def _session(row: sqlite3.Row, prefix: str = "") -> SessionRecord:
    return SessionRecord(
        id=row[f"{prefix}id"],
        user_id=row[f"{prefix}user_id"],
        token_hash=row[f"{prefix}token_hash"],
        created_at=from_db_time(row[f"{prefix}created_at"]),
        expires_at=from_db_time(row[f"{prefix}expires_at"]),
        revoked_at=from_db_time(row[f"{prefix}revoked_at"]),
        revoked_reason=row[f"{prefix}revoked_reason"],
    )


_USER_COLUMNS = (
    "id, email, full_name, password_hash, role, institution_id, is_active, "
    "created_at, updated_at, last_login_at"
)


# --------------------------------------------------------------------------- #
# Institutions
# --------------------------------------------------------------------------- #
class InstitutionRepository:
    def get(self, conn: sqlite3.Connection, institution_id: int) -> Optional[Institution]:
        row = conn.execute(
            "SELECT * FROM institutions WHERE id = ?", (institution_id,)
        ).fetchone()
        return _institution(row) if row else None

    def get_by_code(self, conn: sqlite3.Connection, code: str) -> Optional[Institution]:
        row = conn.execute("SELECT * FROM institutions WHERE code = ?", (code,)).fetchone()
        return _institution(row) if row else None

    def exists(self, conn: sqlite3.Connection, institution_id: int) -> bool:
        return (
            conn.execute(
                "SELECT 1 FROM institutions WHERE id = ?", (institution_id,)
            ).fetchone()
            is not None
        )

    def create(
        self, conn: sqlite3.Connection, *, code: str, name: str, now: datetime
    ) -> Institution:
        ts = to_db_time(now)
        cur = conn.execute(
            "INSERT INTO institutions (code, name, is_active, created_at, updated_at) "
            "VALUES (?, ?, 1, ?, ?)",
            (code, name, ts, ts),
        )
        return self.get(conn, int(cur.lastrowid))  # type: ignore[return-value]

    def set_active(
        self, conn: sqlite3.Connection, institution_id: int, active: bool, now: datetime
    ) -> None:
        conn.execute(
            "UPDATE institutions SET is_active = ?, updated_at = ? WHERE id = ?",
            (1 if active else 0, to_db_time(now), institution_id),
        )

    def list_all(self, conn: sqlite3.Connection) -> list[Institution]:
        rows = conn.execute("SELECT * FROM institutions ORDER BY id").fetchall()
        return [_institution(r) for r in rows]


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
class UserRepository:
    def get(self, conn: sqlite3.Connection, user_id: int) -> Optional[UserRecord]:
        row = conn.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return _user(row) if row else None

    def get_by_email(self, conn: sqlite3.Connection, email: str) -> Optional[UserRecord]:
        row = conn.execute(
            f"SELECT {_USER_COLUMNS} FROM users WHERE email = ?", (email,)
        ).fetchone()
        return _user(row) if row else None

    def create(
        self,
        conn: sqlite3.Connection,
        *,
        email: str,
        full_name: str,
        password_hash: str,
        role: Role,
        institution_id: Optional[int],
        now: datetime,
    ) -> UserRecord:
        ts = to_db_time(now)
        cur = conn.execute(
            "INSERT INTO users (email, full_name, password_hash, role, institution_id, "
            "is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (email, full_name, password_hash, role.value, institution_id, ts, ts),
        )
        return self.get(conn, int(cur.lastrowid))  # type: ignore[return-value]

    def update_role(
        self, conn: sqlite3.Connection, user_id: int, role: Role, now: datetime
    ) -> None:
        conn.execute(
            "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
            (role.value, to_db_time(now), user_id),
        )

    def set_active(
        self, conn: sqlite3.Connection, user_id: int, active: bool, now: datetime
    ) -> None:
        conn.execute(
            "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
            (1 if active else 0, to_db_time(now), user_id),
        )

    def update_password_hash(
        self, conn: sqlite3.Connection, user_id: int, password_hash: str, now: datetime
    ) -> None:
        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (password_hash, to_db_time(now), user_id),
        )

    def touch_last_login(self, conn: sqlite3.Connection, user_id: int, now: datetime) -> None:
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?", (to_db_time(now), user_id)
        )

    def list(
        self, conn: sqlite3.Connection, *, institution_id: Optional[int] = None
    ) -> list[UserRecord]:
        if institution_id is None:
            rows = conn.execute(f"SELECT {_USER_COLUMNS} FROM users ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE institution_id = ? ORDER BY id",
                (institution_id,),
            ).fetchall()
        return [_user(r) for r in rows]

    def count_with_role(
        self, conn: sqlite3.Connection, role: Role, *, active_only: bool = False
    ) -> int:
        sql = "SELECT COUNT(*) FROM users WHERE role = ?"
        if active_only:
            sql += " AND is_active = 1"
        return int(conn.execute(sql, (role.value,)).fetchone()[0])


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #
class SessionRepository:
    def create(
        self,
        conn: sqlite3.Connection,
        *,
        user_id: int,
        token_hash: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> SessionRecord:
        cur = conn.execute(
            "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, token_hash, to_db_time(created_at), to_db_time(expires_at)),
        )
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (cur.lastrowid,)).fetchone()
        return _session(row)

    def get_by_token_hash(
        self, conn: sqlite3.Connection, token_hash: str
    ) -> Optional[SessionRecord]:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        return _session(row) if row else None

    def get_context_by_token_hash(
        self, conn: sqlite3.Connection, token_hash: str
    ) -> Optional[SessionContext]:
        row = conn.execute(
            "SELECT s.id AS s_id, s.user_id AS s_user_id, s.token_hash AS s_token_hash, "
            "s.created_at AS s_created_at, s.expires_at AS s_expires_at, "
            "s.revoked_at AS s_revoked_at, s.revoked_reason AS s_revoked_reason, "
            "u.id AS u_id, u.email AS u_email, u.full_name AS u_full_name, "
            "u.password_hash AS u_password_hash, u.role AS u_role, "
            "u.institution_id AS u_institution_id, u.is_active AS u_is_active, "
            "u.created_at AS u_created_at, u.updated_at AS u_updated_at, "
            "u.last_login_at AS u_last_login_at, i.is_active AS i_is_active "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "LEFT JOIN institutions i ON i.id = u.institution_id "
            "WHERE s.token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        inst_active = None if row["i_is_active"] is None else bool(row["i_is_active"])
        return SessionContext(
            session=_session(row, "s_"), user=_user(row, "u_"), institution_active=inst_active
        )

    def revoke(
        self, conn: sqlite3.Connection, session_id: int, now: datetime, reason: str
    ) -> bool:
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoked_reason = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (to_db_time(now), reason, session_id),
        )
        return cur.rowcount > 0

    def revoke_all_for_user(
        self, conn: sqlite3.Connection, user_id: int, now: datetime, reason: str
    ) -> int:
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoked_reason = ? "
            "WHERE user_id = ? AND revoked_at IS NULL",
            (to_db_time(now), reason, user_id),
        )
        return cur.rowcount

    def revoke_all_for_institution(
        self, conn: sqlite3.Connection, institution_id: int, now: datetime, reason: str
    ) -> int:
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ?, revoked_reason = ? "
            "WHERE revoked_at IS NULL AND user_id IN "
            "(SELECT id FROM users WHERE institution_id = ?)",
            (to_db_time(now), reason, institution_id),
        )
        return cur.rowcount

    def count_active_for_user(
        self, conn: sqlite3.Connection, user_id: int, now: datetime
    ) -> int:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ? "
                "AND revoked_at IS NULL AND expires_at > ?",
                (user_id, to_db_time(now)),
            ).fetchone()[0]
        )

    def delete_expired_or_revoked(self, conn: sqlite3.Connection, now: datetime) -> int:
        cur = conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
            (to_db_time(now),),
        )
        return cur.rowcount


# --------------------------------------------------------------------------- #
# Audit events
# --------------------------------------------------------------------------- #
class AuditRepository:
    def insert(
        self,
        conn: sqlite3.Connection,
        *,
        occurred_at: datetime,
        actor_user_id: Optional[int],
        actor_role: Optional[str],
        action: str,
        target_type: Optional[str],
        target_id: Optional[str],
        institution_id: Optional[int],
        outcome: AuditOutcome,
        description: str,
    ) -> int:
        cur = conn.execute(
            "INSERT INTO audit_events (occurred_at, actor_user_id, actor_role, action, "
            "target_type, target_id, institution_id, outcome, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                to_db_time(occurred_at),
                actor_user_id,
                actor_role,
                action,
                target_type,
                target_id,
                institution_id,
                outcome.value,
                description,
            ),
        )
        return int(cur.lastrowid)

    def list(
        self,
        conn: sqlite3.Connection,
        *,
        institution_id: Optional[int] = None,
        actor_user_id: Optional[int] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if institution_id is not None:
            clauses.append("institution_id = ?")
            params.append(institution_id)
        if actor_user_id is not None:
            clauses.append("actor_user_id = ?")
            params.append(actor_user_id)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [
            AuditEvent(
                id=r["id"],
                occurred_at=from_db_time(r["occurred_at"]),  # type: ignore[arg-type]
                actor_user_id=r["actor_user_id"],
                actor_role=r["actor_role"],
                action=r["action"],
                target_type=r["target_type"],
                target_id=r["target_id"],
                institution_id=r["institution_id"],
                outcome=AuditOutcome(r["outcome"]),
                description=r["description"],
            )
            for r in rows
        ]
