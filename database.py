"""SQLite connection management and schema for Module 6.

This database is completely separate from the existing ChainCert database.
Every connection enables foreign-key enforcement, and the audit table is made
append-only with triggers.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .exceptions import ConfigurationError

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS institutions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT    NOT NULL UNIQUE CHECK (length(code) BETWEEN 2 AND 32),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254),
    full_name       TEXT    NOT NULL CHECK (length(full_name) BETWEEN 1 AND 120),
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN (
                        'PLATFORM_ADMIN', 'INSTITUTION_ADMIN', 'ISSUER',
                        'STUDENT', 'PUBLIC_VERIFIER')),
    institution_id  INTEGER REFERENCES institutions(id) ON DELETE RESTRICT,
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    last_login_at   TEXT,
    CHECK (
        (role IN ('PLATFORM_ADMIN', 'PUBLIC_VERIFIER') AND institution_id IS NULL)
        OR
        (role IN ('INSTITUTION_ADMIN', 'ISSUER', 'STUDENT') AND institution_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_users_institution ON users(institution_id);
CREATE INDEX IF NOT EXISTS idx_users_role        ON users(role);

CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT    NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    created_at      TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    revoked_at      TEXT,
    revoked_reason  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at     TEXT    NOT NULL,
    actor_user_id   INTEGER REFERENCES users(id),
    actor_role      TEXT,
    action          TEXT    NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
    target_type     TEXT,
    target_id       TEXT,
    institution_id  INTEGER REFERENCES institutions(id),
    outcome         TEXT    NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED')),
    description     TEXT    NOT NULL CHECK (length(description) <= 500)
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred    ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_institution ON audit_events(institution_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_events(actor_user_id);

-- Append-only audit trail (defence in depth; NOT tamper-proof against
-- anyone with direct write access to the database file).
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
"""


class Database:
    """Thin wrapper that opens configured SQLite connections.

    Each :meth:`transaction` opens a fresh connection, so the object is safe
    to share between threads (each thread gets its own connection).
    """

    def __init__(self, path: Path | str, *, timeout_seconds: float = 10.0) -> None:
        self._path = Path(path)
        self._timeout = timeout_seconds

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self._path), timeout=self._timeout, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            conn.close()
            raise ConfigurationError("SQLite foreign-key enforcement could not be enabled.")
        return conn

    def initialize(self) -> None:
        """Create the database file (and parent folder) and schema if missing.

        Safe to call repeatedly.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise ConfigurationError(
                    f"Database schema version {version} is newer than supported "
                    f"version {SCHEMA_VERSION}."
                )
            conn.executescript(SCHEMA_SQL)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        finally:
            conn.close()

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[sqlite3.Connection]:
        """Yield a connection inside a transaction.

        Commits on normal exit and rolls back on any exception. Write
        transactions use ``BEGIN IMMEDIATE`` to take the write lock up front.
        """
        if not self._path.exists():
            raise ConfigurationError(
                "Database not initialized; call initialize_database() first."
            )
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
