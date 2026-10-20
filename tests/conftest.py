"""Shared fixtures: isolated temporary SQLite DB, fake clock, seeded data.

Every test gets its own database under pytest's ``tmp_path``; nothing touches
the real ChainCert database or this module's default ``instance/`` folder.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from module6_access_control import AccessControlService, Role, Settings

PASSWORD = "test-only-Passw0rd!"  # fictional, test database only


class FakeClock:
    """Deterministic clock that tests can move forward."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # Cheap Argon2 parameters keep the suite fast; production uses defaults.
    return Settings(
        database_path=tmp_path / "m6_test.db",
        session_ttl=timedelta(minutes=30),
        argon2_time_cost=1,
        argon2_memory_cost=1024,
        argon2_parallelism=1,
    )


@pytest.fixture
def service(settings: Settings, clock: FakeClock) -> AccessControlService:
    svc = AccessControlService(settings, clock=clock)
    svc.initialize_database()
    return svc


@pytest.fixture
def raw_db(settings: Settings):
    """Direct SQLite access for assertions about stored data."""

    def _connect() -> sqlite3.Connection:
        conn = sqlite3.connect(settings.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    return _connect


@dataclass
class World:
    """Seeded fixture data: two institutions with a full cast of users."""

    svc: AccessControlService
    inst_a: int
    inst_b: int
    root_id: int
    admin_a_id: int
    admin_b_id: int
    issuer_a_id: int
    issuer_b_id: int
    student_a1_id: int
    student_a2_id: int
    verifier_id: int
    root: str
    admin_a: str
    admin_b: str
    issuer_a: str
    issuer_b: str
    student_a1: str
    student_a2: str
    verifier: str

    def login(self, email: str) -> str:
        return self.svc.authenticate(email, PASSWORD).session_token


@pytest.fixture
def world(service: AccessControlService) -> World:
    svc = service
    root = svc.bootstrap_platform_admin(
        email="root@platform.test", password=PASSWORD, full_name="Root Admin"
    )
    root_tok = svc.authenticate("root@platform.test", PASSWORD).session_token
    a = svc.create_institution(root_tok, code="ALPHA", name="Alpha University")
    b = svc.create_institution(root_tok, code="BETA", name="Beta College")

    def make(email, role, inst, token=root_tok):
        return svc.provision_user(
            token, email=email, password=PASSWORD, full_name=email.split("@")[0],
            role=role, institution_id=inst,
        )

    admin_a = make("admin@alpha.test", Role.INSTITUTION_ADMIN, a.id)
    admin_b = make("admin@beta.test", Role.INSTITUTION_ADMIN, b.id)
    admin_a_tok = svc.authenticate("admin@alpha.test", PASSWORD).session_token
    admin_b_tok = svc.authenticate("admin@beta.test", PASSWORD).session_token
    issuer_a = make("issuer@alpha.test", Role.ISSUER, a.id, admin_a_tok)
    issuer_b = make("issuer@beta.test", Role.ISSUER, b.id, admin_b_tok)
    s1 = make("s1@alpha.test", Role.STUDENT, a.id, admin_a_tok)
    s2 = make("s2@alpha.test", Role.STUDENT, a.id, admin_a_tok)
    verifier = make("verifier@employer.test", Role.PUBLIC_VERIFIER, None)

    tok = lambda e: svc.authenticate(e, PASSWORD).session_token  # noqa: E731
    return World(
        svc=svc,
        inst_a=a.id,
        inst_b=b.id,
        root_id=root.id,
        admin_a_id=admin_a.id,
        admin_b_id=admin_b.id,
        issuer_a_id=issuer_a.id,
        issuer_b_id=issuer_b.id,
        student_a1_id=s1.id,
        student_a2_id=s2.id,
        verifier_id=verifier.id,
        root=root_tok,
        admin_a=admin_a_tok,
        admin_b=admin_b_tok,
        issuer_a=tok("issuer@alpha.test"),
        issuer_b=tok("issuer@beta.test"),
        student_a1=tok("s1@alpha.test"),
        student_a2=tok("s2@alpha.test"),
        verifier=tok("verifier@employer.test"),
    )
