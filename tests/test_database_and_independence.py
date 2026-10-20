"""Schema constraints, foreign keys, configuration, and module independence."""

from __future__ import annotations

import ast
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from module6_access_control import AccessControlService, ConfigurationError, Settings

PACKAGE_DIR = Path(__file__).resolve().parent.parent


def test_foreign_keys_are_enforced(world, raw_db):
    with raw_db() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO users (email, full_name, password_hash, role, institution_id, "
                "created_at, updated_at) VALUES ('fk@x.test','FK','h','ISSUER', 9999, 't','t')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) "
                "VALUES (9999, ?, 't', 't')",
                ("a" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM institutions WHERE id = ?", (world.inst_a,))


def test_service_connections_enable_foreign_keys(service):
    with service._db.transaction(write=False) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_role_institution_check_constraint(world, raw_db):
    with raw_db() as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (email, full_name, password_hash, role, institution_id, "
            "created_at, updated_at) VALUES ('c@x.test','C','h','PLATFORM_ADMIN', ?, 't','t')",
            (world.inst_a,),
        )
    with raw_db() as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (email, full_name, password_hash, role, institution_id, "
            "created_at, updated_at) VALUES ('d@x.test','D','h','ROOT', NULL, 't','t')"
        )


def test_initialize_is_idempotent_and_creates_tables(service, raw_db):
    service.initialize_database()
    with raw_db() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert {"institutions", "users", "sessions", "audit_events"} <= tables
    assert version == 1


def test_database_path_is_isolated_per_test(service, tmp_path):
    assert service.settings.database_path.parent == tmp_path
    assert service.settings.database_path.exists()


def test_uninitialized_database_raises_configuration_error(tmp_path):
    svc = AccessControlService(Settings(database_path=tmp_path / "missing.db"))
    with pytest.raises(ConfigurationError):
        svc.authenticate("a@b.test", "whatever-password")


def test_settings_from_env(tmp_path):
    s = Settings.from_env({
        "M6_DATABASE_PATH": str(tmp_path / "x.db"),
        "M6_SESSION_TTL_MINUTES": "15",
        "M6_ALLOW_ANONYMOUS_VERIFICATION": "false",
    })
    assert s.database_path == tmp_path / "x.db"
    assert s.session_ttl.total_seconds() == 900
    assert s.allow_anonymous_public_verification is False
    assert "q" * 20 not in repr(Settings(session_token_pepper="q" * 20))


@pytest.mark.parametrize(
    "kwargs",
    [dict(database_path=":memory:"), dict(password_min_length=4), dict(session_token_pepper="short")],
)
def test_invalid_settings_rejected(kwargs):
    with pytest.raises(ConfigurationError):
        Settings(**kwargs)


def test_package_imports_only_stdlib_and_argon2():
    allowed_third_party = {"argon2"}
    stdlib = set(sys.stdlib_module_names)
    offenders = []
    for path in PACKAGE_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top not in stdlib and top not in allowed_third_party and top != "module6_access_control":
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []


def test_runs_without_flask_or_other_modules(tmp_path):
    """Fresh interpreter: import the package, run a login, confirm no Flask."""
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from module6_access_control import AccessControlService, Settings\n"
        f"s = Settings(database_path=Path(r'{tmp_path}') / 'iso.db', argon2_time_cost=1, "
        "argon2_memory_cost=1024, argon2_parallelism=1)\n"
        "svc = AccessControlService(s); svc.initialize_database()\n"
        "svc.bootstrap_platform_admin(email='r@p.test', password='isolated-pass-123', full_name='R')\n"
        "assert svc.authenticate('r@p.test', 'isolated-pass-123').session_token\n"
        "assert 'flask' not in sys.modules\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PACKAGE_DIR.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK"


def test_demo_runs_end_to_end():
    result = subprocess.run(
        [sys.executable, "-m", "module6_access_control.demo"],
        cwd=PACKAGE_DIR.parent,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "cross_institution_access" in result.stdout
    assert "Demo finished" in result.stdout
