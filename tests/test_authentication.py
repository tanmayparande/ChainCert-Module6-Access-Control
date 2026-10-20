"""Login, password hashing, input validation and generic errors."""

from __future__ import annotations

import pytest

from module6_access_control import (
    AuthResult,
    InvalidCredentialsError,
    Role,
    ValidationError,
)
from module6_access_control.password_hasher import PasswordHasher

from conftest import PASSWORD


def test_successful_login_returns_session_and_user(world):
    result = world.svc.authenticate("issuer@alpha.test", PASSWORD)
    assert isinstance(result, AuthResult)
    assert len(result.session_token) >= 40
    assert result.user.role is Role.ISSUER
    assert result.user.institution_id == world.inst_a
    assert world.svc.get_current_user(result.session_token).user_id == world.issuer_a_id


def test_login_email_is_case_and_whitespace_insensitive(world):
    result = world.svc.authenticate("  ISSUER@Alpha.TEST  ", PASSWORD)
    assert result.user.email == "issuer@alpha.test"


def test_wrong_password_fails(world):
    with pytest.raises(InvalidCredentialsError):
        world.svc.authenticate("issuer@alpha.test", PASSWORD + "x")


def test_unknown_email_and_wrong_password_give_identical_error(world):
    with pytest.raises(InvalidCredentialsError) as unknown:
        world.svc.authenticate("ghost@alpha.test", PASSWORD)
    with pytest.raises(InvalidCredentialsError) as wrong:
        world.svc.authenticate("issuer@alpha.test", "not-the-password")
    assert str(unknown.value) == str(wrong.value) == "Invalid email or password."
    assert type(unknown.value) is type(wrong.value)


@pytest.mark.parametrize(
    "email,password",
    [
        ("", PASSWORD),
        ("   ", PASSWORD),
        ("not-an-email", PASSWORD),
        ("a@b@c.test", PASSWORD),
        ("issuer@alpha.test", ""),
        ("x" * 300 + "@alpha.test", PASSWORD),
        ("issuer@alpha.test", "p" * 5000),
        ("issuer\n@alpha.test", PASSWORD),
    ],
)
def test_malformed_credentials_fail_generically(world, email, password):
    with pytest.raises(InvalidCredentialsError):
        world.svc.authenticate(email, password)


@pytest.mark.parametrize("email,password", [(None, PASSWORD), ("a@b.test", None), (123, 456)])
def test_non_string_credentials_raise_validation_error(service, email, password):
    with pytest.raises(ValidationError):
        service.authenticate(email, password)


def test_passwords_are_stored_as_argon2id_hashes(world, raw_db):
    with raw_db() as conn:
        rows = conn.execute("SELECT password_hash FROM users").fetchall()
    assert rows
    for row in rows:
        assert row["password_hash"].startswith("$argon2id$")
        assert PASSWORD not in row["password_hash"]


def test_same_password_produces_different_hashes():
    hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    h1, h2 = hasher.hash("same-password-123"), hasher.hash("same-password-123")
    assert h1 != h2
    assert hasher.verify(h1, "same-password-123") and hasher.verify(h2, "same-password-123")
    assert not hasher.verify(h1, "other-password")
    assert not hasher.verify("not-a-hash", "same-password-123")


def test_outdated_hash_is_upgraded_on_login(settings, clock, raw_db):
    from dataclasses import replace

    from module6_access_control import AccessControlService

    weak = AccessControlService(settings, clock=clock)
    weak.initialize_database()
    weak.bootstrap_platform_admin(email="root@p.test", password=PASSWORD, full_name="Root")
    with raw_db() as conn:
        before = conn.execute("SELECT password_hash FROM users").fetchone()[0]

    stronger = AccessControlService(replace(settings, argon2_time_cost=2), clock=clock)
    stronger.authenticate("root@p.test", PASSWORD)
    with raw_db() as conn:
        after = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert before != after and "t=2" in after


def test_deactivated_user_cannot_log_in_and_gets_generic_error(world):
    world.svc.deactivate_user(world.admin_a, world.issuer_a_id)
    with pytest.raises(InvalidCredentialsError) as exc:
        world.svc.authenticate("issuer@alpha.test", PASSWORD)
    assert str(exc.value) == "Invalid email or password."


def test_reactivated_user_can_log_in_again(world):
    world.svc.deactivate_user(world.admin_a, world.issuer_a_id)
    world.svc.reactivate_user(world.admin_a, world.issuer_a_id)
    assert world.svc.authenticate("issuer@alpha.test", PASSWORD).user.user_id == world.issuer_a_id


def test_users_of_deactivated_institution_cannot_log_in(world):
    world.svc.set_institution_active(world.root, world.inst_a, False)
    with pytest.raises(InvalidCredentialsError):
        world.svc.authenticate("issuer@alpha.test", PASSWORD)
    # Other institutions are unaffected.
    assert world.svc.authenticate("issuer@beta.test", PASSWORD)


def test_auth_result_repr_does_not_leak_token(world):
    result = world.svc.authenticate("issuer@alpha.test", PASSWORD)
    assert result.session_token not in repr(result)
