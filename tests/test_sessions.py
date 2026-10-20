"""Session tokens: storage, expiry, logout, revocation."""

from __future__ import annotations

import hashlib

import pytest

from module6_access_control import (
    AuthenticationError,
    AuthenticationRequiredError,
    InvalidSessionError,
    PermissionDeniedError,
)

from conftest import PASSWORD


def test_raw_token_is_never_stored(world, raw_db):
    token = world.svc.authenticate("issuer@alpha.test", PASSWORD).session_token
    with raw_db() as conn:
        hashes = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert token not in hashes
    assert hashlib.sha256(token.encode()).hexdigest() in hashes


def test_token_hash_uses_hmac_when_pepper_configured(settings, clock, raw_db):
    from dataclasses import replace

    from module6_access_control import AccessControlService

    svc = AccessControlService(replace(settings, session_token_pepper="p" * 32), clock=clock)
    svc.initialize_database()
    svc.bootstrap_platform_admin(email="r@p.test", password=PASSWORD, full_name="R")
    token = svc.authenticate("r@p.test", PASSWORD).session_token
    with raw_db() as conn:
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored != hashlib.sha256(token.encode()).hexdigest()
    assert svc.get_current_user(token).email == "r@p.test"


def test_tokens_are_unique_per_login(world):
    t1 = world.login("issuer@alpha.test")
    t2 = world.login("issuer@alpha.test")
    assert t1 != t2
    assert world.svc.get_current_user(t1).session_id != world.svc.get_current_user(t2).session_id


@pytest.mark.parametrize("token", ["", "short", "x" * 1000, 12345, b"bytes-token-value-xxxxxx", "A" * 43])
def test_invalid_tokens_are_rejected(world, token):
    with pytest.raises(InvalidSessionError):
        world.svc.get_current_user(token)


def test_missing_token_is_authentication_required(world):
    with pytest.raises(AuthenticationRequiredError):
        world.svc.get_current_user(None)
    with pytest.raises(AuthenticationRequiredError):
        world.svc.can_issue_certificate(None, world.inst_a)


def test_session_expires_after_ttl(world, clock):
    token = world.login("issuer@alpha.test")
    clock.advance(minutes=29, seconds=59)
    assert world.svc.get_current_user(token)
    clock.advance(seconds=1)
    with pytest.raises(InvalidSessionError):
        world.svc.get_current_user(token)
    with pytest.raises(InvalidSessionError):
        world.svc.can_issue_certificate(token, world.inst_a)


def test_logout_invalidates_only_that_session(world):
    t1 = world.login("issuer@alpha.test")
    t2 = world.login("issuer@alpha.test")
    assert world.svc.logout(t1) is True
    with pytest.raises(InvalidSessionError):
        world.svc.get_current_user(t1)
    assert world.svc.get_current_user(t2).user_id == world.issuer_a_id


def test_logout_is_idempotent(world):
    token = world.login("issuer@alpha.test")
    assert world.svc.logout(token) is True
    assert world.svc.logout(token) is False
    assert world.svc.logout("never-issued-token-value-123456") is False
    assert world.svc.logout(None) is False


def test_logout_of_expired_session_returns_false(world, clock):
    token = world.login("issuer@alpha.test")
    clock.advance(hours=2)
    assert world.svc.logout(token) is False


def test_deactivation_revokes_existing_sessions(world, raw_db):
    token = world.issuer_a
    assert world.svc.can_issue_certificate(token, world.inst_a).allowed
    world.svc.deactivate_user(world.admin_a, world.issuer_a_id)
    with pytest.raises(InvalidSessionError):
        world.svc.can_issue_certificate(token, world.inst_a)
    with raw_db() as conn:
        rows = conn.execute(
            "SELECT revoked_reason FROM sessions WHERE user_id = ?", (world.issuer_a_id,)
        ).fetchall()
    assert rows and all(r[0] == "user_deactivated" for r in rows)


def test_reactivation_does_not_resurrect_old_sessions(world):
    old = world.issuer_a
    world.svc.deactivate_user(world.admin_a, world.issuer_a_id)
    world.svc.reactivate_user(world.admin_a, world.issuer_a_id)
    with pytest.raises(InvalidSessionError):
        world.svc.get_current_user(old)
    assert world.svc.get_current_user(world.login("issuer@alpha.test"))


def test_deactivated_user_blocked_even_if_session_row_still_live(world, raw_db):
    """Defence in depth: resolution re-checks is_active, not only revocation."""
    with raw_db() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (world.issuer_a_id,))
        conn.commit()
    with pytest.raises(InvalidSessionError):
        world.svc.get_current_user(world.issuer_a)


def test_institution_deactivation_blocks_member_sessions(world):
    world.svc.set_institution_active(world.root, world.inst_a, False)
    for token in (world.admin_a, world.issuer_a, world.student_a1):
        with pytest.raises(InvalidSessionError):
            world.svc.get_current_user(token)
    assert world.svc.get_current_user(world.issuer_b)


def test_role_change_takes_effect_on_existing_session(world):
    token = world.issuer_a
    assert world.svc.can_issue_certificate(token, world.inst_a).allowed
    world.svc.change_user_role(world.admin_a, world.issuer_a_id, "STUDENT")
    assert not world.svc.can_issue_certificate(token, world.inst_a).allowed


def test_purge_removes_expired_and_revoked_sessions(world, clock, raw_db):
    world.svc.logout(world.student_a2)
    clock.advance(hours=1)
    deleted = world.svc.purge_expired_sessions()
    assert deleted > 0
    with raw_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_authentication_and_authorization_errors_are_distinct(world):
    with pytest.raises(AuthenticationError):
        world.svc.authorize("bogus-token-value-1234567890", "certificate.issue", institution_id=world.inst_a)
    with pytest.raises(PermissionDeniedError) as denied:
        world.svc.authorize(world.student_a1, "certificate.issue", institution_id=world.inst_a)
    assert not isinstance(denied.value, AuthenticationError)
    assert denied.value.http_status == 403
    assert AuthenticationError.http_status == 401
