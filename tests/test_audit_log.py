"""Audit logging content, secrecy and read restrictions."""

from __future__ import annotations

import sqlite3

import pytest

from module6_access_control import AuditOutcome, PermissionDeniedError, Role, ValidationError
from module6_access_control.audit_service import sanitize_description

from conftest import PASSWORD


def _actions(events):
    return [(e.action, e.outcome) for e in events]


def test_login_success_and_failure_are_logged(world):
    world.svc.authenticate("issuer@alpha.test", PASSWORD)
    with pytest.raises(Exception):
        world.svc.authenticate("issuer@alpha.test", "wrong-password!!")
    with pytest.raises(Exception):
        world.svc.authenticate("ghost@alpha.test", "wrong-password!!")
    events = world.svc.read_audit_log(world.root, action="auth.login", limit=10)
    outcomes = [e.outcome for e in events]
    assert AuditOutcome.SUCCESS in outcomes and AuditOutcome.FAILURE in outcomes
    unknown = [e for e in events if e.target_type == "login_identifier"]
    assert unknown and unknown[0].target_id.startswith("sha256:")
    assert "ghost" not in unknown[0].target_id


def test_logout_is_logged(world):
    world.svc.logout(world.student_a2)
    events = world.svc.read_audit_log(world.root, action="auth.logout")
    assert events and events[0].actor_user_id == world.student_a2_id


def test_provisioning_role_change_and_status_changes_are_logged(world):
    world.svc.change_user_role(world.admin_a, world.student_a1_id, Role.ISSUER)
    world.svc.deactivate_user(world.admin_a, world.student_a2_id)
    world.svc.reactivate_user(world.admin_a, world.student_a2_id)
    events = world.svc.read_audit_log(world.root, institution_id=world.inst_a, limit=200)
    pairs = _actions(events)
    for action in ("user.provision", "user.role_change", "user.deactivate", "user.reactivate"):
        assert (action, AuditOutcome.SUCCESS) in pairs, action
    role_change = next(e for e in events if e.action == "user.role_change")
    assert role_change.actor_user_id == world.admin_a_id
    assert role_change.target_type == "user" and role_change.target_id == str(world.student_a1_id)
    assert role_change.institution_id == world.inst_a
    assert "STUDENT" in role_change.description and "ISSUER" in role_change.description


def test_institution_administration_is_logged(world):
    world.svc.set_institution_active(world.root, world.inst_b, False)
    pairs = _actions(world.svc.read_audit_log(world.root, limit=200))
    assert ("institution.create", AuditOutcome.SUCCESS) in pairs
    assert ("institution.deactivate", AuditOutcome.SUCCESS) in pairs


def test_privileged_allow_and_all_denials_are_logged(world):
    world.svc.can_issue_certificate(world.issuer_a, world.inst_a)
    world.svc.can_issue_certificate(world.issuer_a, world.inst_b)
    events = world.svc.read_audit_log(world.root, action="authz.certificate.issue")
    assert [e.outcome for e in events[:2]] == [AuditOutcome.DENIED, AuditOutcome.SUCCESS]
    assert "cross_institution_access" in events[0].description


def test_escalation_attempt_is_logged_as_denied(world):
    with pytest.raises(PermissionDeniedError):
        world.svc.provision_user(world.admin_a, email="boss@alpha.test", password=PASSWORD,
                                 full_name="Boss", role=Role.PLATFORM_ADMIN)
    events = world.svc.read_audit_log(world.root, action="authz.user.provision")
    assert events[0].outcome is AuditOutcome.DENIED
    assert events[0].actor_user_id == world.admin_a_id


def test_unknown_institution_reference_keeps_audit_valid(world):
    world.svc.can_issue_certificate(world.issuer_a, 4242)
    event = world.svc.read_audit_log(world.root, action="authz.certificate.issue")[0]
    assert event.institution_id is None and "4242" in event.description


def test_secrets_never_appear_in_database_logs(world, raw_db):
    token = world.svc.authenticate("issuer@alpha.test", PASSWORD).session_token
    with pytest.raises(Exception):
        world.svc.authenticate("issuer@alpha.test", "Typed-Secret-Wrong-1")
    with raw_db() as conn:
        rows = conn.execute("SELECT * FROM audit_events").fetchall()
        hashes = [r[0] for r in conn.execute("SELECT password_hash FROM users")]
    dump = "\n".join(" ".join(str(v) for v in tuple(r)) for r in rows)
    assert PASSWORD not in dump
    assert "Typed-Secret-Wrong-1" not in dump
    assert token not in dump
    assert "$argon2" not in dump
    assert not any(h in dump for h in hashes)


def test_audit_table_is_append_only(world, raw_db):
    with raw_db() as conn:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_events SET outcome = 'SUCCESS'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM audit_events")


@pytest.mark.parametrize("token_attr", ["issuer_a", "student_a1", "verifier"])
def test_non_admins_cannot_read_audit_log(world, token_attr):
    with pytest.raises(PermissionDeniedError):
        world.svc.read_audit_log(getattr(world, token_attr))


def test_institution_admin_reads_only_own_institution(world):
    world.svc.can_issue_certificate(world.issuer_b, world.inst_b)  # beta event
    events = world.svc.read_audit_log(world.admin_a, limit=500)
    assert events and all(e.institution_id == world.inst_a for e in events)
    with pytest.raises(PermissionDeniedError):
        world.svc.read_audit_log(world.admin_a, institution_id=world.inst_b)


def test_audit_reads_are_themselves_audited(world):
    world.svc.read_audit_log(world.admin_a)
    events = world.svc.read_audit_log(world.root, action="authz.audit.read")
    assert any(e.actor_user_id == world.admin_a_id for e in events)


@pytest.mark.parametrize("limit", [0, -1, 5000, "10", True])
def test_audit_limit_validation(world, limit):
    with pytest.raises(ValidationError):
        world.svc.read_audit_log(world.root, limit=limit)


def test_description_sanitizer_strips_control_chars_and_caps_length():
    assert sanitize_description("line1\nFAKE ENTRY\r\x00") == "line1 FAKE ENTRY"
    assert len(sanitize_description("x" * 2000)) == 500
