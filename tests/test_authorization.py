"""Role-permission matrix, deny-by-default, public verification."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from module6_access_control import (
    PERMISSION_MATRIX,
    Action,
    AuthenticationRequiredError,
    AuthorizationDecision,
    CurrentUser,
    DenyReason,
    PermissionDeniedError,
    Role,
    Scope,
    ValidationError,
)
from module6_access_control.authorization import AuthorizationEngine
from module6_access_control.policies import WRITE_ACTIONS, scope_for
from module6_access_control.repositories import InstitutionRepository

# Expected matrix written out independently of policies.py, so a change to the
# policy that is not reflected here fails loudly.
EXPECTED = {
    Role.PLATFORM_ADMIN: {
        "institution.manage", "user.provision", "user.manage_role", "user.manage_status",
        "user.view", "audit.read", "certificate.verify_public",
    },
    Role.INSTITUTION_ADMIN: {
        "user.provision", "user.manage_role", "user.manage_status", "user.view",
        "certificate.batch_admin", "certificate.revoke", "certificate.view",
        "audit.read", "certificate.verify_public",
    },
    Role.ISSUER: {
        "certificate.issue", "certificate.correct", "certificate.batch_admin",
        "certificate.revoke", "certificate.view", "certificate.verify_public",
    },
    Role.STUDENT: {"certificate.view", "certificate.verify_public"},
    Role.PUBLIC_VERIFIER: {"certificate.verify_public"},
}


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", list(Action))
def test_policy_matrix_matches_specification(role, action):
    granted = scope_for(role, action) is not None
    assert granted == (action.value in EXPECTED[role])


def test_every_role_has_a_policy_entry():
    assert set(PERMISSION_MATRIX) == set(Role)


def _token(world, role):
    return {
        Role.PLATFORM_ADMIN: world.root,
        Role.INSTITUTION_ADMIN: world.admin_a,
        Role.ISSUER: world.issuer_a,
        Role.STUDENT: world.student_a1,
        Role.PUBLIC_VERIFIER: world.verifier,
    }[role]


CERT_CHECKS = {
    "can_issue_certificate": {Role.ISSUER},
    "can_correct_certificate": {Role.ISSUER},
    "can_administer_batch": {Role.ISSUER, Role.INSTITUTION_ADMIN},
    "can_revoke_certificate": {Role.ISSUER, Role.INSTITUTION_ADMIN},
}


@pytest.mark.parametrize("method,allowed_roles", CERT_CHECKS.items())
@pytest.mark.parametrize("role", list(Role))
def test_certificate_checks_per_role_in_own_institution(world, method, allowed_roles, role):
    decision = getattr(world.svc, method)(_token(world, role), world.inst_a)
    assert isinstance(decision, AuthorizationDecision)
    assert decision.allowed is (role in allowed_roles)
    assert bool(decision) is decision.allowed


def test_platform_admin_cannot_perform_certificate_writes(world):
    """Separation of duties: platform operators manage tenants, not records."""
    for method in CERT_CHECKS:
        decision = getattr(world.svc, method)(world.root, world.inst_a)
        assert not decision.allowed
        assert decision.reason == DenyReason.NO_PERMISSION


def test_authorize_raises_on_deny_and_returns_on_allow(world):
    ok = world.svc.authorize(world.issuer_a, Action.ISSUE_CERTIFICATE, institution_id=world.inst_a)
    assert ok.allowed and ok.user_id == world.issuer_a_id
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.authorize(world.student_a1, Action.ISSUE_CERTIFICATE, institution_id=world.inst_a)
    assert exc.value.reason == DenyReason.NO_PERMISSION
    assert exc.value.decision.action == "certificate.issue"


def test_actions_accept_value_or_name_strings(world):
    assert world.svc.check_permission(world.issuer_a, "certificate.issue", institution_id=world.inst_a)
    assert world.svc.check_permission(world.issuer_a, "ISSUE_CERTIFICATE", institution_id=world.inst_a)


@pytest.mark.parametrize("action", ["certificate.delete", "", "admin.*", "drop table users", 42, None])
def test_unknown_actions_are_denied_for_every_role(world, action):
    for role in Role:
        decision = world.svc.check_permission(_token(world, role), action, institution_id=world.inst_a)
        assert not decision.allowed
        assert decision.reason == DenyReason.UNKNOWN_ACTION


def test_unknown_role_is_denied(world, service):
    engine = AuthorizationEngine(institutions=InstitutionRepository())
    ghost = CurrentUser(
        user_id=999, email="g@x.test", full_name="G", role="SUPERUSER",  # type: ignore[arg-type]
        institution_id=world.inst_a, session_id=1,
        session_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    with service._db.transaction() as conn:  # internal access for a unit test
        for action in Action:
            d = engine.evaluate(conn, ghost, action, institution_id=world.inst_a)
            assert not d.allowed and d.reason == DenyReason.UNKNOWN_ROLE


def test_institution_scoped_action_requires_institution_id(world):
    d = world.svc.check_permission(world.issuer_a, Action.ISSUE_CERTIFICATE)
    assert not d.allowed and d.reason == DenyReason.INSTITUTION_REQUIRED


@pytest.mark.parametrize("bad", ["1", 1.0, True, 0, -5])
def test_malformed_institution_id_is_rejected(world, bad):
    with pytest.raises(ValidationError):
        world.svc.can_issue_certificate(world.issuer_a, bad)


# ----------------------------- public verification ------------------------- #
@pytest.mark.parametrize("role", list(Role))
def test_every_role_may_verify_publicly(world, role):
    d = world.svc.can_verify_publicly(_token(world, role))
    assert d.allowed and d.reason == DenyReason.PUBLIC


def test_anonymous_public_verification_allowed_by_default(world):
    d = world.svc.can_verify_publicly()
    assert d.allowed and d.user_id is None


def test_anonymous_verification_can_be_disabled(settings, clock):
    from dataclasses import replace

    from module6_access_control import AccessControlService

    svc = AccessControlService(replace(settings, allow_anonymous_public_verification=False), clock=clock)
    svc.initialize_database()
    with pytest.raises(AuthenticationRequiredError):
        svc.can_verify_publicly()


def test_invalid_token_is_not_downgraded_to_anonymous(world):
    from module6_access_control import InvalidSessionError

    with pytest.raises(InvalidSessionError):
        world.svc.can_verify_publicly("forged-token-value-abcdefghijkl")


def test_anonymous_caller_cannot_do_anything_else(world):
    for action in Action:
        if action is Action.VERIFY_CERTIFICATE_PUBLIC:
            continue
        with pytest.raises(AuthenticationRequiredError):
            world.svc.check_permission(None, action, institution_id=world.inst_a)


def test_public_verifier_has_no_write_access(world):
    for action in WRITE_ACTIONS:
        d = world.svc.check_permission(world.verifier, action, institution_id=world.inst_a)
        assert not d.allowed, action
    with pytest.raises(PermissionDeniedError):
        world.svc.provision_user(
            world.verifier, email="x@y.test", password="long-enough-pass-1",
            full_name="X", role=Role.STUDENT, institution_id=world.inst_a,
        )
    with pytest.raises(PermissionDeniedError):
        world.svc.create_institution(world.verifier, code="GAMMA", name="Gamma")


def test_scope_enum_values_are_documented_set():
    assert {s.value for s in Scope} == {"GLOBAL", "INSTITUTION", "OWN", "PUBLIC"}
