"""Institution boundaries and student ownership."""

from __future__ import annotations

import pytest

from module6_access_control import Action, DenyReason, PermissionDeniedError, Role

from conftest import PASSWORD


@pytest.mark.parametrize(
    "method",
    ["can_issue_certificate", "can_correct_certificate", "can_administer_batch", "can_revoke_certificate"],
)
def test_issuer_denied_in_other_institution(world, method):
    assert getattr(world.svc, method)(world.issuer_a, world.inst_a).allowed
    d = getattr(world.svc, method)(world.issuer_a, world.inst_b)
    assert not d.allowed and d.reason == DenyReason.CROSS_INSTITUTION


def test_institution_admin_denied_in_other_institution(world):
    d = world.svc.can_revoke_certificate(world.admin_a, world.inst_b)
    assert not d.allowed and d.reason == DenyReason.CROSS_INSTITUTION


def test_nonexistent_institution_is_denied_not_trusted(world):
    d = world.svc.can_issue_certificate(world.issuer_a, 9999)
    assert not d.allowed and d.reason == DenyReason.CROSS_INSTITUTION


def test_platform_admin_global_scope_validates_institution_exists(world):
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.list_users(world.root, institution_id=9999)
    assert exc.value.reason == DenyReason.UNKNOWN_INSTITUTION


def test_institution_admin_cannot_provision_into_other_institution(world):
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.provision_user(
            world.admin_a, email="intruder@beta.test", password=PASSWORD,
            full_name="Intruder", role=Role.ISSUER, institution_id=world.inst_b,
        )
    assert exc.value.reason == DenyReason.CROSS_INSTITUTION


def test_institution_admin_cannot_manage_users_of_other_institution(world):
    with pytest.raises(PermissionDeniedError):
        world.svc.deactivate_user(world.admin_a, world.issuer_b_id)
    with pytest.raises(PermissionDeniedError):
        world.svc.change_user_role(world.admin_a, world.issuer_b_id, Role.STUDENT)
    # Target unaffected.
    assert world.svc.can_issue_certificate(world.issuer_b, world.inst_b).allowed


def test_institution_admin_lists_only_own_users(world):
    users = world.svc.list_users(world.admin_a)
    assert users and {u.institution_id for u in users} == {world.inst_a}
    with pytest.raises(PermissionDeniedError):
        world.svc.list_users(world.admin_a, institution_id=world.inst_b)


def test_platform_admin_lists_all_users(world):
    users = world.svc.list_users(world.root)
    assert {world.inst_a, world.inst_b, None} <= {u.institution_id for u in users}


def test_listed_users_never_expose_password_hash(world):
    for user in world.svc.list_users(world.root):
        assert not hasattr(user, "password_hash")
        assert "argon2" not in repr(user)


# ------------------------------ student ownership --------------------------- #
def test_student_can_view_only_own_certificate(world):
    own = world.svc.can_view_certificate(world.student_a1, world.inst_a, world.student_a1_id)
    other = world.svc.can_view_certificate(world.student_a1, world.inst_a, world.student_a2_id)
    assert own.allowed
    assert not other.allowed and other.reason == DenyReason.NOT_RESOURCE_OWNER


def test_student_view_requires_owner(world):
    d = world.svc.check_permission(world.student_a1, Action.VIEW_CERTIFICATE, institution_id=world.inst_a)
    assert not d.allowed and d.reason == DenyReason.OWNER_REQUIRED


def test_student_cannot_claim_ownership_across_institutions(world):
    d = world.svc.can_view_certificate(world.student_a1, world.inst_b, world.student_a1_id)
    assert not d.allowed and d.reason == DenyReason.CROSS_INSTITUTION


def test_issuer_can_view_any_certificate_in_own_institution_only(world):
    assert world.svc.can_view_certificate(world.issuer_a, world.inst_a, world.student_a1_id)
    assert not world.svc.can_view_certificate(world.issuer_a, world.inst_b, world.student_a1_id)


def test_student_cannot_perform_any_write(world):
    for method in ("can_issue_certificate", "can_correct_certificate",
                   "can_administer_batch", "can_revoke_certificate"):
        assert not getattr(world.svc, method)(world.student_a1, world.inst_a).allowed
