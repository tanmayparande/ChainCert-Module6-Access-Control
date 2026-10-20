"""Provisioning, duplicates, role changes, privilege escalation, bootstrap."""

from __future__ import annotations

import pytest

from module6_access_control import (
    ConflictError,
    DenyReason,
    DuplicateInstitutionError,
    DuplicateUserError,
    PermissionDeniedError,
    Role,
    UserNotFoundError,
    ValidationError,
)

from conftest import PASSWORD


def test_bootstrap_only_once(service):
    service.bootstrap_platform_admin(email="a@p.test", password=PASSWORD, full_name="A")
    with pytest.raises(ConflictError):
        service.bootstrap_platform_admin(email="b@p.test", password=PASSWORD, full_name="B")


def test_institution_admin_provisions_issuer_and_student(world):
    issuer = world.svc.provision_user(
        world.admin_a, email="New.Issuer@Alpha.test", password=PASSWORD,
        full_name="  New   Issuer ", role="issuer", institution_id=world.inst_a,
    )
    assert issuer.email == "new.issuer@alpha.test"
    assert issuer.full_name == "New Issuer"
    assert issuer.role is Role.ISSUER and issuer.is_active


def test_duplicate_email_rejected_after_normalization(world):
    with pytest.raises(DuplicateUserError):
        world.svc.provision_user(
            world.admin_a, email="  ISSUER@alpha.TEST ", password=PASSWORD,
            full_name="Dup", role=Role.STUDENT, institution_id=world.inst_a,
        )


def test_duplicate_email_rejected_by_database_constraint(world, raw_db):
    import sqlite3

    with raw_db() as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (email, full_name, password_hash, role, institution_id, "
            "created_at, updated_at) VALUES ('issuer@alpha.test','x','h','ISSUER',?, 't','t')",
            (world.inst_a,),
        )


def test_duplicate_institution_code_rejected(world):
    with pytest.raises(DuplicateInstitutionError):
        world.svc.create_institution(world.root, code="alpha", name="Another Alpha")


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(password="short"),
        dict(email="bad-email"),
        dict(full_name="   "),
        dict(role="WIZARD"),
        dict(institution_id=None),  # STUDENT needs an institution
    ],
)
def test_provisioning_validation(world, kwargs):
    base = dict(email="v@alpha.test", password=PASSWORD, full_name="V",
                role=Role.STUDENT, institution_id=world.inst_a)
    base.update(kwargs)
    with pytest.raises(ValidationError):
        world.svc.provision_user(world.root, **base)


def test_global_role_cannot_have_institution(world):
    with pytest.raises(ValidationError):
        world.svc.provision_user(world.root, email="pv@x.test", password=PASSWORD, full_name="PV",
                                 role=Role.PUBLIC_VERIFIER, institution_id=world.inst_a)


def test_cannot_provision_into_inactive_institution(world):
    world.svc.set_institution_active(world.root, world.inst_b, False)
    with pytest.raises(ValidationError):
        world.svc.provision_user(world.root, email="late@beta.test", password=PASSWORD,
                                 full_name="Late", role=Role.STUDENT, institution_id=world.inst_b)


@pytest.mark.parametrize("role", [Role.INSTITUTION_ADMIN, Role.PLATFORM_ADMIN, Role.PUBLIC_VERIFIER])
def test_institution_admin_cannot_create_privileged_or_global_accounts(world, role):
    inst = world.inst_a if role.requires_institution else None
    with pytest.raises(PermissionDeniedError):
        world.svc.provision_user(world.admin_a, email=f"esc-{role.value.lower()}@alpha.test",
                                 password=PASSWORD, full_name="Esc", role=role, institution_id=inst)


@pytest.mark.parametrize("token_attr", ["issuer_a", "student_a1", "verifier"])
def test_non_admins_cannot_provision(world, token_attr):
    with pytest.raises(PermissionDeniedError):
        world.svc.provision_user(getattr(world, token_attr), email="x@alpha.test", password=PASSWORD,
                                 full_name="X", role=Role.STUDENT, institution_id=world.inst_a)


def test_institution_admin_changes_role_within_allowed_set(world):
    user = world.svc.change_user_role(world.admin_a, world.student_a1_id, Role.ISSUER)
    assert user.role is Role.ISSUER


def test_institution_admin_cannot_promote_to_admin(world):
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.change_user_role(world.admin_a, world.issuer_a_id, Role.INSTITUTION_ADMIN)
    assert exc.value.reason == DenyReason.ROLE_NOT_ASSIGNABLE


def test_nobody_can_change_own_role_or_status(world):
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.change_user_role(world.admin_a, world.admin_a_id, Role.ISSUER)
    assert exc.value.reason == DenyReason.SELF_MODIFICATION
    with pytest.raises(PermissionDeniedError):
        world.svc.deactivate_user(world.root, world.root_id)


def test_institution_admin_cannot_manage_peer_admin(world, service):
    second = world.svc.provision_user(world.root, email="admin2@alpha.test", password=PASSWORD,
                                      full_name="Admin Two", role=Role.INSTITUTION_ADMIN,
                                      institution_id=world.inst_a)
    with pytest.raises(PermissionDeniedError) as exc:
        world.svc.deactivate_user(world.admin_a, second.id)
    assert exc.value.reason == DenyReason.TARGET_NOT_MANAGEABLE


def test_issuer_cannot_escalate_self_or_others(world):
    for target in (world.issuer_a_id, world.student_a1_id):
        with pytest.raises(PermissionDeniedError):
            world.svc.change_user_role(world.issuer_a, target, Role.INSTITUTION_ADMIN)


def test_platform_admin_can_promote_and_demote_across_institutions(world):
    assert world.svc.change_user_role(world.root, world.issuer_b_id, Role.INSTITUTION_ADMIN).role \
        is Role.INSTITUTION_ADMIN
    assert world.svc.change_user_role(world.root, world.issuer_b_id, Role.ISSUER).role is Role.ISSUER


def test_platform_admin_can_manage_another_platform_admin(world):
    other = world.svc.provision_user(world.root, email="root2@platform.test", password=PASSWORD,
                                     full_name="Root Two", role=Role.PLATFORM_ADMIN)
    assert not world.svc.deactivate_user(world.root, other.id).is_active
    assert world.svc.reactivate_user(world.root, other.id).is_active


def test_cannot_move_between_institution_and_global_roles(world):
    with pytest.raises(ValidationError):
        world.svc.change_user_role(world.root, world.issuer_a_id, Role.PLATFORM_ADMIN)


def test_unknown_user_raises_not_found(world):
    with pytest.raises(UserNotFoundError):
        world.svc.deactivate_user(world.root, 99999)


def test_role_change_to_same_role_is_a_no_op(world):
    assert world.svc.change_user_role(world.admin_a, world.issuer_a_id, "ISSUER").role is Role.ISSUER


def test_only_platform_admin_manages_institutions(world):
    with pytest.raises(PermissionDeniedError):
        world.svc.create_institution(world.admin_a, code="GAMMA", name="Gamma")
    with pytest.raises(PermissionDeniedError):
        world.svc.set_institution_active(world.admin_a, world.inst_a, False)
    with pytest.raises(PermissionDeniedError):
        world.svc.list_institutions(world.issuer_a)
    assert len(world.svc.list_institutions(world.root)) == 2


@pytest.mark.parametrize("code", ["", "A", "has space", "x" * 40, "bad!code"])
def test_institution_code_validation(world, code):
    with pytest.raises(ValidationError):
        world.svc.create_institution(world.root, code=code, name="Name")
