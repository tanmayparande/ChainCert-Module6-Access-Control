"""Centralized role-permission policy (deny by default).

This file is the single source of truth for *who may do what*. Every check in
the module goes through :func:`scope_for`; if a role/action pair is not listed
here, the answer is "deny".

A permission is granted with a **scope** that says which resources it covers:

* ``GLOBAL``      – any institution (platform administrators only).
* ``INSTITUTION`` – only the caller's own institution.
* ``OWN``         – only resources whose owner is the caller (students).
* ``PUBLIC``      – read-only public access; no institution or owner needed.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional

from .models import Action, Role


class Scope(str, Enum):
    GLOBAL = "GLOBAL"
    INSTITUTION = "INSTITUTION"
    OWN = "OWN"
    PUBLIC = "PUBLIC"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


_G, _I, _O, _P = Scope.GLOBAL, Scope.INSTITUTION, Scope.OWN, Scope.PUBLIC

PERMISSION_MATRIX: Mapping[Role, Mapping[Action, Scope]] = MappingProxyType(
    {
        Role.PLATFORM_ADMIN: MappingProxyType(
            {
                Action.MANAGE_INSTITUTIONS: _G,
                Action.PROVISION_USER: _G,
                Action.MANAGE_USER_ROLES: _G,
                Action.MANAGE_USER_STATUS: _G,
                Action.VIEW_USERS: _G,
                Action.READ_AUDIT_LOG: _G,
                Action.VERIFY_CERTIFICATE_PUBLIC: _P,
            }
        ),
        Role.INSTITUTION_ADMIN: MappingProxyType(
            {
                Action.PROVISION_USER: _I,
                Action.MANAGE_USER_ROLES: _I,
                Action.MANAGE_USER_STATUS: _I,
                Action.VIEW_USERS: _I,
                Action.ADMINISTER_CERTIFICATE_BATCH: _I,
                Action.REVOKE_CERTIFICATE: _I,
                Action.VIEW_CERTIFICATE: _I,
                Action.READ_AUDIT_LOG: _I,
                Action.VERIFY_CERTIFICATE_PUBLIC: _P,
            }
        ),
        Role.ISSUER: MappingProxyType(
            {
                Action.ISSUE_CERTIFICATE: _I,
                Action.CORRECT_CERTIFICATE: _I,
                Action.ADMINISTER_CERTIFICATE_BATCH: _I,
                Action.REVOKE_CERTIFICATE: _I,
                Action.VIEW_CERTIFICATE: _I,
                Action.VERIFY_CERTIFICATE_PUBLIC: _P,
            }
        ),
        Role.STUDENT: MappingProxyType(
            {
                Action.VIEW_CERTIFICATE: _O,
                Action.VERIFY_CERTIFICATE_PUBLIC: _P,
            }
        ),
        Role.PUBLIC_VERIFIER: MappingProxyType(
            {
                Action.VERIFY_CERTIFICATE_PUBLIC: _P,
            }
        ),
    }
)

#: Which roles each role may grant, change *to*, or manage.
#: Institution admins can only manage issuers and students; they cannot create
#: other administrators, so they cannot escalate anyone (including themselves).
ASSIGNABLE_ROLES: Mapping[Role, frozenset[Role]] = MappingProxyType(
    {
        Role.PLATFORM_ADMIN: frozenset(Role),
        Role.INSTITUTION_ADMIN: frozenset({Role.ISSUER, Role.STUDENT}),
    }
)

#: Actions that may be performed without logging in.
ANONYMOUS_ACTIONS: frozenset[Action] = frozenset({Action.VERIFY_CERTIFICATE_PUBLIC})

#: Actions that change state somewhere (here or in a certificate module).
WRITE_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.MANAGE_INSTITUTIONS,
        Action.PROVISION_USER,
        Action.MANAGE_USER_ROLES,
        Action.MANAGE_USER_STATUS,
        Action.ISSUE_CERTIFICATE,
        Action.CORRECT_CERTIFICATE,
        Action.ADMINISTER_CERTIFICATE_BATCH,
        Action.REVOKE_CERTIFICATE,
    }
)

#: Actions whose *allowed* decisions are recorded in the audit log.
#: (Denials are always recorded for authenticated callers.)
PRIVILEGED_ACTIONS: frozenset[Action] = WRITE_ACTIONS | {
    Action.VIEW_USERS,
    Action.READ_AUDIT_LOG,
}


def scope_for(role: object, action: object) -> Optional[Scope]:
    """Return the scope at which ``role`` may perform ``action``, or ``None``.

    ``None`` means deny. Unknown roles and unknown actions always yield ``None``.
    """
    if not isinstance(role, Role) or not isinstance(action, Action):
        return None
    return PERMISSION_MATRIX.get(role, {}).get(action)


def permitted_actions(role: Role) -> frozenset[Action]:
    """All actions a role holds at any scope."""
    return frozenset(PERMISSION_MATRIX.get(role, {}).keys())


def assignable_roles(role: object) -> frozenset[Role]:
    """Roles that ``role`` may grant or manage (empty for everyone else)."""
    if not isinstance(role, Role):
        return frozenset()
    return ASSIGNABLE_ROLES.get(role, frozenset())
