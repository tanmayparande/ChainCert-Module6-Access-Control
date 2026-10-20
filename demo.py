"""Demonstration of Module 6 with fictional data in a throw-away database.

Run (from ``standalone_modules/``)::

    python -m module6_access_control.demo

or (from inside ``module6_access_control/``)::

    python demo.py

All institutions, people and passwords below are fictional and exist only in
a temporary SQLite file that is deleted when the demo ends.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):  # allow `python demo.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module6_access_control import (  # noqa: E402
    AccessControlService,
    InvalidCredentialsError,
    InvalidSessionError,
    PermissionDeniedError,
    Role,
    Settings,
)

# DEMO-ONLY credentials for fictional accounts in a temporary database.
DEMO_PASSWORD = "demo-only-Passw0rd!"


def banner(title: str) -> None:
    print(f"\n=== {title} ===")


def show(label: str, decision) -> None:
    verdict = "ALLOWED" if decision.allowed else "DENIED"
    print(f"  {label:<55} -> {verdict} ({decision.reason})")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="m6-demo-") as tmp:
        settings = Settings(database_path=Path(tmp) / "demo.db")
        svc = AccessControlService(settings)
        svc.initialize_database()

        banner("Setup: fictional institutions and users")
        svc.bootstrap_platform_admin(
            email="root@chaincert.example", password=DEMO_PASSWORD, full_name="Platform Root"
        )
        root = svc.authenticate("root@chaincert.example", DEMO_PASSWORD).session_token
        north = svc.create_institution(root, code="NORTHFIELD", name="Northfield Institute of Technology")
        south = svc.create_institution(root, code="SOUTHBAY", name="Southbay College")
        svc.provision_user(root, email="admin@northfield.example", password=DEMO_PASSWORD,
                           full_name="Nora Admin", role=Role.INSTITUTION_ADMIN, institution_id=north.id)
        n_admin = svc.authenticate("admin@northfield.example", DEMO_PASSWORD).session_token
        issuer = svc.provision_user(n_admin, email="registrar@northfield.example", password=DEMO_PASSWORD,
                                    full_name="Ravi Registrar", role=Role.ISSUER, institution_id=north.id)
        student = svc.provision_user(n_admin, email="asha@northfield.example", password=DEMO_PASSWORD,
                                     full_name="Asha Student", role=Role.STUDENT, institution_id=north.id)
        svc.provision_user(root, email="hr@employer.example", password=DEMO_PASSWORD,
                           full_name="Hiring Verifier", role=Role.PUBLIC_VERIFIER)
        print(f"  Institutions: {north.code} (id {north.id}), {south.code} (id {south.id})")
        print(f"  Issuer id {issuer.id}, student id {student.id}")

        banner("1. Login")
        result = svc.authenticate("  Registrar@Northfield.EXAMPLE ", DEMO_PASSWORD)
        issuer_token = result.session_token
        print(f"  Issuer login OK (email normalized), session expires {result.expires_at:%Y-%m-%d %H:%M} UTC")
        for email in ("registrar@northfield.example", "nobody@northfield.example"):
            try:
                svc.authenticate(email, "wrong-password-123")
            except InvalidCredentialsError as exc:
                print(f"  Failed login for {email:<30} -> '{exc}' (same message either way)")

        banner("2-3. Issuer authorization and institution isolation")
        show(f"Issuer: issue certificate at {north.code}", svc.can_issue_certificate(issuer_token, north.id))
        show(f"Issuer: revoke certificate at {north.code}", svc.can_revoke_certificate(issuer_token, north.id))
        show(f"Issuer: issue certificate at {south.code}", svc.can_issue_certificate(issuer_token, south.id))

        banner("4. Student cannot issue")
        student_token = svc.authenticate("asha@northfield.example", DEMO_PASSWORD).session_token
        show("Student: issue certificate at own institution", svc.can_issue_certificate(student_token, north.id))
        show("Student: view own certificate", svc.can_view_certificate(student_token, north.id, student.id))
        show("Student: view another student's certificate",
             svc.can_view_certificate(student_token, north.id, issuer.id))

        banner("5. Public verifier")
        verifier_token = svc.authenticate("hr@employer.example", DEMO_PASSWORD).session_token
        show("Verifier: public verification", svc.can_verify_publicly(verifier_token))
        show("Anonymous: public verification", svc.can_verify_publicly())
        show(f"Verifier: revoke certificate at {north.code}", svc.can_revoke_certificate(verifier_token, north.id))
        try:
            svc.provision_user(verifier_token, email="x@employer.example", password=DEMO_PASSWORD,
                               full_name="X", role=Role.STUDENT, institution_id=north.id)
        except PermissionDeniedError as exc:
            print(f"  Verifier provisioning a user                            -> DENIED ({exc.reason})")

        banner("6. Deactivation invalidates existing sessions")
        svc.deactivate_user(n_admin, issuer.id)
        try:
            svc.can_issue_certificate(issuer_token, north.id)
        except InvalidSessionError as exc:
            print(f"  Issuer's old token after deactivation -> 401 '{exc}'")
        try:
            svc.authenticate("registrar@northfield.example", DEMO_PASSWORD)
        except InvalidCredentialsError as exc:
            print(f"  Issuer re-login after deactivation    -> '{exc}'")

        banner("7. Audit log (latest privileged events at Northfield)")
        for event in svc.read_audit_log(n_admin, limit=8):
            print(f"  #{event.id:<3} {event.outcome.value:<7} {event.action:<32} "
                  f"actor={event.actor_user_id} target={event.target_type}:{event.target_id}")
        try:
            svc.read_audit_log(student_token)
        except PermissionDeniedError as exc:
            print(f"  Student reading audit log -> DENIED ({exc.reason})")

        svc.logout(n_admin)
        print("\nDemo finished; temporary database removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
