# ChainCert — Module 6: Access Control and Issuer Authorization

A standalone Python package that answers two questions for the rest of ChainCert:

1. **Who is this caller?** (authentication and sessions)
2. **May they do this, here?** (role permissions + institution boundaries + ownership)

It also provides controlled user and institution administration, plus an audit log.

---

## 1. Objective and scope

**In scope**

- Five roles: `PLATFORM_ADMIN`, `INSTITUTION_ADMIN`, `ISSUER`, `STUDENT`, `PUBLIC_VERIFIER`.
- Centralised, deny-by-default role → permission policy with institution scoping.
- Login/logout, Argon2id password hashing, hashed session tokens with expiry.
- User provisioning, role changes, activation/deactivation, institution management.
- Audit log of security-relevant events, readable only by authorised admins.
- A small, stable facade (`AccessControlService`) for later integration.

**Out of scope (deliberately)**

- Issuing, correcting, storing, batching or revoking real certificates. The certificate methods here are **authorization checks only**.
- Modules 1–5, the Flask app, frontend pages, blockchain storage, and the main ChainCert database. This package imports none of them and touches none of their data.
- Password reset by email, MFA, and rate limiting (see [Limitations](#14-security-choices-and-limitations)).

---

## 2. Architecture and folder structure

```
standalone_modules/module6_access_control/
├── __init__.py            Public exports (the integration contract)
├── service.py             AccessControlService facade  ← integrators use this
├── auth_service.py        Login, session resolution, logout
├── management_service.py  Institutions, users, roles, status, audit reads
├── authorization.py       AuthorizationEngine: role + institution + ownership
├── policies.py            Permission matrix, assignable roles (single source of truth)
├── audit_service.py       Writing/reading audit events, sanitisation
├── password_hasher.py     Argon2id wrapper
├── repositories.py        All SQL (parameterised); no security decisions
├── database.py            SQLite connections, schema, transactions
├── models.py              Enums and immutable dataclasses returned by the API
├── validators.py          Email/name/code/ID/password validation
├── exceptions.py          Exception hierarchy with HTTP status hints
├── config.py              Settings (+ environment variables)
├── cli.py                 init-db / bootstrap-admin commands
├── demo.py                End-to-end demonstration with fictional data
├── requirements.txt
├── pytest.ini
├── .env.example
├── .gitignore
└── tests/
    ├── conftest.py
    ├── test_authentication.py
    ├── test_authorization.py
    ├── test_institution_isolation.py
    ├── test_user_management.py
    ├── test_sessions.py
    ├── test_audit_log.py
    └── test_database_and_independence.py
```

Layering (each layer only calls the one below it):

```
AccessControlService (service.py)
   ├── AuthService ─────────────┐
   ├── ManagementService ───────┼──► AuthorizationEngine ──► policies.py
   └── (check_permission) ──────┘          │
                         AuditService ◄────┘
                               │
                    Repositories (SQL only)
                               │
                       Database (SQLite)
```

`authorization.py` and `policies.py` contain no SQL apart from one existence check through a repository. `repositories.py` contains no security logic.

---

## 3. Installation and setup

Requires Python 3.11 or newer (tested on 3.13).

**Linux / macOS**

```bash
cd standalone_modules/module6_access_control
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows PowerShell**

```powershell
cd standalone_modules\module6_access_control
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Dependencies: `argon2-cffi` (runtime) and `pytest` (tests). Everything else is the standard library.

---

## 4. Configuration and database initialisation

Settings come from `Settings(...)` or from `M6_*` environment variables (see `.env.example`). This module does not read `.env` files itself; export the variables in your shell, or let the host application load them.

| Variable | Default | Meaning |
|---|---|---|
| `M6_DATABASE_PATH` | `module6_access_control/instance/module6_access_control.db` | This module's own SQLite file. Relative paths resolve from the current directory. |
| `M6_SESSION_TTL_MINUTES` | `60` | Absolute session lifetime. |
| `M6_PASSWORD_MIN_LENGTH` | `12` | Minimum length for new passwords. |
| `M6_ALLOW_ANONYMOUS_VERIFICATION` | `true` | Allow public verification without login. |
| `M6_SESSION_TOKEN_PEPPER` | unset | Optional secret (≥16 chars). If set, token hashes use HMAC-SHA256. |
| `M6_ARGON2_TIME_COST` / `_MEMORY_COST` / `_PARALLELISM` | `3` / `65536` / `4` | Argon2id cost. |

Run the commands below from `standalone_modules/` (the folder that contains `module6_access_control/`).

**Linux / macOS**

```bash
cd standalone_modules
python -m module6_access_control.cli init-db
python -m module6_access_control.cli bootstrap-admin --email admin@your-university.example --name "Platform Admin"
# optional custom location:
M6_DATABASE_PATH=/tmp/m6.db python -m module6_access_control.cli init-db
```

**Windows PowerShell**

```powershell
cd standalone_modules
python -m module6_access_control.cli init-db
python -m module6_access_control.cli bootstrap-admin --email admin@your-university.example --name "Platform Admin"
# optional custom location:
$env:M6_DATABASE_PATH = "C:\temp\m6.db"; python -m module6_access_control.cli init-db
```

`bootstrap-admin` prompts for the password and works only while no platform administrator exists. All later accounts are created by an authorised administrator through `provision_user`.

In Python:

```python
from module6_access_control import AccessControlService, Settings
svc = AccessControlService(Settings(database_path="instance/m6.db"))
svc.initialize_database()          # idempotent
```

The database file is git-ignored. Never commit it.

---

## 5. Running the demo

The demo creates fictional institutions and users in a **temporary** database that is deleted afterwards.

```bash
# Linux / macOS
cd standalone_modules
python -m module6_access_control.demo
```

```powershell
# Windows PowerShell
cd standalone_modules
python -m module6_access_control.demo
```

(`python demo.py` from inside the package folder also works.)

It shows, in order: successful and failed login; an issuer allowed in their own institution and denied in another; a student denied issuance; a public verifier allowed to verify but denied writes; deactivation killing an existing session; and the resulting audit entries.

---

## 6. Running the tests

```bash
# Linux / macOS
cd standalone_modules/module6_access_control
python -m pytest -v
```

```powershell
# Windows PowerShell
cd standalone_modules\module6_access_control
python -m pytest -v
```

From the repository root, `python -m pytest standalone_modules/module6_access_control` also works; `pytest.ini` puts the parent folder on the import path.

Each test uses its own SQLite file under pytest's `tmp_path` and a fake clock, so the tests are deterministic and never touch any real database. Test-only Argon2 parameters keep the suite fast. The suite also checks that the package imports nothing outside the standard library and `argon2`, and runs a login in a fresh interpreter to confirm that Flask is never loaded.

---

## 7. Public API

Import only from the package root:

```python
from module6_access_control import (
    AccessControlService, Settings, Action, Role, DenyReason,
    AuthenticationError, PermissionDeniedError, ValidationError,
)
```

### 7.1 Error contract

| Exception | HTTP hint | Meaning |
|---|---|---|
| `AuthenticationRequiredError` ⊂ `AuthenticationError` | 401 | No token supplied. |
| `InvalidSessionError` ⊂ `AuthenticationError` | 401 | Token malformed, unknown, expired, revoked, or the account/institution is deactivated. |
| `InvalidCredentialsError` ⊂ `AuthenticationError` | 401 | Login failed. Always the same message. |
| `PermissionDeniedError` ⊂ `AuthorizationError` | 403 | Authenticated but not allowed. `.reason` holds a `DenyReason` code; `.decision` holds the full decision. |
| `ValidationError` | 400 | Malformed argument (for example, a non-integer `institution_id`). |
| `UserNotFoundError`, `InstitutionNotFoundError` | 404 | Target does not exist. |
| `DuplicateUserError`, `DuplicateInstitutionError`, `ConflictError` | 409 | Uniqueness or state conflict. |

Every exception has `.http_status`, so an HTTP layer can map errors generically.

**Unauthenticated always raises** (`AuthenticationError`). For an authenticated caller who is denied:

- `can_*` and `check_permission` **return** a denied `AuthorizationDecision`.
- `authorize` and all administration methods **raise** `PermissionDeniedError`.

### 7.2 `AuthorizationDecision`

```python
@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    action: str                 # e.g. "certificate.issue"
    reason: str                 # DenyReason code, e.g. "cross_institution_access"
    user_id: int | None
    role: Role | None
    institution_id: int | None
    resource_owner_id: int | None
    def __bool__(self): ...     # truthy when allowed
    def raise_if_denied(self): ...
```

Reason codes: `allowed`, `public_access`, `unknown_action`, `unknown_role`, `role_lacks_permission`, `anonymous_not_permitted`, `institution_scope_required`, `cross_institution_access`, `unknown_institution`, `resource_owner_required`, `not_resource_owner`, `self_modification_not_allowed`, `role_not_assignable`, `target_not_manageable`.

### 7.3 Methods of `AccessControlService`

**Setup**

| Method | Returns |
|---|---|
| `AccessControlService(settings=None, *, clock=None)` | Uses `Settings.from_env()` when `settings` is omitted. |
| `AccessControlService.from_env(env=None)` | Builds the service from `M6_*` variables. |
| `initialize_database()` | `None`. Idempotent. |
| `bootstrap_platform_admin(*, email, password, full_name)` | `User`. Raises `ConflictError` once a platform admin exists. |

**Authentication**

| Method | Returns / raises |
|---|---|
| `authenticate(email, password)` | `AuthResult(session_token, expires_at, user: CurrentUser)` / `InvalidCredentialsError` |
| `get_current_user(session_token)` | `CurrentUser` / `AuthenticationError` |
| `logout(session_token)` | `bool`: `True` if a live session was revoked. Never raises. |
| `purge_expired_sessions()` | `int`: rows deleted (housekeeping). |

**Authorization checks** (never perform the operation itself)

| Method | Action checked |
|---|---|
| `check_permission(token, action, *, institution_id=None, resource_owner_id=None)` | Any `Action` (or its string). Returns the decision. |
| `authorize(token, action, *, institution_id=None, resource_owner_id=None)` | Same, but raises `PermissionDeniedError` on deny. |
| `can_issue_certificate(token, institution_id)` | `certificate.issue` |
| `can_correct_certificate(token, institution_id)` | `certificate.correct` |
| `can_administer_batch(token, institution_id)` | `certificate.batch_admin` |
| `can_revoke_certificate(token, institution_id)` | `certificate.revoke` |
| `can_view_certificate(token, institution_id, owner_user_id)` | `certificate.view` (student ownership) |
| `can_verify_publicly(token=None)` | `certificate.verify_public`. Anonymous is allowed by default. A supplied token must be valid; it is never silently treated as anonymous. |

**Administration** (all enforce authorization and raise `PermissionDeniedError`)

| Method | Who may call |
|---|---|
| `create_institution(token, *, code, name)` | Platform admin |
| `set_institution_active(token, institution_id, active)` | Platform admin. Deactivation revokes all member sessions. |
| `list_institutions(token)` | Platform admin |
| `provision_user(token, *, email, password, full_name, role, institution_id=None)` | Platform admin (any role); institution admin (`ISSUER`/`STUDENT`, own institution only) |
| `change_user_role(token, user_id, new_role)` | Same rules. Never yourself. Moving between institution-bound and global roles is not supported. |
| `deactivate_user(token, user_id)` / `reactivate_user(token, user_id)` | Same rules. Never yourself. Deactivation revokes all sessions. |
| `list_users(token, *, institution_id=None)` | Platform admin (all or one institution); institution admin (own only) |
| `read_audit_log(token, *, institution_id=None, action=None, limit=100)` | Platform admin (all); institution admin (own institution only) |

### 7.4 Usage example

```python
from module6_access_control import AccessControlService, Role, Settings

svc = AccessControlService(Settings(database_path="instance/m6.db"))
svc.initialize_database()

login = svc.authenticate("registrar@northfield.example", "a-long-password")
token = login.session_token                     # give to client (e.g. HTTP-only cookie)

me = svc.get_current_user(token)                # CurrentUser(role=Role.ISSUER, institution_id=1, ...)
decision = svc.can_issue_certificate(token, institution_id=1)
if decision:                                    # truthy when allowed
    ...                                         # Module 1–4 code performs the issuance

svc.logout(token)
```

---

## 8. Role-permission matrix

Scopes: **G** = any institution, **I** = own institution only, **O** = own resources only, **P** = public (read-only, no scope). A blank cell means denied.

| Action (`Action.*` / value) | PLATFORM_ADMIN | INSTITUTION_ADMIN | ISSUER | STUDENT | PUBLIC_VERIFIER | Anonymous |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Institution management (`MANAGE_INSTITUTIONS` / `institution.manage`) | G | | | | | |
| User provisioning (`PROVISION_USER` / `user.provision`) | G | I¹ | | | | |
| Role management (`MANAGE_USER_ROLES` / `user.manage_role`) | G | I¹ | | | | |
| Activation / deactivation (`MANAGE_USER_STATUS` / `user.manage_status`) | G | I¹ | | | | |
| View users (`VIEW_USERS` / `user.view`) | G | I | | | | |
| Certificate issuance (`ISSUE_CERTIFICATE` / `certificate.issue`) | | | I | | | |
| Certificate correction (`CORRECT_CERTIFICATE` / `certificate.correct`) | | | I | | | |
| Batch administration (`ADMINISTER_CERTIFICATE_BATCH` / `certificate.batch_admin`) | | I | I | | | |
| Certificate revocation (`REVOKE_CERTIFICATE` / `certificate.revoke`) | | I | I | | | |
| View certificate record (`VIEW_CERTIFICATE` / `certificate.view`) | | I | I | O | | |
| Public verification (`VERIFY_CERTIFICATE_PUBLIC` / `certificate.verify_public`) | P | P | P | P | P | P² |
| Audit-log access (`READ_AUDIT_LOG` / `audit.read`) | G | I | | | | |

¹ Institution admins may only create and manage `ISSUER` and `STUDENT` accounts. They cannot create, promote to, or manage `INSTITUTION_ADMIN`, `PLATFORM_ADMIN` or `PUBLIC_VERIFIER` accounts.
² Configurable with `M6_ALLOW_ANONYMOUS_VERIFICATION`.

**Design choice: separation of duties.** Platform admins manage tenants and accounts but cannot issue, correct or revoke certificates. Academic records are the institution's responsibility. If the team decides otherwise, edit `PERMISSION_MATRIX` in `policies.py`; the matrix test in `tests/test_authorization.py` will flag the change so this table can be updated alongside it.

Anything not in the matrix (an unknown action string, an unknown role, a missing scope argument) is **denied**.

---

## 9. Institution isolation rules

1. A caller's institution comes **only** from the database at session resolution, never from the request.
2. For **I**-scoped permissions, the `institution_id` passed by the caller must equal the caller's own institution. Otherwise the result is `cross_institution_access`. A missing ID gives `institution_scope_required`.
3. For **G**-scoped permissions (platform admin), a supplied `institution_id` must exist (`unknown_institution` otherwise).
4. For **O**-scoped permissions (students), `resource_owner_id` must equal the caller's user ID. If an `institution_id` is supplied, it must also be the student's own.
5. Users of a deactivated institution cannot log in, and their existing sessions stop working.
6. Escalation guards: nobody may change their own role or status; institution admins can only grant and manage `ISSUER`/`STUDENT`.
7. Every denial for an authenticated caller is written to the audit log.

---

## 10. Database schema

A separate SQLite file. Foreign keys are enforced on every connection, and timestamps are UTC ISO-8601 text.

| Table | Key columns and constraints |
|---|---|
| `institutions` | `id` PK, `code` UNIQUE (2–32 chars, upper-case), `name`, `is_active` (0/1), `created_at`, `updated_at` |
| `users` | `id` PK, `email` UNIQUE (normalised), `full_name`, `password_hash` (Argon2id), `role` CHECK ∈ 5 roles, `institution_id` FK → institutions (RESTRICT), `is_active`, `created_at`, `updated_at`, `last_login_at`. CHECK: institution-bound roles must have an institution; global roles must not. |
| `sessions` | `id` PK, `user_id` FK → users (CASCADE), `token_hash` UNIQUE (64 hex), `created_at`, `expires_at`, `revoked_at`, `revoked_reason` |
| `audit_events` | `id` PK, `occurred_at`, `actor_user_id` FK → users, `actor_role`, `action`, `target_type`, `target_id`, `institution_id` FK → institutions, `outcome` ∈ {SUCCESS, FAILURE, DENIED}, `description` (≤500 chars). Append-only triggers block UPDATE and DELETE. |

Indexes cover `users(institution_id)`, `users(role)`, `sessions(user_id)`, `sessions(expires_at)`, and `audit_events(occurred_at, institution_id, actor_user_id)`. The schema version is stored in `PRAGMA user_version` (currently 1).

Users are never deleted through the API; deactivate them instead. This keeps the audit trail's references intact, and the foreign keys prevent deleting a user who has audit history.

---

## 11. Audit logging

**Recorded events:** login success and failure (`auth.login`), logout (`auth.logout`), bootstrap, user provisioning, role change, deactivation and reactivation, institution creation, deactivation and reactivation, list and audit reads, and authorization decisions (`authz.<action>`). All denials are recorded; allowed decisions are recorded for privileged actions (every write action plus `user.view` and `audit.read`). Allowed public verifications are not logged, to avoid noise.

**Each event has:** actor user ID and role, action, target type and ID, institution, UTC timestamp, outcome, and a description generated by the module.

**Never recorded:** passwords (including mistyped ones), password hashes, and session tokens (raw or hashed). A failed login for an unknown email stores only a short SHA-256 fingerprint of the normalised email, so repeated attempts can be correlated without storing raw input. Descriptions have control characters stripped (to prevent log injection) and are capped at 500 characters.

**Access:** only platform admins (everything) and institution admins (their own institution). Reading the log is itself logged.

**Limitation:** SQLite triggers make the table append-only for application code, but **this log is not tamper-proof**. Anyone with write access to the database file can drop the triggers or edit the file. For stronger guarantees, forward events to an external write-once store, or hash-chain them (anchoring the chain on ChainCert's blockchain would fit this project well).

---

## 12. Future Integration Contract

The teammate integrating this module needs only `AccessControlService` and the exceptions. Nothing below requires changing Module 6's internals or database.

**Rules for callers**

1. Create **one** `AccessControlService` at application start-up and call `initialize_database()` once.
2. Pass the raw session token you received from `authenticate()`; never pass a user ID or role from the client.
3. Before every certificate operation, call the matching `can_*` (or `authorize`) with the institution that **owns the certificate**, as read from your own database, not from the request body.
4. Perform the operation only if the decision is allowed. Module 6 never does it for you.
5. Map `AuthenticationError` → 401 and `PermissionDeniedError` → 403 (use `exc.http_status`).
6. `resource_owner_id` / `owner_user_id` refers to the Module 6 user ID of the student. Store it on certificate records so ownership checks can be made.

**Example: a certificate service (framework-independent)**

```python
from module6_access_control import AccessControlService, PermissionDeniedError

class CertificateService:                       # lives in Modules 1–4, not here
    def __init__(self, access: AccessControlService, repo):
        self.access = access
        self.repo = repo

    def revoke(self, session_token: str, certificate_id: str, reason: str):
        cert = self.repo.get(certificate_id)                 # trusted institution_id
        decision = self.access.can_revoke_certificate(session_token, cert.institution_id)
        if not decision:
            raise PermissionDeniedError(decision)
        user = self.access.get_current_user(session_token)
        self.repo.mark_revoked(certificate_id, by_user_id=user.user_id, reason=reason)

    def issue(self, session_token: str, institution_id: int, payload: dict):
        self.access.authorize(session_token, "certificate.issue", institution_id=institution_id)
        return self.repo.create(institution_id=institution_id, **payload)   # only reached if allowed
```

**Example: a Flask route (for later; not included in this module)**

```python
from flask import Flask, request, jsonify
from module6_access_control import AccessControlService, AccessControlError

app = Flask(__name__)
access = AccessControlService.from_env()
access.initialize_database()

@app.errorhandler(AccessControlError)
def handle_access_error(exc):
    return jsonify(error=exc.message, reason=getattr(exc, "reason", None)), exc.http_status

@app.post("/api/certificates/<cert_id>/revoke")
def revoke(cert_id):
    token = request.cookies.get("session") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    cert = certificate_repo.get(cert_id)                        # Module 1–4 data access
    access.authorize(token or None, "certificate.revoke", institution_id=cert.institution_id)
    certificate_repo.mark_revoked(cert_id)
    return jsonify(status="revoked")

@app.get("/verify/<cert_hash>")
def verify(cert_hash):
    access.can_verify_publicly(request.cookies.get("session"))  # anonymous allowed
    return jsonify(result=verification_module.verify(cert_hash))
```

**Stability promise:** the names exported in `__init__.py`, the method signatures in §7.3, the `Action` values and the `DenyReason` codes are the contract. Internal modules (`repositories`, `database`, and so on) may change without notice.

---

## 13. Viva-ready explanations

**Authentication** proves *who* the caller is. The user sends an email and password; we normalise the email, look up the account, and verify the password against its Argon2id hash. On success we create a session. Every failure (unknown email, wrong password, deactivated account) returns the same message, and an unknown email still triggers a dummy hash verification so response time does not reveal whether the account exists.

**Authorization** decides *what* an authenticated caller may do. It is checked in the backend on every call, not in the UI. The decision combines three things: the role's permission for the action (from one central matrix), the scope of that permission (global, own institution, own resources, public), and the actual resource (its institution and owner). Anything not explicitly allowed is denied, including unknown actions and roles.

**Password hashing.** We never store passwords, only Argon2id hashes. Argon2id is deliberately slow and memory-hard, which makes brute-forcing a stolen database expensive even on GPUs. Each hash includes a random salt, so identical passwords produce different hashes, and the cost parameters are stored inside the hash. When we raise the cost, old hashes are upgraded automatically at the user's next login.

**Sessions.** After login we generate a 256-bit random token with Python's `secrets` module and return it to the client once. The database stores only its SHA-256 hash (or HMAC with a secret pepper), so a leaked database cannot be used to hijack sessions. Each request re-checks the session's expiry and revocation and the user's and institution's active status, which is why deactivating a user cuts off their existing sessions immediately. Logout revokes the session row.

**Audit logging** records who did what, to which target, in which institution, when, and whether it succeeded, failed or was denied. It supports accountability and incident investigation. It never contains secrets, it can only be read by authorised admins, and the table rejects updates and deletes. It is not tamper-proof against someone with direct access to the database file, which is why we list external or blockchain anchoring as a future improvement.

---

## 14. Security choices and limitations

**Choices**

- Argon2id via `argon2-cffi` with library defaults (t=3, m=64 MiB, p=4), plus automatic rehashing.
- 256-bit `secrets` tokens; only hashes stored; optional HMAC pepper from the environment.
- Absolute session expiry (default 60 minutes). Each request re-validates user and institution status.
- Deny-by-default policy in one file; parameterised SQL everywhere; foreign keys enforced.
- Generic login errors and timing equalisation for unknown emails.
- No secrets in code. `.env` and `*.db` files are git-ignored.

**Known limitations**

- **No brute-force throttling or lockout.** Add rate limiting at the HTTP layer, or extend `auth_service.authenticate`, before going to production.
- **No password reset, password change, or MFA.**
- **No sliding or idle timeout.** Sessions have a fixed lifetime from login.
- **The audit log is not tamper-proof** against database operators (see §11).
- **SQLite** suits a single application server. Concurrent writers are serialised, and very high write rates would need PostgreSQL or similar.
- **Email lower-casing** treats the local part as case-insensitive.
- **Duplicate-email errors** during provisioning reveal to the provisioning admin that an address is already registered. This is necessary for administration, but it means an admin can learn that an address exists elsewhere on the platform.
- **Role changes** between institution-bound and global roles are unsupported by design. Provision a new account instead.
- **Timing:** a login for an existing but deactivated account does the same hash work as any other attempt, but database timings are not strictly constant-time.
