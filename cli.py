"""Small command-line helper for database setup.

Usage (from ``standalone_modules/``)::

    python -m module6_access_control.cli init-db [--db PATH]
    python -m module6_access_control.cli bootstrap-admin --email E --name N [--db PATH]

``bootstrap-admin`` prompts for the password (never pass it as an argument;
it would end up in shell history). Use ``--password-stdin`` for automation.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from dataclasses import replace
from pathlib import Path

if __package__ in (None, ""):  # allow `python cli.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module6_access_control import AccessControlError, AccessControlService, Settings  # noqa: E402


def _service(db: str | None) -> AccessControlService:
    settings = Settings.from_env()
    if db:
        settings = replace(settings, database_path=Path(db))
    return AccessControlService(settings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="module6_access_control.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-db", help="create the database and schema")
    p_init.add_argument("--db", help="database path (overrides M6_DATABASE_PATH)")

    p_boot = sub.add_parser("bootstrap-admin", help="create the first platform admin")
    p_boot.add_argument("--db")
    p_boot.add_argument("--email", required=True)
    p_boot.add_argument("--name", required=True)
    p_boot.add_argument("--password-stdin", action="store_true",
                        help="read the password from standard input")

    args = parser.parse_args(argv)
    svc = _service(args.db)
    try:
        svc.initialize_database()
        if args.command == "init-db":
            print(f"Database ready at {svc.settings.database_path}")
            return 0
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Repeat password: "):
                print("Passwords do not match.", file=sys.stderr)
                return 2
        user = svc.bootstrap_platform_admin(email=args.email, password=password, full_name=args.name)
        print(f"Created platform admin {user.email} (id {user.id}).")
        return 0
    except AccessControlError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
