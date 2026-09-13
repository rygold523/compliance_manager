import argparse
import json
from pathlib import Path

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.auth_retention import (
    CONFIRMATION_PHRASE,
    RetentionPolicy,
    run_retention,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Preview or execute retention for authentication sessions and audit events."
    )
    result.add_argument("--session-days", type=int, default=settings.auth_session_retention_days)
    result.add_argument("--audit-days", type=int, default=settings.auth_audit_retention_days)
    result.add_argument("--archive-root", default=settings.auth_retention_archive_root)
    result.add_argument("--actor", required=True, help="Administrative username authorizing the action.")
    result.add_argument("--execute", action="store_true", help="Archive and delete eligible rows. Default is preview.")
    result.add_argument("--confirm", help=f"Required with --execute: {CONFIRMATION_PHRASE}")
    return result


def main() -> int:
    args = parser().parse_args()
    policy = RetentionPolicy(args.session_days, args.audit_days)
    db = SessionLocal()
    try:
        result = run_retention(
            db,
            policy,
            Path(args.archive_root),
            args.actor,
            execute=args.execute,
            confirmation=args.confirm,
        )
    finally:
        db.close()
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
