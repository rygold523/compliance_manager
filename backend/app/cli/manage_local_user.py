import argparse
import getpass
import sys

from app.auth.service import VALID_ROLES, audit, hash_password, normalize_username, utc_now
from app.core.database import Base, SessionLocal, engine
from app.models.models import AuthAuditEvent, AuthSession, LocalUser  # noqa: F401


def create_user(args: argparse.Namespace) -> int:
    username = normalize_username(args.username)
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(LocalUser).filter(LocalUser.username == username).first():
            print(f"Local user '{username}' already exists.", file=sys.stderr)
            return 1
        user = LocalUser(
            username=username,
            display_name=args.display_name.strip(),
            password_hash=password_hash,
            role=args.role,
            must_change_password=not args.no_force_password_change,
            password_changed_at=utc_now(),
        )
        db.add(user)
        db.flush()
        audit(db, "local_user_created", username=user.username, user_id=user.id, detail={"role": user.role})
        db.commit()
        print(f"Created local {args.role} account '{username}'.")
        return 0
    finally:
        db.close()


def list_users(_args: argparse.Namespace) -> int:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        users = db.query(LocalUser).order_by(LocalUser.username).all()
        print("USERNAME\tROLE\tENABLED\tMUST_CHANGE_PASSWORD\tDISPLAY_NAME")
        for user in users:
            print(
                f"{user.username}\t{user.role}\t{user.enabled}\t"
                f"{user.must_change_password}\t{user.display_name}"
            )
        return 0
    finally:
        db.close()


def set_enabled(args: argparse.Namespace) -> int:
    username = normalize_username(args.username)
    db = SessionLocal()
    try:
        user = db.query(LocalUser).filter(LocalUser.username == username).first()
        if user is None:
            print(f"Local user '{username}' does not exist.", file=sys.stderr)
            return 1
        user.enabled = args.enabled
        if not args.enabled:
            now = utc_now()
            db.query(AuthSession).filter(
                AuthSession.user_id == user.id,
                AuthSession.revoked_at.is_(None),
            ).update({"revoked_at": now}, synchronize_session=False)
        audit(
            db,
            "local_user_enabled" if args.enabled else "local_user_disabled",
            username=user.username,
            user_id=user.id,
        )
        db.commit()
        print(f"{'Enabled' if args.enabled else 'Disabled'} local user '{username}'.")
        return 0
    finally:
        db.close()


def reset_password(args: argparse.Namespace) -> int:
    username = normalize_username(args.username)
    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        user = db.query(LocalUser).filter(LocalUser.username == username).first()
        if user is None:
            print(f"Local user '{username}' does not exist.", file=sys.stderr)
            return 1
        now = utc_now()
        user.password_hash = password_hash
        user.password_changed_at = now
        user.must_change_password = not args.no_force_password_change
        user.failed_login_attempts = 0
        user.locked_until = None
        db.query(AuthSession).filter(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        ).update({"revoked_at": now}, synchronize_session=False)
        audit(db, "local_user_password_reset", username=user.username, user_id=user.id)
        db.commit()
        print(f"Reset password for local user '{username}'.")
        return 0
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage dashboard local users.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="Create a local dashboard user.")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--role", choices=sorted(VALID_ROLES), default="viewer")
    create.add_argument("--no-force-password-change", action="store_true")
    create.set_defaults(handler=create_user)

    listing = subparsers.add_parser("list", help="List local dashboard users.")
    listing.set_defaults(handler=list_users)

    enable = subparsers.add_parser("enable", help="Enable a local dashboard user.")
    enable.add_argument("--username", required=True)
    enable.set_defaults(handler=set_enabled, enabled=True)

    disable = subparsers.add_parser("disable", help="Disable a user and revoke active sessions.")
    disable.add_argument("--username", required=True)
    disable.set_defaults(handler=set_enabled, enabled=False)

    reset = subparsers.add_parser("reset-password", help="Reset a password and revoke active sessions.")
    reset.add_argument("--username", required=True)
    reset.add_argument("--no-force-password-change", action="store_true")
    reset.set_defaults(handler=reset_password)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
