import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import AuthAuditEvent, AuthSession, LocalUser


VALID_ROLES = frozenset({"admin", "auditor", "viewer"})
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
_dummy_password_hash = _password_hasher.hash(
    "not-a-real-account-password"
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_password(password: str) -> None:
    if len(password) < 14:
        raise ValueError("Password must contain at least 14 characters.")
    if len(password) > 1024:
        raise ValueError("Password is too long.")


def hash_password(password: str) -> str:
    validate_password(password)
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerifyMismatchError):
        return False


def consume_dummy_password_check(password: str) -> None:
    verify_password(_dummy_password_hash, password)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def audit(
    db: Session,
    event_type: str,
    *,
    username: str | None = None,
    user_id: int | None = None,
    source_address: str | None = None,
    detail: dict | None = None,
) -> str:
    audit_event_id = f"AUD-{uuid4().hex}"
    event_detail = dict(detail or {})
    event_detail["audit_event_id"] = audit_event_id
    db.add(
        AuthAuditEvent(
            event_type=event_type,
            username=username,
            user_id=user_id,
            source_address=source_address,
            detail=event_detail,
        )
    )
    return audit_event_id


def create_session(db: Session, user: LocalUser) -> tuple[str, AuthSession]:
    now = utc_now()
    token = secrets.token_urlsafe(48)
    session = AuthSession(
        session_token_hash=token_hash(token),
        user_id=user.id,
        expires_at=now + timedelta(hours=settings.auth_session_hours),
        last_seen_at=now,
    )
    db.add(session)
    return token, session


def resolve_session(db: Session, token: str | None) -> tuple[LocalUser, AuthSession] | None:
    if not token:
        return None
    now = utc_now()
    session = (
        db.query(AuthSession)
        .filter(
            AuthSession.session_token_hash == token_hash(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .first()
    )
    if session is None:
        return None
    user = db.query(LocalUser).filter(LocalUser.id == session.user_id).first()
    if user is None or not user.enabled:
        return None
    last_seen_at = session.last_seen_at
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
    if now - last_seen_at >= timedelta(minutes=5):
        session.last_seen_at = now
        db.commit()
    return user, session


def public_user(user: LocalUser) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "must_change_password": user.must_change_password,
    }
