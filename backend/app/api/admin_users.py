import logging
import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.service import (
    VALID_ROLES,
    audit,
    hash_password,
    normalize_username,
    utc_now,
)
from app.api.changelog import stable_changelog_event_id, write_changelog
from app.core.database import get_db
from app.core.client_address import resolve_client_address
from app.models.models import AuthAuditEvent, AuthSession, LocalUser


router = APIRouter(prefix="/api/admin/users", tags=["User Administration"])
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._@-]{0,127}$")
logger = logging.getLogger(__name__)
CHANGELOG_ASSET_ID = "compliance-dashboard"
SENSITIVE_CHANGELOG_KEYS = frozenset({
    "password",
    "new_password",
    "current_password",
    "password_hash",
    "session_token",
    "session_token_hash",
    "token",
    "secret",
})


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=14, max_length=1024)
    role: Literal["admin", "auditor", "viewer"] = "viewer"


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: Literal["admin", "auditor", "viewer"] | None = None
    enabled: bool | None = None
    inactivity_exempt: bool | None = None
    inactivity_exemption_reason: str | None = Field(default=None, max_length=500)


class DormantDisableRequest(BaseModel):
    inactive_days: int = Field(default=90, ge=30, le=730)
    preview: bool = True


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=14, max_length=1024)


def sanitize_changelog_details(value):
    if isinstance(value, dict):
        return {
            key: sanitize_changelog_details(item)
            for key, item in value.items()
            if str(key).lower() not in SENSITIVE_CHANGELOG_KEYS
        }
    if isinstance(value, list):
        return [sanitize_changelog_details(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_changelog_details(item) for item in value)
    return value


def write_user_changelog(
    event_type: str,
    *,
    user: LocalUser,
    admin,
    summary: str,
    source: str | None,
    audit_event_id: str,
    details: dict | None = None,
) -> None:
    event_details = {
        "username": user.username,
        "target_user_id": user.id,
        "actor_username": admin.username,
        "actor_user_id": admin.id,
        "source": "dashboard_local_auth",
        "source_address": source,
        "audit_event_id": audit_event_id,
    }
    event_details.update(sanitize_changelog_details(details or {}))

    try:
        write_changelog(
            event_id=stable_changelog_event_id(audit_event_id, event_type),
            event_type=event_type,
            asset_id=CHANGELOG_ASSET_ID,
            summary=summary,
            details=event_details,
        )
    except Exception:
        # The authentication audit event remains authoritative if the
        # supplemental compliance changelog is temporarily unavailable.
        logger.exception(
            "Unable to write dashboard user event %s to the changelog",
            event_type,
        )


def _active_session_count(db: Session, user_id: int) -> int:
    now = utc_now()
    return (
        db.query(func.count(AuthSession.id))
        .filter(
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .scalar()
        or 0
    )


def serialize_admin_user(db: Session, user: LocalUser) -> dict:
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=utc_now().tzinfo)
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "enabled": user.enabled,
        "must_change_password": user.must_change_password,
        "failed_login_attempts": user.failed_login_attempts,
        "locked_until": user.locked_until,
        "is_locked": bool(locked_until and locked_until > utc_now()),
        "last_login_at": user.last_login_at,
        "inactivity_exempt": bool(user.inactivity_exempt),
        "inactivity_exemption_reason": user.inactivity_exemption_reason,
        "password_changed_at": user.password_changed_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "active_sessions": _active_session_count(db, user.id),
    }


def dormant_candidates(db: Session, inactive_days: int, admin_id: int) -> list[LocalUser]:
    cutoff = utc_now() - timedelta(days=inactive_days)
    return (
        db.query(LocalUser)
        .filter(
            LocalUser.enabled.is_(True),
            LocalUser.role != "admin",
            LocalUser.id != admin_id,
            LocalUser.inactivity_exempt.is_(False),
            or_(
                LocalUser.last_login_at < cutoff,
                (LocalUser.last_login_at.is_(None) & (LocalUser.created_at < cutoff)),
            ),
        )
        .order_by(LocalUser.username.asc())
        .all()
    )


def serialize_auth_event(event: AuthAuditEvent) -> dict:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "username": event.username,
        "user_id": event.user_id,
        "source_address": event.source_address,
        "detail": event.detail if isinstance(event.detail, dict) else {},
        "created_at": event.created_at,
    }


def session_login_metadata(db: Session, user_id: int) -> dict[int, dict]:
    events = (
        db.query(AuthAuditEvent)
        .filter(
            AuthAuditEvent.user_id == user_id,
            AuthAuditEvent.event_type == "login_succeeded",
        )
        .order_by(AuthAuditEvent.id.desc())
        .all()
    )
    metadata = {}
    for event in events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        session_id = detail.get("session_id")
        if not isinstance(session_id, int) or session_id in metadata:
            continue
        metadata[session_id] = {
            "source_address": event.source_address,
            "user_agent": detail.get("user_agent") or "",
            "login_audit_event_id": detail.get("audit_event_id"),
        }
    return metadata


def serialize_session(session: AuthSession, metadata: dict | None = None) -> dict:
    now = utc_now()
    revoked = session.revoked_at is not None
    expires_at = session.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now.tzinfo)
    expired = expires_at is None or expires_at <= now
    return {
        "id": session.id,
        "created_at": session.created_at,
        "last_seen_at": session.last_seen_at,
        "expires_at": session.expires_at,
        "revoked_at": session.revoked_at,
        "status": "revoked" if revoked else "expired" if expired else "active",
        "source_address": (metadata or {}).get("source_address"),
        "user_agent": (metadata or {}).get("user_agent") or "",
        "login_audit_event_id": (metadata or {}).get("login_audit_event_id"),
    }


def validate_username(username: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username must begin with a letter or number and contain only "
                "letters, numbers, periods, underscores, hyphens, or @."
            ),
        )
    return normalized


def revoke_user_sessions(db: Session, user_id: int) -> int:
    return (
        db.query(AuthSession)
        .filter(
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
        )
        .update(
            {AuthSession.revoked_at: utc_now()},
            synchronize_session=False,
        )
    )


def ensure_admin_remains(
    db: Session,
    user: LocalUser,
    *,
    new_role: str | None = None,
    new_enabled: bool | None = None,
) -> None:
    removes_enabled_admin = (
        user.role == "admin"
        and user.enabled
        and (
            (new_role is not None and new_role != "admin")
            or new_enabled is False
        )
    )
    if not removes_enabled_admin:
        return

    enabled_admins = (
        db.query(LocalUser)
        .filter(LocalUser.role == "admin", LocalUser.enabled.is_(True))
        .with_for_update()
        .all()
    )
    if len(enabled_admins) <= 1:
        raise HTTPException(
            status_code=409,
            detail="The last enabled administrator cannot be disabled or demoted.",
        )


def get_user_for_update(db: Session, user_id: int) -> LocalUser:
    user = (
        db.query(LocalUser)
        .filter(LocalUser.id == user_id)
        .with_for_update()
        .first()
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


@router.get("")
def list_users(
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin")),
):
    users = db.query(LocalUser).order_by(LocalUser.username.asc()).all()
    return {"users": [serialize_admin_user(db, user) for user in users]}


@router.post("/disable-dormant")
def disable_dormant_users(
    payload: DormantDisableRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    users = dormant_candidates(db, payload.inactive_days, admin.id)
    preview = [serialize_admin_user(db, user) for user in users]
    if payload.preview:
        return {"preview": True, "inactive_days": payload.inactive_days, "users": preview, "count": len(preview)}

    request_source = resolve_client_address(request)
    disabled = []
    for user in users:
        user.enabled = False
        revoked_sessions = revoke_user_sessions(db, user.id)
        before = {
            "display_name": user.display_name,
            "role": user.role,
            "enabled": True,
            "inactivity_exempt": False,
            "inactivity_exemption_reason": None,
        }
        after = {**before, "enabled": False}
        audit_event_id = audit(
            db,
            "user_updated",
            username=user.username,
            user_id=user.id,
            source_address=request_source,
            detail={
                "actor_user_id": admin.id,
                "actor_username": admin.username,
                "inactive_days": payload.inactive_days,
                "revoked_sessions": revoked_sessions,
                "before": before,
                "after": after,
            },
        )
        disabled.append((user, audit_event_id, revoked_sessions))
    db.commit()
    for user, audit_event_id, revoked_sessions in disabled:
        write_user_changelog(
            "dashboard_user_disabled",
            user=user,
            admin=admin,
            summary=f"Dashboard user {user.username} was disabled.",
            source=request_source,
            audit_event_id=audit_event_id,
            details={"inactive_days": payload.inactive_days, "revoked_sessions": revoked_sessions},
        )
    return {"preview": False, "inactive_days": payload.inactive_days, "disabled_count": len(disabled), "usernames": [item[0].username for item in disabled]}


@router.get("/audit-events")
def list_auth_audit_events(
    search: str = Query(default="", max_length=200),
    event_type: str = Query(default="", max_length=64),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin")),
):
    query = db.query(AuthAuditEvent)
    if event_type.strip():
        query = query.filter(AuthAuditEvent.event_type == event_type.strip())
    if search.strip():
        pattern = f"%{search.strip()}%"
        query = query.filter(or_(
            AuthAuditEvent.username.ilike(pattern),
            AuthAuditEvent.event_type.ilike(pattern),
            AuthAuditEvent.source_address.ilike(pattern),
        ))

    total = query.count()
    events = (
        query.order_by(AuthAuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "events": [serialize_auth_event(event) for event in events],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/{user_id}/sessions")
def list_user_sessions(
    user_id: int,
    include_inactive: bool = True,
    db: Session = Depends(get_db),
    _admin=Depends(require_roles("admin")),
):
    user = db.query(LocalUser).filter(LocalUser.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    query = db.query(AuthSession).filter(AuthSession.user_id == user_id)
    if not include_inactive:
        query = query.filter(
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > utc_now(),
        )
    sessions = query.order_by(AuthSession.created_at.desc()).limit(200).all()
    metadata = session_login_metadata(db, user_id)
    return {
        "user": {"id": user.id, "username": user.username},
        "sessions": [serialize_session(session, metadata.get(session.id)) for session in sessions],
    }


@router.post("/{user_id}/sessions/{session_id}/revoke")
def revoke_single_session(
    user_id: int,
    session_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    user = get_user_for_update(db, user_id)
    session = (
        db.query(AuthSession)
        .filter(
            AuthSession.id == session_id,
            AuthSession.user_id == user_id,
        )
        .with_for_update()
        .first()
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found.")

    current_session = getattr(request.state, "auth_session", None)
    if current_session is not None and current_session.id == session.id:
        raise HTTPException(
            status_code=409,
            detail="The session currently authorizing this request cannot be revoked here. Use Sign Out instead.",
        )
    if session.revoked_at is not None or session.expires_at <= utc_now():
        raise HTTPException(status_code=409, detail="The session is not active.")

    session.revoked_at = utc_now()
    request_source = resolve_client_address(request)
    audit_event_id = audit(
        db,
        "user_session_revoked",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={
            "actor_user_id": admin.id,
            "actor_username": admin.username,
            "session_id": session.id,
        },
    )
    db.commit()
    write_user_changelog(
        "dashboard_user_session_revoked",
        user=user,
        admin=admin,
        summary=f"Session {session.id} was revoked for dashboard user {user.username}.",
        source=request_source,
        audit_event_id=audit_event_id,
        details={"session_id": session.id, "revoked_sessions": 1},
    )
    return {"message": "Session revoked.", "session_id": session.id}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    request_source = resolve_client_address(request)
    username = validate_username(payload.username)
    display_name = payload.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="Display name is required.")
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role.")
    if db.query(LocalUser).filter(LocalUser.username == username).first():
        raise HTTPException(status_code=409, detail="Username already exists.")

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = LocalUser(
        username=username,
        display_name=display_name,
        password_hash=password_hash,
        role=payload.role,
        enabled=True,
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    audit_event_id = audit(
        db,
        "user_created",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={
            "actor_user_id": admin.id,
            "actor_username": admin.username,
            "role": user.role,
        },
    )
    db.commit()
    db.refresh(user)
    write_user_changelog(
        "dashboard_user_created",
        user=user,
        admin=admin,
        summary=f"Dashboard user {user.username} was created.",
        source=request_source,
        audit_event_id=audit_event_id,
        details={
            "display_name": user.display_name,
            "role_name": user.role,
            "enabled": user.enabled,
            "must_change_password": user.must_change_password,
        },
    )
    return {"user": serialize_admin_user(db, user)}


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    request_source = resolve_client_address(request)
    user = get_user_for_update(db, user_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes were supplied.")
    if user.id == admin.id and (
        ("role" in changes and changes["role"] != "admin")
        or changes.get("enabled") is False
    ):
        raise HTTPException(
            status_code=409,
            detail="You cannot disable or demote your own account.",
        )

    ensure_admin_remains(
        db,
        user,
        new_role=changes.get("role"),
        new_enabled=changes.get("enabled"),
    )
    before = {
        "display_name": user.display_name,
        "role": user.role,
        "enabled": user.enabled,
        "inactivity_exempt": bool(user.inactivity_exempt),
        "inactivity_exemption_reason": user.inactivity_exemption_reason,
    }
    if "display_name" in changes:
        display_name = changes["display_name"].strip()
        if not display_name:
            raise HTTPException(status_code=400, detail="Display name is required.")
        user.display_name = display_name
    if "role" in changes:
        user.role = changes["role"]
    if "enabled" in changes:
        user.enabled = changes["enabled"]
    if "inactivity_exempt" in changes:
        reason = (changes.get("inactivity_exemption_reason") or "").strip()
        if changes["inactivity_exempt"] and not reason:
            raise HTTPException(status_code=400, detail="An exemption reason is required.")
        user.inactivity_exempt = changes["inactivity_exempt"]
        user.inactivity_exemption_reason = reason if changes["inactivity_exempt"] else None

    security_changed = (
        before["role"] != user.role
        or before["enabled"] != user.enabled
    )
    revoked_sessions = revoke_user_sessions(db, user.id) if security_changed else 0
    audit_event_id = audit(
        db,
        "user_updated",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={
            "actor_user_id": admin.id,
            "actor_username": admin.username,
            "before": before,
            "after": {
                "display_name": user.display_name,
                "role": user.role,
                "enabled": user.enabled,
                "inactivity_exempt": bool(user.inactivity_exempt),
                "inactivity_exemption_reason": user.inactivity_exemption_reason,
            },
            "revoked_sessions": revoked_sessions,
        },
    )
    db.commit()
    db.refresh(user)
    after = {
        "display_name": user.display_name,
        "role": user.role,
        "enabled": user.enabled,
        "inactivity_exempt": bool(user.inactivity_exempt),
        "inactivity_exemption_reason": user.inactivity_exemption_reason,
    }
    common_details = {
        "before": before,
        "after": after,
        "revoked_sessions": revoked_sessions,
    }
    if before["role"] != after["role"]:
        write_user_changelog(
            "dashboard_user_role_changed",
            user=user,
            admin=admin,
            summary=(
                f"Dashboard user {user.username} role changed from "
                f"{before['role']} to {after['role']}."
            ),
            source=request_source,
            audit_event_id=audit_event_id,
            details={
                **common_details,
                "previous_role_name": before["role"],
                "role_name": after["role"],
            },
        )
    if before["enabled"] != after["enabled"]:
        event_type = (
            "dashboard_user_enabled"
            if after["enabled"]
            else "dashboard_user_disabled"
        )
        write_user_changelog(
            event_type,
            user=user,
            admin=admin,
            summary=(
                f"Dashboard user {user.username} was "
                f"{'enabled' if after['enabled'] else 'disabled'}."
            ),
            source=request_source,
            audit_event_id=audit_event_id,
            details=common_details,
        )
    if before["display_name"] != after["display_name"]:
        write_user_changelog(
            "dashboard_user_profile_updated",
            user=user,
            admin=admin,
            summary=f"Dashboard user {user.username} display name was updated.",
            source=request_source,
            audit_event_id=audit_event_id,
            details=common_details,
        )
    if before["inactivity_exempt"] != after["inactivity_exempt"] or before["inactivity_exemption_reason"] != after["inactivity_exemption_reason"]:
        write_user_changelog(
            "dashboard_user_inactivity_exemption_changed",
            user=user,
            admin=admin,
            summary=f"Dashboard user {user.username} inactivity exemption was {'enabled' if after['inactivity_exempt'] else 'removed'}.",
            source=request_source,
            audit_event_id=audit_event_id,
            details=common_details,
        )
    return {"user": serialize_admin_user(db, user)}


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: int,
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    request_source = resolve_client_address(request)
    user = get_user_for_update(db, user_id)
    try:
        user.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    user.must_change_password = True
    user.password_changed_at = utc_now()
    user.failed_login_attempts = 0
    user.locked_until = None
    revoked_sessions = revoke_user_sessions(db, user.id)
    audit_event_id = audit(
        db,
        "user_password_reset",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={
            "actor_user_id": admin.id,
            "actor_username": admin.username,
            "revoked_sessions": revoked_sessions,
        },
    )
    db.commit()
    write_user_changelog(
        "dashboard_user_password_reset",
        user=user,
        admin=admin,
        summary=f"Dashboard user {user.username} password was reset.",
        source=request_source,
        audit_event_id=audit_event_id,
        details={
            "must_change_password": True,
            "revoked_sessions": revoked_sessions,
        },
    )
    return {"message": "Password reset. A password change is required at next login."}


@router.post("/{user_id}/unlock")
def unlock_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    request_source = resolve_client_address(request)
    user = get_user_for_update(db, user_id)
    user.failed_login_attempts = 0
    user.locked_until = None
    audit_event_id = audit(
        db,
        "user_unlocked",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={"actor_user_id": admin.id, "actor_username": admin.username},
    )
    db.commit()
    write_user_changelog(
        "dashboard_user_unlocked",
        user=user,
        admin=admin,
        summary=f"Dashboard user {user.username} was unlocked.",
        source=request_source,
        audit_event_id=audit_event_id,
    )
    return {"message": "Account unlocked."}


@router.post("/{user_id}/revoke-sessions")
def revoke_sessions(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    request_source = resolve_client_address(request)
    user = get_user_for_update(db, user_id)
    revoked_sessions = revoke_user_sessions(db, user.id)
    audit_event_id = audit(
        db,
        "user_sessions_revoked",
        username=user.username,
        user_id=user.id,
        source_address=request_source,
        detail={
            "actor_user_id": admin.id,
            "actor_username": admin.username,
            "revoked_sessions": revoked_sessions,
        },
    )
    db.commit()
    write_user_changelog(
        "dashboard_user_sessions_revoked",
        user=user,
        admin=admin,
        summary=f"Active sessions were revoked for dashboard user {user.username}.",
        source=request_source,
        audit_event_id=audit_event_id,
        details={"revoked_sessions": revoked_sessions},
    )
    return {"message": "Active sessions revoked.", "revoked_sessions": revoked_sessions}
