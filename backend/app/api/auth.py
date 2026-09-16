import hashlib
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth.service import (
    audit,
    consume_dummy_password_check,
    create_session,
    hash_password,
    normalize_username,
    public_user,
    resolve_session,
    utc_now,
    verify_password,
)
from app.core.config import settings
from app.core.client_address import resolve_client_address
from app.core.database import get_db
from app.models.models import AuthLoginThrottle, AuthSession, LocalUser


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=14, max_length=1024)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=settings.auth_session_hours * 3600,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        path="/",
    )


INVALID_LOGIN_DETAIL = "Invalid username or password."


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _throttle_scope_key(kind: str, username: str, address: str | None) -> str:
    material = f"{kind}\0{address or 'unknown'}"
    if kind == "identity_source":
        material += f"\0{username}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _throttle_records(db: Session, username: str, address: str | None):
    keys = {
        "source": _throttle_scope_key("source", username, address),
        "identity_source": _throttle_scope_key(
            "identity_source", username, address
        ),
    }
    if db.get_bind().dialect.name == "postgresql":
        for key in sorted(keys.values()):
            lock_key = int(key[:16], 16)
            if lock_key >= 2**63:
                lock_key -= 2**64
            db.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": lock_key},
            )
    records = {
        row.scope_key: row
        for row in (
            db.query(AuthLoginThrottle)
            .filter(AuthLoginThrottle.scope_key.in_(keys.values()))
            .with_for_update()
            .all()
        )
    }
    return keys, records


def _login_is_throttled(db: Session, username: str, address: str | None, now) -> bool:
    _, records = _throttle_records(db, username, address)
    return any(
        _aware(record.blocked_until) is not None
        and _aware(record.blocked_until) > now
        for record in records.values()
    )


def _record_login_failure(
    db: Session,
    username: str,
    address: str | None,
    now,
    *,
    identity_known: bool,
) -> None:
    keys, records = _throttle_records(db, username, address)
    if not identity_known:
        keys.pop("identity_source")
    window = timedelta(minutes=settings.auth_login_throttle_window_minutes)

    for kind, key in keys.items():
        record = records.get(key)
        if record is None:
            record = AuthLoginThrottle(
                scope_key=key,
                failure_count=0,
                window_started_at=now,
            )
            db.add(record)
        elif now - _aware(record.window_started_at) >= window:
            record.failure_count = 0
            record.window_started_at = now
            record.blocked_until = None

        record.failure_count += 1
        threshold = (
            settings.auth_login_source_max_attempts
            if kind == "source"
            else settings.auth_max_failed_attempts
        )
        if record.failure_count >= threshold:
            exponent = min(record.failure_count - threshold, 10)
            seconds = min(
                settings.auth_login_max_backoff_seconds,
                settings.auth_login_initial_backoff_seconds * (2**exponent),
            )
            record.blocked_until = now + timedelta(seconds=seconds)


def _clear_identity_source_throttle(
    db: Session, username: str, address: str | None
) -> None:
    key = _throttle_scope_key("identity_source", username, address)
    db.query(AuthLoginThrottle).filter(
        AuthLoginThrottle.scope_key == key
    ).delete(synchronize_session=False)


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    if settings.auth_provider != "local":
        raise HTTPException(status_code=503, detail="Local authentication is disabled.")

    username = normalize_username(payload.username)
    now = utc_now()
    address = resolve_client_address(request)
    user = db.query(LocalUser).filter(LocalUser.username == username).first()

    password_valid = False
    if user is None:
        consume_dummy_password_check(payload.password)
    else:
        password_valid = verify_password(user.password_hash, payload.password)

    throttled = _login_is_throttled(db, username, address, now)
    account_locked = bool(
        user is not None
        and user.locked_until is not None
        and _aware(user.locked_until) > now
    )
    login_valid = bool(
        user is not None
        and user.enabled
        and not account_locked
        and password_valid
        and not throttled
    )

    if not login_valid:
        _record_login_failure(
            db,
            username,
            address,
            now,
            identity_known=user is not None,
        )
        if user is not None and not password_valid:
            user.failed_login_attempts = min(
                user.failed_login_attempts + 1,
                2_147_483_647,
            )
        reason = "rate_limited" if throttled else "invalid_credentials"
        if user is not None and not user.enabled:
            reason = "account_disabled"
        elif account_locked:
            reason = "account_locked"
        audit(
            db,
            "login_failed",
            username=user.username if user is not None else username,
            user_id=user.id if user is not None else None,
            source_address=address,
            detail={"reason": reason},
        )
        db.commit()
        raise HTTPException(status_code=401, detail=INVALID_LOGIN_DETAIL)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    _clear_identity_source_throttle(db, username, address)
    token, session = create_session(db, user)
    db.flush()
    audit(
        db,
        "login_succeeded",
        username=user.username,
        user_id=user.id,
        source_address=address,
        detail={
            "session_id": session.id,
            "user_agent": (request.headers.get("user-agent") or "")[:512],
        },
    )
    db.commit()
    set_session_cookie(response, token)
    return {"user": public_user(user)}


@router.get("/me")
def me(request: Request):
    user = getattr(request.state, "auth_user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return {"user": public_user(user)}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    token = request.cookies.get(settings.auth_cookie_name)
    resolved = resolve_session(db, token)
    if resolved:
        user, session = resolved
        session.revoked_at = utc_now()
        audit(
            db,
            "logout",
            username=user.username,
            user_id=user.id,
            source_address=resolve_client_address(request),
        )
        db.commit()
    response.delete_cookie(
        settings.auth_cookie_name,
        path="/",
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite=settings.auth_cookie_samesite,
    )


@router.post("/password")
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    authenticated_user = getattr(request.state, "auth_user", None)
    authenticated_session = getattr(request.state, "auth_session", None)
    if authenticated_user is None or authenticated_session is None:
        raise HTTPException(status_code=401, detail="Authentication required.")

    user = (
        db.query(LocalUser)
        .filter(LocalUser.id == authenticated_user.id)
        .with_for_update()
        .first()
    )
    current_session = (
        db.query(AuthSession)
        .filter(AuthSession.id == authenticated_session.id)
        .first()
    )
    if user is None or current_session is None or not user.enabled:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    try:
        user.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user.must_change_password = False
    user.password_changed_at = utc_now()
    (
        db.query(AuthSession)
        .filter(
            AuthSession.user_id == user.id,
            AuthSession.id != current_session.id,
            AuthSession.revoked_at.is_(None),
        )
        .update({AuthSession.revoked_at: utc_now()}, synchronize_session=False)
    )
    audit(
        db,
        "password_changed",
        username=user.username,
        user_id=user.id,
        source_address=resolve_client_address(request),
    )
    db.commit()
    return {"user": public_user(user)}
