from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
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
from app.core.database import get_db
from app.models.models import AuthSession, LocalUser


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=14, max_length=1024)


def source_address(request: Request) -> str | None:
    return request.client.host if request.client else None


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
    user = db.query(LocalUser).filter(LocalUser.username == username).first()
    now = utc_now()

    if user is None:
        consume_dummy_password_check(payload.password)
        audit(
            db,
            "login_failed",
            username=username,
            source_address=source_address(request),
            detail={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not user.enabled:
        consume_dummy_password_check(payload.password)
        audit(
            db,
            "login_failed",
            username=user.username,
            user_id=user.id,
            source_address=source_address(request),
            detail={"reason": "account_disabled"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if user.locked_until and user.locked_until > now:
        audit(
            db,
            "login_failed",
            username=user.username,
            user_id=user.id,
            source_address=source_address(request),
            detail={"reason": "account_locked"},
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Account is temporarily locked.")

    if not verify_password(user.password_hash, payload.password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.auth_max_failed_attempts:
            user.locked_until = now + timedelta(minutes=settings.auth_lockout_minutes)
            user.failed_login_attempts = 0
        audit(
            db,
            "login_failed",
            username=user.username,
            user_id=user.id,
            source_address=source_address(request),
            detail={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    token, session = create_session(db, user)
    db.flush()
    audit(
        db,
        "login_succeeded",
        username=user.username,
        user_id=user.id,
        source_address=source_address(request),
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
            source_address=source_address(request),
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
        source_address=source_address(request),
    )
    db.commit()
    return {"user": public_user(user)}
