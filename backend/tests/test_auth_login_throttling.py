from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import INVALID_LOGIN_DETAIL, LoginRequest, login
from app.auth.service import hash_password, utc_now
from app.core.config import settings
from app.core.database import Base
from app.models.models import (
    AuthAuditEvent,
    AuthLoginThrottle,
    AuthSession,
    LocalUser,
)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    for table in (
        LocalUser.__table__,
        AuthSession.__table__,
        AuthAuditEvent.__table__,
        AuthLoginThrottle.__table__,
    ):
        table.create(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


def request(address: str):
    return SimpleNamespace(
        client=SimpleNamespace(host=address),
        headers={},
    )


def add_user(db, username: str, *, enabled=True, locked=False):
    user = LocalUser(
        username=username,
        display_name=username,
        password_hash=hash_password("correct horse battery staple"),
        role="viewer",
        enabled=enabled,
        must_change_password=False,
        failed_login_attempts=0,
        locked_until=(utc_now() + timedelta(minutes=10)) if locked else None,
    )
    db.add(user)
    db.commit()
    return user


def attempt(db, username: str, password: str, address: str):
    return login(
        LoginRequest(username=username, password=password),
        request(address),
        Response(),
        db,
    )


@pytest.mark.parametrize(
    ("username", "enabled", "locked", "password", "address"),
    [
        ("missing", None, None, "wrong password", "192.0.2.10"),
        ("disabled", False, False, "correct horse battery staple", "192.0.2.11"),
        ("locked", True, True, "correct horse battery staple", "192.0.2.12"),
        ("wrong", True, False, "wrong password", "192.0.2.13"),
    ],
)
def test_all_failed_login_states_return_identical_response(
    db, username, enabled, locked, password, address
):
    if enabled is not None:
        add_user(db, username, enabled=enabled, locked=locked)

    with pytest.raises(HTTPException) as exc_info:
        attempt(db, username, password, address)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == INVALID_LOGIN_DETAIL


def test_bad_passwords_do_not_create_account_wide_lock(db, monkeypatch):
    monkeypatch.setattr(settings, "auth_max_failed_attempts", 3)
    user = add_user(db, "target")

    for index in range(3):
        with pytest.raises(HTTPException):
            attempt(db, "target", "wrong password", f"192.0.2.{20 + index}")

    db.refresh(user)
    assert user.failed_login_attempts == 3
    assert user.locked_until is None


def test_unknown_usernames_create_only_one_source_record(db):
    for index in range(10):
        with pytest.raises(HTTPException):
            attempt(
                db,
                f"unknown-{index}",
                "wrong password",
                "192.0.2.25",
            )

    assert db.query(AuthLoginThrottle).count() == 1


def test_throttle_is_limited_to_attacking_source(db, monkeypatch):
    monkeypatch.setattr(settings, "auth_max_failed_attempts", 2)
    add_user(db, "target")

    for _ in range(2):
        with pytest.raises(HTTPException):
            attempt(db, "target", "wrong password", "192.0.2.30")

    with pytest.raises(HTTPException) as exc_info:
        attempt(
            db,
            "target",
            "correct horse battery staple",
            "192.0.2.30",
        )
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == INVALID_LOGIN_DETAIL

    result = attempt(
        db,
        "target",
        "correct horse battery staple",
        "192.0.2.31",
    )
    assert result["user"]["username"] == "target"
