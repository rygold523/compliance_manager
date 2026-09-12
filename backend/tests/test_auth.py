from types import SimpleNamespace

import pytest

from app.auth.middleware import _path_is_public
from app.auth.service import (
    hash_password,
    normalize_username,
    public_user,
    token_hash,
    verify_password,
)
from app.api.admin_users import DormantDisableRequest, UserCreateRequest, validate_username
from fastapi import HTTPException


def test_password_hash_round_trip():
    password_hash = hash_password("correct horse battery staple")
    assert password_hash.startswith("$argon2id$")
    assert verify_password(password_hash, "correct horse battery staple")
    assert not verify_password(password_hash, "incorrect password")


def test_short_password_is_rejected():
    with pytest.raises(ValueError):
        hash_password("too-short")


def test_username_normalization():
    assert normalize_username("  Dashboard.Admin ") == "dashboard.admin"


def test_session_tokens_are_hashed_deterministically():
    assert token_hash("session-token") == token_hash("session-token")
    assert token_hash("session-token") != token_hash("another-token")
    assert len(token_hash("session-token")) == 64


def test_public_user_never_exposes_password_hash():
    user = SimpleNamespace(
        id=7,
        username="auditor",
        display_name="Compliance Auditor",
        role="auditor",
        must_change_password=False,
        password_hash="must-not-leak",
    )
    result = public_user(user)
    assert result["username"] == "auditor"
    assert "password_hash" not in result


def test_authentication_route_exposure_is_narrow():
    assert _path_is_public("/api/auth/login")
    assert _path_is_public("/api/health")
    assert _path_is_public("/api/live")
    assert _path_is_public("/api/ready")
    assert not _path_is_public("/api/auth/me")
    assert not _path_is_public("/api/auth/logout")
    assert not _path_is_public("/api/auth/password")


def test_admin_username_validation_normalizes_safe_names():
    assert validate_username(" Dashboard.Admin ") == "dashboard.admin"


@pytest.mark.parametrize(
    "username",
    ["has spaces", "../admin", "<admin>", ""],
)
def test_admin_username_validation_rejects_unsafe_names(username):
    with pytest.raises(HTTPException):
        validate_username(username)


def test_admin_create_request_rejects_unknown_role():
    with pytest.raises(ValueError):
        UserCreateRequest(
            username="reviewer",
            display_name="Reviewer",
            password="a-secure-temporary-password",
            role="owner",
        )


def test_dormant_disable_threshold_is_bounded():
    assert DormantDisableRequest(inactive_days=90).inactive_days == 90
    with pytest.raises(ValueError):
        DormantDisableRequest(inactive_days=29)
    with pytest.raises(ValueError):
        DormantDisableRequest(inactive_days=731)
