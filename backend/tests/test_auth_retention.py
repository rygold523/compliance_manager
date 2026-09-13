import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.core.database import Base
from app.models.models import AuthAuditEvent, AuthSession
from app.services import auth_retention
from app.services.auth_retention import CONFIRMATION_PHRASE, RetentionPolicy


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def add_session(db, token, expires_at, revoked_at=None):
    row = AuthSession(
        session_token_hash=token,
        user_id=1,
        created_at=NOW - timedelta(days=100),
        expires_at=expires_at,
        last_seen_at=NOW - timedelta(days=100),
        revoked_at=revoked_at,
    )
    db.add(row)
    db.flush()
    return row


def test_preview_identifies_old_records_and_protects_active_sessions(db, monkeypatch, tmp_path):
    expired = add_session(db, "a" * 64, NOW - timedelta(days=31))
    active = add_session(db, "b" * 64, NOW + timedelta(hours=1))
    db.add(AuthAuditEvent(event_type="login_succeeded", created_at=NOW - timedelta(days=401)))
    db.add(AuthAuditEvent(event_type="login_succeeded", created_at=NOW - timedelta(days=10)))
    db.commit()
    monkeypatch.setattr(auth_retention, "write_changelog", lambda **kwargs: kwargs)

    result = auth_retention.run_retention(
        db, RetentionPolicy(30, 400), tmp_path, "admin", now=NOW
    )

    assert result["mode"] == "preview"
    assert [row["id"] for row in result["sessions"]] == [expired.id]
    assert active.id not in [row["id"] for row in result["sessions"]]
    assert result["counts"] == {"sessions": 1, "audit_events": 1}
    assert db.query(AuthSession).count() == 2
    assert db.query(AuthAuditEvent).filter_by(event_type="auth_retention_previewed").count() == 1


def test_execute_requires_exact_confirmation(db, tmp_path):
    with pytest.raises(ValueError, match="Execution requires"):
        auth_retention.run_retention(
            db, RetentionPolicy(30, 400), tmp_path, "admin", execute=True
        )


def test_execute_archives_before_deleting_and_preserves_action_audit(db, monkeypatch, tmp_path):
    old_session = add_session(db, "c" * 64, NOW - timedelta(days=31))
    active_session = add_session(db, "d" * 64, NOW + timedelta(days=1))
    old_event = AuthAuditEvent(event_type="login_failed", created_at=NOW - timedelta(days=401))
    db.add(old_event)
    db.commit()
    old_session_id = old_session.id
    active_session_id = active_session.id
    old_event_id = old_event.id
    monkeypatch.setattr(auth_retention, "write_changelog", lambda **kwargs: kwargs)

    result = auth_retention.run_retention(
        db,
        RetentionPolicy(30, 400),
        tmp_path,
        "admin",
        execute=True,
        confirmation=CONFIRMATION_PHRASE,
        now=NOW,
    )

    assert db.get(AuthSession, old_session_id) is None
    assert db.get(AuthSession, active_session_id) is not None
    assert db.query(AuthAuditEvent).filter_by(event_type="login_failed").count() == 0
    assert db.query(AuthAuditEvent).filter_by(event_type="auth_retention_executed").count() == 1
    archive = tmp_path / result["archive"]["archive_id"]
    assert (archive / "manifest.json").is_file()
    assert str(old_session_id) in (archive / "auth_sessions.jsonl").read_text()
    assert str(old_event_id) in (archive / "auth_audit_events.jsonl").read_text()


def test_retention_periods_must_be_positive():
    with pytest.raises(ValueError):
        RetentionPolicy(0, 400)
