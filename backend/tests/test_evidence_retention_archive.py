import json
import os
import tarfile
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.core.database import Base
from app.models.models import AuthAuditEvent, Evidence
from app.services import evidence_retention_archive as archive
from app.services import evidence_retention_preview as preview
from app.services.evidence_retention_preview import PreviewPolicy


NOW = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def configure(monkeypatch, tmp_path):
    access_file = tmp_path / "access_reviews.json"
    access_file.write_text('{"campaigns": []}\n', encoding="utf-8")
    monkeypatch.setattr(preview, "_read_events", lambda: [])
    monkeypatch.setattr(preview, "_read_notes", lambda: {})
    monkeypatch.setattr(archive, "write_changelog", lambda **kwargs: kwargs)
    return access_file


def add_candidate(db, root):
    old_path = root / "old.json"
    old_path.write_text('{"old": true}\n', encoding="utf-8")
    old = Evidence(
        evidence_id="EV-OLD",
        asset_id="asset-1",
        control_id="AC-02",
        framework="pci_dss",
        filename="old.json",
        file_path=str(old_path),
        source="test",
        collector="iam_users",
        validated=True,
        created_at=NOW - timedelta(days=500),
    )
    current_path = root / "current.json"
    current_path.write_text('{"current": true}\n', encoding="utf-8")
    current = Evidence(
        evidence_id="EV-CURRENT",
        asset_id="asset-1",
        control_id="AC-02",
        framework="pci_dss",
        filename="current.json",
        file_path=str(current_path),
        source="test",
        collector="iam_users",
        validated=True,
        created_at=NOW - timedelta(days=5),
    )
    db.add_all([old, current])
    db.commit()
    return old, current, old_path


def test_archive_requires_actor_approval_and_fingerprint(db, tmp_path, monkeypatch):
    access_file = configure(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="actor"):
        archive.create_archive(
            db, PreviewPolicy(), tmp_path, access_file, tmp_path / "archives",
            "", "CHG-1", "0" * 64, now=NOW,
        )
    with pytest.raises(ValueError, match="approval"):
        archive.create_archive(
            db, PreviewPolicy(), tmp_path, access_file, tmp_path / "archives",
            "admin", "", "0" * 64, now=NOW,
        )
    with pytest.raises(ValueError, match="fingerprint"):
        archive.create_archive(
            db, PreviewPolicy(), tmp_path, access_file, tmp_path / "archives",
            "admin", "CHG-1", "invalid", now=NOW,
        )


def test_archive_rejects_changed_candidate_set(db, tmp_path, monkeypatch):
    access_file = configure(monkeypatch, tmp_path)
    old, _, old_path = add_candidate(db, tmp_path)
    approved = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    old_path.write_text('{"changed": true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="mismatch"):
        archive.create_archive(
            db, PreviewPolicy(), tmp_path, access_file, tmp_path / "archives",
            "admin", "CHG-1", approved["candidate_fingerprint_sha256"], now=NOW,
        )


def test_archive_packages_and_verifies_without_deleting(db, tmp_path, monkeypatch):
    access_file = configure(monkeypatch, tmp_path)
    old, current, _ = add_candidate(db, tmp_path)
    approved = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    original_count = db.query(Evidence).count()

    result = archive.create_archive(
        db,
        PreviewPolicy(),
        tmp_path,
        access_file,
        tmp_path / "archives",
        "admin",
        "CHG-APPROVED-1",
        approved["candidate_fingerprint_sha256"],
        now=NOW,
    )

    archive_path = result["archive_path"]
    assert result["status"] == "completed"
    assert result["actions_performed"] == {"archived": True, "deleted": False, "scheduled": False}
    assert result["backup_confirmation"]["status"] == "pending_external_copy"
    assert db.query(Evidence).count() == original_count
    assert db.get(Evidence, old.id) is not None
    assert db.get(Evidence, current.id) is not None
    assert db.query(AuthAuditEvent).filter_by(event_type=archive.ARCHIVE_EVENT_TYPE).count() == 1
    with tarfile.open(archive_path, "r:gz") as package:
        names = package.getnames()
    assert any(name.endswith("/manifest.json") for name in names)
    assert any(name.endswith("/records/evidence.jsonl") for name in names)
    assert any(name.endswith("/evidence-files/EV-OLD/old.json") for name in names)


def test_empty_candidate_set_is_logged_and_does_not_create_archive(db, tmp_path, monkeypatch):
    access_file = configure(monkeypatch, tmp_path)
    approved = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    result = archive.create_archive(
        db,
        PreviewPolicy(),
        tmp_path,
        access_file,
        tmp_path / "archives",
        "admin",
        "CHG-EMPTY",
        approved["candidate_fingerprint_sha256"],
        now=NOW,
    )
    assert result["status"] == "skipped"
    assert result["actions_performed"]["archived"] is False
    assert not (tmp_path / "archives").exists()
    assert db.query(AuthAuditEvent).filter_by(event_type=archive.ARCHIVE_SKIPPED_EVENT_TYPE).count() == 1
