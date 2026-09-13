import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.core.database import Base
from app.models.models import Approval, AuthAuditEvent, Evidence, Finding
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


def add_evidence(db, tmp_path, name, *, days=500, validated=False, finding_id=None):
    path = tmp_path / f"{name}.json"
    path.write_text('{"ok": true}\n', encoding="utf-8")
    row = Evidence(
        evidence_id=name,
        finding_id=finding_id,
        asset_id="asset-1",
        control_id="AC-02",
        framework="pci_dss",
        filename=path.name,
        file_path=str(path),
        source="test",
        collector="iam_users",
        evidence_type="iam_users",
        validated=validated,
        created_at=NOW - timedelta(days=days),
    )
    db.add(row)
    db.flush()
    return row


def configure_files(monkeypatch, tmp_path, events=None, notes=None, campaigns=None):
    access_file = tmp_path / "access_reviews.json"
    access_file.write_text(json.dumps({"campaigns": campaigns or []}), encoding="utf-8")
    monkeypatch.setattr(preview, "_read_events", lambda: events or [])
    monkeypatch.setattr(preview, "_read_notes", lambda: notes or {})
    monkeypatch.setattr(preview, "write_changelog", lambda **kwargs: kwargs)
    return access_file


def test_preview_protects_current_and_lists_older_candidate(db, tmp_path, monkeypatch):
    old = add_evidence(db, tmp_path, "EV-OLD", days=500, validated=True)
    current = add_evidence(db, tmp_path, "EV-CURRENT", days=5, validated=True)
    db.commit()
    access_file = configure_files(monkeypatch, tmp_path)

    result = preview.build_preview(
        db, PreviewPolicy(), tmp_path, access_file, now=NOW
    )

    assert [item["evidence_id"] for item in result["candidates"]["evidence"]] == [old.evidence_id]
    assert current.evidence_id not in [item["evidence_id"] for item in result["candidates"]["evidence"]]
    assert result["actions_performed"] == {"archived": False, "deleted": False, "scheduled": False}


def test_open_finding_and_pending_approval_protect_evidence(db, tmp_path, monkeypatch):
    finding_id = "F-OPEN"
    add_evidence(db, tmp_path, "EV-LINKED", finding_id=finding_id)
    db.add(Finding(
        finding_id=finding_id,
        asset_id="asset-1",
        source="test",
        title="Open finding",
        severity="medium",
        finding_type="test",
        status="open",
    ))
    db.add(Approval(
        approval_id="APR-1",
        finding_id=finding_id,
        asset_id="asset-1",
        action_type="retain",
        proposed_action="Keep evidence",
        status="pending",
    ))
    db.commit()
    access_file = configure_files(monkeypatch, tmp_path)

    result = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    item = result["protected"]["evidence"][0]
    assert "active_finding" in item["protection_reasons"]
    assert "pending_approval" in item["protection_reasons"]


def test_legal_hold_file_is_enforced_and_malformed_file_fails(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path, "EV-HOLD")
    db.commit()
    access_file = configure_files(monkeypatch, tmp_path)
    hold_file = tmp_path / "holds.json"
    hold_file.write_text(json.dumps({"evidence_ids": ["EV-HOLD"]}), encoding="utf-8")

    result = preview.build_preview(
        db, PreviewPolicy(), tmp_path, access_file, hold_file, NOW
    )
    assert "legal_hold_evidence" in result["protected"]["evidence"][0]["protection_reasons"]

    hold_file.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable"):
        preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, hold_file, NOW)


def test_active_access_review_and_annotation_protect_changelog(db, tmp_path, monkeypatch):
    events = [{
        "event_id": "EVT-1",
        "timestamp": (NOW - timedelta(days=500)).isoformat(),
        "event_type": "access_review_item_decided",
        "asset_id": "compliance-dashboard",
        "summary": "review",
        "details": {"campaign_id": "AR-1"},
    }]
    access_file = configure_files(
        monkeypatch,
        tmp_path,
        events=events,
        notes={"EVT-1": {"note": "Retain for assessment", "jira_url": ""}},
        campaigns=[{"campaign_id": "AR-1", "status": "open"}],
    )
    result = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    reasons = result["protected"]["changelog"][0]["protection_reasons"]
    assert reasons == ["active_access_review", "has_annotation"]


def test_fingerprint_is_deterministic_and_preview_is_logged(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path, "EV-STABLE")
    db.commit()
    access_file = configure_files(monkeypatch, tmp_path)
    first = preview.run_preview(db, PreviewPolicy(), tmp_path, access_file, "admin", now=NOW)
    second = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    assert first["candidate_fingerprint_sha256"] == second["candidate_fingerprint_sha256"]
    assert db.query(AuthAuditEvent).filter_by(event_type=preview.PREVIEW_EVENT_TYPE).count() == 1


def test_missing_legal_hold_file_fails_closed(db, tmp_path, monkeypatch):
    access_file = configure_files(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        preview.build_preview(
            db, PreviewPolicy(), tmp_path, access_file, tmp_path / "missing.json", NOW
        )


def test_policy_rejects_zero_days():
    with pytest.raises(ValueError):
        PreviewPolicy(changelog_days=0)
