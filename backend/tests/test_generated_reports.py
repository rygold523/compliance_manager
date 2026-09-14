import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api import report_records
from app.core.config import settings
from app.core.database import Base
from app.models.models import AuthAuditEvent, Evidence, GeneratedReportEvidence
from app.services import evidence_retention_preview as preview
from app.services import generated_reports as service
from app.services.evidence_retention_preview import PreviewPolicy


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def add_evidence(db, tmp_path):
    path = tmp_path / "old.json"
    path.write_text('{"old": true}\n', encoding="utf-8")
    row = Evidence(
        evidence_id="EV-REPORT", asset_id="asset-1", control_id="AC-02",
        framework="pci_dss", filename=path.name, file_path=str(path), source="test",
        collector="iam_users", evidence_type="iam_users", validated=True,
        created_at=NOW - timedelta(days=500),
    )
    db.add(row)
    db.commit()
    return row


def configure(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_root", str(tmp_path))
    monkeypatch.setattr(service, "write_changelog", lambda *args, **kwargs: None)
    monkeypatch.setattr(preview, "_read_events", lambda: [])
    monkeypatch.setattr(preview, "_read_notes", lambda: {})
    access_file = tmp_path / "access_reviews.json"
    access_file.write_text('{"campaigns": []}\n', encoding="utf-8")
    return access_file


def test_register_report_persists_hash_file_links_and_audit(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path)
    configure(monkeypatch, tmp_path)
    content = b"report-content"
    report = service.register_report(
        db, report_type="pdf", framework="pci_dss", actor="dashboard.admin",
        content=content, extension="pdf", evidence_ids=["EV-REPORT"],
    )
    assert report.sha256 == hashlib.sha256(content).hexdigest()
    assert report.status == "current"
    assert open(report.file_path, "rb").read() == content
    assert db.query(GeneratedReportEvidence).count() == 1
    assert db.query(AuthAuditEvent).filter_by(event_type="generated_report_recorded").count() == 1


def test_current_report_protects_evidence_and_superseded_report_does_not(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path)
    access_file = configure(monkeypatch, tmp_path)
    report = service.register_report(
        db, report_type="evidence_package", framework="soc2", actor="admin",
        content=b"zip", extension="zip", evidence_ids=["EV-REPORT"],
    )
    result = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    assert "generated_report" in result["protected"]["evidence"][0]["protection_reasons"]
    assert "persistently indexed" not in " ".join(result["dependency_check_limitations"])
    service.update_status(db, report.report_id, "superseded", "admin")
    assert service.protected_report_evidence_ids(db) == set()


def test_unknown_evidence_and_invalid_transition_are_rejected(db, tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown evidence"):
        service.register_report(
            db, report_type="pdf", framework="pci_dss", actor="admin",
            content=b"pdf", extension="pdf", evidence_ids=["EV-MISSING"],
        )
    add_evidence(db, tmp_path)
    report = service.register_report(
        db, report_type="pdf", framework="pci_dss", actor="admin",
        content=b"pdf", extension="pdf", evidence_ids=["EV-REPORT"],
    )
    service.update_status(db, report.report_id, "revoked", "admin")
    with pytest.raises(ValueError, match="cannot transition"):
        service.update_status(db, report.report_id, "current", "admin")


def test_report_record_routes_registered():
    paths = {route.path for route in report_records.router.routes}
    assert "/api/report-records" in paths
    assert "/api/report-records/{report_id}" in paths
    assert "/api/report-records/{report_id}/status" in paths
