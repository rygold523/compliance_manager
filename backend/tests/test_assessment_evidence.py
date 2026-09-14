import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api import assessments as api
from app.core.database import Base
from app.models.models import AssessmentEvidence, AuthAuditEvent, Evidence
from app.services import assessment_evidence as service
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


def add_evidence(db, tmp_path, evidence_id="EV-ASSESSMENT"):
    path = tmp_path / "assessment.json"
    path.write_text('{"assessment": true}\n', encoding="utf-8")
    row = Evidence(
        evidence_id=evidence_id, asset_id="asset-1", control_id="AC-02",
        framework="pci_dss", filename=path.name, file_path=str(path), source="test",
        collector="iam_users", evidence_type="iam_users", validated=True,
        created_at=NOW - timedelta(days=500),
    )
    db.add(row)
    db.commit()
    return row


def configure(monkeypatch, tmp_path):
    access_file = tmp_path / "access_reviews.json"
    access_file.write_text('{"campaigns": []}\n', encoding="utf-8")
    monkeypatch.setattr(service, "write_changelog", lambda *args, **kwargs: None)
    monkeypatch.setattr(preview, "_read_events", lambda: [])
    monkeypatch.setattr(preview, "_read_notes", lambda: {})
    return access_file


def test_assessment_lifecycle_link_and_audit(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path)
    configure(monkeypatch, tmp_path)
    assessment = service.create_assessment(
        db, name="2026 PCI DSS", owner="Compliance", actor="dashboard.admin",
        framework="pci_dss",
    )
    link = service.link_evidence(
        db, assessment.assessment_id, "EV-ASSESSMENT", "dashboard.admin", "Control sample",
    )
    assert link.evidence_id == "EV-ASSESSMENT"
    assert service.active_assessment_evidence_ids(db) == {"EV-ASSESSMENT"}
    assert db.query(AuthAuditEvent).filter_by(event_type="assessment_created").count() == 1
    assert db.query(AuthAuditEvent).filter_by(event_type="assessment_evidence_linked").count() == 1
    service.update_status(db, assessment.assessment_id, "in_progress", "dashboard.admin")
    service.update_status(db, assessment.assessment_id, "completed", "dashboard.admin")
    assert service.active_assessment_evidence_ids(db) == set()


def test_active_assessment_protects_old_evidence(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path)
    access_file = configure(monkeypatch, tmp_path)
    assessment = service.create_assessment(
        db, name="SOC 2", owner="Compliance", actor="dashboard.admin", framework="soc2",
    )
    service.link_evidence(db, assessment.assessment_id, "EV-ASSESSMENT", "dashboard.admin")
    result = preview.build_preview(db, PreviewPolicy(), tmp_path, access_file, now=NOW)
    protected = result["protected"]["evidence"][0]
    assert "active_assessment" in protected["protection_reasons"]
    assert "assessment-to-evidence" not in " ".join(result["dependency_check_limitations"])


def test_relationship_is_unique_and_unlink_is_audited(db, tmp_path, monkeypatch):
    add_evidence(db, tmp_path)
    configure(monkeypatch, tmp_path)
    assessment = service.create_assessment(
        db, name="Review", owner="Compliance", actor="dashboard.admin",
    )
    first = service.link_evidence(db, assessment.assessment_id, "EV-ASSESSMENT", "dashboard.admin")
    second = service.link_evidence(db, assessment.assessment_id, "EV-ASSESSMENT", "dashboard.admin")
    assert first.id == second.id
    assert db.query(AssessmentEvidence).count() == 1
    service.unlink_evidence(db, assessment.assessment_id, "EV-ASSESSMENT", "dashboard.admin")
    assert db.query(AssessmentEvidence).count() == 0
    assert db.query(AuthAuditEvent).filter_by(event_type="assessment_evidence_unlinked").count() == 1


def test_invalid_status_transition_is_rejected(db, monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    assessment = service.create_assessment(
        db, name="Review", owner="Compliance", actor="dashboard.admin",
    )
    with pytest.raises(ValueError, match="cannot transition"):
        service.update_status(db, assessment.assessment_id, "closed", "dashboard.admin")


def test_routes_and_role_boundaries_are_registered():
    paths = {route.path for route in api.router.routes}
    assert "/api/assessments" in paths
    assert "/api/assessments/{assessment_id}" in paths
    assert "/api/assessments/{assessment_id}/status" in paths
    assert "/api/assessments/{assessment_id}/evidence" in paths
    assert "/api/assessments/{assessment_id}/evidence/{evidence_id}" in paths
