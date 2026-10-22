"""Phase 4D-5: requirements lifecycle integration preservation regressions.

Uses only temporary filesystem storage and an in-memory SQLite database.
"""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.api import reports
from app.core.database import Base
from app.models.models import Assessment, AssessmentEvidence, Evidence, GeneratedReport, GeneratedReportEvidence
from app.services import requirements_lifecycle as lifecycle
from app.services import requirements_registry as registry
from app.services import assessment_evidence, generated_reports
from app.core.config import settings


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    root = tmp_path / "requirements"
    monkeypatch.setattr(registry, "ROOT", root)
    monkeypatch.setattr(settings, "evidence_root", str(tmp_path / "evidence-root"))
    monkeypatch.setattr(assessment_evidence, "write_changelog", lambda *a, **k: None)
    monkeypatch.setattr(generated_reports, "write_changelog", lambda *a, **k: None)
    try:
        yield db, root, tmp_path
    finally:
        db.close()
        engine.dispose()


def stage(root, version):
    return registry.stage_version(
        "pci_dss", version,
        [{"id": "R-1", "title": f"Requirement {version}"}],
        {"publisher": "Phase 4D-5 integration test"},
        "test-admin", root=root,
    )


def advance(root, version, action):
    return lifecycle.transition("pci_dss", version, action, "test-admin", "integration regression", root)


def seed_records(db, tmp_path):
    source = tmp_path / "original-evidence.json"
    source.write_bytes(b'{"historical":true}\n')
    db.add(Evidence(
        evidence_id="EV-INTEGRATION", asset_id="asset-test", control_id="AC-02",
        framework="pci_dss", filename=source.name, file_path=str(source),
        source="test", collector="iam_users", evidence_type="iam_users", validated=True,
    ))
    db.commit()
    assessment = assessment_evidence.create_assessment(
        db, name="Historical PCI assessment", owner="Compliance", actor="test-admin",
        framework="pci_dss",
    )
    assessment_evidence.link_evidence(db, assessment.assessment_id, "EV-INTEGRATION", "test-admin")
    report = generated_reports.register_report(
        db, report_type="pdf", framework="pci_dss", actor="test-admin",
        content=b"historical report bytes", extension="pdf", evidence_ids=["EV-INTEGRATION"],
    )
    return assessment.assessment_id, report.report_id, source


def snapshot(db, assessment_id, report_id, source):
    db.expire_all()
    assessment = db.query(Assessment).filter_by(assessment_id=assessment_id).one()
    report = db.query(GeneratedReport).filter_by(report_id=report_id).one()
    evidence = db.query(Evidence).filter_by(evidence_id="EV-INTEGRATION").one()
    links = db.query(AssessmentEvidence).filter_by(assessment_id=assessment_id).all()
    report_links = db.query(GeneratedReportEvidence).filter_by(report_id=report_id).all()
    return {
        "assessment": (assessment.assessment_id, assessment.framework, assessment.status,
                       assessment.name, assessment.owner, assessment.updated_at),
        "evidence": (evidence.evidence_id, evidence.control_id, evidence.framework,
                     evidence.validated, evidence.file_path, hashlib.sha256(source.read_bytes()).hexdigest()),
        "assessment_links": sorted((x.assessment_id, x.evidence_id, x.rationale) for x in links),
        "report": (report.report_id, report.framework, report.status, report.sha256,
                   report.file_path, report.size_bytes,
                   hashlib.sha256(open(report.file_path, "rb").read()).hexdigest()),
        "report_links": sorted((x.report_id, x.evidence_id) for x in report_links),
        "active_protection": assessment_evidence.active_assessment_evidence_ids(db),
        "report_protection": generated_reports.protected_report_evidence_ids(db),
    }


def test_publish_and_rollback_preserve_assessment_evidence_and_reports(isolated):
    db, root, tmp_path = isolated
    assessment_id, report_id, source = seed_records(db, tmp_path)
    before = snapshot(db, assessment_id, report_id, source)
    assert before["active_protection"] == {"EV-INTEGRATION"}
    assert before["report_protection"] == {"EV-INTEGRATION"}
    for version in ("v1", "v2"):
        stage(root, version)
        assert snapshot(db, assessment_id, report_id, source) == before
        advance(root, version, "approve")
        assert snapshot(db, assessment_id, report_id, source) == before
        advance(root, version, "publish")
        assert lifecycle.lifecycle_status("pci_dss", root)["published_version"] == version
        assert snapshot(db, assessment_id, report_id, source) == before
    advance(root, "v1", "rollback")
    assert lifecycle.lifecycle_status("pci_dss", root)["published_version"] == "v1"
    assert snapshot(db, assessment_id, report_id, source) == before
    assert lifecycle.audit_gaps("pci_dss", root) == []
    assert len(registry.list_versions("pci_dss", root)) == 2
    assert len((root / "lifecycle.jsonl").read_text().splitlines()) == 5
    assert len((root / "audit.jsonl").read_text().splitlines()) == 2


def test_reporting_scores_and_mappings_unchanged_by_lifecycle(isolated, monkeypatch):
    _, root, _ = isolated
    controls = [{"control_id": "AC-02", "title": "Access Control", "framework_mappings": {"pci_dss": ["8.2"]}}]
    monkeypatch.setattr(reports, "list_controls", lambda: controls)
    monkeypatch.setattr(reports, "load_json", lambda path: [])
    monkeypatch.setattr(reports, "get_db_rows", lambda model: [
        {"evidence_id": "EV-1", "asset_id": "asset-1", "collector": "iam_users",
         "control_id": "AC-02", "validated": True, "created_at": "2026-01-01T00:00:00Z"}
    ] if model == "Evidence" else [])
    before = reports.build_requirement_rows("pci_dss")
    assert len(before) == 1
    assert before[0]["score"] == 100
    for version in ("v1", "v2"):
        stage(root, version)
        advance(root, version, "approve")
        advance(root, version, "publish")
        assert reports.build_requirement_rows("pci_dss") == before
    advance(root, "v1", "rollback")
    assert reports.build_requirement_rows("pci_dss") == before


def test_framework_availability_independent_of_publication(isolated, monkeypatch):
    _, root, _ = isolated
    from app.services import framework_registry
    path = root.parent / "frameworks.json"
    assert framework_registry.is_enabled("pci_dss", path)
    stage(root, "v1")
    advance(root, "v1", "approve")
    advance(root, "v1", "publish")
    assert framework_registry.is_enabled("pci_dss", path)
    assert not path.exists()
    assert lifecycle.lifecycle_status("pci_dss", root)["published_version"] == "v1"


def test_rejected_lifecycle_operation_preserves_existing_records(isolated):
    db, root, tmp_path = isolated
    assessment_id, report_id, source = seed_records(db, tmp_path)
    before = snapshot(db, assessment_id, report_id, source)
    stage(root, "v1")
    with pytest.raises(ValueError):
        advance(root, "v1", "publish")
    assert lifecycle.lifecycle_status("pci_dss", root)["published_version"] is None
    assert snapshot(db, assessment_id, report_id, source) == before
