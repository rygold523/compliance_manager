import inspect

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models import Evidence, Finding
from app.services import evidence_finding_analyzer as analyzer


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()


def evidence_record(evidence_id="EV-IDEMPOTENCY-01"):
    return Evidence(
        evidence_id=evidence_id,
        asset_id="asset-01",
        control_id="CM-01",
        filename=f"{evidence_id}.json",
        file_path=f"/tmp/{evidence_id}.json",
        source="collector",
        description="test evidence",
        collector="collector_health",
        evidence_type="collector_health",
        frameworks={},
        validated=False,
    )


def test_repeated_analysis_is_idempotent():
    db = session()
    db.add(evidence_record())
    db.commit()

    first = analyzer.analyze_all_evidence(db)
    second = analyzer.analyze_all_evidence(db)

    assert first["created_findings_count"] == 1
    assert second["created_findings_count"] == 0
    assert db.query(Finding).count() == 1


def test_pending_findings_are_deduplicated_before_commit():
    db = session()
    evidence = evidence_record()
    known_ids = set()

    first = analyzer.analyze_evidence_record(
        db,
        evidence,
        known_finding_ids=known_ids,
    )
    second = analyzer.analyze_evidence_record(
        db,
        evidence,
        known_finding_ids=known_ids,
    )

    db.commit()

    assert len(first) == 1
    assert second == []
    assert db.query(Finding).count() == 1


def test_postgresql_analysis_uses_transaction_advisory_lock():
    source = inspect.getsource(analyzer.analyze_all_evidence)

    assert "pg_advisory_xact_lock" in source
    assert "evidence-finding-analyzer" in source
