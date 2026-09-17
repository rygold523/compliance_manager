import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import Base, Evidence
from app.services.change_aware_evidence import evidence_hash
from app.services.evidence_compaction_preview import preview_compaction


def test_compaction_is_preview_only_and_protects_latest(tmp_path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    now = datetime.now(timezone.utc)
    payload = {"status": "completed", "value": "same"}
    digest = evidence_hash(payload)
    for index in range(3):
        evidence_id = f"EV-{index}"
        path = tmp_path / f"{evidence_id}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        db.add(Evidence(
            evidence_id=evidence_id,
            asset_id="asset-01",
            collector="os_inventory",
            filename=path.name,
            file_path=str(path),
            source="collector",
            baseline_hash=digest,
            created_at=now + timedelta(minutes=index),
        ))
    db.commit()

    result = preview_compaction(db)

    assert result["mode"] == "preview_only"
    assert result["deletion_performed"] is False
    assert result["duplicate_candidates"] == 1
    assert result["candidates"][0]["evidence_id"] == "EV-1"
    assert db.query(Evidence).count() == 3
