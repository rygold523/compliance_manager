from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.models import Base, CollectorRun, Evidence
from app.services.change_aware_evidence import evidence_hash, record_collection


def _session(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_root", str(tmp_path))
    monkeypatch.setattr(settings, "evidence_forced_snapshot_hours", 168)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _record(db, now, value, force=False):
    return record_collection(
        db,
        asset_id="asset-01",
        collector="os_inventory",
        output={"status": "completed", "collected_at": now.isoformat(), "value": value},
        source="collector",
        control_id="AM-01",
        frameworks={},
        validated=True,
        description="test",
        force_snapshot=force,
        now=now,
    )


def test_volatile_collection_time_does_not_change_hash():
    assert evidence_hash({"value": 1, "collected_at": "a"}) == evidence_hash(
        {"value": 1, "collected_at": "b"}
    )


def test_nested_raw_collection_time_does_not_change_hash():
    first = {
        "status": "completed",
        "raw": {
            "collected_at": "first",
            "users": [{"name": "example", "created_at": "preserved"}],
        },
    }
    second = {
        "status": "completed",
        "raw": {
            "collected_at": "second",
            "users": [{"name": "example", "created_at": "preserved"}],
        },
    }
    assert evidence_hash(first) == evidence_hash(second)


def test_observed_event_timestamps_remain_significant():
    first = {"status": "completed", "events": [{"timestamp": "first"}]}
    second = {"status": "completed", "events": [{"timestamp": "second"}]}
    assert evidence_hash(first) != evidence_hash(second)


def test_unchanged_run_reuses_evidence_and_stores_small_run(tmp_path, monkeypatch):
    db = _session(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    first = _record(db, now, "same")
    db.commit()
    second = _record(db, now + timedelta(minutes=15), "same")
    db.commit()

    assert first.evidence_created is True
    assert second.evidence_created is False
    assert second.evidence_id == first.evidence_id
    assert db.query(Evidence).count() == 1
    assert db.query(CollectorRun).count() == 2
    latest_run = db.query(CollectorRun).order_by(CollectorRun.id.desc()).first()
    assert latest_run.output["unchanged"] is True


def test_changed_and_periodic_snapshots_create_evidence(tmp_path, monkeypatch):
    db = _session(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    _record(db, now, "one")
    db.commit()
    changed = _record(db, now + timedelta(minutes=15), "two")
    db.commit()
    checkpoint = _record(db, now + timedelta(hours=169), "two")
    db.commit()

    assert changed.reason == "state_changed"
    assert checkpoint.reason == "periodic_checkpoint"
    assert db.query(Evidence).count() == 3
