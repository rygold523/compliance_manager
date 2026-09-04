import json
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import iam
from app.core.database import Base
from app.models import Evidence


def _write_evidence(path, collected_at, username):
    path.write_text(
        json.dumps(
            {
                "collector": "iam_users",
                "status": "completed",
                "collected_at": collected_at,
                "stdout": json.dumps(
                    {
                        "hostname": "host-a",
                        "collected_at": collected_at,
                        "users": [
                            {
                                "username": username,
                                "uid": 1000,
                                "home": f"/home/{username}",
                                "access": ["ssh"],
                                "groups": ["users"],
                            }
                        ],
                        "service_accounts": [],
                    }
                ),
            }
        )
    )


def _reset_cache():
    iam._CACHE.update(
        {
            "checked_at": 0.0,
            "state": None,
            "snapshot": None,
        }
    )


def test_snapshot_uses_latest_evidence_and_all_views_share_cache(
    tmp_path,
    monkeypatch,
):
    evidence_dir = tmp_path / "asset-a" / "iam_users"
    evidence_dir.mkdir(parents=True)
    old_path = evidence_dir / "old.json"
    new_path = evidence_dir / "new.json"
    _write_evidence(old_path, "2026-01-01T00:00:00+00:00", "old-user")
    time.sleep(0.01)
    _write_evidence(new_path, "2026-09-03T12:00:00+00:00", "new-user")

    monkeypatch.setattr(iam, "EVIDENCE_ROOT", tmp_path)
    monkeypatch.setattr(iam, "IAM_CACHE_TTL_SECONDS", 60.0)
    _reset_cache()

    calls = 0
    original_read_json = iam._read_json

    def counted_read_json(path):
        nonlocal calls
        calls += 1
        return original_read_json(path)

    monkeypatch.setattr(iam, "_read_json", counted_read_json)

    first = iam._get_snapshot()
    assert [row["username"] for row in first["users"]] == ["new-user"]
    assert first["access_matrix"]["rows"][0]["asset-a"] == "ssh"
    assert calls == 1

    iam._get_snapshot()
    iam._get_snapshot()
    iam._get_snapshot()
    iam._get_snapshot()
    iam._get_snapshot()
    assert calls == 1


def test_snapshot_refreshes_when_new_evidence_arrives(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "asset-a" / "iam_users"
    evidence_dir.mkdir(parents=True)
    _write_evidence(
        evidence_dir / "first.json",
        "2026-09-03T12:00:00+00:00",
        "first-user",
    )

    monkeypatch.setattr(iam, "EVIDENCE_ROOT", tmp_path)
    monkeypatch.setattr(iam, "IAM_CACHE_TTL_SECONDS", 0.0)
    _reset_cache()

    assert iam._get_snapshot()["users"][0]["username"] == "first-user"
    time.sleep(0.01)
    _write_evidence(
        evidence_dir / "second.json",
        "2026-09-03T12:01:00+00:00",
        "second-user",
    )
    assert iam._get_snapshot()["users"][0]["username"] == "second-user"


def test_database_snapshot_uses_latest_evidence_without_tree_scan(
    tmp_path,
    monkeypatch,
):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    evidence_dir = tmp_path / "asset-a" / "iam_users"
    evidence_dir.mkdir(parents=True)
    old_path = evidence_dir / "old.json"
    new_path = evidence_dir / "new.json"
    _write_evidence(old_path, "2026-01-01T00:00:00+00:00", "old-user")
    _write_evidence(new_path, "2026-09-03T12:00:00+00:00", "new-user")

    session.add_all(
        [
            Evidence(
                evidence_id="EV-OLD",
                asset_id="asset-a",
                filename=old_path.name,
                file_path=str(old_path),
                source="collector",
                collector="iam_users",
                validated=True,
            ),
            Evidence(
                evidence_id="EV-NEW",
                asset_id="asset-a",
                filename=new_path.name,
                file_path=str(new_path),
                source="collector",
                collector="iam_users",
                validated=True,
            ),
        ]
    )
    session.commit()

    monkeypatch.setattr(
        iam,
        "_iam_directories",
        lambda: (_ for _ in ()).throw(
            AssertionError("filesystem scan should not run")
        ),
    )
    _reset_cache()
    iam._CACHE["database_state"] = None

    result = iam._get_snapshot(session)
    assert [row["username"] for row in result["users"]] == ["new-user"]
