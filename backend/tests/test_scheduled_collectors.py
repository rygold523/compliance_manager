from types import SimpleNamespace

import pytest

from app.cli import scheduled_collectors


class Query:
    def __init__(self, assets):
        self.assets = assets

    def order_by(self, _column):
        return self

    def all(self):
        return self.assets


class Database:
    def __init__(self, assets):
        self.assets = assets
        self.commits = 0

    def query(self, _model):
        return Query(self.assets)

    def commit(self):
        self.commits += 1


def asset(asset_id, status="deployed", os_family="linux"):
    return SimpleNamespace(
        asset_id=asset_id,
        agent_status=status,
        os_family=os_family,
        last_seen=None,
    )


def persistence(run_id, evidence_id, created, reason):
    return SimpleNamespace(
        run_id=run_id,
        evidence_id=evidence_id,
        evidence_created=created,
        change_detected=reason in {"initial_snapshot", "state_changed"},
        reason=reason,
    )


def test_default_schedule_contains_all_privileged_collectors():
    assert scheduled_collectors.DEFAULT_COLLECTORS == (
        "iam_users",
        "user_changes",
        "auth_success",
        "auth_failure",
        "sudo_activity",
        "os_inventory",
        "firewall_status",
        "ssh_config",
        "disk_usage",
        "docker_inventory",
        "listening_ports",
        "package_inventory",
        "agent_lifecycle",
        "collector_health",
    )


def test_scheduler_filters_assets_and_returns_compatible_results(monkeypatch):
    linux = asset("linux-01")
    db = Database([
        linux,
        asset("windows-01", os_family="windows"),
        asset("pending-01", status="pending"),
    ])

    monkeypatch.setattr(
        scheduled_collectors,
        "COLLECTORS",
        {"os_inventory": {}},
    )
    monkeypatch.setattr(
        scheduled_collectors,
        "run_collector",
        lambda _asset, collector: {
            "collector": collector,
            "status": "completed",
            "control_ids": ["AM-01"],
            "frameworks": {},
        },
    )
    monkeypatch.setattr(
        scheduled_collectors,
        "record_collection",
        lambda *_args, **_kwargs: persistence(
            "COL-1", "EV-1", False, "unchanged"
        ),
    )

    result = scheduled_collectors.run_scheduled_collections(
        db, ["os_inventory"]
    )

    assert result["asset_count"] == 1
    assert result["results"] == [{
        "asset_id": "linux-01",
        "results": [{
            "run_id": "COL-1",
            "evidence_id": "EV-1",
            "collector": "os_inventory",
            "status": "completed",
            "evidence_created": False,
            "change_detected": False,
            "change_reason": "unchanged",
        }],
    }]
    assert linux.last_seen is not None
    assert db.commits == 1


def test_collector_exception_is_persisted_and_does_not_abort(monkeypatch):
    db = Database([asset("linux-01")])
    monkeypatch.setattr(
        scheduled_collectors,
        "COLLECTORS",
        {"iam_users": {}, "os_inventory": {}},
    )

    def collect(_asset, collector):
        if collector == "iam_users":
            raise RuntimeError("expected test failure")
        return {"collector": collector, "status": "completed"}

    recorded = []

    def record(_db, **kwargs):
        recorded.append(kwargs)
        index = len(recorded)
        return persistence(
            f"COL-{index}", f"EV-{index}", True, "state_changed"
        )

    monkeypatch.setattr(scheduled_collectors, "run_collector", collect)
    monkeypatch.setattr(scheduled_collectors, "record_collection", record)

    result = scheduled_collectors.run_scheduled_collections(
        db, ["iam_users", "os_inventory"]
    )

    statuses = [
        item["status"] for item in result["results"][0]["results"]
    ]
    assert statuses == ["failed", "completed"]
    assert recorded[0]["output"]["stderr"] == "expected test failure"
    assert db.commits == 1


def test_unknown_collector_is_rejected_before_execution(monkeypatch):
    monkeypatch.setattr(
        scheduled_collectors,
        "COLLECTORS",
        {"os_inventory": {}},
    )

    with pytest.raises(ValueError, match="Unknown collectors: arbitrary_shell"):
        scheduled_collectors.run_scheduled_collections(
            Database([]), ["arbitrary_shell"]
        )
