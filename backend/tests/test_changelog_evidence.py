import csv
import io
from types import SimpleNamespace
from datetime import datetime, timezone

from app.api import changelog
from app.api import admin_users
from app.auth.service import audit
from app.services.control_catalog_v2 import CONTROL_CATALOG


def test_access_change_mapping():
    event_types = (
        "server_user_added",
        "server_user_removed",
        "server_group_added",
        "db_user_added",
        "db_user_removed",
        "db_role_added",
        "db_role_removed",
        "dashboard_user_created",
        "dashboard_user_role_changed",
        "dashboard_user_enabled",
        "dashboard_user_disabled",
        "dashboard_user_profile_updated",
        "dashboard_user_password_reset",
        "dashboard_user_unlocked",
        "dashboard_user_sessions_revoked",
        "dashboard_user_session_revoked",
    )

    for event_type in event_types:
        result = changelog._event_evidence_definition({
            "event_type": event_type,
        })

        assert result is not None
        assert result["control_id"] == "AC-02"
        assert (
            result["collector"]
            == "changelog_access_management"
        )


def test_asset_change_mapping():
    event_types = (
        "agent_deployed",
        "agent_upgraded",
        "agent_removed",
        "asset_added",
        "asset_updated",
        "asset_removed",
    )

    for event_type in event_types:
        result = changelog._event_evidence_definition({
            "event_type": event_type,
        })

        assert result is not None
        assert result["control_id"] == "AM-01"
        assert (
            result["collector"]
            == "changelog_asset_inventory"
        )


def test_unrelated_event_is_ignored():
    result = changelog._event_evidence_definition({
        "event_type": "collector_state_changed",
    })

    assert result is None


def test_catalog_mappings():
    access_collectors = CONTROL_CATALOG[
        "AC-02"
    ]["supporting_collectors"]

    asset_collectors = CONTROL_CATALOG[
        "AM-01"
    ]["supporting_collectors"]

    assert (
        "changelog_access_management"
        in access_collectors
    )
    assert (
        "changelog_asset_inventory"
        in asset_collectors
    )


def test_evidence_id_is_deterministic():
    event = {
        "event_id": "event-123",
        "event_type": "server_user_added",
    }

    first = changelog._event_evidence_id(
        event,
        "AC-02",
    )
    second = changelog._event_evidence_id(
        event,
        "AC-02",
    )

    assert first == second
    assert first.startswith("EV-CHG-")


def test_user_group_csv_export(monkeypatch):
    events = [
        {
            "event_id": "access-1",
            "timestamp": "2026-09-10T12:00:00Z",
            "event_type": "server_user_added",
            "asset_id": "server-01",
            "summary": "=unsafe summary",
            "details": {
                "username": "+formula",
                "group_name": "sudo",
                "source": "iam_users",
            },
        },
        {
            "event_id": "asset-1",
            "timestamp": "2026-09-10T12:01:00Z",
            "event_type": "agent_deployed",
            "asset_id": "server-02",
            "summary": "Agent deployed",
            "details": {},
        },
    ]

    notes = {
        "access-1": {
            "note": "@unsafe note",
            "jira_url": (
                "https://jira.example/browse/SEC-1"
            ),
        },
    }

    monkeypatch.setattr(
        changelog,
        "_read_events",
        lambda: events,
    )
    monkeypatch.setattr(
        changelog,
        "_read_notes",
        lambda: notes,
    )

    response = changelog.export_user_group_changes()

    assert (
        response.headers["x-exported-event-count"]
        == "1"
    )

    rows = list(
        csv.DictReader(
            io.StringIO(
                response.body.decode("utf-8")
            )
        )
    )

    assert len(rows) == 1
    assert rows[0]["event_id"] == "access-1"
    assert rows[0]["username"] == "'+formula"
    assert rows[0]["summary"] == "'=unsafe summary"
    assert rows[0]["note"] == "'@unsafe note"


def test_export_and_sync_routes_registered():
    paths = {
        route.path
        for route in changelog.router.routes
    }

    assert (
        "/api/changelog/user-group-export"
        in paths
    )
    assert (
        "/api/changelog/evidence/sync"
        in paths
    )
    assert "/api/changelog/integrity" in paths
    assert "/api/changelog/integrity/reconcile" in paths


def test_stable_changelog_event_id_is_deterministic_and_projection_specific():
    role_change = changelog.stable_changelog_event_id(
        "AUD-123",
        "dashboard_user_role_changed",
    )
    assert role_change == changelog.stable_changelog_event_id(
        "AUD-123",
        "dashboard_user_role_changed",
    )
    assert role_change != changelog.stable_changelog_event_id(
        "AUD-123",
        "dashboard_user_disabled",
    )


def test_auth_audit_assigns_stable_id_to_authoritative_record():
    class FakeDb:
        def __init__(self):
            self.added = []

        def add(self, value):
            self.added.append(value)

    db = FakeDb()
    audit_event_id = audit(
        db,
        "user_unlocked",
        username="auditor",
        user_id=9,
        detail={"actor_username": "dashboard.admin"},
    )

    assert audit_event_id.startswith("AUD-")
    assert db.added[0].detail["audit_event_id"] == audit_event_id


def test_user_update_auth_event_creates_each_expected_projection():
    event = SimpleNamespace(
        event_type="user_updated",
        username="auditor",
        user_id=9,
        source_address="192.0.2.10",
        created_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
        detail={
            "audit_event_id": "AUD-update-1",
            "actor_user_id": 1,
            "actor_username": "dashboard.admin",
            "before": {
                "display_name": "Old Name",
                "role": "auditor",
                "enabled": True,
            },
            "after": {
                "display_name": "New Name",
                "role": "viewer",
                "enabled": False,
            },
            "revoked_sessions": 2,
        },
    )

    projections = changelog._auth_event_projections(event)
    assert {item["event_type"] for item in projections} == {
        "dashboard_user_role_changed",
        "dashboard_user_disabled",
        "dashboard_user_profile_updated",
    }
    assert len({item["event_id"] for item in projections}) == 3
    assert all(
        item["details"]["audit_event_id"] == "AUD-update-1"
        for item in projections
    )


def test_write_changelog_is_idempotent_for_stable_event_id(monkeypatch, tmp_path):
    changelog_file = tmp_path / "changelog.jsonl"
    monkeypatch.setattr(changelog, "CHANGELOG_FILE", changelog_file)
    monkeypatch.setattr(changelog, "_persist_event_evidence", lambda event: False)

    arguments = {
        "event_id": "EVT-AUD-stable",
        "event_type": "dashboard_user_unlocked",
        "asset_id": "compliance-dashboard",
        "summary": "Dashboard user auditor was unlocked.",
        "details": {"audit_event_id": "AUD-unlock-1"},
    }
    first = changelog.write_changelog(**arguments)
    second = changelog.write_changelog(**arguments)

    assert first["event_id"] == second["event_id"]
    assert len(changelog_file.read_text(encoding="utf-8").splitlines()) == 1


def test_reconciliation_writes_only_missing_projections(monkeypatch):
    missing = {
        "event_id": "EVT-AUD-missing",
        "timestamp": "2026-09-11T12:00:00+00:00",
        "event_type": "dashboard_user_unlocked",
        "asset_id": "compliance-dashboard",
        "summary": "Dashboard user auditor was unlocked.",
        "details": {"audit_event_id": "AUD-missing"},
    }
    snapshots = iter([
        {"status": "degraded", "missing": [missing]},
        {"status": "healthy", "missing": [], "duplicate_event_ids": []},
    ])
    written = []

    monkeypatch.setattr(changelog, "_integrity_snapshot", lambda db: next(snapshots))
    monkeypatch.setattr(changelog, "write_changelog", lambda **kwargs: written.append(kwargs))

    result = changelog.reconcile_integrity(object())
    assert result["created"] == 1
    assert result["status"] == "healthy"
    assert written == [missing]


def test_dashboard_user_changelog_is_sanitized(monkeypatch):
    captured = {}

    def capture_event(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(
        admin_users,
        "write_changelog",
        capture_event,
    )

    admin_users.write_user_changelog(
        "dashboard_user_password_reset",
        user=SimpleNamespace(
            id=9,
            username="auditor",
        ),
        admin=SimpleNamespace(
            id=1,
            username="dashboard.admin",
        ),
        summary="Dashboard user auditor password was reset.",
        source="192.0.2.10",
        audit_event_id="AUD-reset-1",
        details={
            "new_password": "must-not-appear",
            "password_hash": "must-not-appear",
            "must_change_password": True,
            "revoked_sessions": 2,
        },
    )

    assert captured["event_type"] == "dashboard_user_password_reset"
    assert captured["asset_id"] == "compliance-dashboard"
    assert captured["details"]["username"] == "auditor"
    assert captured["details"]["actor_username"] == "dashboard.admin"
    assert captured["details"]["must_change_password"] is True
    assert captured["details"]["revoked_sessions"] == 2
    assert captured["details"]["audit_event_id"] == "AUD-reset-1"
    assert captured["event_id"] == admin_users.stable_changelog_event_id(
        "AUD-reset-1",
        "dashboard_user_password_reset",
    )
    assert "new_password" not in captured["details"]
    assert "password_hash" not in captured["details"]
