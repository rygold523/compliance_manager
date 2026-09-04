from datetime import datetime, timedelta, timezone

from app.api import agent_lifecycle


def test_newest_datetime_accepts_database_and_iso_values():
    older = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
    newer = "2026-09-03T12:05:00Z"

    assert agent_lifecycle._newest_datetime(older, newer) == datetime(
        2026,
        9,
        3,
        12,
        5,
        tzinfo=timezone.utc,
    )


def test_heartbeat_status_uses_configured_age_thresholds(monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(agent_lifecycle, "AGENT_STALE_SECONDS", 60)
    monkeypatch.setattr(agent_lifecycle, "AGENT_OFFLINE_SECONDS", 300)

    assert agent_lifecycle._heartbeat_status(now, now) == "online"
    assert (
        agent_lifecycle._heartbeat_status(
            now - timedelta(seconds=120),
            now,
        )
        == "stale"
    )
    assert (
        agent_lifecycle._heartbeat_status(
            now - timedelta(seconds=600),
            now,
        )
        == "offline"
    )
    assert agent_lifecycle._heartbeat_status(None, now) == "never_seen"
