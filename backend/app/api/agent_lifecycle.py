from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from pathlib import Path
from datetime import datetime, timezone
import json
import os

from app.core.database import get_db
from app.models import Asset, CollectorRun

router = APIRouter(prefix="/api/agent-lifecycle", tags=["agent-lifecycle"])

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/var/lib/ai-vulnerability-management/evidence"))
CHANGELOG = Path(os.environ.get("CHANGELOG_FILE", "/app/evidence/changelog.jsonl"))
AGENT_STALE_SECONDS = max(
    1,
    int(os.environ.get("AGENT_STALE_SECONDS", "900")),
)
AGENT_OFFLINE_SECONDS = max(
    AGENT_STALE_SECONDS,
    int(os.environ.get("AGENT_OFFLINE_SECONDS", "3600")),
)


def _read_json(path):
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return {}


def _unwrap(data):
    if not isinstance(data, dict):
        return {}

    stdout = data.get("stdout")
    if isinstance(stdout, str) and stdout.strip():
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return data


def _latest_payload(asset_id, collector):
    cdir = EVIDENCE_ROOT / asset_id / collector
    if not cdir.exists():
        return {}

    candidates = []
    for path in cdir.glob("*.json"):
        try:
            candidates.append((path.stat().st_mtime_ns, path))
        except OSError:
            continue

    for _, path in sorted(candidates, reverse=True):
        data = _read_json(path)
        if data.get("collector") != collector:
            continue
        if data.get("status") and data.get("status") != "completed":
            continue
        return _unwrap(data)
    return {}


def _as_utc_datetime(value):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _newest_datetime(*values):
    parsed = [value for value in map(_as_utc_datetime, values) if value]
    return max(parsed) if parsed else None


def _heartbeat_status(last_seen, now):
    if last_seen is None:
        return "never_seen"
    age_seconds = max(0, (now - last_seen).total_seconds())
    if age_seconds <= AGENT_STALE_SECONDS:
        return "online"
    if age_seconds <= AGENT_OFFLINE_SECONDS:
        return "stale"
    return "offline"


@router.get("/")
def lifecycle(db: Session = Depends(get_db)):
    rows = []
    now = datetime.now(timezone.utc)

    assets = (
        db.query(Asset)
        .filter(Asset.agent_status.contains("deployed"))
        .order_by(Asset.asset_id.asc())
        .all()
    )
    latest_successful_contacts = dict(
        db.query(
            CollectorRun.asset_id,
            func.max(CollectorRun.created_at),
        )
        .filter(CollectorRun.status == "completed")
        .group_by(CollectorRun.asset_id)
        .all()
    )

    for asset in assets:
        asset_id = asset.asset_id

        lifecycle = _latest_payload(asset_id, "agent_lifecycle")
        health = _latest_payload(asset_id, "collector_health")
        last_seen = _newest_datetime(
            asset.last_seen,
            latest_successful_contacts.get(asset_id),
            lifecycle.get("collected_at"),
        )
        last_seen_source = (
            "agent_contact"
            if _as_utc_datetime(asset.last_seen) == last_seen
            else "successful_collection"
            if _as_utc_datetime(latest_successful_contacts.get(asset_id))
            == last_seen
            else "lifecycle_evidence"
            if last_seen
            else None
        )

        rows.append({
            "asset_id": asset_id,
            "hostname": asset.hostname or asset_id,
            "address": asset.address,
            "agent_status": asset.agent_status,
            "agent_version": lifecycle.get("agent_version", "Unknown"),
            "expected_agent_version": lifecycle.get("expected_agent_version", "Unknown"),
            "agent_current": lifecycle.get("agent_current", False),
            "collector_manifest_version": lifecycle.get("collector_manifest_version"),
            "manifest_present": lifecycle.get("manifest_present", False),
            "collector_drift_detected": health.get("drift_detected", None),
            "last_seen": last_seen.isoformat() if last_seen else None,
            "last_seen_source": last_seen_source,
            "heartbeat_status": _heartbeat_status(last_seen, now),
        })

    return {"assets": rows}


@router.get("/changelog")
def changelog(limit: int = 100):
    if not CHANGELOG.exists():
        return {"events": []}

    events = []
    for line in CHANGELOG.read_text(errors="ignore").splitlines():
        try:
            events.append(json.loads(line))
        except Exception:
            continue

    return {"events": events[-limit:]}
