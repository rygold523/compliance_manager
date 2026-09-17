"""Change-aware persistence for collector output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import CollectorRun, Evidence
from app.services.path_security import contained_path


VOLATILE_TOP_LEVEL_FIELDS = {
    "collected_at", "collection_started_at", "collection_finished_at", "duration_ms",
}


@dataclass(frozen=True)
class CollectionPersistenceResult:
    run_id: str
    evidence_id: str | None
    evidence_created: bool
    change_detected: bool
    reason: str
    baseline_hash: str


def _remove_execution_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _remove_execution_metadata(item)
            for key, item in value.items()
            if key not in VOLATILE_TOP_LEVEL_FIELDS
        }
    if isinstance(value, list):
        return [_remove_execution_metadata(item) for item in value]
    return value


def normalized_output(output: dict[str, Any]) -> dict[str, Any]:
    """Remove execution metadata without removing observed event timestamps."""
    normalized = _remove_execution_metadata(output)
    stdout = normalized.get("stdout")
    if isinstance(stdout, str):
        try:
            decoded = json.loads(stdout)
        except ValueError:
            decoded = None
        if isinstance(decoded, dict):
            normalized["stdout"] = _remove_execution_metadata(decoded)
    if str(normalized.get("status", "")).lower() == "completed":
        normalized.pop("stderr", None)
    return normalized


def evidence_hash(output: dict[str, Any]) -> str:
    canonical = json.dumps(
        normalized_output(output), sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _advisory_lock(db: Session, asset_id: str, collector: str) -> None:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    digest = hashlib.sha256(f"{asset_id}\0{collector}".encode()).digest()
    lock_key = int.from_bytes(digest[:8], "big", signed=True)
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})


def _latest_evidence(db: Session, asset_id: str, collector: str) -> Evidence | None:
    return (
        db.query(Evidence)
        .filter(Evidence.asset_id == asset_id, Evidence.collector == collector)
        .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        .first()
    )


def _hash_from_record(record: Evidence | None) -> str | None:
    if record is None:
        return None
    if record.baseline_hash:
        return record.baseline_hash
    try:
        payload = json.loads(Path(record.file_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return evidence_hash(payload) if isinstance(payload, dict) else None


def _checkpoint_due(record: Evidence | None, now: datetime) -> bool:
    if record is None or record.created_at is None:
        return False
    created_at = record.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    hours = max(1, int(settings.evidence_forced_snapshot_hours))
    return now - created_at >= timedelta(hours=hours)


def record_collection(
    db: Session,
    *,
    asset_id: str,
    collector: str,
    output: dict[str, Any],
    source: str,
    control_id: str | None,
    frameworks: dict[str, Any] | None,
    validated: bool,
    description: str,
    force_snapshot: bool = False,
    run_status: str | None = None,
    now: datetime | None = None,
) -> CollectionPersistenceResult:
    if not isinstance(output, dict):
        raise TypeError("Collector output must be a dictionary")

    now = now or datetime.now(timezone.utc)
    _advisory_lock(db, asset_id, collector)
    latest = _latest_evidence(db, asset_id, collector)
    current_hash = evidence_hash(output)
    previous_hash = _hash_from_record(latest)

    if latest is None:
        reason = "initial_snapshot"
    elif force_snapshot:
        reason = "forced_snapshot"
    elif previous_hash != current_hash:
        reason = "state_changed"
    elif _checkpoint_due(latest, now):
        reason = "periodic_checkpoint"
    else:
        reason = "unchanged"

    create_evidence = reason != "unchanged"
    run_id = f"COL-{uuid4().hex[:12].upper()}"
    evidence_id = latest.evidence_id if latest else None
    run_output = output if create_evidence else {
        "collector": collector,
        "asset_id": asset_id,
        "status": output.get("status", "unknown"),
        "unchanged": True,
        "baseline_hash": current_hash,
        "evidence_id": evidence_id,
    }

    db.add(CollectorRun(
        run_id=run_id, asset_id=asset_id, collector=collector,
        status=run_status or str(output.get("status", "unknown")), output=run_output,
    ))

    if create_evidence:
        evidence_id = f"EV-{uuid4().hex[:12].upper()}"
        evidence_dir = contained_path(settings.evidence_root, asset_id, collector)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / f"{evidence_id}.json"
        evidence_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        db.add(Evidence(
            evidence_id=evidence_id, asset_id=asset_id, control_id=control_id,
            filename=evidence_path.name, file_path=str(evidence_path), source=source,
            description=description, collector=collector, evidence_type=collector,
            frameworks=frameworks or {}, validated=validated, baseline_hash=current_hash,
        ))

    return CollectionPersistenceResult(
        run_id=run_id,
        evidence_id=evidence_id,
        evidence_created=create_evidence,
        change_detected=reason in {"initial_snapshot", "state_changed"},
        reason=reason,
        baseline_hash=current_hash,
    )
