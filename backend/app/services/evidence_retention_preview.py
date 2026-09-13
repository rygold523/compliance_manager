import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.api.changelog import (
    CHANGELOG_FILE,
    CHANGELOG_NOTES_FILE,
    _file_lock,
    _read_events,
    _read_notes,
    write_changelog,
)
from app.auth.service import audit
from app.models.models import Approval, Evidence, Finding


PREVIEW_EVENT_TYPE = "changelog_evidence_retention_previewed"
ACTIVE_FINDING_STATUSES = frozenset({"open", "active", "investigating", "in_progress"})
ACTIVE_APPROVAL_STATUSES = frozenset({"pending", "review_required"})


@dataclass(frozen=True)
class PreviewPolicy:
    changelog_days: int = 400
    validated_evidence_days: int = 400
    unvalidated_evidence_days: int = 400

    def __post_init__(self):
        if min(
            self.changelog_days,
            self.validated_evidence_days,
            self.unvalidated_evidence_days,
        ) < 1:
            raise ValueError("All preview retention periods must be at least one day.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.astimezone(timezone.utc).isoformat() if aware else None


def _parse_timestamp(value) -> datetime | None:
    if isinstance(value, datetime):
        return _aware(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _aware(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
    except ValueError:
        return None


def _read_json(path: Path, *, required: bool) -> dict:
    if not path.exists():
        if required:
            raise ValueError(f"Required JSON file does not exist: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"JSON file is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return value


def load_legal_holds(path: Path | None) -> dict[str, set[str]]:
    keys = {
        "evidence_ids",
        "changelog_event_ids",
        "finding_ids",
        "asset_ids",
        "control_ids",
        "file_paths",
    }
    result = {key: set() for key in keys}
    if path is None:
        return result
    payload = _read_json(path, required=True)
    unknown = set(payload) - keys - {"description", "updated_at", "approved_by"}
    if unknown:
        raise ValueError(f"Legal-hold file contains unsupported keys: {sorted(unknown)}")
    for key in keys:
        values = payload.get(key, [])
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise ValueError(f"Legal-hold field {key} must be a list of strings.")
        result[key] = {item.strip() for item in values if item.strip()}
    return result


def _active_access_review_ids(path: Path) -> set[str]:
    payload = _read_json(path, required=False)
    campaigns = payload.get("campaigns", [])
    if not isinstance(campaigns, list):
        raise ValueError(f"Access-review file has an invalid campaigns value: {path}")
    return {
        str(item.get("campaign_id"))
        for item in campaigns
        if isinstance(item, dict)
        and item.get("campaign_id")
        and item.get("status") != "archived"
    }


def _logical_key(row: Evidence) -> tuple[str, str, str, str]:
    return (
        row.asset_id or "unknown",
        row.collector or row.evidence_type or row.source or "unknown",
        row.control_id or "unknown",
        row.framework or "unknown",
    )


def _current_evidence_ids(rows: list[Evidence]) -> set[int]:
    latest_all = {}
    latest_validated = {}
    for row in rows:
        key = _logical_key(row)
        rank = (_aware(row.created_at) or datetime.min.replace(tzinfo=timezone.utc), row.id)
        if key not in latest_all or rank > latest_all[key][0]:
            latest_all[key] = (rank, row.id)
        if row.validated and (key not in latest_validated or rank > latest_validated[key][0]):
            latest_validated[key] = (rank, row.id)
    return {value[1] for value in latest_all.values()} | {
        value[1] for value in latest_validated.values()
    }


def _file_metadata(path_text: str, evidence_root: Path) -> dict:
    path = Path(path_text)
    result = {
        "path": str(path),
        "exists": False,
        "is_file": False,
        "within_evidence_root": False,
        "size_bytes": None,
        "sha256": None,
        "error": None,
    }
    try:
        resolved = path.resolve(strict=False)
        root = evidence_root.resolve(strict=False)
        result["within_evidence_root"] = resolved == root or root in resolved.parents
        result["exists"] = resolved.exists()
        result["is_file"] = resolved.is_file()
        if result["is_file"]:
            result["size_bytes"] = resolved.stat().st_size
            digest = hashlib.sha256()
            with resolved.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            result["sha256"] = digest.hexdigest()
    except OSError as exc:
        result["error"] = str(exc)
    return result


def _evidence_entry(
    row: Evidence,
    cutoff: datetime,
    current_ids: set[int],
    open_findings: set[str],
    pending_approval_findings: set[str],
    holds: dict[str, set[str]],
    evidence_root: Path,
    duplicate_paths: set[str],
) -> dict:
    reasons = []
    if row.id in current_ids:
        reasons.append("current_evidence")
    if row.finding_id and row.finding_id in open_findings:
        reasons.append("active_finding")
    if row.finding_id and row.finding_id in pending_approval_findings:
        reasons.append("pending_approval")
    if row.evidence_id in holds["evidence_ids"]:
        reasons.append("legal_hold_evidence")
    if row.finding_id and row.finding_id in holds["finding_ids"]:
        reasons.append("legal_hold_finding")
    if row.asset_id and row.asset_id in holds["asset_ids"]:
        reasons.append("legal_hold_asset")
    if row.control_id and row.control_id in holds["control_ids"]:
        reasons.append("legal_hold_control")
    if row.file_path in holds["file_paths"]:
        reasons.append("legal_hold_file")
    if row.file_path in duplicate_paths:
        reasons.append("shared_file_path")
    file_info = _file_metadata(row.file_path, evidence_root)
    if not file_info["exists"]:
        reasons.append("missing_file")
    elif not file_info["is_file"]:
        reasons.append("path_not_file")
    if not file_info["within_evidence_root"]:
        reasons.append("outside_evidence_root")
    created_at = _aware(row.created_at)
    eligible_by_age = created_at is not None and created_at <= cutoff
    if created_at is None:
        reasons.append("missing_created_at")
    return {
        "record_id": row.id,
        "evidence_id": row.evidence_id,
        "created_at": _iso(created_at),
        "validated": bool(row.validated),
        "asset_id": row.asset_id,
        "control_id": row.control_id,
        "framework": row.framework,
        "frameworks": row.frameworks or {},
        "collector": row.collector,
        "evidence_type": row.evidence_type,
        "source": row.source,
        "finding_id": row.finding_id,
        "filename": row.filename,
        "file": file_info,
        "eligible_by_age": eligible_by_age,
        "protected": bool(reasons),
        "protection_reasons": sorted(set(reasons)),
        "disposition": "protected" if reasons else "archive_candidate",
    }


def _changelog_entry(
    event: dict,
    cutoff: datetime,
    notes: dict,
    active_campaigns: set[str],
    holds: dict[str, set[str]],
) -> dict:
    event_id = str(event.get("event_id") or "")
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    timestamp = _parse_timestamp(event.get("timestamp"))
    reasons = []
    if not event_id:
        reasons.append("missing_event_id")
    if timestamp is None:
        reasons.append("invalid_timestamp")
    if event_id in holds["changelog_event_ids"]:
        reasons.append("legal_hold_event")
    if str(details.get("asset_id") or event.get("asset_id") or "") in holds["asset_ids"]:
        reasons.append("legal_hold_asset")
    campaign_id = str(details.get("campaign_id") or "")
    if campaign_id and campaign_id in active_campaigns:
        reasons.append("active_access_review")
    note = notes.get(event_id, {})
    if note.get("note") or note.get("jira_url"):
        reasons.append("has_annotation")
    eligible_by_age = timestamp is not None and timestamp <= cutoff
    return {
        "event_id": event_id,
        "timestamp": _iso(timestamp),
        "event_type": event.get("event_type"),
        "asset_id": event.get("asset_id"),
        "summary": event.get("summary"),
        "details": details,
        "eligible_by_age": eligible_by_age,
        "protected": bool(reasons),
        "protection_reasons": sorted(set(reasons)),
        "disposition": "protected" if reasons else "archive_candidate",
    }


def _fingerprint(entries: list[dict]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_preview(
    db: Session,
    policy: PreviewPolicy,
    evidence_root: Path,
    access_review_file: Path,
    legal_hold_file: Path | None = None,
    now: datetime | None = None,
) -> dict:
    generated_at = _aware(now or utc_now())
    holds = load_legal_holds(legal_hold_file)
    active_campaigns = _active_access_review_ids(access_review_file)
    rows = db.query(Evidence).order_by(Evidence.id.asc()).all()
    current_ids = _current_evidence_ids(rows)
    open_findings = {
        value for (value,) in db.query(Finding.finding_id).filter(Finding.status.in_(ACTIVE_FINDING_STATUSES)).all()
    }
    pending_approval_findings = {
        value for (value,) in db.query(Approval.finding_id).filter(
            Approval.finding_id.is_not(None), Approval.status.in_(ACTIVE_APPROVAL_STATUSES)
        ).all()
    }
    path_counts = Counter(row.file_path for row in rows)
    duplicate_paths = {path for path, count in path_counts.items() if count > 1}

    evidence_entries = []
    for row in rows:
        days = policy.validated_evidence_days if row.validated else policy.unvalidated_evidence_days
        cutoff = generated_at - timedelta(days=days)
        if _aware(row.created_at) is None or _aware(row.created_at) <= cutoff:
            evidence_entries.append(
                _evidence_entry(
                    row,
                    cutoff,
                    current_ids,
                    open_findings,
                    pending_approval_findings,
                    holds,
                    evidence_root,
                    duplicate_paths,
                )
            )

    with _file_lock:
        changelog_events = _read_events()
        notes = _read_notes()
    changelog_cutoff = generated_at - timedelta(days=policy.changelog_days)
    changelog_entries = [
        _changelog_entry(event, changelog_cutoff, notes, active_campaigns, holds)
        for event in changelog_events
        if _parse_timestamp(event.get("timestamp")) is None
        or _parse_timestamp(event.get("timestamp")) <= changelog_cutoff
    ]

    candidates = {
        "evidence": [entry for entry in evidence_entries if not entry["protected"]],
        "changelog": [entry for entry in changelog_entries if not entry["protected"]],
    }
    protected = {
        "evidence": [entry for entry in evidence_entries if entry["protected"]],
        "changelog": [entry for entry in changelog_entries if entry["protected"]],
    }
    fingerprint_entries = [
        {"kind": kind, "record": item}
        for kind in ("evidence", "changelog")
        for item in candidates[kind]
    ]
    reason_counts = Counter(
        reason
        for kind in protected.values()
        for item in kind
        for reason in item["protection_reasons"]
    )
    candidate_file_bytes = sum(
        entry["file"]["size_bytes"] or 0 for entry in candidates["evidence"]
    )
    protected_file_bytes = sum(
        entry["file"]["size_bytes"] or 0 for entry in protected["evidence"]
    )
    return {
        "mode": "preview_only",
        "generated_at": _iso(generated_at),
        "policy": asdict(policy),
        "cutoffs": {
            "changelog": _iso(changelog_cutoff),
            "validated_evidence": _iso(generated_at - timedelta(days=policy.validated_evidence_days)),
            "unvalidated_evidence": _iso(generated_at - timedelta(days=policy.unvalidated_evidence_days)),
        },
        "sources": {
            "changelog_file": str(CHANGELOG_FILE),
            "changelog_notes_file": str(CHANGELOG_NOTES_FILE),
            "evidence_root": str(evidence_root),
            "access_review_file": str(access_review_file),
            "legal_hold_file": str(legal_hold_file) if legal_hold_file else None,
        },
        "counts": {
            "candidate_evidence": len(candidates["evidence"]),
            "protected_evidence": len(protected["evidence"]),
            "candidate_changelog": len(candidates["changelog"]),
            "protected_changelog": len(protected["changelog"]),
            "candidate_file_bytes": candidate_file_bytes,
            "protected_file_bytes": protected_file_bytes,
        },
        "protection_reason_counts": dict(sorted(reason_counts.items())),
        "candidate_fingerprint_sha256": _fingerprint(fingerprint_entries),
        "candidates": candidates,
        "protected": protected,
        "dependency_check_limitations": [
            "The current schema has no persistent assessment-to-evidence relationship table.",
            "Generated reports are not persistently indexed to evidence records.",
            "Active incident relationships are not represented in the current database schema.",
            "Use the legal-hold inventory to protect records affected by these limitations.",
        ],
        "actions_performed": {"archived": False, "deleted": False, "scheduled": False},
    }


def run_preview(
    db: Session,
    policy: PreviewPolicy,
    evidence_root: Path,
    access_review_file: Path,
    actor: str,
    legal_hold_file: Path | None = None,
    now: datetime | None = None,
) -> dict:
    actor = actor.strip()
    if not actor:
        raise ValueError("An administrative actor is required.")
    result = build_preview(
        db, policy, evidence_root, access_review_file, legal_hold_file, now
    )
    detail = {
        "actor_username": actor,
        "policy": result["policy"],
        "cutoffs": result["cutoffs"],
        "counts": result["counts"],
        "candidate_fingerprint_sha256": result["candidate_fingerprint_sha256"],
        "legal_hold_file": result["sources"]["legal_hold_file"],
        "actions_performed": result["actions_performed"],
    }
    audit_event_id = audit(db, PREVIEW_EVENT_TYPE, username=actor, detail=detail)
    db.commit()
    write_changelog(
        event_type=PREVIEW_EVENT_TYPE,
        asset_id="compliance-dashboard",
        summary=f"Changelog and evidence retention candidates were previewed by {actor}.",
        details={"audit_event_id": audit_event_id, **detail},
    )
    return {**result, "audit_event_id": audit_event_id}
