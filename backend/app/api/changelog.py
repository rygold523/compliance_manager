from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
from uuid import uuid4
import csv
import io
import json
import os
from collections import Counter

from fastapi.responses import Response

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import BaseModel

from app.core.database import SessionLocal
from app.auth.dependencies import require_roles
from app.models import Evidence
from app.models.models import AuthAuditEvent


router = APIRouter(
    prefix="/api/changelog",
    tags=["changelog"],
)

CHANGELOG_FILE = Path(
    os.environ.get(
        "CHANGELOG_FILE",
        "/app/evidence/changelog.jsonl",
    )
)

CHANGELOG_NOTES_FILE = Path(
    os.environ.get(
        "CHANGELOG_NOTES_FILE",
        "/app/evidence/changelog_notes.json",
    )
)

_file_lock = Lock()

ACCESS_CHANGE_PREFIXES = (
    "server_user_",
    "server_group_",
    "db_user_",
    "db_role_",
    "dashboard_user_",
    "access_review_",
)

ASSET_CHANGE_EVENT_TYPES = {
    "agent_deployed",
    "agent_upgraded",
    "agent_removed",
}

ACCESS_CHANGE_FRAMEWORKS = {
    "pci_dss": ["7.2", "8.2"],
    "soc2": ["CC6.1", "CC6.2", "CC6.3"],
    "nist_800_53": ["AC-2", "AC-3"],
    "iso_27001": ["A.5.15", "A.5.16"],
    "iso_27002": ["5.15", "5.16"],
}

ASSET_CHANGE_FRAMEWORKS = {
    "pci_dss": ["12.5"],
    "soc2": ["CC6.1", "CC8.1"],
    "nist_800_53": ["CM-8"],
    "iso_27001": ["A.5.9"],
    "iso_27002": ["5.9"],
}

RECONCILABLE_AUTH_EVENT_TYPES = {
    "user_created",
    "user_updated",
    "user_password_reset",
    "user_unlocked",
    "user_sessions_revoked",
    "user_session_revoked",
}


class ChangelogNoteUpdate(BaseModel):
    note: str = ""
    jira_url: str = ""


def _legacy_event_id(
    raw_line: str,
) -> str:
    digest = sha256(
        raw_line.encode("utf-8")
    ).hexdigest()[:24]

    return f"legacy-{digest}"


def stable_changelog_event_id(
    audit_event_id: str,
    event_type: str,
) -> str:
    digest = sha256(
        f"{audit_event_id}:{event_type}".encode("utf-8")
    ).hexdigest()[:32]
    return f"EVT-AUD-{digest}"


def _auth_event_projections(audit_event) -> list[dict]:
    detail = audit_event.detail if isinstance(audit_event.detail, dict) else {}
    audit_event_id = str(detail.get("audit_event_id") or "").strip()
    if not audit_event_id or audit_event.event_type not in RECONCILABLE_AUTH_EVENT_TYPES:
        return []

    username = audit_event.username or "unknown"
    common = {
        "username": username,
        "target_user_id": audit_event.user_id,
        "actor_username": detail.get("actor_username"),
        "actor_user_id": detail.get("actor_user_id"),
        "source": "dashboard_local_auth",
        "source_address": audit_event.source_address,
        "audit_event_id": audit_event_id,
        "reconciled_from_auth_audit": True,
    }

    definitions = []
    if audit_event.event_type == "user_created":
        definitions.append((
            "dashboard_user_created",
            f"Dashboard user {username} was created.",
            {"role_name": detail.get("role")},
        ))
    elif audit_event.event_type == "user_password_reset":
        definitions.append((
            "dashboard_user_password_reset",
            f"Dashboard user {username} password was reset.",
            {
                "must_change_password": True,
                "revoked_sessions": detail.get("revoked_sessions", 0),
            },
        ))
    elif audit_event.event_type == "user_unlocked":
        definitions.append((
            "dashboard_user_unlocked",
            f"Dashboard user {username} was unlocked.",
            {},
        ))
    elif audit_event.event_type == "user_sessions_revoked":
        definitions.append((
            "dashboard_user_sessions_revoked",
            f"Active sessions were revoked for dashboard user {username}.",
            {"revoked_sessions": detail.get("revoked_sessions", 0)},
        ))
    elif audit_event.event_type == "user_session_revoked":
        session_id = detail.get("session_id")
        definitions.append((
            "dashboard_user_session_revoked",
            f"Session {session_id} was revoked for dashboard user {username}.",
            {"session_id": session_id, "revoked_sessions": 1},
        ))
    elif audit_event.event_type == "user_updated":
        before = detail.get("before") if isinstance(detail.get("before"), dict) else {}
        after = detail.get("after") if isinstance(detail.get("after"), dict) else {}
        shared = {
            "before": before,
            "after": after,
            "revoked_sessions": detail.get("revoked_sessions", 0),
        }
        if before.get("role") != after.get("role"):
            definitions.append((
                "dashboard_user_role_changed",
                f"Dashboard user {username} role changed from {before.get('role')} to {after.get('role')}.",
                {
                    **shared,
                    "previous_role_name": before.get("role"),
                    "role_name": after.get("role"),
                },
            ))
        if before.get("enabled") != after.get("enabled"):
            enabled = bool(after.get("enabled"))
            definitions.append((
                "dashboard_user_enabled" if enabled else "dashboard_user_disabled",
                f"Dashboard user {username} was {'enabled' if enabled else 'disabled'}.",
                shared,
            ))
        if before.get("display_name") != after.get("display_name"):
            definitions.append((
                "dashboard_user_profile_updated",
                f"Dashboard user {username} display name was updated.",
                shared,
            ))
        if (
            before.get("inactivity_exempt") != after.get("inactivity_exempt")
            or before.get("inactivity_exemption_reason") != after.get("inactivity_exemption_reason")
        ):
            exempt = bool(after.get("inactivity_exempt"))
            definitions.append((
                "dashboard_user_inactivity_exemption_changed",
                f"Dashboard user {username} inactivity exemption was {'enabled' if exempt else 'removed'}.",
                shared,
            ))

    timestamp = audit_event.created_at
    if timestamp is not None and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return [
        {
            "event_id": stable_changelog_event_id(audit_event_id, event_type),
            "timestamp": timestamp.isoformat() if timestamp is not None else None,
            "event_type": event_type,
            "asset_id": "compliance-dashboard",
            "summary": summary,
            "details": {**common, **extra},
        }
        for event_type, summary, extra in definitions
    ]


def _integrity_snapshot(db) -> dict:
    auth_events = (
        db.query(AuthAuditEvent)
        .filter(AuthAuditEvent.event_type.in_(RECONCILABLE_AUTH_EVENT_TYPES))
        .order_by(AuthAuditEvent.id.asc())
        .all()
    )
    projections = [
        projection
        for auth_event in auth_events
        for projection in _auth_event_projections(auth_event)
    ]

    with _file_lock:
        events = _read_events()

    event_ids = [str(event.get("event_id") or "") for event in events]
    present_ids = set(event_ids)
    events_by_id = {
        str(event.get("event_id") or ""): event
        for event in events
        if event.get("event_id")
    }
    expected_ids = {projection["event_id"] for projection in projections}
    duplicate_ids = sorted(
        event_id
        for event_id, count in Counter(event_ids).items()
        if event_id and count > 1
    )
    missing = [projection for projection in projections if projection["event_id"] not in present_ids]
    mismatched = []
    for projection in projections:
        actual = events_by_id.get(projection["event_id"])
        if actual is None:
            continue
        actual_details = actual.get("details") if isinstance(actual.get("details"), dict) else {}
        if (
            actual.get("event_type") != projection["event_type"]
            or actual.get("asset_id") != projection["asset_id"]
            or actual_details.get("audit_event_id") != projection["details"]["audit_event_id"]
        ):
            mismatched.append({
                "event_id": projection["event_id"],
                "expected_event_type": projection["event_type"],
                "actual_event_type": actual.get("event_type"),
            })

    tracked_auth_events = sum(
        1
        for event in auth_events
        if isinstance(event.detail, dict) and event.detail.get("audit_event_id")
    )

    return {
        "status": "healthy" if not missing and not duplicate_ids and not mismatched else "degraded",
        "auth_events_examined": len(auth_events),
        "tracked_auth_events": tracked_auth_events,
        "legacy_untracked_auth_events": len(auth_events) - tracked_auth_events,
        "expected_projections": len(projections),
        "present_projections": len(expected_ids & present_ids),
        "missing_count": len(missing),
        "duplicate_event_ids": duplicate_ids,
        "mismatched_projections": mismatched,
        "missing": missing,
    }


def reconcile_integrity(db) -> dict:
    before = _integrity_snapshot(db)
    created = 0

    for projection in before["missing"]:
        write_changelog(
            event_id=projection["event_id"],
            timestamp=projection["timestamp"],
            event_type=projection["event_type"],
            asset_id=projection["asset_id"],
            summary=projection["summary"],
            details=projection["details"],
        )
        created += 1

    after = _integrity_snapshot(db)
    return {
        "status": after["status"],
        "created": created,
        "before": before,
        "after": after,
    }


def _normalize_event(
    event: dict,
    raw_line: str,
) -> dict:
    normalized = dict(event)

    if not normalized.get("event_id"):
        normalized["event_id"] = (
            _legacy_event_id(raw_line)
        )

    if "summary" not in normalized:
        normalized["summary"] = (
            normalized.get("message")
            or ""
        )

    if "details" not in normalized:
        normalized["details"] = {}

    return normalized


def _read_events() -> list[dict]:
    if not CHANGELOG_FILE.exists():
        return []

    events = []

    for raw_line in CHANGELOG_FILE.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines():
        try:
            event = json.loads(
                raw_line
            )
        except Exception:
            continue

        if not isinstance(event, dict):
            continue

        events.append(
            _normalize_event(
                event,
                raw_line,
            )
        )

    return events


def _read_notes() -> dict[str, dict]:
    if not CHANGELOG_NOTES_FILE.exists():
        return {}

    try:
        payload = json.loads(
            CHANGELOG_NOTES_FILE.read_text(
                encoding="utf-8",
            )
        )
    except Exception:
        return {}

    if not isinstance(payload, dict):
        return {}

    notes = {}

    for event_id, value in payload.items():
        if not isinstance(value, dict):
            continue

        notes[str(event_id)] = {
            "note": str(
                value.get("note")
                or ""
            ),
            "jira_url": str(
                value.get("jira_url")
                or ""
            ),
            "updated_at": value.get(
                "updated_at"
            ),
        }

    return notes


def _write_notes(
    notes: dict[str, dict],
):
    CHANGELOG_NOTES_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = (
        CHANGELOG_NOTES_FILE.with_suffix(
            CHANGELOG_NOTES_FILE.suffix
            + ".tmp"
        )
    )

    temporary_file.write_text(
        json.dumps(
            notes,
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )

    os.replace(
        temporary_file,
        CHANGELOG_NOTES_FILE,
    )


def _validate_jira_url(
    jira_url: str,
) -> str:
    jira_url = jira_url.strip()

    if not jira_url:
        return ""

    if len(jira_url) > 2048:
        raise HTTPException(
            status_code=400,
            detail=(
                "The Jira URL cannot exceed "
                "2048 characters."
            ),
        )

    parsed = urlparse(
        jira_url
    )

    if (
        parsed.scheme not in {
            "http",
            "https",
        }
        or not parsed.netloc
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "The Jira URL must be a valid "
                "HTTP or HTTPS URL."
            ),
        )

    return jira_url


def _event_evidence_definition(
    event: dict,
) -> dict | None:
    event_type = str(
        event.get("event_type") or ""
    )

    if event_type.startswith(
        ACCESS_CHANGE_PREFIXES
    ):
        return {
            "control_id": "AC-02",
            "collector": (
                "changelog_access_management"
            ),
            "description": (
                "User or group access change "
                "recorded in the changelog."
            ),
            "frameworks": ACCESS_CHANGE_FRAMEWORKS,
        }

    if (
        event_type in ASSET_CHANGE_EVENT_TYPES
        or event_type.startswith("asset_")
    ):
        return {
            "control_id": "AM-01",
            "collector": (
                "changelog_asset_inventory"
            ),
            "description": (
                "Asset lifecycle change recorded "
                "in the changelog."
            ),
            "frameworks": ASSET_CHANGE_FRAMEWORKS,
        }

    return None


def _event_evidence_id(
    event: dict,
    control_id: str,
) -> str:
    event_id = str(
        event.get("event_id") or ""
    )

    digest = sha256(
        f"{event_id}:{control_id}".encode(
            "utf-8"
        )
    ).hexdigest()[:20].upper()

    return f"EV-CHG-{digest}"


def _persist_event_evidence(
    event: dict,
    db=None,
) -> bool:
    definition = _event_evidence_definition(
        event
    )

    if definition is None:
        return False

    evidence_id = _event_evidence_id(
        event,
        definition["control_id"],
    )

    owns_session = db is None
    session = db or SessionLocal()

    try:
        existing = (
            session.query(Evidence)
            .filter(
                Evidence.evidence_id
                == evidence_id
            )
            .first()
        )

        if existing is not None:
            return False

        session.add(
            Evidence(
                evidence_id=evidence_id,
                asset_id=(
                    event.get("asset_id")
                    or "environment"
                ),
                control_id=(
                    definition["control_id"]
                ),
                filename=CHANGELOG_FILE.name,
                file_path=str(CHANGELOG_FILE),
                source="changelog",
                description=(
                    event.get("summary")
                    or definition["description"]
                ),
                collector=(
                    definition["collector"]
                ),
                evidence_type=(
                    definition["collector"]
                ),
                frameworks=(
                    definition["frameworks"]
                ),
                validated=True,
            )
        )

        if owns_session:
            session.commit()
        else:
            session.flush()

        return True
    except Exception:
        if owns_session:
            session.rollback()
        raise
    finally:
        if owns_session:
            session.close()


def _csv_safe(
    value,
) -> str:
    text = str(
        value
        if value is not None
        else ""
    )

    if text.startswith(
        ("=", "+", "-", "@")
    ):
        return "'" + text

    return text


def write_changelog(
    event_type: str,
    asset_id: str,
    summary: str,
    details: dict | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
):
    CHANGELOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    event = {
        "event_id": event_id or f"EVT-{uuid4().hex}",
        "timestamp": (
            timestamp or datetime.now(timezone.utc).isoformat()
        ),
        "event_type": event_type,
        "asset_id": asset_id,
        "summary": summary,
        "details": details or {},
    }

    serialized = (
        json.dumps(
            event,
            default=str,
        )
        + "\n"
    )

    with _file_lock:
        if event_id:
            for existing in _read_events():
                if existing.get("event_id") == event_id:
                    return existing
        with CHANGELOG_FILE.open(
            mode="a",
            encoding="utf-8",
        ) as changelog:
            changelog.write(
                serialized
            )

    try:
        _persist_event_evidence(event)
    except Exception:
        # Changelog persistence must not cause the
        # originating management action to fail.
        pass

    return event


@router.get("/integrity")
def changelog_integrity(
    _reviewer=Depends(require_roles("admin", "auditor")),
):
    db = SessionLocal()
    try:
        return _integrity_snapshot(db)
    finally:
        db.close()


@router.post("/integrity/reconcile")
def reconcile_changelog_integrity(
    _admin=Depends(require_roles("admin")),
):
    db = SessionLocal()
    try:
        return reconcile_integrity(db)
    finally:
        db.close()


@router.get("/user-group-export")
def export_user_group_changes():
    with _file_lock:
        events = _read_events()
        notes = _read_notes()

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "timestamp",
        "event_type",
        "asset_id",
        "username",
        "group_or_role",
        "source",
        "summary",
        "note",
        "jira_url",
        "event_id",
    ])

    exported_count = 0

    for event in events:
        event_type = str(
            event.get("event_type") or ""
        )

        if not event_type.startswith(
            ACCESS_CHANGE_PREFIXES
        ):
            continue

        details = event.get("details") or {}
        annotation = notes.get(
            event.get("event_id"),
            {},
        )

        username = (
            details.get("username")
            or details.get("user_name")
            or ""
        )
        group_or_role = (
            details.get("group_name")
            or details.get("role_name")
            or ""
        )
        source = (
            details.get("source")
            or details.get("source_name")
            or details.get("source_type")
            or ""
        )

        writer.writerow([
            _csv_safe(event.get("timestamp")),
            _csv_safe(event_type),
            _csv_safe(event.get("asset_id")),
            _csv_safe(username),
            _csv_safe(group_or_role),
            _csv_safe(source),
            _csv_safe(event.get("summary")),
            _csv_safe(annotation.get("note")),
            _csv_safe(annotation.get("jira_url")),
            _csv_safe(event.get("event_id")),
        ])

        exported_count += 1

    filename = "user-group-changes.csv"

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "X-Exported-Event-Count": str(
                exported_count
            ),
        },
    )


@router.post("/evidence/sync")
def sync_changelog_evidence():
    with _file_lock:
        events = _read_events()

    db = SessionLocal()
    created = 0
    existing = 0
    ignored = 0

    try:
        for event in events:
            if (
                _event_evidence_definition(event)
                is None
            ):
                ignored += 1
                continue

            if _persist_event_evidence(
                event,
                db=db,
            ):
                created += 1
            else:
                existing += 1

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return {
        "status": "completed",
        "created": created,
        "existing": existing,
        "ignored": ignored,
        "total": len(events),
    }


@router.get("/")
def list_changelog(
    limit: int = 250,
):
    limit = max(
        1,
        min(
            limit,
            1000,
        ),
    )

    with _file_lock:
        events = _read_events()
        notes = _read_notes()

    enriched_events = []

    for event in events[-limit:]:
        annotation = notes.get(
            event["event_id"],
            {},
        )

        enriched = dict(event)
        enriched["note"] = annotation.get(
            "note",
            "",
        )
        enriched["jira_url"] = (
            annotation.get(
                "jira_url",
                "",
            )
        )
        enriched["note_updated_at"] = (
            annotation.get(
                "updated_at"
            )
        )

        enriched_events.append(
            enriched
        )

    return {
        "events": list(
            reversed(
                enriched_events
            )
        ),
    }


@router.put(
    "/{event_id}/note"
)
def update_changelog_note(
    event_id: str,
    payload: ChangelogNoteUpdate,
):
    event_id = event_id.strip()

    if not event_id:
        raise HTTPException(
            status_code=400,
            detail="Event ID is required.",
        )

    note = payload.note.strip()
    jira_url = _validate_jira_url(
        payload.jira_url
    )

    if len(note) > 4000:
        raise HTTPException(
            status_code=400,
            detail=(
                "The note cannot exceed "
                "4000 characters."
            ),
        )

    with _file_lock:
        events = _read_events()

        if not any(
            event.get("event_id")
            == event_id
            for event in events
        ):
            raise HTTPException(
                status_code=404,
                detail=(
                    "Changelog event "
                    "was not found."
                ),
            )

        notes = _read_notes()

        if not note and not jira_url:
            notes.pop(
                event_id,
                None,
            )
        else:
            notes[event_id] = {
                "note": note,
                "jira_url": jira_url,
                "updated_at": (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                ),
            }

        _write_notes(
            notes
        )

    return {
        "event_id": event_id,
        "note": note,
        "jira_url": jira_url,
        "status": "updated",
    }
