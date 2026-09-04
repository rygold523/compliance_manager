from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
from uuid import uuid4
import json
import os

from fastapi import (
    APIRouter,
    HTTPException,
)
from pydantic import BaseModel


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


def write_changelog(
    event_type: str,
    asset_id: str,
    summary: str,
    details: dict | None = None,
):
    CHANGELOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    event = {
        "event_id": (
            f"EVT-{uuid4().hex}"
        ),
        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
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
        with CHANGELOG_FILE.open(
            mode="a",
            encoding="utf-8",
        ) as changelog:
            changelog.write(
                serialized
            )

    return event


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
