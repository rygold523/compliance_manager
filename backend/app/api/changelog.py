from datetime import datetime, timezone
from pathlib import Path
import json

from fastapi import APIRouter

router = APIRouter(prefix="/api/changelog", tags=["changelog"])

CHANGELOG_FILE = Path("/app/evidence/changelog.jsonl")


def write_changelog(event_type: str, asset_id: str, summary: str, details: dict | None = None):
    CHANGELOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "asset_id": asset_id,
        "summary": summary,
        "details": details or {},
    }

    with CHANGELOG_FILE.open("a") as f:
        f.write(json.dumps(event, default=str) + "\n")

    return event


@router.get("/")
def list_changelog(limit: int = 250):
    if not CHANGELOG_FILE.exists():
        return {"events": []}

    rows = CHANGELOG_FILE.read_text().splitlines()
    events = []

    for row in rows[-limit:]:
        try:
            events.append(json.loads(row))
        except Exception:
            continue

    return {"events": list(reversed(events))}
