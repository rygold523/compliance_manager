from datetime import date, datetime, timezone
from pathlib import Path
from threading import Lock
from uuid import uuid4
import csv
import io
import json
import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.changelog import write_changelog
from app.auth.dependencies import require_roles


router = APIRouter(prefix="/api/access-reviews", tags=["Access Reviews"])
STORE_FILE = Path(os.environ.get("ACCESS_REVIEW_FILE", "/app/evidence/access_reviews.json"))
_store_lock = Lock()
DECISIONS = {"pending", "retain", "remove", "investigate"}


class ReviewItemInput(BaseModel):
    subject_type: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=256)
    system: str = Field(min_length=1, max_length=256)
    access: str = Field(default="", max_length=8000)
    privileged: bool = False


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    reviewer: str = Field(min_length=1, max_length=255)
    due_date: str = Field(min_length=10, max_length=32)
    scope_note: str = Field(default="", max_length=4000)
    items: list[ReviewItemInput] = Field(min_length=1, max_length=10000)


class ItemDecision(BaseModel):
    decision: str
    comment: str = Field(default="", max_length=4000)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _csv_safe(value) -> str:
    text = str(value if value is not None else "")
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def _read_store() -> dict:
    if not STORE_FILE.exists():
        return {"campaigns": []}
    try:
        value = json.loads(STORE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Access-review storage is unreadable.") from exc
    if not isinstance(value, dict) or not isinstance(value.get("campaigns"), list):
        raise HTTPException(status_code=500, detail="Access-review storage has an invalid format.")
    return value


def _write_store(store: dict) -> None:
    STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STORE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, STORE_FILE)


def _summary(campaign: dict) -> dict:
    counts = {decision: 0 for decision in DECISIONS}
    for item in campaign["items"]:
        counts[item["decision"]] = counts.get(item["decision"], 0) + 1
    return {
        key: campaign.get(key)
        for key in ("campaign_id", "name", "reviewer", "due_date", "scope_note", "status", "created_at", "created_by", "completed_at", "completed_by", "archived_at", "archived_by")
    } | {"total_items": len(campaign["items"]), "decision_counts": counts}


def _find_campaign(store: dict, campaign_id: str) -> dict:
    campaign = next((item for item in store["campaigns"] if item.get("campaign_id") == campaign_id), None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Access-review campaign not found.")
    return campaign


@router.get("")
def list_campaigns(_reviewer=Depends(require_roles("admin", "auditor"))):
    with _store_lock:
        campaigns = [_summary(item) for item in _read_store()["campaigns"]]
    return {"campaigns": sorted(campaigns, key=lambda item: item["created_at"], reverse=True)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_campaign(payload: CampaignCreate, admin=Depends(require_roles("admin"))):
    name = payload.name.strip()
    reviewer = payload.reviewer.strip()
    if not name or not reviewer:
        raise HTTPException(status_code=400, detail="Campaign name and reviewer are required.")
    try:
        due_date = date.fromisoformat(payload.due_date)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Due date must use YYYY-MM-DD format.") from exc
    if due_date < datetime.now(timezone.utc).date():
        raise HTTPException(status_code=400, detail="Due date cannot be in the past.")
    created_at = _now()
    campaign_id = f"AR-{uuid4().hex}"
    seen = set()
    items = []
    for submitted in payload.items:
        key = (submitted.subject_type, submitted.username, submitted.system, submitted.access)
        if key in seen:
            continue
        seen.add(key)
        items.append({
            "item_id": f"ARI-{uuid4().hex}",
            **submitted.model_dump(),
            "decision": "pending",
            "comment": "",
            "decided_at": None,
            "decided_by": None,
        })
    campaign = {
        "campaign_id": campaign_id,
        "name": name,
        "reviewer": reviewer,
        "due_date": due_date.isoformat(),
        "scope_note": payload.scope_note.strip(),
        "status": "open",
        "created_at": created_at,
        "created_by": admin.username,
        "completed_at": None,
        "completed_by": None,
        "items": items,
    }
    with _store_lock:
        store = _read_store()
        store["campaigns"].append(campaign)
        _write_store(store)
    write_changelog("access_review_campaign_created", "compliance-dashboard", f"Access-review campaign {campaign['name']} was created.", {"campaign_id": campaign_id, "reviewer": campaign["reviewer"], "due_date": campaign["due_date"], "item_count": len(items), "actor_username": admin.username})
    return {"campaign": campaign}


@router.get("/{campaign_id}")
def get_campaign(campaign_id: str, _reviewer=Depends(require_roles("admin", "auditor"))):
    with _store_lock:
        return {"campaign": _find_campaign(_read_store(), campaign_id)}


@router.patch("/{campaign_id}/items/{item_id}")
def decide_item(campaign_id: str, item_id: str, payload: ItemDecision, admin=Depends(require_roles("admin"))):
    decision = payload.decision.strip().lower()
    if decision not in DECISIONS:
        raise HTTPException(status_code=400, detail="Decision must be pending, retain, remove, or investigate.")
    with _store_lock:
        store = _read_store()
        campaign = _find_campaign(store, campaign_id)
        if campaign["status"] != "open":
            raise HTTPException(status_code=409, detail="Completed campaigns cannot be modified.")
        item = next((entry for entry in campaign["items"] if entry["item_id"] == item_id), None)
        if item is None:
            raise HTTPException(status_code=404, detail="Review item not found.")
        item.update({"decision": decision, "comment": payload.comment.strip(), "decided_at": _now() if decision != "pending" else None, "decided_by": admin.username if decision != "pending" else None})
        _write_store(store)
    write_changelog("access_review_item_decided", "compliance-dashboard", f"Access for {item['username']} on {item['system']} was marked {decision}.", {"campaign_id": campaign_id, "item_id": item_id, "username": item["username"], "system": item["system"], "decision": decision, "actor_username": admin.username})
    return {"item": item}


@router.post("/{campaign_id}/complete")
def complete_campaign(campaign_id: str, admin=Depends(require_roles("admin"))):
    with _store_lock:
        store = _read_store()
        campaign = _find_campaign(store, campaign_id)
        if campaign["status"] == "completed":
            return {"campaign": campaign}
        pending = sum(1 for item in campaign["items"] if item["decision"] == "pending")
        if pending:
            raise HTTPException(status_code=409, detail=f"{pending} review items still require a decision.")
        campaign.update({"status": "completed", "completed_at": _now(), "completed_by": admin.username})
        _write_store(store)
    write_changelog("access_review_campaign_completed", "compliance-dashboard", f"Access-review campaign {campaign['name']} was completed.", {"campaign_id": campaign_id, "item_count": len(campaign["items"]), "actor_username": admin.username})
    return {"campaign": campaign}


@router.post("/{campaign_id}/archive")
def archive_campaign(campaign_id: str, admin=Depends(require_roles("admin"))):
    with _store_lock:
        store = _read_store()
        campaign = _find_campaign(store, campaign_id)
        if campaign["status"] == "archived":
            return {"campaign": campaign}
        campaign.update({
            "status": "archived",
            "archived_at": _now(),
            "archived_by": admin.username,
        })
        _write_store(store)
    write_changelog(
        "access_review_campaign_archived",
        "compliance-dashboard",
        f"Access-review campaign {campaign['name']} was archived.",
        {"campaign_id": campaign_id, "actor_username": admin.username},
    )
    return {"campaign": campaign}


@router.get("/{campaign_id}/export")
def export_campaign(campaign_id: str, _reviewer=Depends(require_roles("admin", "auditor"))):
    with _store_lock:
        campaign = _find_campaign(_read_store(), campaign_id)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["campaign_id", "campaign", "status", "due_date", "reviewer", "subject_type", "username", "system", "access", "privileged", "decision", "comment", "decided_by", "decided_at"])
    for item in campaign["items"]:
        writer.writerow([_csv_safe(value) for value in [campaign_id, campaign["name"], campaign["status"], campaign["due_date"], campaign["reviewer"], item["subject_type"], item["username"], item["system"], item["access"], item["privileged"], item["decision"], item["comment"], item["decided_by"], item["decided_at"]]])
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="access-review-{campaign_id}.csv"'})
