from fastapi import APIRouter
from pathlib import Path
import json
import os

router = APIRouter(prefix="/api/iam", tags=["iam"])

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/var/lib/ai-vulnerability-management/evidence"))

def _is_quarantined(path: Path) -> bool:
    return any(part.startswith("_quarantine") for part in path.parts)

def _load_iam_records(kind: str):
    records = []

    if not EVIDENCE_ROOT.exists():
        return records

    for path in EVIDENCE_ROOT.rglob("*.json"):
        if _is_quarantined(path):
            continue

        try:
            data = json.loads(path.read_text(errors="ignore"))
        except Exception:
            continue

        if data.get("collector") != "iam_users":
            continue

        asset_id = data.get("asset_id") or data.get("hostname") or path.parent.name
        hostname = data.get("hostname") or asset_id

        items = data.get(kind, [])

        for item in items:
            row = dict(item)
            row["asset_id"] = asset_id
            row["hostname"] = hostname
            row["collected_at"] = data.get("collected_at")
            records.append(row)

    return records

def _matrix(records, field):
    users = sorted(set(r["username"] for r in records))
    servers = sorted(set(r["asset_id"] for r in records))

    rows = []

    for username in users:
        row = {"username": username}

        for server in servers:
            matches = [
                r for r in records
                if r["username"] == username and r["asset_id"] == server
            ]

            if not matches:
                row[server] = ""
            else:
                value = matches[0].get(field, [])
                if isinstance(value, list):
                    row[server] = ", ".join(value)
                else:
                    row[server] = str(value)

        rows.append(row)

    return {"servers": servers, "rows": rows}

@router.get("/users")
def users():
    return {"users": _load_iam_records("users")}

@router.get("/service-accounts")
def service_accounts():
    return {"service_accounts": _load_iam_records("service_accounts")}

@router.get("/access-matrix")
def access_matrix():
    return _matrix(_load_iam_records("users"), "access")

@router.get("/group-matrix")
def group_matrix():
    return _matrix(_load_iam_records("users"), "groups")

@router.get("/service-account-matrix")
def service_account_matrix():
    return _matrix(_load_iam_records("service_accounts"), "groups")
