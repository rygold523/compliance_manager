from fastapi import APIRouter
from pathlib import Path
import json
import os

router = APIRouter(prefix="/api/iam", tags=["iam"])

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/var/lib/ai-vulnerability-management/evidence"))

def load_iam_evidence():
    records = []
    if not EVIDENCE_ROOT.exists():
        return records

    for path in EVIDENCE_ROOT.rglob("*.json"):
        try:
            data = json.loads(path.read_text(errors="ignore"))
        except Exception:
            continue

        if data.get("collector") != "iam_users":
            continue

        asset_id = data.get("asset_id") or data.get("hostname") or path.parent.name
        hostname = data.get("hostname") or asset_id

        for user in data.get("users", []):
            row = dict(user)
            row["asset_id"] = asset_id
            row["hostname"] = hostname
            row["collected_at"] = data.get("collected_at")
            records.append(row)

    return records

@router.get("/users")
def users():
    return {"users": load_iam_evidence()}

@router.get("/access-matrix")
def access_matrix():
    records = load_iam_evidence()
    users = sorted(set(r["username"] for r in records))
    servers = sorted(set(r["asset_id"] for r in records))

    matrix = []
    for username in users:
        row = {"username": username}
        for server in servers:
            matches = [r for r in records if r["username"] == username and r["asset_id"] == server]
            if not matches:
                row[server] = ""
            else:
                row[server] = ", ".join(matches[0].get("access", ["None"]))
        matrix.append(row)

    return {"servers": servers, "rows": matrix}

@router.get("/group-matrix")
def group_matrix():
    records = load_iam_evidence()
    users = sorted(set(r["username"] for r in records))
    servers = sorted(set(r["asset_id"] for r in records))

    matrix = []
    for username in users:
        row = {"username": username}
        for server in servers:
            matches = [r for r in records if r["username"] == username and r["asset_id"] == server]
            if not matches:
                row[server] = ""
            else:
                row[server] = ", ".join(matches[0].get("groups", []))
        matrix.append(row)

    return {"servers": servers, "rows": matrix}
