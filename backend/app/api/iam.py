from fastapi import APIRouter
from pathlib import Path
import json
import os

router = APIRouter(prefix="/api/iam", tags=["iam"])

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/var/lib/ai-vulnerability-management/evidence"))


def _is_quarantined(path: Path) -> bool:
    return any(str(part).startswith("_quarantine") for part in path.parts)


def _parse_evidence_payload(data: dict) -> dict:
    """
    Normal collector evidence wraps command output in stdout.
    IAM collector stdout contains the real JSON payload.
    """
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


def _load_iam_records(kind: str):
    records = []

    if not EVIDENCE_ROOT.exists():
        return records

    for path in EVIDENCE_ROOT.rglob("*.json"):
        if _is_quarantined(path):
            continue

        try:
            wrapper = json.loads(path.read_text(errors="ignore"))
        except Exception:
            continue

        if wrapper.get("collector") != "iam_users":
            continue

        if wrapper.get("status") and wrapper.get("status") != "completed":
            continue

        payload = _parse_evidence_payload(wrapper)

        asset_id = wrapper.get("asset_id") or payload.get("asset_id") or payload.get("hostname") or path.parent.parent.name
        hostname = payload.get("hostname") or wrapper.get("hostname") or asset_id
        collected_at = payload.get("collected_at") or wrapper.get("collected_at")

        for item in payload.get(kind, []):
            if not isinstance(item, dict):
                continue

            row = dict(item)
            row["asset_id"] = asset_id
            row["hostname"] = hostname
            row["collected_at"] = collected_at
            records.append(row)

    return records


def _matrix(records, field):
    usernames = sorted(set(r.get("username", "") for r in records if r.get("username")))
    servers = sorted(set(r.get("asset_id", "") for r in records if r.get("asset_id")))

    rows = []

    for username in usernames:
        row = {"username": username}

        for server in servers:
            matches = [
                r for r in records
                if r.get("username") == username and r.get("asset_id") == server
            ]

            if not matches:
                row[server] = ""
                continue

            value = matches[0].get(field, [])

            if isinstance(value, list):
                row[server] = ", ".join(str(v) for v in value)
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
