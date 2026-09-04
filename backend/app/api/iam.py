from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Evidence

router = APIRouter(prefix="/api/iam", tags=["iam"])

EVIDENCE_ROOT = Path(
    os.environ.get(
        "EVIDENCE_ROOT",
        "/var/lib/ai-vulnerability-management/evidence",
    )
)
IAM_CACHE_TTL_SECONDS = max(
    0.0,
    float(os.environ.get("IAM_CACHE_TTL_SECONDS", "1.0")),
)

_CACHE_LOCK = RLock()
_CACHE: dict[str, Any] = {
    "checked_at": 0.0,
    "state": None,
    "database_state": None,
    "snapshot": None,
}


def _is_quarantined(path: Path) -> bool:
    return any(str(part).startswith("_quarantine") for part in path.parts)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except (OSError, ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _parse_evidence_payload(data: dict[str, Any]) -> dict[str, Any]:
    stdout = data.get("stdout")
    if isinstance(stdout, str) and stdout.strip():
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    return data


def _iam_directories() -> list[tuple[str, Path]]:
    if not EVIDENCE_ROOT.exists():
        return []

    directories = []
    try:
        asset_directories = EVIDENCE_ROOT.iterdir()
    except OSError:
        return []

    for asset_dir in asset_directories:
        if not asset_dir.is_dir() or _is_quarantined(asset_dir):
            continue
        iam_dir = asset_dir / "iam_users"
        if iam_dir.is_dir():
            directories.append((asset_dir.name, iam_dir))
    return directories


def _evidence_state(
    directories: list[tuple[str, Path]],
) -> tuple[tuple[str, int, int, int], ...]:
    """Return a cheap fingerprint that changes when IAM evidence changes."""
    state = []

    for asset_id, iam_dir in directories:
        try:
            directory_mtime = iam_dir.stat().st_mtime_ns
        except OSError:
            continue

        newest_mtime = 0
        file_count = 0
        try:
            for path in iam_dir.glob("*.json"):
                if _is_quarantined(path):
                    continue
                try:
                    newest_mtime = max(newest_mtime, path.stat().st_mtime_ns)
                    file_count += 1
                except OSError:
                    continue
        except OSError:
            continue

        state.append((asset_id, directory_mtime, newest_mtime, file_count))

    return tuple(sorted(state))


def _latest_completed_wrapper(iam_dir: Path) -> dict[str, Any]:
    """Read newest files first and stop after the latest valid collection."""
    candidates = []
    try:
        for path in iam_dir.glob("*.json"):
            if _is_quarantined(path):
                continue
            try:
                candidates.append((path.stat().st_mtime_ns, path))
            except OSError:
                continue
    except OSError:
        return {}

    for _, path in sorted(candidates, reverse=True):
        wrapper = _read_json(path)
        if (
            wrapper.get("collector") == "iam_users"
            and wrapper.get("status") == "completed"
        ):
            return wrapper
    return {}


def _records_from_wrapper(
    asset_id: str,
    wrapper: dict[str, Any],
    kind: str,
) -> list[dict[str, Any]]:
    payload = _parse_evidence_payload(wrapper)
    hostname = payload.get("hostname") or wrapper.get("hostname") or asset_id
    collected_at = payload.get("collected_at") or wrapper.get("collected_at")
    items = payload.get(kind, [])
    if not isinstance(items, list):
        return []

    records = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        dedupe_key = (
            asset_id,
            item.get("username"),
            item.get("uid"),
            item.get("home"),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        row = dict(item)
        row["asset_id"] = asset_id
        row["hostname"] = hostname
        row["collected_at"] = collected_at
        records.append(row)
    return records


def _matrix(records: list[dict[str, Any]], field: str) -> dict[str, Any]:
    servers = sorted(
        {record["asset_id"] for record in records if record.get("asset_id")}
    )
    values: dict[tuple[str, str], Any] = {}
    for record in records:
        username = record.get("username")
        server = record.get("asset_id")
        if username and server:
            values.setdefault((username, server), record.get(field, []))

    rows = []
    for username in sorted({username for username, _ in values}):
        row = {"username": username}
        for server in servers:
            value = values.get((username, server), "")
            row[server] = (
                ", ".join(str(item) for item in value)
                if isinstance(value, list)
                else str(value)
            )
        rows.append(row)
    return {"servers": servers, "rows": rows}


def _build_snapshot(
    directories: list[tuple[str, Path]],
) -> dict[str, Any]:
    users = []
    service_accounts = []
    for asset_id, iam_dir in directories:
        wrapper = _latest_completed_wrapper(iam_dir)
        if not wrapper:
            continue
        users.extend(_records_from_wrapper(asset_id, wrapper, "users"))
        service_accounts.extend(
            _records_from_wrapper(asset_id, wrapper, "service_accounts")
        )

    return {
        "users": users,
        "service_accounts": service_accounts,
        "access_matrix": _matrix(users, "access"),
        "group_matrix": _matrix(users, "groups"),
        "service_account_matrix": _matrix(service_accounts, "groups"),
    }


def _get_filesystem_snapshot() -> dict[str, Any]:
    now = monotonic()
    with _CACHE_LOCK:
        snapshot = _CACHE["snapshot"]
        if (
            snapshot is not None
            and now - _CACHE["checked_at"] < IAM_CACHE_TTL_SECONDS
        ):
            return snapshot

        directories = _iam_directories()
        state = _evidence_state(directories)
        _CACHE["checked_at"] = now
        if snapshot is not None and state == _CACHE["state"]:
            return snapshot

        snapshot = _build_snapshot(directories)
        _CACHE["state"] = state
        _CACHE["snapshot"] = snapshot
        return snapshot


def _latest_database_wrappers(
    db: Session,
) -> list[tuple[str, dict[str, Any]]]:
    latest_ids = (
        db.query(func.max(Evidence.id).label("id"))
        .filter(Evidence.collector == "iam_users")
        .filter(Evidence.validated.is_(True))
        .group_by(Evidence.asset_id)
        .subquery()
    )
    evidence_rows = (
        db.query(Evidence)
        .join(latest_ids, Evidence.id == latest_ids.c.id)
        .all()
    )

    wrappers = []
    for evidence in evidence_rows:
        wrapper = _read_json(Path(evidence.file_path))
        if (
            wrapper.get("collector") == "iam_users"
            and wrapper.get("status") == "completed"
        ):
            wrappers.append((evidence.asset_id, wrapper))
    return wrappers


def _get_snapshot(db: Session | None = None) -> dict[str, Any]:
    if db is None:
        return _get_filesystem_snapshot()

    database_state = (
        db.query(func.max(Evidence.id))
        .filter(Evidence.collector == "iam_users")
        .filter(Evidence.validated.is_(True))
        .scalar()
    )
    if database_state is None:
        return _get_filesystem_snapshot()

    with _CACHE_LOCK:
        if (
            _CACHE["snapshot"] is not None
            and _CACHE["database_state"] == database_state
        ):
            return _CACHE["snapshot"]

        users = []
        service_accounts = []
        for asset_id, wrapper in _latest_database_wrappers(db):
            users.extend(_records_from_wrapper(asset_id, wrapper, "users"))
            service_accounts.extend(
                _records_from_wrapper(asset_id, wrapper, "service_accounts")
            )

        snapshot = {
            "users": users,
            "service_accounts": service_accounts,
            "access_matrix": _matrix(users, "access"),
            "group_matrix": _matrix(users, "groups"),
            "service_account_matrix": _matrix(service_accounts, "groups"),
        }
        _CACHE["database_state"] = database_state
        _CACHE["snapshot"] = snapshot
        return snapshot


@router.get("/snapshot")
def snapshot(db: Session = Depends(get_db)):
    """Return all IAM views from one consistent evidence snapshot."""
    return deepcopy(_get_snapshot(db))


@router.get("/users")
def users(db: Session = Depends(get_db)):
    return {"users": deepcopy(_get_snapshot(db)["users"])}


@router.get("/service-accounts")
def service_accounts(db: Session = Depends(get_db)):
    return {
        "service_accounts": deepcopy(
            _get_snapshot(db)["service_accounts"]
        )
    }


@router.get("/access-matrix")
def access_matrix(db: Session = Depends(get_db)):
    return deepcopy(_get_snapshot(db)["access_matrix"])


@router.get("/group-matrix")
def group_matrix(db: Session = Depends(get_db)):
    return deepcopy(_get_snapshot(db)["group_matrix"])


@router.get("/service-account-matrix")
def service_account_matrix(db: Session = Depends(get_db)):
    return deepcopy(_get_snapshot(db)["service_account_matrix"])
