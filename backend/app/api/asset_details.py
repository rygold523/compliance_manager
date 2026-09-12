from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from pathlib import Path
from copy import deepcopy
from threading import RLock
from typing import Any
import json
import os

from app.core.database import get_db
from app.models import Asset, Evidence

router = APIRouter(prefix="/api/asset-details", tags=["asset-details"])

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/var/lib/ai-vulnerability-management/evidence"))
DETAIL_COLLECTORS = (
    "os_inventory",
    "package_inventory",
    "disk_usage",
    "packages",
    "apt_policy",
    "held_packages",
    "resource_usage",
    "available_updates",
)
_DETAIL_CACHE_LOCK = RLock()
_DETAIL_CACHE: dict[str, Any] = {
    "state": None,
    "response": None,
}


def _latest_db_evidence(db: Session, asset_id: str, collector: str):
    return (
        db.query(Evidence)
        .filter(Evidence.asset_id == asset_id)
        .filter(Evidence.collector == collector)
        .order_by(Evidence.id.desc())
        .first()
    )


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(errors="ignore"))
    except Exception:
        return {}


def _unwrap(data):
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


def _latest_file_payload(asset_id: str, collector: str):
    cdir = EVIDENCE_ROOT / asset_id / collector
    if not cdir.exists():
        return {}

    newest = None
    newest_mtime = -1

    for path in cdir.glob("*.json"):
        data = _read_json(path)

        if data.get("collector") != collector:
            continue

        if data.get("status") and data.get("status") != "completed":
            continue

        try:
            mtime = path.stat().st_mtime
        except Exception:
            continue

        if mtime > newest_mtime:
            newest = path
            newest_mtime = mtime

    if not newest:
        return {}

    return _unwrap(_read_json(newest))


def _legacy_output(db: Session, asset_id: str, collector: str):
    ev = _latest_db_evidence(db, asset_id, collector)
    if not ev:
        return ""

    data = _read_json(ev.file_path)
    return data.get("stdout") or data.get("output") or data.get("raw_output") or ""


def _parse_os(payload):
    result = {
        "os_name": "Unknown",
        "os_version": "Unknown",
        "kernel_version": "Unknown",
    }

    if isinstance(payload, dict) and payload:
        os_release = payload.get("os_release") or {}

        result["os_name"] = (
            os_release.get("PRETTY_NAME")
            or os_release.get("NAME")
            or payload.get("os_name")
            or payload.get("os")
            or "Unknown"
        )

        result["os_version"] = (
            os_release.get("VERSION_ID")
            or os_release.get("VERSION")
            or payload.get("os_version")
            or "Unknown"
        )

        result["kernel_version"] = (
            payload.get("kernel")
            or payload.get("kernel_version")
            or "Unknown"
        )

        return result

    return result


def _parse_resource(payload):
    result = {
        "cpu_cores": "Unknown",
        "memory_total_mb": "Unknown",
        "disk_total": "Unknown",
    }

    if isinstance(payload, dict):
        result["cpu_cores"] = str(payload.get("cpu_cores") or payload.get("cpu") or "Unknown")

        mem = payload.get("memory_total_mb") or payload.get("memory_mb") or payload.get("memory")
        if mem is not None:
            result["memory_total_mb"] = str(mem)

        disk = payload.get("disk_total") or payload.get("root_disk_allocated") or payload.get("disk_allocated")
        if disk is not None:
            result["disk_total"] = str(disk)

    return result


def _parse_legacy_resource(output):
    result = {
        "cpu_cores": "Unknown",
        "memory_total_mb": "Unknown",
        "disk_total": "Unknown",
    }

    for line in str(output or "").splitlines():
        line = line.strip()

        if line.startswith("CPU_CORES="):
            result["cpu_cores"] = line.split("=", 1)[1].strip()

        elif line.startswith("MEMORY="):
            parts = line.split("=", 1)[1].split()
            if parts:
                result["memory_total_mb"] = parts[0]

        elif line.startswith("DISK_ALLOCATED_BYTES="):
            try:
                gb = float(line.split("=", 1)[1].strip()) / 1024 / 1024 / 1024
                result["disk_total"] = f"{gb:.0f}G"
            except Exception:
                pass

    return result


def _package_status_from_new(payload):
    if not isinstance(payload, dict):
        return []

    packages = payload.get("packages") or []
    if not isinstance(packages, list):
        return []

    rows = []
    for p in packages:
        if not isinstance(p, dict):
            continue

        name = p.get("name") or p.get("package")
        if not name:
            continue

        installed = p.get("installed_version") or p.get("version") or ""
        candidate = p.get("latest_candidate") or p.get("candidate") or installed
        held = p.get("held") or "no"

        update_available = p.get("update_available")
        if update_available is None:
            update_available = "yes" if candidate and installed and candidate != installed else "no"

        rows.append({
            "name": name,
            "installed_version": installed,
            "latest_candidate": candidate,
            "update_available": str(update_available),
            "held": str(held),
        })

    return rows


def _available_update_count(payload):
    if not isinstance(payload, dict):
        return 0

    available_count = payload.get("available_count")
    if available_count is not None:
        try:
            return max(0, int(available_count))
        except (TypeError, ValueError):
            pass

    updates = payload.get("updates")
    if isinstance(updates, list):
        return len(updates)

    return 0


def _parse_dpkg(output):
    packages = []

    for line in str(output).splitlines():
        if not line.startswith("ii "):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        packages.append({
            "name": parts[1],
            "installed_version": parts[2],
            "latest_candidate": "Latest version information not available",
            "update_available": "unknown",
            "held": "no",
        })

    return packages


def _parse_apt_policy(output):
    package_map = {}
    current = None

    for raw in str(output).splitlines():
        line = raw.rstrip()

        if line and not line.startswith(" ") and line.endswith(":"):
            current = line[:-1]
            package_map[current] = {
                "candidate": "Latest version information not available",
                "installed": None,
            }
            continue

        if not current:
            continue

        stripped = line.strip()

        if stripped.startswith("Installed:"):
            package_map[current]["installed"] = stripped.split(":", 1)[1].strip()

        elif stripped.startswith("Candidate:"):
            package_map[current]["candidate"] = stripped.split(":", 1)[1].strip()

    return package_map


def _parse_held(output):
    return {line.strip() for line in str(output).splitlines() if line.strip()}


def _merge_package_status(packages, apt_policy, held_packages):
    merged = []

    for pkg in packages:
        name = pkg["name"]
        normalized = name.split(":", 1)[0]
        info = apt_policy.get(name) or apt_policy.get(normalized) or {}

        installed = pkg["installed_version"]
        candidate = info.get("candidate") or pkg.get("latest_candidate") or "Latest version information not available"

        if candidate == "Latest version information not available":
            update_available = "unknown"
        elif candidate == installed:
            update_available = "no"
        else:
            update_available = "yes"

        merged.append({
            "name": name,
            "installed_version": installed,
            "latest_candidate": candidate,
            "update_available": update_available,
            "held": "yes" if name in held_packages else "no",
        })

    return merged


def _latest_evidence_map(db: Session):
    latest_ids = (
        db.query(func.max(Evidence.id).label("id"))
        .filter(Evidence.collector.in_(DETAIL_COLLECTORS))
        .filter(Evidence.validated.is_(True))
        .group_by(Evidence.asset_id, Evidence.collector)
        .subquery()
    )
    rows = (
        db.query(Evidence)
        .join(latest_ids, Evidence.id == latest_ids.c.id)
        .all()
    )
    return {
        (row.asset_id, row.collector): row
        for row in rows
    }


def _payload_from_evidence(evidence):
    if evidence is None:
        return {}
    return _unwrap(_read_json(evidence.file_path))


def _output_from_evidence(evidence):
    if evidence is None:
        return ""
    data = _read_json(evidence.file_path)
    return (
        data.get("stdout")
        or data.get("output")
        or data.get("raw_output")
        or ""
    )


@router.get("/")
def list_asset_details(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.id.asc()).all()
    latest_evidence_id = (
        db.query(func.max(Evidence.id))
        .filter(Evidence.collector.in_(DETAIL_COLLECTORS))
        .filter(Evidence.validated.is_(True))
        .scalar()
    )
    asset_state = tuple(
        (
            asset.id,
            asset.asset_id,
            asset.hostname,
            asset.address,
            asset.environment,
            asset.agent_status,
            asset.os_family,
        )
        for asset in assets
    )
    cache_state = (asset_state, latest_evidence_id)

    with _DETAIL_CACHE_LOCK:
        if (
            _DETAIL_CACHE["response"] is not None
            and _DETAIL_CACHE["state"] == cache_state
        ):
            return deepcopy(_DETAIL_CACHE["response"])

    evidence = _latest_evidence_map(db)
    results = []

    for asset in assets:
        asset_id = asset.asset_id

        os_payload = _payload_from_evidence(
            evidence.get((asset_id, "os_inventory"))
        )
        pkg_payload = _payload_from_evidence(
            evidence.get((asset_id, "package_inventory"))
        )
        disk_payload = _payload_from_evidence(
            evidence.get((asset_id, "disk_usage"))
        )
        update_payload = _payload_from_evidence(
            evidence.get((asset_id, "available_updates"))
        )

        os_info = _parse_os(os_payload)

        package_status = _package_status_from_new(pkg_payload)
        available_update_count = _available_update_count(
            update_payload
        )

        if not package_status:
            legacy_packages = _parse_dpkg(
                _output_from_evidence(
                    evidence.get((asset_id, "packages"))
                )
            )
            legacy_policy = _parse_apt_policy(
                _output_from_evidence(
                    evidence.get((asset_id, "apt_policy"))
                )
            )
            legacy_held = _parse_held(
                _output_from_evidence(
                    evidence.get((asset_id, "held_packages"))
                )
            )
            package_status = _merge_package_status(legacy_packages, legacy_policy, legacy_held)

        resource_usage = _parse_resource(disk_payload)
        if resource_usage["disk_total"] == "Unknown":
            resource_usage = _parse_legacy_resource(
                _output_from_evidence(
                    evidence.get((asset_id, "resource_usage"))
                )
            )

        results.append({
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "address": asset.address,
            "environment": asset.environment,
            "agent_status": asset.agent_status,
            "os_family": getattr(asset, "os_family", None) or "linux",
            "os_name": os_info["os_name"],
            "os_version": os_info["os_version"],
            "kernel_version": os_info["kernel_version"],
            "package_count": len(package_status),
            "packages_with_updates": max(
                len([
                    p for p in package_status
                    if p["update_available"] == "yes"
                ]),
                available_update_count,
            ),
            "packages_unknown_latest": len([p for p in package_status if p["update_available"] == "unknown"]),
            "held_packages": len([p for p in package_status if p["held"] == "yes"]),
            "resources": resource_usage,
            "packages": package_status,
        })

    response = {
        "asset_count": len(results),
        "assets": results,
    }
    with _DETAIL_CACHE_LOCK:
        _DETAIL_CACHE["state"] = cache_state
        _DETAIL_CACHE["response"] = response
    return deepcopy(response)
